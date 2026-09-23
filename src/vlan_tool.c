/*
 * vlan_tool.c - Linux VLAN and non-VLAN TCP/UDP test tool
 *
 * Self-contained implementation (no Npcap/WinDivert dependency).
 * Supports four combinations:
 *   - VLAN TCP   client/server  (AF_PACKET raw frames + 802.1Q)
 *   - VLAN UDP   client/server  (AF_PACKET raw frames + 802.1Q)
 *   - non-VLAN TCP client/server (regular SOCK_STREAM)
 *   - non-VLAN UDP client/server (regular SOCK_DGRAM)
 *
 * Build:  make -f Makefile.linux
 * Usage:  ./vlan_tool -s|-c host [-p port] [-t sec] [-b bw] [-P n]
 *                [-V vlan_id] [-u] [-B if] [-J] [-i interval]
 *
 * VLAN mode requires root and a bindable interface (-B eth0).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <ifaddrs.h>

/* ───────────── constants ───────────── */
#define ETH_P_8021Q   0x8100
#define IPPROTO_EXP   250   /* experimental; avoids kernel interference */
#define MAX_PKT       2048
#define MAX_STREAMS   256
#define PAYLOAD_SZ    1400
#define ARP_TIMEOUT   3
#define TCP_RTO_INIT  1000   /* ms */
#define TCP_RTO_MAX   60000  /* ms */

/* ───────────── options ───────────── */
typedef struct {
    int       is_server;
    int       use_udp;
    int       use_vlan;
    int       port;
    char      host[64];
    int       duration;        /* seconds */
    uint64_t  bandwidth;       /* bits/sec, 0 = unlimited */
    int       streams;
    uint16_t  vlan_id;
    int       report_interval;
    int       json;
    char      bind_if[32];
    uint32_t  bind_ip;         /* network order */
} opts_t;

static volatile sig_atomic_t g_stop = 0;
static opts_t g_opt;

/* ───────────── helpers ───────────── */
static void on_signal(int s) { (void)s; g_stop = 1; }

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static uint64_t now_ms(void) {
    return (uint64_t)(now_sec() * 1000.0);
}

/* Internet checksum (RFC 1071) */
static uint16_t checksum(const void *data, int len) {
    const uint8_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += (p[0] << 8) | p[1]; p += 2; len -= 2; }
    if (len) sum += p[0] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* IP pseudo-header checksum contribution */
static uint16_t pseudo_cksum(uint32_t src, uint32_t dst,
                              uint8_t proto, uint16_t len) {
    struct { uint32_t s, d; uint8_t z, p; uint16_t l; } ph;
    ph.s = src; ph.d = dst; ph.z = 0; ph.p = proto; ph.l = htons(len);
    return checksum(&ph, sizeof(ph));
}

static void fmt_rate(uint64_t bits, double secs, char *buf, int sz) {
    double bps = (secs > 0) ? bits / secs : 0;
    if (bps >= 1e9) snprintf(buf, sz, "%.2f Gbits/sec", bps / 1e9);
    else if (bps >= 1e6) snprintf(buf, sz, "%.2f Mbits/sec", bps / 1e6);
    else if (bps >= 1e3) snprintf(buf, sz, "%.2f Kbits/sec", bps / 1e3);
    else snprintf(buf, sz, "%.0f bits/sec", bps);
}

static void fmt_bytes(uint64_t b, char *buf, int sz) {
    double v = (double)b;
    const char *u = "Bytes";
    if (v >= 1e9) { v /= 1e9; u = "GBytes"; }
    else if (v >= 1e6) { v /= 1e6; u = "MBytes"; }
    else if (v >= 1e3) { v /= 1e3; u = "KBytes"; }
    snprintf(buf, sz, "%.2f %s", v, u);
}

/* ───────────── bandwidth pacer ───────────── */
typedef struct {
    uint64_t rate_bps;
    double   interval_us;
    double   next_us;
    int      pktsize;
} pacer_t;

static void pacer_init(pacer_t *p, uint64_t bps, int pktsize) {
    p->rate_bps = bps;
    p->pktsize  = pktsize;
    p->interval_us = (bps > 0) ? (double)pktsize * 8.0 / (double)bps * 1e6 : 0;
    p->next_us  = 0;
}

static void pacer_wait(pacer_t *p) {
    if (p->rate_bps <= 0) return;
    double now = now_sec() * 1e6;
    if (p->next_us == 0.0) p->next_us = now + p->interval_us;
    if (now < p->next_us) {
        double us = p->next_us - now;
        if (us > 100.0) { usleep((useconds_t)(us * 0.8)); now = now_sec() * 1e6; }
        while (now_sec() * 1e6 < p->next_us) { /* spin for precision */ }
    }
    p->next_us += p->interval_us;
    if (now_sec() * 1e6 > p->next_us) p->next_us = now_sec() * 1e6 + p->interval_us;
}

/* ───────────── interface helpers ───────────── */
static int if_get_index(const char *name) {
    return if_nametoindex(name);
}

static int if_get_mac(const char *name, uint8_t mac[6]) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", name);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    unsigned m[6];
    if (fscanf(f, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) != 6) {
        fclose(f); return -1;
    }
    fclose(f);
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
    return 0;
}

static int if_get_ip(const char *name, uint32_t *ip) {
    struct ifaddrs *ifap, *p;
    if (getifaddrs(&ifap) != 0) return -1;
    for (p = ifap; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(p->ifa_name, name) != 0) continue;
        *ip = ((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr;
        freeifaddrs(ifap);
        return 0;
    }
    freeifaddrs(ifap);
    return -1;
}

/* ───────────── TCP helpers ───────────── */
static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                              const void *seg, int seglen) {
    uint16_t ph = pseudo_cksum(src_ip, dst_ip, IPPROTO_TCP, seglen);
    uint32_t sum = 0;
    const uint8_t *p = seg;
    /* Fold pseudo checksum with segment */
    sum = ~ph & 0xffff;
    while (seglen > 1) { sum += (p[0] << 8) | p[1]; p += 2; seglen -= 2; }
    if (seglen) sum += p[0] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t udp_checksum(uint32_t src_ip, uint32_t dst_ip,
                              const void *seg, int seglen) {
    uint16_t ph = pseudo_cksum(src_ip, dst_ip, IPPROTO_UDP, seglen);
    uint32_t sum = (~ph) & 0xffff;
    const uint8_t *p = seg;
    while (seglen > 1) { sum += (p[0] << 8) | p[1]; p += 2; seglen -= 2; }
    if (seglen) sum += p[0] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ═══════════════════════════════════════════════════════════════
 *  VLAN MODE  (AF_PACKET)
 * ═══════════════════════════════════════════════════════════════ */

/* VLAN TCP state machine */
typedef enum { VST_CLOSED, VST_SYN_SENT, VST_SYN_RECV,
               VST_ESTABLISHED, VST_FIN_WAIT, VST_CLOSING } vst_t;

typedef struct {
    int       sock;
    uint32_t  src_ip, dst_ip;
    uint8_t   src_mac[6], dst_mac[6];
    uint16_t  src_port, dst_port;
    uint16_t  vlan_id;
    uint32_t  seq, ack;
    vst_t     state;
    uint64_t  tx_bytes, rx_bytes;
    uint64_t  rto_ms;
    uint64_t  rtx_deadline;
    uint8_t   last_flag;
    int       is_server;
    uint32_t  peer_seq;       /* last seq seen from peer */
    uint32_t  peer_ack;       /* last ack from peer */
    int       peer_win;
    uint8_t   buf[MAX_PKT];
    int       buflen;
} vlan_stream_t;

/* Build a VLAN-tagged IP packet */
static int build_vlan_pkt(uint8_t *pkt, int pktsz,
                           const uint8_t dstmac[6], const uint8_t srcmac[6],
                           uint16_t vlan_id, uint32_t src_ip, uint32_t dst_ip,
                           uint8_t proto, const void *payload, int paylen) {
    if (pktsz < 14 + 4 + 20 + paylen) return -1;
    struct ether_header *eh = (struct ether_header *)pkt;
    memcpy(eh->ether_dhost, dstmac, 6);
    memcpy(eh->ether_shost, srcmac, 6);
    eh->ether_type = htons(ETH_P_8021Q);

    /* 802.1Q tag */
    uint16_t *tag = (uint16_t *)(pkt + 14);
    tag[0] = htons(vlan_id & 0x0fff);
    tag[1] = htons(proto == IPPROTO_TCP ? ETHERTYPE_IP :
                   proto == IPPROTO_UDP ? ETHERTYPE_IP : 0x0800);

    /* IP header */
    struct iphdr *ip = (struct iphdr *)(pkt + 18);
    memset(ip, 0, 20);
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tot_len  = htons(20 + paylen);
    ip->ttl      = 64;
    ip->protocol = proto;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;
    ip->check    = checksum(ip, 20);

    if (paylen > 0)
        memcpy(pkt + 18 + 20, payload, paylen);
    return 18 + 20 + paylen;
}

/* Build a TCP segment (caller provides buffer) */
static int build_tcp_seg(uint8_t *seg, int segsz,
                          uint16_t sp, uint16_t dp,
                          uint32_t seq, uint32_t ack,
                          uint8_t flags, uint16_t win,
                          const void *data, int datalen) {
    if (segsz < 20 + datalen) return -1;
    struct tcphdr *tcp = (struct tcphdr *)seg;
    memset(tcp, 0, 20);
    tcp->source  = htons(sp);
    tcp->dest    = htons(dp);
    tcp->seq     = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff    = 5;
    tcp->window  = htons(win);
    if (flags & 0x02) tcp->syn = 1;
    if (flags & 0x10) tcp->ack = 1;
    if (flags & 0x01) tcp->fin = 1;
    if (flags & 0x08) tcp->psh = 1;
    if (flags & 0x04) tcp->rst = 1;
    if (datalen > 0)
        memcpy(seg + 20, data, datalen);
    /* checksum set by caller after IP known */
    return 20 + datalen;
}

/* Build a UDP datagram */
static int build_udp_dat(uint8_t *seg, int segsz,
                          uint16_t sp, uint16_t dp,
                          const void *data, int datalen) {
    if (segsz < 8 + datalen) return -1;
    struct udphdr *udp = (struct udphdr *)seg;
    udp->source = htons(sp);
    udp->dest   = htons(dp);
    udp->len    = htons(8 + datalen);
    udp->check  = 0;
    if (datalen > 0)
        memcpy(seg + 8, data, datalen);
    return 8 + datalen;
}

/* Send a raw packet out AF_PACKET */
static int vlan_send(vlan_stream_t *vs, const void *data, int len) {
    uint8_t pkt[MAX_PKT];
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex  = if_get_index(g_opt.bind_if);
    sa.sll_halen    = 6;
    memcpy(sa.sll_addr, vs->dst_mac, 6);

    int n = sendto(vs->sock, data, len, 0,
                   (struct sockaddr *)&sa, sizeof(sa));
    if (n > 0) vs->tx_bytes += (uint64_t)n;
    return n;
}

/* Resolve ARP for dst_ip, fills dst_mac */
static int arp_resolve(int sock, const char *ifname,
                        uint32_t src_ip, const uint8_t src_mac[6],
                        uint32_t dst_ip, uint8_t dst_mac[6],
                        uint16_t vlan_id) {
    uint8_t pkt[MAX_PKT];
    struct ether_header *eh = (struct ether_header *)pkt;
    memset(eh->ether_dhost, 0xff, 6);       /* broadcast */
    memcpy(eh->ether_shost, src_mac, 6);
    eh->ether_type = htons(ETH_P_8021Q);

    uint16_t *tag = (uint16_t *)(pkt + 14);
    tag[0] = htons(vlan_id & 0x0fff);
    tag[1] = htons(ETH_P_ARP);

    struct arphdr *ah = (struct arphdr *)(pkt + 18);
    ah->ar_hrd = htons(ARPHRD_ETHER);
    ah->ar_pro = htons(ETH_P_IP);
    ah->ar_hln = 6;
    ah->ar_pln = 4;
    ah->ar_op  = htons(ARPOP_REQUEST);

    uint8_t *payload = pkt + 18 + sizeof(struct arphdr);
    memcpy(payload, src_mac, 6);  payload += 6;
    memcpy(payload, &src_ip, 4);  payload += 4;
    memset(payload, 0, 6);        payload += 6;  /* zero target mac */
    memcpy(payload, &dst_ip, 4);  payload += 4;

    int pktlen = (int)(payload - pkt);
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex  = if_get_index(ifname);
    sa.sll_halen    = 6;
    memset(sa.sll_addr, 0xff, 6);

    fd_set rfds;
    struct timeval tv;
    for (int attempt = 0; attempt < ARP_TIMEOUT; attempt++) {
        sendto(sock, pkt, pktlen, 0, (struct sockaddr *)&sa, sizeof(sa));
        /* wait for reply */
        for (int w = 0; w < 10; w++) {
            FD_ZERO(&rfds);
            FD_SET(sock, &rfds);
            tv.tv_sec = 0; tv.tv_usec = 100000;
            if (select(sock + 1, &rfds, NULL, NULL, &tv) <= 0) continue;

            uint8_t rx[MAX_PKT];
            struct sockaddr_ll from;
            socklen_t fromlen = sizeof(from);
            int n = recvfrom(sock, rx, sizeof(rx), 0,
                             (struct sockaddr *)&from, &fromlen);
            if (n < 18 + (int)sizeof(struct arphdr) + 16) continue;
            if (ntohs(eh->ether_type) != ETH_P_8021Q) continue;
            uint16_t *rtag = (uint16_t *)(rx + 14);
            if (ntohs(rtag[1]) != ETH_P_ARP) continue;
            struct arphdr *rah = (struct arphdr *)(rx + 18);
            if (ntohs(rah->ar_op) != ARPOP_REPLY) continue;
            uint8_t *rp = rx + 18 + sizeof(struct arphdr);
            uint32_t sip;
            memcpy(&sip, rp + 6 + 4, 4);
            if (sip == dst_ip) {
                memcpy(dst_mac, rp, 6);
                return 0;
            }
        }
    }
    return -1;
}

/* ───────────── VLAN TCP ───────────── */
static void vlan_tcp_set_checksum(vlan_stream_t *vs, uint8_t *seg, int seglen) {
    struct tcphdr *tcp = (struct tcphdr *)seg;
    tcp->check = 0;
    tcp->check = tcp_checksum(vs->src_ip, vs->dst_ip, seg, seglen);
}

static int vlan_tcp_send_flag(vlan_stream_t *vs, uint8_t flags,
                               const void *data, int datalen) {
    uint8_t seg[MAX_PKT];
    int seglen = build_tcp_seg(seg, sizeof(seg),
                                vs->src_port, vs->dst_port,
                                vs->seq, vs->ack, flags,
                                65535, data, datalen);
    vlan_tcp_set_checksum(vs, seg, seglen);

    uint8_t pkt[MAX_PKT];
    int pktlen = build_vlan_pkt(pkt, sizeof(pkt),
                                 vs->dst_mac, vs->src_mac, vs-> vlan_id,
                                 vs->src_ip, vs->dst_ip,
                                 IPPROTO_TCP, seg, seglen);
    if (pktlen < 0) return -1;
    int n = vlan_send(vs, pkt, pktlen);
    if (n > 0 && (flags & (0x02 | 0x01))) { /* SYN or FIN */
        vs->seq++;
    }
    if (n > 0 && datalen > 0)
        vs->seq += datalen;
    if (n > 0) {
        vs->last_flag = flags;
        vs->rtx_deadline = now_ms() + vs->rto_ms;
    }
    return n;
}

/* Parse incoming packet, returns 1 if it matches this stream */
static int vlan_tcp_input(vlan_stream_t *vs, const uint8_t *pkt, int pktlen) {
    if (pktlen < 18 + 20 + 20) return 0;
    struct ether_header *eh = (struct ether_header *)pkt;
    if (ntohs(eh->ether_type) != ETH_P_8021Q) return 0;
    uint16_t *tag = (uint16_t *)(pkt + 14);
    if (ntohs(tag[0]) != (vs->vlan_id & 0x0fff)) return 0;
    if (ntohs(tag[1]) != ETHERTYPE_IP) return 0;

    struct iphdr *ip = (struct iphdr *)(pkt + 18);
    if (ip->protocol != IPPROTO_TCP) return 0;
    if (ip->daddr != vs->src_ip || ip->saddr != vs->dst_ip) return 0;

    int iphl = ip->ihl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(pkt + 18 + iphl);
    uint16_t sp = ntohs(tcp->source);
    uint16_t dp = ntohs(tcp->dest);
    if (sp != vs->dst_port || dp != vs->src_port) return 0;

    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack = ntohl(tcp->ack_seq);
    uint8_t flags = 0;
    if (tcp->syn) flags |= 0x02;
    if (tcp->ack) flags |= 0x10;
    if (tcp->fin) flags |= 0x01;
    if (tcp->rst) flags |= 0x04;
    if (tcp->psh) flags |= 0x08;

    int paylen = ntohs(ip->tot_len) - iphl - tcp->doff * 4;
    if (paylen < 0) paylen = 0;

    vs->peer_seq = seq;
    vs->peer_ack = ack;
    vs->peer_win = ntohs(tcp->window);

    if (flags & 0x04) { vs->state = VST_CLOSED; return 1; }

    switch (vs->state) {
    case VST_SYN_SENT:
        if ((flags & 0x12) == 0x12) { /* SYN+ACK */
            vs->ack = seq + 1;
            vlan_tcp_send_flag(vs, 0x10, NULL, 0);
            vs->state = VST_ESTABLISHED;
        }
        break;
    case VST_SYN_RECV:
        if (flags & 0x10) {
            vs->state = VST_ESTABLISHED;
        }
        break;
    case VST_ESTABLISHED:
        if (paylen > 0) {
            vs->rx_bytes += paylen;
            vs->ack = seq + paylen;
            vlan_tcp_send_flag(vs, 0x10, NULL, 0);
        }
        if (flags & 0x01) {
            vs->ack = seq + 1;
            vlan_tcp_send_flag(vs, 0x11, NULL, 0); /* FIN+ACK */
            vs->state = VST_CLOSING;
        }
        break;
    case VST_FIN_WAIT:
        if (flags & 0x10) {
            vs->state = VST_CLOSED;
        }
        break;
    case VST_CLOSING:
        if (flags & 0x01) {
            vs->ack = seq + 1;
            vlan_tcp_send_flag(vs, 0x10, NULL, 0);
            vs->state = VST_CLOSED;
        }
        break;
    default:
        break;
    }
    if (paylen > 0 && paylen < MAX_PKT) {
        memcpy(vs->buf, pkt + 18 + iphl + tcp->doff * 4, paylen);
        vs->buflen = paylen;
    }
    return 1;
}

static int vlan_tcp_client_stream(vlan_stream_t *vs) {
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex  = if_get_index(g_opt.bind_if);
    vs->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (vs->sock < 0) { perror("socket"); return -1; }
    if (bind(vs->sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind"); close(vs->sock); return -1;
    }

    if (arp_resolve(vs->sock, g_opt.bind_if, vs->src_ip, vs->src_mac,
                    vs->dst_ip, vs->dst_mac, vs->vlan_id) < 0) {
        fprintf(stderr, "ARP resolve failed for %s\n", g_opt.host);
        close(vs->sock); return -1;
    }

    vs->state = VST_SYN_SENT;
    vs->rto_ms = TCP_RTO_INIT;
    vlan_tcp_send_flag(vs, 0x02, NULL, 0); /* SYN */

    double start = now_sec();
    pacer_t pacer;
    pacer_init(&pacer, g_opt.bandwidth, PAYLOAD_SZ + 58);

    fd_set rfds;
    struct timeval tv;
    uint8_t payload[PAYLOAD_SZ];
    memset(payload, 0x55, sizeof(payload));
    int data_sent = 0;

    while (!g_stop) {
        uint64_t tnow = now_ms();
        if (vs->state == VST_CLOSED) break;

        /* retransmit check */
        if (vs->state != VST_ESTABLISHED && vs->state != VST_CLOSED) {
            if (tnow >= vs->rtx_deadline) {
                vlan_tcp_send_flag(vs, vs->last_flag, NULL, 0);
                vs->rto_ms *= 2;
                if (vs->rto_ms > TCP_RTO_MAX) vs->rto_ms = TCP_RTO_MAX;
            }
        }

        /* check duration */
        if (now_sec() - start >= g_opt.duration) {
            if (vs->state == VST_ESTABLISHED) {
                vlan_tcp_send_flag(vs, 0x11, NULL, 0); /* FIN+ACK */
                vs->state = VST_FIN_WAIT;
            }
        }

        /* send data */
        if (vs->state == VST_ESTABLISHED &&
            now_sec() - start < g_opt.duration) {
            pacer_wait(&pacer);
            vlan_tcp_send_flag(vs, 0x18, payload, PAYLOAD_SZ); /* PSH+ACK */
            data_sent += PAYLOAD_SZ;
        }

        /* receive */
        FD_ZERO(&rfds);
        FD_SET(vs->sock, &rfds);
        tv.tv_sec = 0; tv.tv_usec = 1000;
        if (select(vs->sock + 1, &rfds, NULL, NULL, &tv) > 0) {
            uint8_t rx[MAX_PKT];
            int n = recvfrom(vs->sock, rx, sizeof(rx), 0, NULL, NULL);
            if (n > 0) vlan_tcp_input(vs, rx, n);
        }
    }
    close(vs->sock);
    return 0;
}

static int vlan_tcp_server_stream(vlan_stream_t *vs) {
    vs->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (vs->sock < 0) { perror("socket"); return -1; }
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex  = if_get_index(g_opt.bind_if);
    if (bind(vs->sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind"); close(vs->sock); return -1;
    }

    /* drop kernel RST */
    int rc = system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null");
    (void)rc;

    vs->state = VST_CLOSED;
    fd_set rfds;
    struct timeval tv;

    /* wait for SYN */
    while (!g_stop && vs->state == VST_CLOSED) {
        FD_ZERO(&rfds); FD_SET(vs->sock, &rfds);
        tv.tv_sec = 0; tv.tv_usec = 100000;
        if (select(vs->sock + 1, &rfds, NULL, NULL, &tv) > 0) {
            uint8_t rx[MAX_PKT];
            int n = recvfrom(vs->sock, rx, sizeof(rx), 0, NULL, NULL);
            if (n > 0) {
                struct ether_header *eh = (struct ether_header *)rx;
                if (ntohs(eh->ether_type) != ETH_P_8021Q) continue;
                uint16_t *tag = (uint16_t *)(rx + 14);
                if (ntohs(tag[1]) != ETHERTYPE_IP) continue;
                struct iphdr *ip = (struct iphdr *)(rx + 18);
                if (ip->protocol != IPPROTO_TCP) continue;
                int iphl = ip->ihl * 4;
                struct tcphdr *tcp = (struct tcphdr *)(rx + 18 + iphl);
                if (!tcp->syn) continue;
                /* setup stream from incoming SYN */
                vs->dst_ip   = ip->saddr;
                vs->src_ip   = ip->daddr;  /* any - we use bind_ip */
                vs->dst_port = ntohs(tcp->source);
                vs->src_port = g_opt.port;
                memcpy(vs->dst_mac, eh->ether_shost, 6);
                if_get_mac(g_opt.bind_if, vs->src_mac);
                if (vs->src_ip == 0) if_get_ip(g_opt.bind_if, &vs->src_ip);
                vs->seq = 1000;
                vs->ack = ntohl(tcp->seq) + 1;
                vlan_tcp_send_flag(vs, 0x12, NULL, 0); /* SYN+ACK */
                vs->state = VST_SYN_RECV;
            }
        }
    }

    while (!g_stop && vs->state != VST_CLOSED) {
        FD_ZERO(&rfds); FD_SET(vs->sock, &rfds);
        tv.tv_sec = 0; tv.tv_usec = 10000;
        if (select(vs->sock + 1, &rfds, NULL, NULL, &tv) > 0) {
            uint8_t rx[MAX_PKT];
            int n = recvfrom(vs->sock, rx, sizeof(rx), 0, NULL, NULL);
            if (n > 0) vlan_tcp_input(vs, rx, n);
        }
    }

    system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null");
    close(vs->sock);
    return 0;
}

/* ───────────── VLAN UDP ───────────── */
typedef struct {
    uint32_t seq;
    uint32_t ts_ms;
} udp_hdr_t;

static int vlan_udp_client_stream(vlan_stream_t *vs) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return -1; }
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex  = if_get_index(g_opt.bind_if);
    bind(sock, (struct sockaddr *)&sa, sizeof(sa));

    if_get_mac(g_opt.bind_if, vs->src_mac);
    if (arp_resolve(sock, g_opt.bind_if, vs->src_ip, vs->src_mac,
                    vs->dst_ip, vs->dst_mac, vs->vlan_id) < 0) {
        fprintf(stderr, "ARP failed for %s\n", g_opt.host);
        close(sock); return -1;
    }

    pacer_t pacer;
    int pkt_len = sizeof(udp_hdr_t) + PAYLOAD_SZ;
    pacer_init(&pacer, g_opt.bandwidth, pkt_len + 58);

    uint8_t payload[PAYLOAD_SZ];
    memset(payload, 0xAA, sizeof(payload));

    double start = now_sec();
    uint64_t total = 0;
    uint32_t seq = 0;

    fd_set rfds;
    struct timeval tv;

    while (!g_stop && now_sec() - start < g_opt.duration) {
        pacer_wait(&pacer);

        uint8_t seg[MAX_PKT];
        udp_hdr_t *uh = (udp_hdr_t *)seg;
        uh->seq = htonl(seq++);
        uh->ts_ms = htonl((uint32_t)(now_sec() * 1000));
        memcpy(seg + sizeof(udp_hdr_t), payload, PAYLOAD_SZ);
        int seglen = sizeof(udp_hdr_t) + PAYLOAD_SZ;

        /* UDP checksum */
        struct udphdr *udp = (struct udphdr *)seg;
        /* We put udp header first, then payload - rebuild properly */
        uint8_t udp_seg[MAX_PKT];
        int udplen = build_udp_dat(udp_seg, sizeof(udp_seg),
                                    vs->src_port, vs->dst_port,
                                    uh, seglen);
        ((struct udphdr *)udp_seg)->check = udp_checksum(vs->src_ip, vs->dst_ip,
                                                          udp_seg, udplen);

        uint8_t pkt[MAX_PKT];
        int pktlen = build_vlan_pkt(pkt, sizeof(pkt),
                                     vs->dst_mac, vs->src_mac, vs->vlan_id,
                                     vs->src_ip, vs->dst_ip,
                                     IPPROTO_UDP, udp_seg, udplen);
        sendto(sock, pkt, pktlen, 0, (struct sockaddr *)&sa, sizeof(sa));
        total += pktlen;

        /* drain rx */
        FD_ZERO(&rfds); FD_SET(sock, &rfds);
        tv.tv_sec = 0; tv.tv_usec = 1000;
        if (select(sock + 1, &rfds, NULL, NULL, &tv) > 0) {
            uint8_t rx[MAX_PKT];
            recvfrom(sock, rx, sizeof(rx), 0, NULL, NULL);
        }
    }

    double secs = now_sec() - start;
    char rb[64], rt[64];
    fmt_bytes(total, rb, sizeof(rb));
    fmt_rate(total * 8, secs, rt, sizeof(rt));
    if (g_opt.json)
        printf("{\"bytes\":%llu,\"rate\":\"%s\"}\n",
               (unsigned long long)total, rt);
    else
        printf("[VLAN UDP] sent %s in %.1fs = %s\n", rb, secs, rt);
    close(sock);
    return 0;
}

static int vlan_udp_server_stream(vlan_stream_t *vs) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return -1; }
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex  = if_get_index(g_opt.bind_if);
    bind(sock, (struct sockaddr *)&sa, sizeof(sa));

    /* bind IP for ARP to answer */
    if_get_ip(g_opt.bind_if, &vs->src_ip);
    if_get_mac(g_opt.bind_if, vs->src_mac);

    fd_set rfds;
    struct timeval tv;
    uint64_t total = 0, pkts = 0;
    double start = now_sec();

    while (!g_stop) {
        FD_ZERO(&rfds); FD_SET(sock, &rfds);
        tv.tv_sec = 0; tv.tv_usec = 100000;
        if (select(sock + 1, &rfds, NULL, NULL, &tv) > 0) {
            uint8_t rx[MAX_PKT];
            int n = recvfrom(sock, rx, sizeof(rx), 0, NULL, NULL);
            if (n > 0) {
                total += n;
                pkts++;
            }
        }
        if (pkts > 0 && ((uint64_t)(now_sec() - start) % g_opt.report_interval == 0)) {
            double secs = now_sec() - start;
            char rb[64], rt[64];
            fmt_bytes(total, rb, sizeof(rb));
            fmt_rate(total * 8, secs, rt, sizeof(rt));
            if (!g_opt.json)
                printf("[VLAN UDP] rx %s (%llu pkts) in %.1fs = %s\n",
                       rb, (unsigned long long)pkts, secs, rt);
        }
    }
    close(sock);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 *  NON-VLAN MODE  (regular sockets)
 * ═══════════════════════════════════════════════════════════════ */

static int nonvlan_tcp_client(const char *host, int port,
                               uint64_t bw, int dur, int stream_idx) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    if (g_opt.bind_if[0]) {
        setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
                   g_opt.bind_if, strlen(g_opt.bind_if));
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); close(sock); return -1;
    }

    pacer_t pacer;
    pacer_init(&pacer, bw, PAYLOAD_SZ);

    uint8_t payload[PAYLOAD_SZ];
    memset(payload, 0x55, sizeof(payload));

    double start = now_sec();
    uint64_t total = 0;

    while (!g_stop && now_sec() - start < dur) {
        pacer_wait(&pacer);
        int n = send(sock, payload, sizeof(payload), 0);
        if (n <= 0) break;
        total += n;
    }

    close(sock);
    double secs = now_sec() - start;
    char rb[64], rt[64];
    fmt_bytes(total, rb, sizeof(rb));
    fmt_rate(total * 8, secs, rt, sizeof(rt));
    printf("[TCP stream %d] sent %s in %.1fs = %s\n", stream_idx, rb, secs, rt);
    return 0;
}

static int nonvlan_tcp_server(int port, int streams) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); return -1; }
    int opt = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (g_opt.bind_if[0]) {
        setsockopt(listener, SOL_SOCKET, SO_BINDTODEVICE,
                   g_opt.bind_if, strlen(g_opt.bind_if));
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = g_opt.bind_ip ? g_opt.bind_ip : INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(listener); return -1;
    }
    if (listen(listener, streams) < 0) {
        perror("listen"); close(listener); return -1;
    }

    int clients[MAX_STREAMS];
    uint64_t client_bytes[MAX_STREAMS] = {0};
    int num_clients = 0;

    printf("[TCP server] listening on port %d\n", port);

    fd_set rfds;
    struct timeval tv;
    double start = now_sec();

    while (!g_stop) {
        FD_ZERO(&rfds);
        FD_SET(listener, &rfds);
        int maxfd = listener;
        for (int i = 0; i < num_clients; i++) {
            FD_SET(clients[i], &rfds);
            if (clients[i] > maxfd) maxfd = clients[i];
        }
        tv.tv_sec = 0; tv.tv_usec = 100000;
        if (select(maxfd + 1, &rfds, NULL, NULL, &tv) <= 0) continue;

        if (FD_ISSET(listener, &rfds) && num_clients < streams) {
            struct sockaddr_in ca;
            socklen_t calen = sizeof(ca);
            int cs = accept(listener, (struct sockaddr *)&ca, &calen);
            if (cs >= 0) {
                clients[num_clients] = cs;
                client_bytes[num_clients] = 0;
                num_clients++;
                printf("[TCP server] client %d connected\n", num_clients);
            }
        }
        for (int i = 0; i < num_clients; i++) {
            if (!FD_ISSET(clients[i], &rfds)) continue;
            uint8_t buf[PAYLOAD_SZ * 2];
            int n = recv(clients[i], buf, sizeof(buf), 0);
            if (n <= 0) {
                close(clients[i]);
                clients[i] = clients[num_clients - 1];
                client_bytes[i] = client_bytes[num_clients - 1];
                num_clients--;
                i--;
            } else {
                client_bytes[i] += n;
            }
        }
    }

    for (int i = 0; i < num_clients; i++) close(clients[i]);
    close(listener);

    double secs = now_sec() - start;
    uint64_t total = 0;
    for (int i = 0; i < num_clients; i++) total += client_bytes[i];
    char rb[64], rt[64];
    fmt_bytes(total, rb, sizeof(rb));
    fmt_rate(total * 8, secs, rt, sizeof(rt));
    printf("[TCP server] total %s in %.1fs = %s\n", rb, secs, rt);
    return 0;
}

static int nonvlan_udp_client(const char *host, int port,
                               uint64_t bw, int dur, int stream_idx) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return -1; }
    if (g_opt.bind_if[0]) {
        setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
                   g_opt.bind_if, strlen(g_opt.bind_if));
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    pacer_t pacer;
    pacer_init(&pacer, bw, PAYLOAD_SZ);

    uint8_t payload[PAYLOAD_SZ];
    memset(payload, 0xAA, sizeof(payload));

    double start = now_sec();
    uint64_t total = 0;

    while (!g_stop && now_sec() - start < dur) {
        pacer_wait(&pacer);
        int n = sendto(sock, payload, sizeof(payload), 0,
                       (struct sockaddr *)&addr, sizeof(addr));
        if (n <= 0) break;
        total += n;
    }

    close(sock);
    double secs = now_sec() - start;
    char rb[64], rt[64];
    fmt_bytes(total, rb, sizeof(rb));
    fmt_rate(total * 8, secs, rt, sizeof(rt));
    printf("[UDP stream %d] sent %s in %.1fs = %s\n", stream_idx, rb, secs, rt);
    return 0;
}

static int nonvlan_udp_server(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return -1; }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (g_opt.bind_if[0]) {
        setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
                   g_opt.bind_if, strlen(g_opt.bind_if));
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = g_opt.bind_ip ? g_opt.bind_ip : INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(sock); return -1;
    }

    printf("[UDP server] listening on port %d\n", port);

    fd_set rfds;
    struct timeval tv;
    uint64_t total = 0, pkts = 0;
    double start = now_sec();

    while (!g_stop) {
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        tv.tv_sec = 0; tv.tv_usec = 100000;
        if (select(sock + 1, &rfds, NULL, NULL, &tv) > 0) {
            uint8_t buf[MAX_PKT];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            int n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &fromlen);
            if (n > 0) { total += n; pkts++; }
        }
        /* periodic report */
        double secs = now_sec() - start;
        if (pkts > 0 && ((uint64_t)secs % g_opt.report_interval == 0)) {
            char rb[64], rt[64];
            fmt_bytes(total, rb, sizeof(rb));
            fmt_rate(total * 8, secs, rt, sizeof(rt));
            if (!g_opt.json)
                printf("[UDP server] rx %s (%llu pkts) in %.1fs = %s\n",
                       rb, (unsigned long long)pkts, secs, rt);
        }
    }
    close(sock);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 *  MAIN
 * ═══════════════════════════════════════════════════════════════ */

static void usage(void) {
    printf("vlan_tool - Linux VLAN / non-VLAN TCP/UDP test\n");
    printf("Usage:\n");
    printf("  ./vlan_tool -s|-c host [-p port] [-t sec] [-b bw] [-P n]\n");
    printf("               [-V vlan_id] [-u] [-B if] [-J] [-i interval]\n");
    printf("  -s              server mode\n");
    printf("  -c host         client mode, target host\n");
    printf("  -p port         port (default 5001)\n");
    printf("  -t seconds      duration (default 10)\n");
    printf("  -b bw           bandwidth (e.g. 10M, 100M, 1G)\n");
    printf("  -P n            parallel streams\n");
    printf("  -V vlan_id      enable VLAN mode with this ID\n");
    printf("  -u              UDP (default TCP)\n");
    printf("  -B if           bind interface (required for VLAN)\n");
    printf("  -J              JSON output\n");
    printf("  -i interval     report interval (default 1s)\n");
}

static uint64_t parse_bw(const char *s) {
    double v;
    char suffix = 0;
    if (sscanf(s, "%lf%c", &v, &suffix) < 1) return 0;
    switch (suffix) {
    case 'g': case 'G': return (uint64_t)(v * 1e9);
    case 'm': case 'M': return (uint64_t)(v * 1e6);
    case 'k': case 'K': return (uint64_t)(v * 1e3);
    default:            return (uint64_t)v;
    }
}

int main(int argc, char **argv) {
    memset(&g_opt, 0, sizeof(g_opt));
    g_opt.port = 5001;
    g_opt.duration = 10;
    g_opt.report_interval = 1;

    int opt;
    while ((opt = getopt(argc, argv,
            "sc:p:t:b:P:V:uB:i:Jvh")) != -1) {
        switch (opt) {
        case 's': g_opt.is_server = 1; break;
        case 'c': snprintf(g_opt.host, sizeof(g_opt.host), "%s", optarg); break;
        case 'p': g_opt.port = atoi(optarg); break;
        case 't': g_opt.duration = atoi(optarg); break;
        case 'b': g_opt.bandwidth = parse_bw(optarg); break;
        case 'P': g_opt.streams = atoi(optarg); break;
        case 'V': g_opt.use_vlan = 1;
                  g_opt.vlan_id = (uint16_t)atoi(optarg); break;
        case 'u': g_opt.use_udp = 1; break;
        case 'B': snprintf(g_opt.bind_if, sizeof(g_opt.bind_if), "%s", optarg); break;
        case 'i': g_opt.report_interval = atoi(optarg); break;
        case 'J': g_opt.json = 1; break;
        case 'v': break;
        case 'h': default: usage(); return 0;
        }
    }
    if (g_opt.streams <= 0) g_opt.streams = 1;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (g_opt.use_vlan) {
        if (!g_opt.bind_if[0]) {
            fprintf(stderr, "VLAN mode requires -B <interface>\n");
            return 1;
        }
        vlan_stream_t vs;
        memset(&vs, 0, sizeof(vs));
        vs.vlan_id  = g_opt.vlan_id;
        vs.src_port = 10000 + getpid();
        vs.dst_port = (uint16_t)g_opt.port;
        vs.src_ip   = g_opt.bind_ip;
        if (vs.src_ip == 0) if_get_ip(g_opt.bind_if, &vs.src_ip);
        if_get_mac(g_opt.bind_if, vs.src_mac);
        if (g_opt.host[0])
            inet_pton(AF_INET, g_opt.host, &vs.dst_ip);

        if (g_opt.use_udp) {
            if (g_opt.is_server)
                return vlan_udp_server_stream(&vs);
            else
                return vlan_udp_client_stream(&vs);
        } else {
            if (g_opt.is_server)
                return vlan_tcp_server_stream(&vs);
            else
                return vlan_tcp_client_stream(&vs);
        }
    } else {
        /* non-VLAN */
        if (g_opt.bind_ip == 0 && g_opt.bind_if[0]) {
            /* try to resolve IP from interface */
            uint32_t ip;
            if (if_get_ip(g_opt.bind_if, &ip) == 0)
                g_opt.bind_ip = ip;
        }
        if (g_opt.use_udp) {
            if (g_opt.is_server)
                return nonvlan_udp_server(g_opt.port);
            else
                return nonvlan_udp_client(g_opt.host, g_opt.port,
                                          g_opt.bandwidth, g_opt.duration, 0);
        } else {
            if (g_opt.is_server)
                return nonvlan_tcp_server(g_opt.port, g_opt.streams);
            else
                return nonvlan_tcp_client(g_opt.host, g_opt.port,
                                          g_opt.bandwidth, g_opt.duration, 0);
        }
    }
}
