/*
 * vlan_tag_switch.c - WinPcap/Npcap VLAN tag switch test tool (Windows)
 *
 * Function: Simulate switch behavior, L3 (IP+UDP or IP+TCP) packets, optional L2 VLAN tag
 *   -s (server) mode: listen on port, strip VLAN tag and print payload, reply/stats
 *   -c (client) mode: connect to server, send packets with VLAN tag, receive replies
 *   -t (test)   mode: iperf-like bandwidth test, send high traffic and statistics
 *
 * VLAN optional: without -v no VLAN tag, with -v <vlan_id> adds VLAN tag
 * Protocol: -P udp (default) or -P tcp
 *
 * Usage:
 *   Server: vlan_tag_switch.exe -s [-p <port>] [-a <ip>] [-v <vlan_id>] [-P udp|tcp]
 *   Client: vlan_tag_switch.exe -c <server_ip:port> [-v <vlan_id>] [-i] [-P udp|tcp]
 *   Test:   vlan_tag_switch.exe -c <server_ip:port> -t [-b <bw>] [-d <sec>] [-l <len>] [-v <vlan_id>] [-P udp|tcp]
 *
 * Build (MinGW):
 *   gcc -Wall -O2 -IC:\WpdPack\Include -o vlan_tag_switch.exe vlan_tag_switch.c ^
 *       -LC:\WpdPack\Lib -lwpcap -lPacket -lws2_32 -liphlpapi
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <conio.h>

#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

/* Constants */
#define VLAN_VID_MASK    0x0FFF
#define VLAN_PCP_SHIFT   13
#define ETH_HDR_LEN      14
#define VLAN_TAG_LEN     4
#define VLAN_ETH_HDR_LEN (ETH_HDR_LEN + VLAN_TAG_LEN)
#define IP_HDR_LEN       20
#define UDP_HDR_LEN      8
#define TCP_HDR_LEN      20
#define MAX_PACKET_LEN   2048
#define DEFAULT_PORT     9999
#define ARP_TIMEOUT_MS   3000
#define RECV_TIMEOUT_MS  5000

/* EtherType */
#define ETHERTYPE_VLAN   0x8100
#define ETHERTYPE_IP     0x0800
#define ETHERTYPE_ARP    0x0806

/* IP Protocol */
#define IP_PROTOCOL_UDP  17
#define IP_PROTOCOL_TCP  6

/* Transport protocol selection */
#define PROTO_UDP  0
#define PROTO_TCP  1

/* ARP */
#define ARP_HW_TYPE_ETH  0x0001
#define ARP_OP_REQUEST   0x0001
#define ARP_OP_REPLY     0x0002

/* Mode */
typedef enum {
    MODE_NONE = 0,
    MODE_SERVER,
    MODE_CLIENT
} run_mode_t;

/* Globals */
static uint8_t g_my_mac[6]    = {0};
static uint8_t g_my_ip[4]     = {0};
static uint8_t g_peer_mac[6]  = {0};
static uint8_t g_peer_ip[4]   = {0};
static uint16_t g_vlan_id     = 0;  /* 0 = no VLAN */
static uint8_t  g_pcp         = 0;
static uint16_t g_listen_port = 0;
static pcap_t   *g_handle     = NULL;
static int       g_running    = 1;
static run_mode_t g_mode      = MODE_NONE;
static int       g_interactive = 0;  /* print payload details (interactive mode) */
static int       g_protocol   = PROTO_TCP;  /* PROTO_UDP or PROTO_TCP (default TCP) */

/* Test parameters (iperf-compatible) */
static double   g_target_bps  = 0;      /* -b: target bandwidth */
static int      g_test_duration = 10;   /* -t: transmit time in seconds */
static uint64_t g_bytes_to_send = 0;    /* -n: bytes to transmit (0 = use -t) */
static int      g_report_interval = 1;  /* -i: bandwidth report interval */
static int      g_silence_timeout = 3;  /* -T: server auto-stop after N seconds of silence */
static int      g_pkt_size    = 1400;   /* -l: packet/buffer length */
static int      g_parallel    = 1;      /* -P: parallel streams */
static char     g_bind_host[64] = {0};  /* -B: bind to interface */

/*=======================================================================
 * Data structures (packed)
 *=====================================================================*/

#pragma pack(push, 1)

typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
} eth_header_t;

typedef struct {
    uint16_t tpid;
    uint16_t tci;
} vlan_tag_t;

typedef struct {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
} ip_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;  /* high 4 bits = data offset in 32-bit words */
    uint8_t  flags;     /* bit0=FIN,bit1=SYN,bit2=RST,bit3=PSH,bit4=ACK,bit5=URG */
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_header_t;

/* TCP flag bits */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

/* Pseudo header for TCP checksum */
typedef struct {
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_length;
} tcp_pseudo_header_t;

typedef struct {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
} arp_packet_t;

typedef struct {
    uint32_t seq;
    uint32_t sec;
    uint32_t usec;
} test_header_t;

#pragma pack(pop)

/*=======================================================================
 * Utility functions
 *=====================================================================*/

static BOOL WINAPI ctrl_handler(DWORD ctrl_type)
{
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        g_running = 0;
        return TRUE;
    }
    return FALSE;
}

static int parse_ip(const char *str, uint8_t *ip)
{
    int values[4];
    int i;

    if (sscanf(str, "%d.%d.%d.%d",
               &values[0], &values[1], &values[2], &values[3]) == 4) {
        for (i = 0; i < 4; i++) {
            if (values[i] < 0 || values[i] > 255) return -1;
            ip[i] = (uint8_t)values[i];
        }
        return 0;
    }
    return -1;
}

static void print_mac(const char *label, const uint8_t *mac)
{
    printf("    %s: %02X:%02X:%02X:%02X:%02X:%02X\n",
           label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_ip(const char *label, const uint8_t *ip)
{
    printf("    %s: %u.%u.%u.%u\n", label, ip[0], ip[1], ip[2], ip[3]);
}

static uint16_t calc_checksum(const uint16_t *data, int len)
{
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)data;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/*
 * TCP checksum with pseudo-header
 */
static uint16_t calc_tcp_checksum(const uint8_t *src_ip, const uint8_t *dst_ip,
                                  const tcp_header_t *tcp, int tcp_len)
{
    tcp_pseudo_header_t pseudo;
    memset(&pseudo, 0, sizeof(pseudo));
    memcpy(pseudo.src_ip, src_ip, 4);
    memcpy(pseudo.dst_ip, dst_ip, 4);
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.tcp_length = htons((uint16_t)tcp_len);

    /* Sum pseudo header */
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)&pseudo;
    for (int i = 0; i < (int)sizeof(tcp_pseudo_header_t) / 2; i++)
        sum += p[i];

    /* Sum TCP header + payload */
    p = (const uint16_t *)tcp;
    while (tcp_len > 1) {
        sum += *p++;
        tcp_len -= 2;
    }
    if (tcp_len == 1)
        sum += *(const uint8_t *)p;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

static int get_local_address(const char *adapter_name, uint8_t *mac, uint8_t *ip)
{
    ULONG buf_len = 0;
    GetAdaptersInfo(NULL, &buf_len);
    if (buf_len == 0) return -1;

    PIP_ADAPTER_INFO adapter_info = (PIP_ADAPTER_INFO)malloc(buf_len);
    if (!adapter_info) return -1;

    if (GetAdaptersInfo(adapter_info, &buf_len) != ERROR_SUCCESS) {
        free(adapter_info);
        return -1;
    }

    char guid[260] = {0};
    const char *p = strstr(adapter_name, "{");
    if (p) strncpy(guid, p, sizeof(guid) - 1);

    int found = 0;
    PIP_ADAPTER_INFO adapter = adapter_info;
    while (adapter) {
        if (guid[0] && strstr(adapter->AdapterName, guid)) {
            if (adapter->AddressLength == 6) {
                memcpy(mac, adapter->Address, 6);
                if (adapter->IpAddressList.IpAddress.String[0] != '\0') {
                    parse_ip(adapter->IpAddressList.IpAddress.String, ip);
                }
                found = 1;
                break;
            }
        }
        adapter = adapter->Next;
    }

    if (!found) {
        adapter = adapter_info;
        while (adapter) {
            if (adapter->AddressLength == 6 && adapter->Type == MIB_IF_TYPE_ETHERNET) {
                memcpy(mac, adapter->Address, 6);
                if (adapter->IpAddressList.IpAddress.String[0] != '\0') {
                    parse_ip(adapter->IpAddressList.IpAddress.String, ip);
                }
                found = 1;
                break;
            }
            adapter = adapter->Next;
        }
    }

    free(adapter_info);
    return found ? 0 : -1;
}

static int list_adapters(pcap_if_t *alldevs)
{
    pcap_if_t *d;
    int i = 0;
    for (d = alldevs; d != NULL; d = d->next) {
        printf("\n%d. %s\n", ++i, d->name);
        if (d->description)
            printf("   Description: %s\n", d->description);
        else
            printf("   Description: (no description)\n");
    }
    return i;
}

/*=======================================================================
 * ARP resolution
 *=====================================================================*/

static int send_arp_request(pcap_t *handle, const uint8_t *src_mac, const uint8_t *src_ip,
                            const uint8_t *target_ip)
{
    uint8_t frame[ETH_HDR_LEN + 28];
    eth_header_t *eth = (eth_header_t *)frame;
    arp_packet_t *arp = (arp_packet_t *)(frame + ETH_HDR_LEN);

    memset(eth->dst_mac, 0xFF, 6);
    memcpy(eth->src_mac, src_mac, 6);
    eth->ethertype = htons(ETHERTYPE_ARP);

    arp->hw_type     = htons(ARP_HW_TYPE_ETH);
    arp->proto_type  = htons(ETHERTYPE_IP);
    arp->hw_len      = 6;
    arp->proto_len   = 4;
    arp->opcode      = htons(ARP_OP_REQUEST);
    memcpy(arp->sender_mac, src_mac, 6);
    memcpy(arp->sender_ip, src_ip, 4);
    memset(arp->target_mac, 0, 6);
    memcpy(arp->target_ip, target_ip, 4);

    return (pcap_sendpacket(handle, frame, sizeof(frame)) == 0) ? 0 : -1;
}

static int arp_resolve(pcap_t *handle, const uint8_t *src_mac, const uint8_t *src_ip,
                       const uint8_t *target_ip, uint8_t *target_mac, int timeout_ms)
{
    LARGE_INTEGER freq, start;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    if (send_arp_request(handle, src_mac, src_ip, target_ip) < 0) {
        fprintf(stderr, "Error: Failed to send ARP request\n");
        return -1;
    }

    printf("  [ARP] Requesting MAC for %u.%u.%u.%u...\n",
           target_ip[0], target_ip[1], target_ip[2], target_ip[3]);

    while (g_running) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        double elapsed = (double)(now.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
        if (elapsed >= timeout_ms) {
            printf("  [ARP] Timeout\n");
            return -1;
        }

        struct pcap_pkthdr *hdr;
        const u_char *pkt;
        int ret = pcap_next_ex(handle, &hdr, &pkt);
        if (ret == 1 && hdr->caplen >= ETH_HDR_LEN + 28) {
            eth_header_t *eth = (eth_header_t *)pkt;
            if (ntohs(eth->ethertype) == ETHERTYPE_ARP) {
                arp_packet_t *arp = (arp_packet_t *)(pkt + ETH_HDR_LEN);
                if (ntohs(arp->opcode) == ARP_OP_REPLY &&
                    memcmp(arp->sender_ip, target_ip, 4) == 0) {
                    memcpy(target_mac, arp->sender_mac, 6);
                    printf("  [ARP] Resolved successfully\n");
                    return 0;
                }
            }
        } else if (ret == 0) {
            Sleep(10);
        } else if (ret < 0) {
            break;
        }
    }

    return -1;
}

/*=======================================================================
 * Packet construction and parsing
 *=====================================================================*/

/*
 * Build packet (optional VLAN tag, UDP or TCP)
 * vlan_id=0 means no VLAN tag
 * protocol: PROTO_UDP or PROTO_TCP
 */
static int build_packet(uint8_t *frame, int frame_size,
                        const uint8_t *dst_mac, const uint8_t *src_mac,
                        uint16_t vlan_id, uint8_t pcp,
                        const uint8_t *src_ip, const uint8_t *dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        const uint8_t *payload, int payload_len,
                        int protocol, uint32_t tcp_seq, uint32_t tcp_ack, uint8_t tcp_flags)
{
    int transport_hdr_len = (protocol == PROTO_TCP) ? TCP_HDR_LEN : UDP_HDR_LEN;
    int ip_protocol = (protocol == PROTO_TCP) ? IP_PROTOCOL_TCP : IP_PROTOCOL_UDP;
    int hdr_len = ETH_HDR_LEN + IP_HDR_LEN + transport_hdr_len;
    uint16_t eth_type = ETHERTYPE_IP;

    if (vlan_id > 0) {
        hdr_len += VLAN_TAG_LEN;
        eth_type = ETHERTYPE_VLAN;
    }

    int total_len = hdr_len + payload_len;
    if (total_len > frame_size) return -1;

    eth_header_t  *eth   = (eth_header_t *)frame;
    ip_header_t   *ip    = (ip_header_t *)(frame + hdr_len - IP_HDR_LEN - transport_hdr_len);
    uint8_t       *data  = frame + hdr_len;
    int ip_payload_len   = transport_hdr_len + payload_len;

    /* Ethernet header */
    memcpy(eth->dst_mac, dst_mac, 6);
    memcpy(eth->src_mac, src_mac, 6);
    eth->ethertype = htons(eth_type);

    /* VLAN tag (optional) - 802.1Q format:
     * [Dst MAC(6)] [Src MAC(6)] [TPID=0x8100(2)] [TCI(2)] [EtherType=0x0800(2)] [IP]...
     * The TPID is already written as eth->ethertype above */
    if (vlan_id > 0) {
        /* TCI at offset 14-15 (after TPID) */
        uint16_t *tci = (uint16_t *)(frame + ETH_HDR_LEN);
        *tci = htons(((uint16_t)(pcp & 0x07) << VLAN_PCP_SHIFT) | (vlan_id & VLAN_VID_MASK));
        /* Inner EtherType at offset 16-17 (after TCI) */
        uint16_t *inner_type = (uint16_t *)(frame + ETH_HDR_LEN + 2);
        *inner_type = htons(ETHERTYPE_IP);
    }

    /* IP header */
    ip->ver_ihl    = 0x45;
    ip->tos        = 0;
    ip->total_len  = htons(IP_HDR_LEN + ip_payload_len);
    ip->id         = htons((uint16_t)GetTickCount());
    ip->flags_frag = 0;
    ip->ttl        = 64;
    ip->protocol   = (uint8_t)ip_protocol;
    ip->checksum   = 0;
    memcpy(ip->src_ip, src_ip, 4);
    memcpy(ip->dst_ip, dst_ip, 4);
    ip->checksum   = calc_checksum((uint16_t *)ip, IP_HDR_LEN);

    if (protocol == PROTO_TCP) {
        /* TCP header */
        tcp_header_t *tcp = (tcp_header_t *)(frame + hdr_len - transport_hdr_len);
        tcp->src_port  = htons(src_port);
        tcp->dst_port  = htons(dst_port);
        tcp->seq       = htonl(tcp_seq);
        tcp->ack       = htonl(tcp_ack);
        tcp->data_off  = (5 << 4);  /* 5 words = 20 bytes, no options */
        tcp->flags     = tcp_flags;
        tcp->window    = htons(65535);
        tcp->checksum  = 0;
        tcp->urgent    = 0;

        /* Copy payload after TCP header */
        if (payload_len > 0)
            memcpy(data, payload, payload_len);

        /* TCP checksum (requires pseudo-header) */
        tcp->checksum = calc_tcp_checksum(src_ip, dst_ip, tcp, TCP_HDR_LEN + payload_len);
    } else {
        /* UDP header */
        udp_header_t *udp = (udp_header_t *)(frame + hdr_len - transport_hdr_len);
        udp->src_port  = htons(src_port);
        udp->dst_port  = htons(dst_port);
        udp->length    = htons(UDP_HDR_LEN + payload_len);
        udp->checksum  = 0;

        /* Payload */
        if (payload_len > 0)
            memcpy(data, payload, payload_len);
    }

    return total_len;
}

/*
 * Parse received packet (auto-detect VLAN tag, UDP or TCP)
 * Returns payload length
 * out_is_vlan: if not NULL, returns whether packet has VLAN
 * out_is_tcp: if not NULL, returns whether packet is TCP (1) or UDP (0)
 */
static int parse_packet(const uint8_t *pkt, int pkt_len,
                        uint8_t *out_src_mac, uint8_t *out_dst_mac,
                        uint16_t *out_vlan_id, uint8_t *out_pcp,
                        uint8_t *out_src_ip, uint8_t *out_dst_ip,
                        uint16_t *out_src_port, uint16_t *out_dst_port,
                        uint8_t *out_payload, int max_payload_len,
                        uint16_t expected_dst_port,
                        int *out_is_vlan,
                        int *out_is_tcp,
                        int expected_protocol)
{
    int min_transport_len = (UDP_HDR_LEN < TCP_HDR_LEN) ? UDP_HDR_LEN : TCP_HDR_LEN;
    if (pkt_len < ETH_HDR_LEN + IP_HDR_LEN + min_transport_len)
        return -1;

    const eth_header_t *eth = (const eth_header_t *)pkt;
    uint16_t ethertype = ntohs(eth->ethertype);
    int vlan = 0;
    int ip_offset = ETH_HDR_LEN;

    if (ethertype == ETHERTYPE_VLAN) {
        vlan = 1;
        ip_offset = VLAN_ETH_HDR_LEN;
        if (pkt_len < VLAN_ETH_HDR_LEN + IP_HDR_LEN + min_transport_len)
            return -1;
    }

    const ip_header_t *ip = (const ip_header_t *)(pkt + ip_offset);

    /* Check IP protocol - accept both UDP and TCP */
    int is_tcp;
    int transport_hdr_len;
    if (ip->protocol == IP_PROTOCOL_TCP) {
        is_tcp = 1;
        transport_hdr_len = TCP_HDR_LEN;
    } else if (ip->protocol == IP_PROTOCOL_UDP) {
        is_tcp = 0;
        transport_hdr_len = UDP_HDR_LEN;
    } else {
        return -3;  /* unsupported protocol */
    }

    /* Protocol filter: if expected_protocol is set, skip non-matching packets */
    if (expected_protocol == PROTO_TCP && !is_tcp)
        return -100;  /* wrong protocol, keep listening */
    if (expected_protocol == PROTO_UDP && is_tcp)
        return -100;  /* wrong protocol, keep listening */

    if (out_is_tcp) *out_is_tcp = is_tcp;

    if (pkt_len < ip_offset + IP_HDR_LEN + transport_hdr_len)
        return -1;

    const uint8_t *transport = pkt + ip_offset + IP_HDR_LEN;
    const uint8_t *data = transport + transport_hdr_len;

    /* Extract MAC */
    if (out_dst_mac) memcpy(out_dst_mac, eth->dst_mac, 6);
    if (out_src_mac) memcpy(out_src_mac, eth->src_mac, 6);

    /* VLAN info */
    if (out_vlan_id) *out_vlan_id = vlan ? 1 : 0;  /* simplified, only returns VLAN presence */
    if (out_pcp)     *out_pcp = 0;
    if (out_is_vlan) *out_is_vlan = vlan;

    if (vlan) {
        /* TCI is at offset 14-15 (after TPID at 12-13) */
        uint16_t tci = ntohs(*(const uint16_t *)(pkt + ETH_HDR_LEN));
        if (out_vlan_id) *out_vlan_id = tci & VLAN_VID_MASK;
        if (out_pcp)     *out_pcp = (tci >> VLAN_PCP_SHIFT) & 0x07;
    }

    /* Extract IP */
    if (out_src_ip) memcpy(out_src_ip, ip->src_ip, 4);
    if (out_dst_ip) memcpy(out_dst_ip, ip->dst_ip, 4);

    /* Extract ports (same offset for UDP and TCP) */
    uint16_t dst_port = ntohs(((const uint16_t *)transport)[1]);
    uint16_t src_port = ntohs(((const uint16_t *)transport)[0]);

    /* Filter by expected port (only if not in mixed mode) */
    if (expected_dst_port != 0 && dst_port != expected_dst_port)
        return -4;

    if (out_src_port) *out_src_port = src_port;
    if (out_dst_port) *out_dst_port = dst_port;

    /* Extract payload */
    int payload_len;
    if (is_tcp) {
        /* TCP: data offset is in 32-bit words */
        const tcp_header_t *tcp_hdr = (const tcp_header_t *)transport;
        int tcp_hdr_len = (tcp_hdr->data_off >> 4) * 4;
        if (tcp_hdr_len < TCP_HDR_LEN) tcp_hdr_len = TCP_HDR_LEN;
        payload_len = ntohs(ip->total_len) - IP_HDR_LEN - tcp_hdr_len;
    } else {
        /* UDP: length field includes header */
        uint16_t udp_len = ntohs(((const udp_header_t *)transport)->length);
        payload_len = udp_len - UDP_HDR_LEN;
    }

    if (payload_len < 0) payload_len = 0;
    if (payload_len > max_payload_len) payload_len = max_payload_len;

    if (out_payload && payload_len > 0)
        memcpy(out_payload, data, payload_len);

    return payload_len;
}

/*=======================================================================
 * Send and receive
 *=====================================================================*/

static int send_packet(const uint8_t *dst_mac,
                       const uint8_t *src_ip, const uint8_t *dst_ip,
                       uint16_t src_port, uint16_t dst_port,
                       const uint8_t *payload, int payload_len)
{
    uint8_t frame[MAX_PACKET_LEN];
    int frame_len = build_packet(frame, sizeof(frame),
                                 dst_mac, g_my_mac,
                                 g_vlan_id, g_pcp,
                                 src_ip, dst_ip,
                                 src_port, dst_port,
                                 payload, payload_len,
                                 g_protocol,
                                 0, 0,  /* tcp_seq, tcp_ack - managed per-connection */
                                 TCP_PSH | TCP_ACK);
    if (frame_len < 0) return -1;

    if (pcap_sendpacket(g_handle, frame, frame_len) != 0) {
        return -1;
    }
    return frame_len;
}

static int recv_packet(uint16_t expected_dst_port,
                       uint8_t *out_src_mac, uint8_t *out_src_ip,
                       uint16_t *out_src_port,
                       uint8_t *out_payload, int max_payload_len,
                       int timeout_ms,
                       int *out_is_vlan,
                       int *out_is_tcp,
                       int expected_protocol)
{
    int min_hdr = (UDP_HDR_LEN < TCP_HDR_LEN) ? UDP_HDR_LEN : TCP_HDR_LEN;
    LARGE_INTEGER freq, start;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    while (g_running) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        double elapsed = (double)(now.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
        if (elapsed >= timeout_ms) return 0;

        struct pcap_pkthdr *hdr;
        const u_char *pkt;
        int ret = pcap_next_ex(g_handle, &hdr, &pkt);
        if (ret == 1 && hdr->caplen >= (size_t)(ETH_HDR_LEN + IP_HDR_LEN + min_hdr)) {
            int result = parse_packet(pkt, hdr->caplen,
                                     out_src_mac, NULL, NULL, NULL,
                                     out_src_ip, NULL,
                                     out_src_port, NULL,
                                     out_payload, max_payload_len,
                                     expected_dst_port,
                                     out_is_vlan,
                                     out_is_tcp,
                                     expected_protocol);
            if (result == -100)
                continue;  /* wrong protocol, keep listening */
            return result;
        } else if (ret == 0) {
            Sleep(10);
        } else if (ret < 0) {
            return -1;
        }
    }
    return -1;
}

/*=======================================================================
 * Interactive mode
 *=====================================================================*/

static void server_interactive_loop(void)
{
    char input[1024];
    uint8_t src_mac[6], src_ip[4];
    uint16_t src_port;
    uint8_t payload[MAX_PACKET_LEN];
    int has_client = 0;
    int is_vlan;

    printf("\n--- Server Interactive Mode ---\n");
    printf("--- Listening on port %u", g_listen_port);
    if (g_vlan_id > 0) printf(", VLAN %u", g_vlan_id);
    printf(" ---\n");
    printf("--- Type messages to send to client (quit to exit) ---\n\n");

    int is_tcp = 0;
    while (g_running) {
        int payload_len = recv_packet(g_listen_port, src_mac, src_ip, &src_port,
                                      payload, sizeof(payload) - 1, 100, &is_vlan, &is_tcp, g_protocol);
        if (payload_len > 0) {
            payload[payload_len] = '\0';
            SYSTEMTIME st;
            GetLocalTime(&st);
            printf("\n[%02d:%02d:%02d.%03d] ========== Packet from client ==========\n",
                   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            print_mac("  Src MAC", src_mac);
            print_ip("  Src IP", src_ip);
            printf("  Src Port  : %u\n", src_port);
            if (is_vlan) {
                printf("  VLAN      : Yes\n");
            } else {
                printf("  VLAN      : None\n");
            }
            printf("  [Stripped Payload] %d bytes:\n", payload_len);
            printf("  >> %.*s\n", payload_len, payload);
            fflush(stdout);

            memcpy(g_peer_mac, src_mac, 6);
            memcpy(g_peer_ip, src_ip, 4);
            has_client = 1;

            /* Auto reply */
            char reply[1300];
            GetLocalTime(&st);
            int reply_len = sprintf(reply, "[%02d:%02d:%02d.%03d] AUTO_REPLY: Received '%.*s'",
                                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                                    payload_len > 200 ? 200 : payload_len, payload);

            send_packet(src_mac, g_my_ip, src_ip, g_listen_port, src_port,
                        (uint8_t *)reply, reply_len);
            printf("  [Auto Reply] Sent\n");
            fflush(stdout);
        }

        if (_kbhit()) {
            if (fgets(input, sizeof(input), stdin)) {
                int len = (int)strlen(input);
                while (len > 0 && (input[len-1] == '\n' || input[len-1] == '\r'))
                    input[--len] = '\0';

                if (len == 0) continue;
                if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0)
                    break;

                if (!has_client) {
                    printf("  [Hint] No client packet received yet, cannot send\n");
                    continue;
                }

                SYSTEMTIME st;
                GetLocalTime(&st);
                char msg[1200];
                int msg_len = sprintf(msg, "[%02d:%02d:%02d.%03d] SERVER: %s",
                                      st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, input);

                send_packet(g_peer_mac, g_my_ip, g_peer_ip, g_listen_port, src_port,
                            (uint8_t *)msg, msg_len);
                printf("  -> Sent %d bytes", msg_len);
                if (g_vlan_id > 0) printf(" (with VLAN tag)");
                printf("\n");
                fflush(stdout);
            }
        }
    }
}

static void client_interactive_loop(void)
{
    char input[1024];
    uint8_t src_mac[6], src_ip[4];
    uint16_t src_port;
    uint8_t payload[MAX_PACKET_LEN];
    int is_vlan;

    printf("\n--- Client Interactive Mode ---\n");
    printf("--- Server %u.%u.%u.%u:%u",
           g_peer_ip[0], g_peer_ip[1], g_peer_ip[2], g_peer_ip[3],
           g_listen_port);
    if (g_vlan_id > 0) printf(", VLAN %u", g_vlan_id);
    printf(" ---\n");
    printf("--- Type messages to send to server (quit to exit) ---\n\n");

    int is_tcp = 0;
    while (g_running) {
        int payload_len = recv_packet(g_listen_port, src_mac, src_ip, &src_port,
                                      payload, sizeof(payload) - 1, 100, &is_vlan, &is_tcp, g_protocol);
        if (payload_len > 0) {
            payload[payload_len] = '\0';
            SYSTEMTIME st;
            GetLocalTime(&st);
            printf("\n[%02d:%02d:%02d.%03d] ========== Reply from server ==========\n",
                   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            print_mac("  Src MAC", src_mac);
            print_ip("  Src IP", src_ip);
            printf("  Src Port  : %u\n", src_port);
            if (is_vlan) {
                printf("  VLAN      : Yes\n");
            } else {
                printf("  VLAN      : None\n");
            }
            printf("  [Stripped Payload] %d bytes:\n", payload_len);
            printf("  >> %.*s\n", payload_len, payload);
            fflush(stdout);
        }

        if (_kbhit()) {
            if (fgets(input, sizeof(input), stdin)) {
                int len = (int)strlen(input);
                while (len > 0 && (input[len-1] == '\n' || input[len-1] == '\r'))
                    input[--len] = '\0';

                if (len == 0) continue;
                if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0)
                    break;

                SYSTEMTIME st;
                GetLocalTime(&st);
                char msg[1200];
                int msg_len = sprintf(msg, "[%02d:%02d:%02d.%03d] CLIENT: %s",
                                      st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, input);

                uint16_t src_port = 50000 + (uint16_t)(rand() % 10000);
                send_packet(g_peer_mac, g_my_ip, g_peer_ip, src_port, g_listen_port,
                            (uint8_t *)msg, msg_len);
                printf("  -> Sent %d bytes", msg_len);
                if (g_vlan_id > 0) printf(" (with VLAN tag)");
                printf("\n");
                fflush(stdout);
            }
        }
    }
}

/*=======================================================================
 * iperf test mode
 *=====================================================================*/

static void format_bps(double bps, char *buf, int buf_size)
{
    if (bps >= 1e9)
        snprintf(buf, buf_size, "%.2f Gbps", bps / 1e9);
    else if (bps >= 1e6)
        snprintf(buf, buf_size, "%.2f Mbps", bps / 1e6);
    else if (bps >= 1e3)
        snprintf(buf, buf_size, "%.2f Kbps", bps / 1e3);
    else
        snprintf(buf, buf_size, "%.2f bps", bps);
}

static void format_bytes(uint64_t bytes, char *buf, int buf_size)
{
    if (bytes >= 1024ULL * 1024 * 1024)
        snprintf(buf, buf_size, "%.2f GB", (double)bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024 * 1024)
        snprintf(buf, buf_size, "%.2f MB", (double)bytes / (1024.0 * 1024));
    else if (bytes >= 1024)
        snprintf(buf, buf_size, "%.2f KB", (double)bytes / 1024.0);
    else
        snprintf(buf, buf_size, "%llu B", (unsigned long long)bytes);
}

/*
 * Calculate frame header length (incl. VLAN)
 */
static int get_frame_header_len(void)
{
    return (g_vlan_id > 0) ? VLAN_ETH_HDR_LEN : ETH_HDR_LEN;
}

/*
 * iperf client test
 */
static void iperf_client_test(void)
{
    uint8_t payload[MAX_PACKET_LEN];
    test_header_t *test_hdr = (test_header_t *)payload;
    int header_size = sizeof(test_header_t);
    int data_size = g_pkt_size - header_size;
    if (data_size < 0) data_size = 0;

    for (int i = 0; i < data_size; i++) {
        payload[header_size + i] = (uint8_t)(i & 0xFF);
    }

    uint32_t seq = 0;
    uint64_t total_bytes = 0;
    uint64_t total_pkts = 0;
    LARGE_INTEGER freq, start;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    double interval_us = 0;
    if (g_target_bps > 0) {
        int transport_hdr_len = (g_protocol == PROTO_TCP) ? TCP_HDR_LEN : UDP_HDR_LEN;
        int hdr_len = get_frame_header_len() + IP_HDR_LEN + transport_hdr_len;
        double bits_per_pkt = (double)(g_pkt_size + hdr_len) * 8;
        interval_us = (bits_per_pkt / g_target_bps) * 1e6;
    }

    printf("\n--- iperf Client Test ---\n");
    printf("  Target: %u.%u.%u.%u:%u\n", g_peer_ip[0], g_peer_ip[1], g_peer_ip[2], g_peer_ip[3], g_listen_port);
    if (g_vlan_id > 0) {
        printf("  VLAN: %u\n", g_vlan_id);
    } else {
        printf("  VLAN: None\n");
    }
    printf("  Pkt Size: %d bytes (payload)\n", g_pkt_size);
    if (g_target_bps > 0) {
        char bw_str[32];
        format_bps(g_target_bps, bw_str, sizeof(bw_str));
        printf("  Target BW: %s\n", bw_str);
    } else {
        printf("  Target BW: Unlimited (as fast as possible)\n");
    }
    if (g_bytes_to_send > 0) {
        printf("  Bytes to Send: %llu\n", (unsigned long long)g_bytes_to_send);
    } else {
        printf("  Duration: %d sec\n", g_test_duration);
    }
    printf("========================================\n\n");

    uint64_t interval_bytes = 0;
    uint64_t interval_pkts = 0;
    LARGE_INTEGER interval_start;
    QueryPerformanceCounter(&interval_start);

    while (g_running) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        double elapsed_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;

        /* Stop by time (-t) or by byte count (-n) */
        if (g_bytes_to_send > 0) {
            if (total_bytes >= g_bytes_to_send) break;
        } else {
            if (elapsed_sec >= g_test_duration) break;
        }

        /* Send a burst of packets for high bandwidth targets */
        int burst_size = 1;
        if (interval_us > 0 && interval_us < 1000) {
            /* For sub-ms intervals, send multiple packets per wait */
            burst_size = (int)(1000.0 / interval_us);
            if (burst_size < 1) burst_size = 1;
            if (burst_size > 100) burst_size = 100;
        }

        for (int b = 0; b < burst_size; b++) {
            test_hdr->seq = htonl(seq++);
            test_hdr->sec = htonl((uint32_t)elapsed_sec);
            test_hdr->usec = htonl((uint32_t)((elapsed_sec - (uint32_t)elapsed_sec) * 1e6));

            int sent = send_packet(g_peer_mac, g_my_ip, g_peer_ip,
                                   50000 + (seq % 10000), g_listen_port,
                                   payload, g_pkt_size);
            if (sent > 0) {
                total_bytes += sent;
                total_pkts++;
                interval_bytes += sent;
                interval_pkts++;
            }

            /* Re-check stop condition inside burst */
            QueryPerformanceCounter(&now);
            elapsed_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
            if (g_bytes_to_send > 0) {
                if (total_bytes >= g_bytes_to_send) break;
            } else {
                if (elapsed_sec >= g_test_duration) break;
            }
        }

        double interval_sec = (double)(now.QuadPart - interval_start.QuadPart) / freq.QuadPart;
        if (interval_sec >= g_report_interval) {
            double bps = (double)interval_bytes * 8 / interval_sec;
            char bw_str[32], bytes_str[32];
            format_bps(bps, bw_str, sizeof(bw_str));
            format_bytes(interval_bytes, bytes_str, sizeof(bytes_str));
            printf("  [%5.1fs] %s  %s/s  %llu packets\n",
                   elapsed_sec, bytes_str, bw_str, (unsigned long long)interval_pkts);

            interval_bytes = 0;
            interval_pkts = 0;
            interval_start = now;
            fflush(stdout);
        }

        if (interval_us > 0) {
            /* Convert us to ms, minimum 1ms */
            DWORD sleep_ms = (DWORD)(interval_us / 1000);
            if (sleep_ms < 1) sleep_ms = 1;
            Sleep(sleep_ms);
        }
    }

    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    double total_sec = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double avg_bps = (total_sec > 0) ? (double)total_bytes * 8 / total_sec : 0;

    char bw_str[32], bytes_str[32];
    format_bps(avg_bps, bw_str, sizeof(bw_str));
    format_bytes(total_bytes, bytes_str, sizeof(bytes_str));

    printf("\n========================================\n");
    printf("  [Test Complete]\n");
    printf("  Total Time: %.2f sec\n", total_sec);
    printf("  Total Data: %s\n", bytes_str);
    printf("  Total Pkts: %llu\n", (unsigned long long)total_pkts);
    printf("  Avg Bandwidth: %s\n", bw_str);
    printf("========================================\n");
}

/*
 * iperf server test
 */
static void iperf_server_test(void)
{
    uint8_t src_mac[6], src_ip[4];
    uint16_t src_port;
    uint8_t payload[MAX_PACKET_LEN];

    uint64_t total_bytes = 0;
    uint64_t total_pkts = 0;
    int first_pkt = 1;
    int is_vlan;

    LARGE_INTEGER freq, start;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    uint64_t interval_bytes = 0;
    uint64_t interval_pkts = 0;
    LARGE_INTEGER interval_start;
    QueryPerformanceCounter(&interval_start);

    printf("\n--- iperf Server Receive ---\n");
    printf("  Listen Port: %u\n", g_listen_port);
    if (g_vlan_id > 0) {
        printf("  VLAN: %u\n", g_vlan_id);
    } else {
        printf("  VLAN: None\n");
    }
    printf("  Timeout: %d sec (auto-stop after silence)\n", g_silence_timeout);
    printf("========================================\n\n");

    int is_tcp = 0;
    LARGE_INTEGER last_pkt_time;
    QueryPerformanceCounter(&last_pkt_time);
    int silence_timeout_ms = g_silence_timeout * 1000;

    while (g_running) {
        int payload_len = recv_packet(g_listen_port, src_mac, src_ip, &src_port,
                                      payload, sizeof(payload) - 1, 100, &is_vlan, &is_tcp, g_protocol);
        if (payload_len >= (int)sizeof(test_header_t)) {
            test_header_t *test_hdr = (test_header_t *)payload;
            (void)test_hdr;  /* payload already validated */

            if (first_pkt) {
                first_pkt = 0;
            }

            int transport_hdr_len = (g_protocol == PROTO_TCP) ? TCP_HDR_LEN : UDP_HDR_LEN;
            int hdr_len = get_frame_header_len();
            total_bytes += payload_len + hdr_len + IP_HDR_LEN + transport_hdr_len;
            total_pkts++;
            interval_bytes += payload_len + hdr_len + IP_HDR_LEN + transport_hdr_len;
            interval_pkts++;

            /* Reset silence timer on every received packet */
            QueryPerformanceCounter(&last_pkt_time);
        }

        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);

        /* Check silence timeout - auto stop if no packets for silence_timeout_ms */
        double silence_ms = (double)(now.QuadPart - last_pkt_time.QuadPart) * 1000.0 / freq.QuadPart;
        if (!first_pkt && silence_ms >= silence_timeout_ms) {
            break;
        }

        double interval_sec = (double)(now.QuadPart - interval_start.QuadPart) / freq.QuadPart;
        if (interval_sec >= g_report_interval) {
            /* Only print if we received packets this interval */
            if (interval_pkts > 0) {
                double bps = (double)interval_bytes * 8 / interval_sec;
                char bw_str[32], bytes_str[32];
                format_bps(bps, bw_str, sizeof(bw_str));
                format_bytes(interval_bytes, bytes_str, sizeof(bytes_str));
                printf("  [%5.1fs] %s  %s/s  %llu packets\n",
                       (double)(now.QuadPart - start.QuadPart) / freq.QuadPart,
                       bytes_str, bw_str,
                       (unsigned long long)interval_pkts);
            }

            interval_bytes = 0;
            interval_pkts = 0;
            interval_start = now;
            fflush(stdout);
        }
    }

    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    double total_sec = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    double avg_bps = (total_sec > 0) ? (double)total_bytes * 8 / total_sec : 0;

    char bw_str[32], bytes_str[32];
    format_bps(avg_bps, bw_str, sizeof(bw_str));
    format_bytes(total_bytes, bytes_str, sizeof(bytes_str));

    printf("\n========================================\n");
    printf("  [Test Complete]\n");
    printf("  Total Time: %.2f sec\n", total_sec);
    printf("  Total Data: %s\n", bytes_str);
    printf("  Total Pkts: %llu\n", (unsigned long long)total_pkts);
    printf("  Avg Bandwidth: %s\n", bw_str);
    printf("========================================\n");
}

/*=======================================================================
 * usage
 *=====================================================================*/

static void usage(const char *prog)
{
    printf("VLAN Tag Switch Test Tool (WinPcap/Npcap)\n");
    printf("L3 (IP+UDP/TCP) packet tester with optional VLAN tag\n");
    printf("\n");
    printf("Usage:\n");
    printf("  %s --list                            List available adapters\n", prog);
    printf("  %s -s [options]                      Server mode\n", prog);
    printf("  %s -c <host> [options]               Client mode\n", prog);
    printf("\n");
    printf("Common options:\n");
    printf("  -h              Show this help message\n");
    printf("  -v              Show version information\n");
    printf("  --list          List available adapters\n");
    printf("\n");
    printf("Server or Client:\n");
    printf("  -p, --port      #         server port to listen on/connect to (default %d)\n", DEFAULT_PORT);
    printf("  -B, --bind      <host>    bind to a specific interface\n");
    printf("  -V, --vlan      #         VLAN ID (1-4094, optional)\n");
    printf("  -u, --udp                 use UDP (default is TCP)\n");
    printf("\n");
    printf("Client specific:\n");
    printf("  -c, --client    <host>    run in client mode, connecting to <host>\n");
    printf("  -b, --bandwidth #[KMG]    target bandwidth in bits/sec (0 for unlimited)\n");
    printf("  -t, --time      #         time in seconds to transmit for (default 10)\n");
    printf("  -n, --bytes     #[KMG]    number of bytes to transmit (instead of -t)\n");
    printf("  -l, --len       #[KMG]    length of buffer to read or write (default 1400)\n");
    printf("  -P, --parallel  #         number of parallel client streams (default 1)\n");
    printf("  -i, --interval  #         seconds between bandwidth reports (default 1)\n");
    printf("      --interactive         interactive mode (print payload details)\n");
    printf("\n");
    printf("Server specific:\n");
    printf("  -s, --server              run in server mode\n");
    printf("  -T, --timeout     #       auto-stop after N seconds of silence (default 3)\n");
    printf("\n");
    printf("[KMG] indicates options that support a K/M/G suffix for kilo-, mega-, or giga-\n");
    printf("\n");
    printf("Description:\n");
    printf("  L3 (IP+UDP or IP+TCP) packets with optional L2 VLAN tag\n");
    printf("  Without -V: no VLAN tag, with -V <vlan_id>: add VLAN tag\n");
    printf("  Peer MAC resolved automatically via ARP\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --list\n", prog);
    printf("  %s -s -p 9999                    # TCP server, no VLAN\n", prog);
    printf("  %s -s -p 9999 -u                 # UDP server\n", prog);
    printf("  %s -s -p 9999 -V 100             # with VLAN 100\n", prog);
    printf("  %s -c 192.168.1.100 -p 9999       # TCP client, no VLAN\n", prog);
    printf("  %s -c 192.168.1.100 -p 9999 -u -V 100\n", prog);
    printf("  %s -c 192.168.1.100 -p 9999 -b 100M -t 30\n", prog);
    printf("  %s -c 192.168.1.100 -p 9999 -b 1G -u -V 100\n", prog);
    printf("  %s -s -p 9999 -T 30              # server waits 30s before auto-stop\n", prog);
    printf("  %s -c 192.168.1.100 -p 9999 --interactive  # interactive mode\n", prog);
}

static double parse_bandwidth(const char *str)
{
    double value;
    char unit[16] = {0};

    if (sscanf(str, "%lf%15s", &value, unit) < 1) return 0;

    if (unit[0] == 'G' || unit[0] == 'g')
        return value * 1e9;
    else if (unit[0] == 'M' || unit[0] == 'm')
        return value * 1e6;
    else if (unit[0] == 'K' || unit[0] == 'k')
        return value * 1e3;
    else
        return value;
}

static uint64_t parse_bytes(const char *str)
{
    double value;
    char unit[16] = {0};

    if (sscanf(str, "%lf%15s", &value, unit) < 1) return 0;

    if (unit[0] == 'G' || unit[0] == 'g')
        return (uint64_t)(value * 1073741824.0);  /* 1024^3 */
    else if (unit[0] == 'M' || unit[0] == 'm')
        return (uint64_t)(value * 1048576.0);     /* 1024^2 */
    else if (unit[0] == 'K' || unit[0] == 'k')
        return (uint64_t)(value * 1024.0);
    else
        return (uint64_t)value;
}

/*=======================================================================
 * Main function
 *=====================================================================*/

int main(int argc, char *argv[])
{
    pcap_if_t *alldevs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *adapter_name = NULL;
    char *server_ip_port = NULL;

    if (argc < 2 || (argc == 2 && (strcmp(argv[1], "-l") == 0 ||
                                    strcmp(argv[1], "--list") == 0))) {
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error: pcap_findalldevs: %s\n", errbuf);
            fprintf(stderr, "Hint: Make sure WinPcap or Npcap is installed\n");
            return 1;
        }
        printf("Available adapters:\n");
        list_adapters(alldevs);
        pcap_freealldevs(alldevs);
        return 0;
    }

    int arg_idx = 1;
    while (arg_idx < argc) {
        if (strcmp(argv[arg_idx], "-h") == 0 || strcmp(argv[arg_idx], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[arg_idx], "-v") == 0 || strcmp(argv[arg_idx], "--version") == 0) {
            printf("vlan_tag_switch version 1.0.15\n");
            return 0;
        } else if (strcmp(argv[arg_idx], "--list") == 0) {
            if (pcap_findalldevs(&alldevs, errbuf) == -1) {
                fprintf(stderr, "Error: pcap_findalldevs: %s\n", errbuf);
                return 1;
            }
            printf("Available adapters:\n");
            list_adapters(alldevs);
            pcap_freealldevs(alldevs);
            return 0;
        } else if (strcmp(argv[arg_idx], "-s") == 0 || strcmp(argv[arg_idx], "--server") == 0) {
            g_mode = MODE_SERVER;
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "-c") == 0 || strcmp(argv[arg_idx], "--client") == 0) {
            g_mode = MODE_CLIENT;
            arg_idx++;
            if (arg_idx < argc && argv[arg_idx][0] != '-') {
                server_ip_port = argv[arg_idx];
                arg_idx++;
            }
        } else if (strcmp(argv[arg_idx], "-p") == 0 || strcmp(argv[arg_idx], "--port") == 0) {
            if (arg_idx + 1 < argc) {
                g_listen_port = (uint16_t)atoi(argv[arg_idx + 1]);
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -p requires a port number\n");
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-B") == 0 || strcmp(argv[arg_idx], "--bind") == 0) {
            if (arg_idx + 1 < argc) {
                strncpy(g_bind_host, argv[arg_idx + 1], sizeof(g_bind_host) - 1);
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -B requires a host address\n");
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-V") == 0 || strcmp(argv[arg_idx], "--vlan") == 0) {
            if (arg_idx + 1 < argc) {
                g_vlan_id = (uint16_t)atoi(argv[arg_idx + 1]);
                if (g_vlan_id < 1 || g_vlan_id > 4094) {
                    fprintf(stderr, "Error: VLAN ID must be between 1-4094\n");
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -V requires a VLAN ID\n");
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-u") == 0 || strcmp(argv[arg_idx], "--udp") == 0) {
            g_protocol = PROTO_UDP;
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "-b") == 0 || strcmp(argv[arg_idx], "--bandwidth") == 0) {
            if (arg_idx + 1 < argc) {
                g_target_bps = parse_bandwidth(argv[arg_idx + 1]);
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -b requires a bandwidth value\n");
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-t") == 0 || strcmp(argv[arg_idx], "--time") == 0) {
            if (arg_idx + 1 < argc) {
                g_test_duration = atoi(argv[arg_idx + 1]);
                if (g_test_duration < 1 || g_test_duration > 3600) {
                    fprintf(stderr, "Error: time must be between 1-3600\n");
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -t requires a time value\n");
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-n") == 0 || strcmp(argv[arg_idx], "--bytes") == 0) {
            if (arg_idx + 1 < argc) {
                g_bytes_to_send = parse_bytes(argv[arg_idx + 1]);
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -n requires a byte count\n");
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-l") == 0 || strcmp(argv[arg_idx], "--len") == 0) {
            if (arg_idx + 1 < argc) {
                g_pkt_size = atoi(argv[arg_idx + 1]);
                if (g_pkt_size < 64 || g_pkt_size > 1472) {
                    fprintf(stderr, "Error: length must be between 64-1472\n");
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -l requires a length value\n");
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-P") == 0 || strcmp(argv[arg_idx], "--parallel") == 0) {
            if (arg_idx + 1 < argc) {
                g_parallel = atoi(argv[arg_idx + 1]);
                if (g_parallel < 1 || g_parallel > 100) {
                    fprintf(stderr, "Error: parallel must be between 1-100\n");
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -P requires a parallel count\n");
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-i") == 0 || strcmp(argv[arg_idx], "--interval") == 0) {
            if (arg_idx + 1 < argc) {
                g_report_interval = atoi(argv[arg_idx + 1]);
                if (g_report_interval < 1 || g_report_interval > 60) {
                    fprintf(stderr, "Error: interval must be between 1-60\n");
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -i requires an interval value\n");
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-T") == 0 || strcmp(argv[arg_idx], "--timeout") == 0) {
            if (arg_idx + 1 < argc) {
                g_silence_timeout = atoi(argv[arg_idx + 1]);
                if (g_silence_timeout < 1 || g_silence_timeout > 300) {
                    fprintf(stderr, "Error: timeout must be between 1-300\n");
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -T requires a timeout value\n");
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "--interactive") == 0) {
            g_interactive = 1;
            arg_idx++;
        } else if (adapter_name == NULL && argv[arg_idx][0] != '-') {
            adapter_name = argv[arg_idx];
            arg_idx++;
        } else {
            fprintf(stderr, "Error: Unknown argument: %s\n", argv[arg_idx]);
            usage(argv[0]);
            return 1;
        }
    }

    if (g_mode == MODE_NONE) {
        fprintf(stderr, "Error: Please use -s (server) or -c (client) to specify mode\n\n");
        usage(argv[0]);
        return 1;
    }

    if (g_mode == MODE_CLIENT && server_ip_port == NULL) {
        fprintf(stderr, "Error: Client mode requires server host address\n\n");
        usage(argv[0]);
        return 1;
    }

    if (g_listen_port == 0) {
        g_listen_port = DEFAULT_PORT;
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error: pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    if (adapter_name == NULL) {
        if (alldevs == NULL) {
            fprintf(stderr, "Error: No network adapter found\n");
            return 1;
        }
        adapter_name = alldevs->name;
        printf("Auto-selected adapter: %s\n", adapter_name);
        if (alldevs->description)
            printf("  Description: %s\n", alldevs->description);
    }

    g_handle = pcap_open_live(adapter_name,
                              MAX_PACKET_LEN,
                              1,
                              1,
                              errbuf);

    if (!g_handle) {
        fprintf(stderr, "Error: pcap_open_live: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (pcap_datalink(g_handle) != DLT_EN10MB) {
        fprintf(stderr, "Error: Adapter is not Ethernet type\n");
        pcap_close(g_handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (get_local_address(adapter_name, g_my_mac, g_my_ip) < 0) {
        fprintf(stderr, "Warning: Cannot get local MAC/IP\n");
    }

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    printf("========================================\n");
    printf(" VLAN Tag Switch Test Tool\n");
    printf("========================================\n");
    printf(" Mode      : %s\n", g_mode == MODE_SERVER ? "Server (-s)" : "Client (-c)");
    printf(" Adapter   : %s\n", adapter_name);
    print_mac("Local MAC", g_my_mac);
    print_ip("Local IP", g_my_ip);
    if (g_vlan_id > 0) {
        printf(" VLAN ID   : %u\n", g_vlan_id);
    } else {
        printf(" VLAN      : None (no VLAN tag)\n");
    }
    printf(" Protocol  : %s\n", g_protocol == PROTO_TCP ? "TCP" : "UDP");
    printf(" Port      : %u\n", g_listen_port);
    if (g_target_bps > 0) {
        char bw_str[32];
        format_bps(g_target_bps, bw_str, sizeof(bw_str));
        printf(" Target BW : %s\n", bw_str);
    }
    printf(" Duration  : %d sec\n", g_test_duration);
    printf(" Timeout   : %d sec (server auto-stop)\n", g_silence_timeout);
    printf(" Pkt Size  : %d bytes\n", g_pkt_size);
    printf(" Interval  : %d sec (report interval)\n", g_report_interval);
    printf("========================================\n");

    if (g_mode == MODE_CLIENT) {
        /* Parse server address: support both "ip:port" and "ip" (port from -p) */
        char ip_str[64];
        strncpy(ip_str, server_ip_port, sizeof(ip_str) - 1);
        ip_str[sizeof(ip_str) - 1] = '\0';

        /* Check if port is embedded in the address (contains ':') */
        char *colon = strrchr(ip_str, ':');
        if (colon) {
            /* Format: ip:port - extract both */
            *colon = '\0';
            int port = atoi(colon + 1);
            if (port > 0 && port <= 65535) {
                g_listen_port = (uint16_t)port;
            }
        }
        /* else: port comes from -p flag (already set) */

        if (parse_ip(ip_str, g_peer_ip) < 0) {
            fprintf(stderr, "Error: Invalid IP address: %s\n", ip_str);
            pcap_close(g_handle);
            pcap_freealldevs(alldevs);
            return 1;
        }
        print_ip("Peer IP", g_peer_ip);
        printf(" Peer Port : %u\n", g_listen_port);
        printf("========================================\n");

        printf("\n[ARP] Resolving peer MAC address...\n");
        if (arp_resolve(g_handle, g_my_mac, g_my_ip, g_peer_ip, g_peer_mac,
                        ARP_TIMEOUT_MS) < 0) {
            fprintf(stderr, "Error: ARP resolution failed, cannot get peer MAC\n");
            pcap_close(g_handle);
            pcap_freealldevs(alldevs);
            return 1;
        }
        print_mac("Peer MAC", g_peer_mac);
        printf("========================================\n");
    }

    if (g_interactive) {
        /* Interactive mode: print packet payload details */
        if (g_mode == MODE_SERVER) {
            server_interactive_loop();
        } else {
            client_interactive_loop();
        }
    } else {
        /* Default / iperf test mode: only print bandwidth */
        if (g_mode == MODE_CLIENT) {
            iperf_client_test();
        } else {
            iperf_server_test();
        }
    }

    printf("\nStopped.\n");
    pcap_close(g_handle);
    pcap_freealldevs(alldevs);
    return 0;
}
