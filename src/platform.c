/*
 * platform.c - Platform Layer implementation
 *
 * Send pipeline: tcp_build -> ipv4_build -> [vlan_build] -> eth_build -> pcap_sendpacket
 * Receive pipeline: pcap_next_ex -> eth_parse -> ipv4_parse -> tcp_parse -> tcp_fsm_input
 *
 * Constraints enforced here:
 *   - ALL TCP via pcap_sendpacket(), never a socket.
 *   - pcap_open_live timeout = 100ms (never 1ms).
 *   - All buffers static/global/malloc, never on the stack.
 *   - Software checksums (IP + TCP/UDP pseudo-header).
 */
#include "platform.h"

volatile LONG g_stop = 0;
int g_platform_verbose = 0;
void platform_set_verbose(int v) { g_platform_verbose = v; }

#ifdef USE_WINPCAP
static pcap_t *g_pcap = NULL;
#endif

/* ---------------------------------------------------------------------
 * Timing
 * -------------------------------------------------------------------*/
static LARGE_INTEGER g_qpc_freq;
static int g_have_qpc = 0;
static UINT g_timer_period = 0;

uint64_t time_now_ms(void)
{
    LARGE_INTEGER now;
    if (g_have_qpc && QueryPerformanceCounter(&now))
        return (uint64_t)(now.QuadPart * 1000ULL / g_qpc_freq.QuadPart);
    return GetTickCount64();
}

/* ---------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------*/
int platform_init(void)
{
    if (QueryPerformanceFrequency(&g_qpc_freq)) g_have_qpc = 1;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Error: WSAStartup failed\n");
        return -1;
    }
    return 0;
}

void platform_cleanup(void)
{
#ifdef USE_WINPCAP
    if (g_pcap) { pcap_close(g_pcap); g_pcap = NULL; }
#endif
    WSACleanup();
}

void platform_set_timer_resolution(void)
{
    TIMECAPS tc;
    if (timeGetDevCaps(&tc, sizeof(tc)) == MMSYSERR_NOERROR) {
        g_timer_period = tc.wPeriodMin;
        timeBeginPeriod(g_timer_period);
    }
}
void platform_restore_timer_resolution(void)
{
    if (g_timer_period) { timeEndPeriod(g_timer_period); g_timer_period = 0; }
}

static BOOL WINAPI ctrl_handler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        InterlockedExchange(&g_stop, 1);
#ifdef USE_WINPCAP
        if (g_pcap) pcap_breakloop(g_pcap);
#endif
        return TRUE;
    }
    return FALSE;
}
int platform_install_ctrl_handler(void)
{
    return SetConsoleCtrlHandler(ctrl_handler, TRUE) ? 0 : -1;
}

/* ---------------------------------------------------------------------
 * Adapter enumeration (IP Helper API)
 * -------------------------------------------------------------------*/
int get_mac_for_ip(uint32_t ip, uint8_t *mac)
{
    ULONG buf_len = 0;
    if (GetAdaptersInfo(NULL, &buf_len) != ERROR_BUFFER_OVERFLOW) return -1;
    IP_ADAPTER_INFO *info = (IP_ADAPTER_INFO *)malloc(buf_len);
    if (!info) return -1;
    int ok = -1;
    if (GetAdaptersInfo(info, &buf_len) == NO_ERROR) {
        for (IP_ADAPTER_INFO *p = info; p; p = p->Next) {
            if (inet_addr(p->IpAddressList.IpAddress.String) == ip) {
                int n = p->AddressLength < 6 ? p->AddressLength : 6;
                memcpy(mac, p->Address, n);
                ok = 0; break;
            }
        }
    }
    free(info);
    return ok;
}

#ifdef USE_WINPCAP

int get_adapter_name_by_ip(uint32_t ip, char *name, int name_len)
{
    ULONG buf_len = 0;
    if (GetAdaptersInfo(NULL, &buf_len) != ERROR_BUFFER_OVERFLOW) return -1;
    IP_ADAPTER_INFO *info = (IP_ADAPTER_INFO *)malloc(buf_len);
    if (!info) return -1;
    int ok = -1;
    if (GetAdaptersInfo(info, &buf_len) == NO_ERROR) {
        for (IP_ADAPTER_INFO *p = info; p; p = p->Next) {
            if (inet_addr(p->IpAddressList.IpAddress.String) == ip) {
                /* p->AdapterName is the GUID; build the pcap device name */
                snprintf(name, name_len, "\\Device\\NPF_%s", p->AdapterName);
                ok = 0;
                break;
            }
        }
    }
    free(info);
    return ok;
}

int get_mac_for_bind(uint32_t bind_ip, uint8_t *mac)
{
    adapter_info_t list[32];
    int n = platform_enum_adapters(list, 32);
    if (bind_ip == 0) {
        /* default: first non-loopback adapter with an IP */
        for (int i = 0; i < n; i++) {
            if (!list[i].is_loopback && list[i].ip) {
                memcpy(mac, list[i].mac, 6);
                return 0;
            }
        }
    } else {
        for (int i = 0; i < n; i++) {
            if (list[i].ip == bind_ip) {
                memcpy(mac, list[i].mac, 6);
                return 0;
            }
        }
    }
    return -1;
}

int platform_enum_adapters(adapter_info_t *out, int cap)
{
    pcap_if_t *alldevs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) return 0;

    for (pcap_if_t *d = alldevs; d && count < cap; d = d->next) {
        adapter_info_t *a = &out[count];
        snprintf(a->name, sizeof(a->name), "%s", d->name);
        snprintf(a->desc, sizeof(a->desc), "%s", d->description ? d->description : "");
        a->ip = 0; memset(a->mac, 0, 6);
        a->is_loopback = (d->flags & PCAP_IF_LOOPBACK) ? 1 : 0;
        for (pcap_addr_t *ad = d->addresses; ad; ad = ad->next) {
            if (ad->addr && ad->addr->sa_family == AF_INET) {
                a->ip = ((struct sockaddr_in *)ad->addr)->sin_addr.s_addr;
                break;
            }
        }
        if (a->ip) get_mac_for_ip(a->ip, a->mac);
        count++;
    }
    pcap_freealldevs(alldevs);
    return count;
}

int platform_find_adapter_by_ip(uint32_t ip)
{
    adapter_info_t list[32];
    int n = platform_enum_adapters(list, 32);
    for (int i = 0; i < n; i++) if (list[i].ip == ip) return i;
    return -1;
}

/* ---------------------------------------------------------------------
 * Send pipeline -- builds a complete frame in a static buffer
 *
 * Layout (tagged): DMAC(6) SMAC(6) TPID(2) TCI(2) ETYPE(2) IP(20) TCP(20) payload
 *        (plain):  DMAC(6) SMAC(6) ETYPE(2)                 IP(20) TCP(20) payload
 * -------------------------------------------------------------------*/

/* ---------------------------------------------------------------------
 * Debug helpers (defined first: arp_resolve / send paths call log_send)
 * -------------------------------------------------------------------*/
const char *fmt_ip(uint32_t ip)
{
    static char buf[4][20];
    static int rot = 0;
    char *b = buf[rot++ & 3];
    snprintf(b, 20, "%u.%u.%u.%u",
             ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    return b;
}

static void log_send(const uint8_t *frame, int len, const char *kind,
                     uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp,
                     uint16_t vlan_id, const char *extra)
{
    (void)vlan_id;
    if (!g_platform_verbose) return;
    uint16_t et = (frame[12] << 8) | frame[13];
    printf("[SEND] %s %s:%u -> %s:%u et=0x%04x",
           kind, fmt_ip(sip), sp, fmt_ip(dip), dp, et);
    if (et == ETHERTYPE_VLAN) {
        uint16_t tci = (frame[14] << 8) | frame[15];
        uint16_t inner = (frame[16] << 8) | frame[17];
        printf(" VLAN=%u inner=0x%04x", tci & 0xFFF, inner);
    }
    printf(" len=%d", len);
    if (extra) printf(" %s", extra);
    printf("\n");
    if (g_platform_verbose > 1) hex_dump(frame, len < 72 ? len : 72, "      ");
}

/* ARP resolution (used by flow engine before active open) */
static int arp_resolve(uint32_t my_ip, uint32_t peer_ip, uint8_t *peer_mac,
                       const char *dev_name)
{
    (void)dev_name;
    uint8_t my_mac[6];
    get_mac_for_ip(my_ip, my_mac);

    uint8_t *frame = (uint8_t *)malloc(60);
    if (!frame) return -1;
    eth_header_t *eth = (eth_header_t *)frame;
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, my_mac, 6);
    eth->ethertype = htons(ETHERTYPE_ARP);

    /* ARP payload */
    uint8_t *arp = frame + ETH_HDR_LEN;
    memset(arp, 0, 28);
    arp[0] = 0; arp[1] = 1;          /* hw type eth */
    arp[2] = 8; arp[3] = 0;          /* proto IPv4 */
    arp[4] = 6; arp[5] = 4;          /* hw/proto len */
    arp[6] = 0; arp[7] = 1;          /* request */
    memcpy(arp + 8, my_mac, 6);      /* sender mac */
    memcpy(arp + 14, &my_ip, 4);     /* sender ip */
    /* target mac zero */
    memcpy(arp + 24, &peer_ip, 4);   /* target ip */

    log_send(frame, 60, "ARP", my_ip, peer_ip, 0, 0, 0, "request");
    pcap_sendpacket(g_pcap, frame, 60);
    free(frame);

    int deadline = GetTickCount() + ARP_TIMEOUT_MS;
    int ok = -1;
    while (!g_stop && (int)(GetTickCount() - deadline) < 0) {
        struct pcap_pkthdr *hdr;
        const uint8_t *pkt;
        int r = pcap_next_ex(g_pcap, &hdr, &pkt);
        if (r == 1 && hdr->len >= 42) {
            if (g_platform_verbose) {
                uint16_t et = (pkt[12] << 8) | pkt[13];
                printf("[RECV] ARP-REPLY et=0x%04x len=%u\n", et, hdr->len);
                if (g_platform_verbose > 1) hex_dump(pkt, hdr->len < 72 ? (int)hdr->len : 72, "      ");
            }
            eth_header_t *re = (eth_header_t *)pkt;
            uint16_t et = ntohs(re->ethertype);
            const uint8_t *ra = (uint8_t *)pkt + ETH_HDR_LEN;
            /* skip VLAN tag if present */
            if (et == ETHERTYPE_VLAN) {
                if (hdr->len < ETH_HDR_LEN + VLAN_TAG_LEN + 28) continue;
                et = (uint16_t)((pkt[ETH_HDR_LEN + 2] << 8) | pkt[ETH_HDR_LEN + 3]);
                ra = (uint8_t *)pkt + ETH_HDR_LEN + VLAN_TAG_LEN;
            }
            if (et != ETHERTYPE_ARP) continue;
            if (ra[6] || ra[7] != 2) continue;   /* not a reply */
            uint32_t sip; memcpy(&sip, ra + 14, 4);
            if (sip != peer_ip) continue;
            memcpy(peer_mac, ra + 8, 6);
            ok = 0; break;
        } else if (r == -1) break;
    }
    return ok;
}

/* public: resolve peer MAC given our TCB's addresses */
int platform_arp_resolve_tcb(tcb_t *tcb)
{
    if (arp_resolve(tcb->local_ip, tcb->remote_ip, tcb->remote_mac,
                    NULL) != 0) return -1;
    return 0;
}

/* ---------------------------------------------------------------------
 * eth_build: plain Ethernet header (no VLAN)
 * -------------------------------------------------------------------*/
static uint8_t *eth_build(uint8_t *p, const uint8_t *dst, const uint8_t *src)
{
    eth_header_t *eth = (eth_header_t *)p;
    memcpy(eth->dst, dst, 6);
    memcpy(eth->src, src, 6);
    eth->ethertype = htons(ETHERTYPE_IP);
    return p + ETH_HDR_LEN;
}

/* ---------------------------------------------------------------------
 * eth_build_with_vlan: Ethernet header + 802.1Q tag
 * -------------------------------------------------------------------*/
static uint8_t *eth_build_with_vlan(uint8_t *p, const uint8_t *dst, const uint8_t *src,
                                    uint16_t vlan_id, uint8_t vlan_pcp)
{
    eth_header_t *eth = (eth_header_t *)p;
    memcpy(eth->dst, dst, 6);
    memcpy(eth->src, src, 6);
    eth->ethertype = htons(ETHERTYPE_VLAN);  /* offset 12-13: TPID 0x8100 */
    p += ETH_HDR_LEN;                         /* p -> offset 14 */

    /* TCI (2 bytes) at offset 14-15 */
    uint16_t tci = (uint16_t)(((vlan_pcp & 7) << VLAN_PCP_SHIFT)
                              | (vlan_id & VLAN_VID_MASK));
    p[0] = (uint8_t)(tci >> 8);
    p[1] = (uint8_t)(tci & 0xFF);

    /* Inner EtherType (2 bytes) at offset 16-17 */
    { uint16_t et = htons(ETHERTYPE_IP); memcpy(p + 2, &et, 2); }

    return p + VLAN_TAG_LEN;  /* VLAN_TAG_LEN=4: TCI(2)+EtherType(2) -> offset 18 */
}

/* ---------------------------------------------------------------------
 * raw_send_segment: the ONLY TCP transmit path
 * vlan_id == 0 -> eth_build(), vlan_id > 0 -> eth_build_with_vlan()
 * -------------------------------------------------------------------*/
int raw_send_segment(const tcb_t *tcb, const uint8_t *tcp_payload,
                     int payload_len, uint8_t flags)
{
    static uint8_t frame[FRAME_BUF_SIZE];   /* static: never on stack */
    uint8_t *p = frame;

    /* --- eth_build / eth_build_with_vlan --- */
    if (tcb->vlan_id > 0) {
        p = eth_build_with_vlan(p, tcb->remote_mac, tcb->local_mac,
                                tcb->vlan_id, tcb->vlan_pcp);
    } else {
        p = eth_build(p, tcb->remote_mac, tcb->local_mac);
    }

    /* --- ipv4_build --- */
    int total_payload = TCP_HDR_LEN + payload_len;
    ipv4_header_t *ip = (ipv4_header_t *)p;
    memset(ip, 0, IPV4_HDR_LEN);
    ip->ver_ihl  = 0x45;
    ip->tos      = 0;
    ip->total_len = htons(IPV4_HDR_LEN + total_payload);
    ip->id       = htons((uint16_t)(GetTickCount() & 0xFFFF));
    ip->frag_off = htons(IP_FRAG_DF);
    ip->ttl      = 64;
    ip->protocol = IP_PROTOCOL_TCP;
    ip->src      = tcb->local_ip;
    ip->dst      = tcb->remote_ip;
    ip->checksum = inet_checksum(ip, IPV4_HDR_LEN);
    p += IPV4_HDR_LEN;

    /* --- tcp_build --- */
    tcp_header_t *tcp = (tcp_header_t *)p;
    memset(tcp, 0, TCP_HDR_LEN);
    tcp->sport   = htons(tcb->local_port);
    tcp->dport   = htons(tcb->remote_port);
    tcp->seq     = htonl(tcb->snd_nxt);
    tcp->ack_seq = htonl(tcb->rcv_nxt);
    tcp->data_off = (TCP_HDR_WORDS << 4);
    tcp->flags   = flags;
    tcp->window  = htons((uint16_t)MIN(tcb->rcv_wnd, 0xFFFF));
    tcp->urg_ptr = 0;

    if (tcp_payload && payload_len > 0) {
        memcpy(p + TCP_HDR_LEN, tcp_payload, payload_len);
    }

    /* TCP checksum over header + payload + pseudo-header */
    tcp->checksum = tcp_udp_checksum(tcb->local_ip, tcb->remote_ip,
                                     IP_PROTOCOL_TCP, tcp,
                                     TCP_HDR_LEN + payload_len);
    p += TCP_HDR_LEN + payload_len;
    int len = (int)(p - frame);

    /* Pad to minimum Ethernet frame (60 bytes without FCS).
     * A bare TCP SYN is only 54 bytes (14+20+20); some NICs/Npcap
     * reject or corrupt frames below the minimum. UDP datagrams with
     * a full payload already exceed this, so the memset is a no-op. */
    if (len < 60) {
        memset(frame + len, 0, 60 - len);
        len = 60;
    }

    log_send(frame, len, "TCP", tcb->local_ip, tcb->remote_ip,
             tcb->local_port, tcb->remote_port, tcb->vlan_id, NULL);

    if (pcap_sendpacket(g_pcap, frame, len) != 0) {
        fprintf(stderr, "Error: pcap_sendpacket: %s\n", pcap_geterr(g_pcap));
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * raw_send_udp: UDP datagram (no TCP state machine)
 * -------------------------------------------------------------------*/
int raw_send_udp(uint32_t src_ip, const uint8_t *src_mac,
                 uint32_t dst_ip, const uint8_t *dst_mac,
                 uint16_t sport, uint16_t dport,
                 const uint8_t *payload, int payload_len,
                 uint16_t vlan_id, uint8_t vlan_pcp)
{
    static uint8_t frame[FRAME_BUF_SIZE];
    uint8_t *p = frame;

    /* eth_build / eth_build_with_vlan */
    if (vlan_id > 0) {
        p = eth_build_with_vlan(p, dst_mac, src_mac, vlan_id, vlan_pcp);
    } else {
        p = eth_build(p, dst_mac, src_mac);
    }

    ipv4_header_t *ip = (ipv4_header_t *)p;
    memset(ip, 0, IPV4_HDR_LEN);
    ip->ver_ihl  = 0x45;
    ip->total_len = htons(IPV4_HDR_LEN + UDP_HDR_LEN + payload_len);
    ip->id       = htons((uint16_t)(GetTickCount() & 0xFFFF));
    ip->frag_off = htons(IP_FRAG_DF);
    ip->ttl      = 64;
    ip->protocol = IP_PROTOCOL_UDP;
    ip->src      = src_ip;
    ip->dst      = dst_ip;
    ip->checksum = inet_checksum(ip, IPV4_HDR_LEN);
    p += IPV4_HDR_LEN;

    udp_header_t *udp = (udp_header_t *)p;
    memset(udp, 0, UDP_HDR_LEN);
    udp->sport = htons(sport);
    udp->dport = htons(dport);
    udp->len   = htons(UDP_HDR_LEN + payload_len);
    if (payload && payload_len > 0) memcpy(p + UDP_HDR_LEN, payload, payload_len);
    udp->checksum = tcp_udp_checksum(src_ip, dst_ip, IP_PROTOCOL_UDP,
                                     udp, UDP_HDR_LEN + payload_len);
    p += UDP_HDR_LEN + payload_len;

    int len = (int)(p - frame);
    /* pad to minimum Ethernet frame (60 bytes without FCS) */
    if (len < 60) {
        memset(frame + len, 0, 60 - len);
        len = 60;
    }
    log_send(frame, len, "UDP", src_ip, dst_ip, sport, dport, vlan_id, NULL);

    if (pcap_sendpacket(g_pcap, frame, len) != 0) {
        fprintf(stderr, "Error: pcap_sendpacket: %s\n", pcap_geterr(g_pcap));
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * Receive pipeline
 * -------------------------------------------------------------------*/

int platform_open_sniffer(uint32_t bind_ip, const char *name)
{
    pcap_if_t *alldevs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char dev_name[1024] = {0};

    /* If caller provided the exact pcap device name, use it directly. */
    if (name && name[0]) {
        snprintf(dev_name, sizeof(dev_name), "%s", name);
        goto open_it;
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error: pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    /* find adapter owning bind_ip, else first non-loopback with IP */
    int found = 0;
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        if (d->flags & PCAP_IF_LOOPBACK) continue;
        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                uint32_t ip = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
                if (ip == bind_ip) {
                    snprintf(dev_name, sizeof(dev_name), "%s", d->name);
                    found = 1; break;
                }
            }
        }
        if (found) break;
    }
    if (!found) {
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            if (d->flags & PCAP_IF_LOOPBACK) continue;
            for (pcap_addr_t *a = d->addresses; a; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    snprintf(dev_name, sizeof(dev_name), "%s", d->name);
                    found = 1; break;
                }
            }
            if (found) break;
        }
    }
    pcap_freealldevs(alldevs);

    if (!dev_name[0]) {
        fprintf(stderr, "Error: no suitable adapter\n");
        return -1;
    }

open_it:
    /* snaplen: 2048 is plenty for Eth+VLAN+IP+TCP+MSS (max ~1542 bytes).
     * Some Npcap versions reject 65536 on older Windows. */
    g_pcap = pcap_open_live(dev_name, 2048, 1, 100, errbuf);
    if (!g_pcap) {
        fprintf(stderr, "Error: pcap_open_live(%s): %s\n", dev_name, errbuf);
        return -1;
    }
    if (pcap_datalink(g_pcap) != DLT_EN10MB) {
        fprintf(stderr, "Error: %s is not Ethernet\n", dev_name);
        pcap_close(g_pcap); g_pcap = NULL;
        return -1;
    }
    printf("Sniffing on %s\n", dev_name);
    return 0;
}

void platform_close_sniffer(void)
{
    if (g_pcap) { pcap_close(g_pcap); g_pcap = NULL; }
}

void platform_breakloop(void)
{
    if (g_pcap) pcap_breakloop(g_pcap);
}

/*
 * Parse one frame and dispatch.
 *   cb  : UDP-mode callback (NULL = TCP mode)
 *   ctx : callback context
 */
int platform_recv_dispatch(udp_rx_cb_t cb, void *ctx)
{
    struct pcap_pkthdr *hdr;
    const uint8_t *pkt;
    int r = pcap_next_ex(g_pcap, &hdr, &pkt);
    if (r != 1) return (r == 0) ? 0 : -1;
    int pkt_len = (int)hdr->len;
    if (pkt_len < ETH_HDR_LEN + IPV4_HDR_LEN + 8) return 0;

    if (g_platform_verbose) {
        uint16_t et_raw = (pkt[12] << 8) | pkt[13];
        printf("[RECV] et=0x%04x len=%d", et_raw, pkt_len);
        if (et_raw == ETHERTYPE_VLAN) {
            uint16_t tci = (pkt[14] << 8) | pkt[15];
            uint16_t inner = (pkt[16] << 8) | pkt[17];
            printf(" VLAN=%u inner=0x%04x", tci & 0xFFF, inner);
        }
    }

    /* --- eth_parse --- */
    eth_header_t *eth = (eth_header_t *)pkt;
    uint16_t et = ntohs(eth->ethertype);
    const uint8_t *l3 = pkt + ETH_HDR_LEN;
    int l3_len = pkt_len - ETH_HDR_LEN;
    int has_vlan = 0;
    uint16_t vlan_tci = 0;

    if (et == ETHERTYPE_VLAN) {
        if (pkt_len < ETH_HDR_LEN + VLAN_TAG_LEN + IPV4_HDR_LEN) return 0;
        has_vlan = 1;
        vlan_tci = (uint16_t)((pkt[ETH_HDR_LEN] << 8) | pkt[ETH_HDR_LEN + 1]);
        l3 = pkt + ETH_HDR_LEN + VLAN_TAG_LEN;
        l3_len = pkt_len - ETH_HDR_LEN - VLAN_TAG_LEN;
        /* inner ethertype = bytes at offset ETH_HDR_LEN+2..+3 (after TPID) */
        et = (uint16_t)((pkt[ETH_HDR_LEN + 2] << 8) | pkt[ETH_HDR_LEN + 3]);
    }
    if (et != ETHERTYPE_IP) {
        if (g_platform_verbose) printf(" -> SKIP (et=0x%04x != 0x%04x)\n", et, ETHERTYPE_IP);
        return 0;
    }

    /* --- ipv4_parse --- */
    ipv4_header_t *ip = (ipv4_header_t *)l3;
    int ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ihl < IPV4_HDR_LEN) return 0;
    int total_len = ntohs(ip->total_len);
    if (total_len > l3_len) total_len = l3_len;

    if (ip->protocol == IP_PROTOCOL_UDP && cb) {
        if (g_platform_verbose)
            printf(" UDP %s:%u -> %s:%u pay=%d\n",
                   fmt_ip(ip->src), ntohs(((udp_header_t *)(l3 + ihl))->sport),
                   fmt_ip(ip->dst), ntohs(((udp_header_t *)(l3 + ihl))->dport),
                   total_len - ihl - UDP_HDR_LEN);
        /* UDP mode: hand raw frame to callback */
        cb(pkt, pkt_len, ctx);
        return 1;
    }
    if (ip->protocol != IP_PROTOCOL_TCP) return 0;

    /* --- tcp_parse --- */
    const uint8_t *tp = l3 + ihl;
    int tp_len = total_len - ihl;
    if (tp_len < TCP_HDR_LEN) return 0;

    tcp_header_t *tcp = (tcp_header_t *)tp;
    int tcp_doff = ((tcp->data_off >> 4) & 0x0F) * 4;
    if (tcp_doff < TCP_HDR_LEN || tcp_doff > tp_len) return 0;

    parsed_tcp_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    memcpy(parsed.src_mac, eth->src, 6);
    memcpy(parsed.dst_mac, eth->dst, 6);
    parsed.has_vlan   = has_vlan;
    parsed.vlan_id    = has_vlan ? (uint16_t)(vlan_tci & VLAN_VID_MASK) : 0;
    parsed.vlan_pcp   = has_vlan ? (uint8_t)((vlan_tci >> VLAN_PCP_SHIFT) & 7) : 0;
    parsed.src_ip     = ip->src;
    parsed.dst_ip     = ip->dst;
    parsed.sport      = ntohs(tcp->sport);
    parsed.dport      = ntohs(tcp->dport);
    parsed.seq        = ntohl(tcp->seq);
    parsed.ack_seq    = ntohl(tcp->ack_seq);
    parsed.flags      = tcp->flags;
    parsed.window     = ntohs(tcp->window);
    parsed.payload    = (uint8_t *)(tp + tcp_doff);
    parsed.payload_len = tp_len - tcp_doff;

    if (g_platform_verbose) {
        char fb[64];
        int n = 0;
        if (tcp->flags & TCP_SYN) n += snprintf(fb + n, sizeof(fb) - n, "SYN ");
        if (tcp->flags & TCP_ACK) n += snprintf(fb + n, sizeof(fb) - n, "ACK ");
        if (tcp->flags & TCP_FIN) n += snprintf(fb + n, sizeof(fb) - n, "FIN ");
        if (tcp->flags & TCP_RST) n += snprintf(fb + n, sizeof(fb) - n, "RST ");
        if (tcp->flags & TCP_PSH) n += snprintf(fb + n, sizeof(fb) - n, "PSH ");
        if (n > 0) fb[n - 1] = '\0';
        else snprintf(fb, sizeof(fb), "0x%02x", tcp->flags);
        printf(" TCP %s:%u -> %s:%u %s seq=%u ack=%u pay=%d\n",
               fmt_ip(ip->src), parsed.sport, fmt_ip(ip->dst), parsed.dport,
               fb, parsed.seq, parsed.ack_seq, parsed.payload_len);
    }

    /* --- dispatch to FSM --- */
    tcp_fsm_input(&parsed, eth->src);
    return 1;
}

#else  /* !USE_WINPCAP */

/* Stubs for builds without WinPcap */
int platform_enum_adapters(adapter_info_t *o, int c) { (void)o;(void)c; return 0; }
int platform_find_adapter_by_ip(uint32_t i) { (void)i; return -1; }
int platform_open_sniffer(uint32_t b, const char *n) { (void)b;(void)n; return -1; }
int platform_recv_dispatch(udp_rx_cb_t c, void *x) { (void)c;(void)x; return -1; }
void platform_close_sniffer(void) {}
void platform_breakloop(void) {}
int raw_send_segment(const tcb_t *t, const uint8_t *p, int l, uint8_t f)
{ (void)t;(void)p;(void)l;(void)f; return -1; }
int raw_send_udp(uint32_t a,const uint8_t *b,uint32_t c,const uint8_t *d,
                 uint16_t e,uint16_t f,const uint8_t *g,int h,uint16_t i,uint8_t j)
{ (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;(void)j; return -1; }

#endif /* USE_WINPCAP */
