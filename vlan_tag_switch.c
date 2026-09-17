/*
 * vlan_tag_switch.c - WinPcap/Npcap VLAN tag switch test tool (Windows)
 *
 * Function: Simulate switch behavior, L3 (IP+UDP) packets, optional L2 VLAN tag
 *   -s (server) mode: listen on port, strip VLAN tag and print payload, reply/stats
 *   -c (client) mode: connect to server, send packets with VLAN tag, receive replies
 *   -t (test)   mode: iperf-like bandwidth test, send high traffic and statistics
 *
 * VLAN optional: without -v no VLAN tag, with -v <vlan_id> adds VLAN tag
 *
 * Usage:
 *   Server: vlan_tag_switch.exe -s [-p <port>] [-a <ip>] [-v <vlan_id>]
 *   Client: vlan_tag_switch.exe -c <server_ip:port> [-v <vlan_id>] [-i]
 *   Test:   vlan_tag_switch.exe -c <server_ip:port> -t [-b <bw>] [-d <sec>] [-l <len>] [-v <vlan_id>]
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
static int       g_interactive = 1;
static int       g_test_mode  = 0;

/* Test parameters */
static double   g_target_bps  = 0;
static int      g_test_duration = 10;
static int      g_pkt_size    = 1400;

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

static int parse_ip_port(const char *str, uint8_t *ip, uint16_t *port)
{
    char ip_str[64];
    int p;
    const char *colon = strrchr(str, ':');
    if (!colon) return -1;

    int ip_len = (int)(colon - str);
    if (ip_len >= (int)sizeof(ip_str)) return -1;
    strncpy(ip_str, str, ip_len);
    ip_str[ip_len] = '\0';
    p = atoi(colon + 1);

    if (p < 1 || p > 65535) return -1;
    if (parse_ip(ip_str, ip) < 0) return -1;
    *port = (uint16_t)p;
    return 0;
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
 * Build packet (optional VLAN tag)
 * vlan_id=0 means no VLAN tag
 */
static int build_packet(uint8_t *frame, int frame_size,
                        const uint8_t *dst_mac, const uint8_t *src_mac,
                        uint16_t vlan_id, uint8_t pcp,
                        const uint8_t *src_ip, const uint8_t *dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        const uint8_t *payload, int payload_len)
{
    int hdr_len = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    uint16_t eth_type = ETHERTYPE_IP;

    if (vlan_id > 0) {
        hdr_len += VLAN_TAG_LEN;
        eth_type = ETHERTYPE_VLAN;
    }

    int total_len = hdr_len + payload_len;
    if (total_len > frame_size) return -1;

    eth_header_t  *eth   = (eth_header_t *)frame;
    ip_header_t   *ip    = (ip_header_t *)(frame + hdr_len - IP_HDR_LEN - UDP_HDR_LEN);
    udp_header_t  *udp   = (udp_header_t *)(frame + hdr_len - UDP_HDR_LEN);
    uint8_t       *data  = frame + hdr_len;

    /* Ethernet header */
    memcpy(eth->dst_mac, dst_mac, 6);
    memcpy(eth->src_mac, src_mac, 6);
    eth->ethertype = htons(eth_type);

    /* VLAN tag (optional) */
    if (vlan_id > 0) {
        vlan_tag_t *vlan = (vlan_tag_t *)(frame + ETH_HDR_LEN);
        vlan->tpid = htons(ETHERTYPE_VLAN);
        vlan->tci  = htons(((uint16_t)(pcp & 0x07) << VLAN_PCP_SHIFT) | (vlan_id & VLAN_VID_MASK));
    }

    /* IP header */
    ip->ver_ihl    = 0x45;
    ip->tos        = 0;
    ip->total_len  = htons(IP_HDR_LEN + UDP_HDR_LEN + payload_len);
    ip->id         = htons((uint16_t)GetTickCount());
    ip->flags_frag = 0;
    ip->ttl        = 64;
    ip->protocol   = IP_PROTOCOL_UDP;
    ip->checksum   = 0;
    memcpy(ip->src_ip, src_ip, 4);
    memcpy(ip->dst_ip, dst_ip, 4);
    ip->checksum   = calc_checksum((uint16_t *)ip, IP_HDR_LEN);

    /* UDP header */
    udp->src_port  = htons(src_port);
    udp->dst_port  = htons(dst_port);
    udp->length    = htons(UDP_HDR_LEN + payload_len);
    udp->checksum  = 0;

    /* Payload */
    if (payload_len > 0)
        memcpy(data, payload, payload_len);

    return total_len;
}

/*
 * Parse received packet (auto-detect VLAN tag)
 * Returns payload length
 * out_is_vlan: if not NULL, returns whether packet has VLAN
 */
static int parse_packet(const uint8_t *pkt, int pkt_len,
                        uint8_t *out_src_mac, uint8_t *out_dst_mac,
                        uint16_t *out_vlan_id, uint8_t *out_pcp,
                        uint8_t *out_src_ip, uint8_t *out_dst_ip,
                        uint16_t *out_src_port, uint16_t *out_dst_port,
                        uint8_t *out_payload, int max_payload_len,
                        uint16_t expected_dst_port,
                        int *out_is_vlan)
{
    if (pkt_len < ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN)
        return -1;

    const eth_header_t *eth = (const eth_header_t *)pkt;
    uint16_t ethertype = ntohs(eth->ethertype);
    int vlan = 0;
    int ip_offset = ETH_HDR_LEN;

    if (ethertype == ETHERTYPE_VLAN) {
        vlan = 1;
        ip_offset = VLAN_ETH_HDR_LEN;
        if (pkt_len < VLAN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN)
            return -1;
    }

    const ip_header_t  *ip   = (const ip_header_t *)(pkt + ip_offset);
    const udp_header_t *udp  = (const udp_header_t *)(pkt + ip_offset + IP_HDR_LEN);
    const uint8_t      *data = pkt + ip_offset + IP_HDR_LEN + UDP_HDR_LEN;

    /* Extract MAC */
    if (out_dst_mac) memcpy(out_dst_mac, eth->dst_mac, 6);
    if (out_src_mac) memcpy(out_src_mac, eth->src_mac, 6);

    /* VLAN info */
    if (out_vlan_id) *out_vlan_id = vlan ? 1 : 0;  /* simplified, only returns VLAN presence */
    if (out_pcp)     *out_pcp = 0;
    if (out_is_vlan) *out_is_vlan = vlan;

    if (vlan) {
        const vlan_tag_t *vlan_tag = (const vlan_tag_t *)(pkt + ETH_HDR_LEN);
        uint16_t tci = ntohs(vlan_tag->tci);
        if (out_vlan_id) *out_vlan_id = tci & VLAN_VID_MASK;
        if (out_pcp)     *out_pcp = (tci >> VLAN_PCP_SHIFT) & 0x07;
    }

    /* Check IP protocol */
    if (ip->protocol != IP_PROTOCOL_UDP)
        return -3;

    /* Extract IP */
    if (out_src_ip) memcpy(out_src_ip, ip->src_ip, 4);
    if (out_dst_ip) memcpy(out_dst_ip, ip->dst_ip, 4);

    /* Check UDP port */
    uint16_t dst_port = ntohs(udp->dst_port);
    uint16_t src_port = ntohs(udp->src_port);
    if (expected_dst_port != 0 && dst_port != expected_dst_port)
        return -4;

    if (out_src_port) *out_src_port = src_port;
    if (out_dst_port) *out_dst_port = dst_port;

    /* Extract payload */
    int udp_len = ntohs(udp->length);
    int payload_len = udp_len - UDP_HDR_LEN;
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
                                 payload, payload_len);
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
                       int *out_is_vlan)
{
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
        if (ret == 1 && hdr->caplen >= ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN) {
            return parse_packet(pkt, hdr->caplen,
                               out_src_mac, NULL, NULL, NULL,
                               out_src_ip, NULL,
                               out_src_port, NULL,
                               out_payload, max_payload_len,
                               expected_dst_port,
                               out_is_vlan);
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

    while (g_running) {
        int payload_len = recv_packet(g_listen_port, src_mac, src_ip, &src_port,
                                      payload, sizeof(payload) - 1, 100, &is_vlan);
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

    while (g_running) {
        int payload_len = recv_packet(g_listen_port, src_mac, src_ip, &src_port,
                                      payload, sizeof(payload) - 1, 100, &is_vlan);
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
        int hdr_len = get_frame_header_len() + IP_HDR_LEN + UDP_HDR_LEN;
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
    printf("  Duration: %d sec\n", g_test_duration);
    printf("========================================\n\n");

    uint64_t interval_bytes = 0;
    uint64_t interval_pkts = 0;
    LARGE_INTEGER interval_start;
    QueryPerformanceCounter(&interval_start);

    while (g_running) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        double elapsed_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
        if (elapsed_sec >= g_test_duration) break;

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

        double interval_sec = (double)(now.QuadPart - interval_start.QuadPart) / freq.QuadPart;
        if (interval_sec >= 1.0) {
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
            Sleep((DWORD)(interval_us / 1000));
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
    uint64_t lost_pkts = 0;
    uint32_t last_seq = 0;
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
    printf("========================================\n\n");

    while (g_running) {
        int payload_len = recv_packet(g_listen_port, src_mac, src_ip, &src_port,
                                      payload, sizeof(payload) - 1, 100, &is_vlan);
        if (payload_len >= (int)sizeof(test_header_t)) {
            test_header_t *test_hdr = (test_header_t *)payload;
            uint32_t seq = ntohl(test_hdr->seq);

            if (first_pkt) {
                first_pkt = 0;
                last_seq = seq;
                printf("  [First Pkt] From %u.%u.%u.%u:%u\n",
                       src_ip[0], src_ip[1], src_ip[2], src_ip[3], src_port);
            } else {
                if (seq > last_seq + 1) {
                    lost_pkts += (seq - last_seq - 1);
                }
                last_seq = seq;
            }

            int hdr_len = get_frame_header_len();
            total_bytes += payload_len + hdr_len + IP_HDR_LEN + UDP_HDR_LEN;
            total_pkts++;
            interval_bytes += payload_len + hdr_len + IP_HDR_LEN + UDP_HDR_LEN;
            interval_pkts++;
        }

        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        double interval_sec = (double)(now.QuadPart - interval_start.QuadPart) / freq.QuadPart;
        if (interval_sec >= 1.0) {
            double bps = (double)interval_bytes * 8 / interval_sec;
            char bw_str[32], bytes_str[32];
            format_bps(bps, bw_str, sizeof(bw_str));
            format_bytes(interval_bytes, bytes_str, sizeof(bytes_str));
            double loss_rate = (total_pkts + lost_pkts > 0) ?
                               100.0 * lost_pkts / (total_pkts + lost_pkts) : 0;
            printf("  [%5.1fs] %s  %s/s  %llu pkts  lost=%llu (%.1f%%)\n",
                   (double)(now.QuadPart - start.QuadPart) / freq.QuadPart,
                   bytes_str, bw_str,
                   (unsigned long long)interval_pkts,
                   (unsigned long long)lost_pkts, loss_rate);

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
    double loss_rate = (total_pkts + lost_pkts > 0) ?
                       100.0 * lost_pkts / (total_pkts + lost_pkts) : 0;

    char bw_str[32], bytes_str[32];
    format_bps(avg_bps, bw_str, sizeof(bw_str));
    format_bytes(total_bytes, bytes_str, sizeof(bytes_str));

    printf("\n========================================\n");
    printf("  [Receive Complete]\n");
    printf("  Total Time: %.2f sec\n", total_sec);
    printf("  Total Data: %s\n", bytes_str);
    printf("  Total Pkts: %llu\n", (unsigned long long)total_pkts);
    printf("  Lost Pkts: %llu (%.1f%%)\n", (unsigned long long)lost_pkts, loss_rate);
    printf("  Avg Bandwidth: %s\n", bw_str);
    printf("========================================\n");
}

/*=======================================================================
 * usage
 *=====================================================================*/

static void usage(const char *prog)
{
    printf("VLAN Tag Switch Test Tool (WinPcap/Npcap)\n");
    printf("\n");
    printf("Usage:\n");
    printf("  %s -l                                List available adapters\n", prog);
    printf("  %s -s [-p <port>] [-a <ip>] [-v <vlan_id>]           Server mode\n", prog);
    printf("  %s -c <server_ip:port> [-v <vlan_id>] [-i]            Client mode\n", prog);
    printf("  %s -c <server_ip:port> -t [-b <bw>] [-d <sec>] [-l <len>] [-v <vlan_id>]  iperf test\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -l              List available adapters\n");
    printf("  -s              Server mode\n");
    printf("  -c <ip:port>    Client mode, specify server address\n");
    printf("  -i              Interactive mode (default)\n");
    printf("  -t              iperf bandwidth test mode\n");
    printf("  -p <port>       Listen port (default %d)\n", DEFAULT_PORT);
    printf("  -a <ip>         Listen IP (default: auto detect)\n");
    printf("  -v <vlan_id>    VLAN ID (optional, no VLAN tag if not specified)\n");
    printf("  -b <bandwidth>  Target bandwidth (e.g. 100M, 1G, default unlimited)\n");
    printf("  -d <duration>   Test duration in seconds (default 10)\n");
    printf("  -l <length>     Packet payload size (default 1400)\n");
    printf("\n");
    printf("Description:\n");
    printf("  L3 (IP+UDP) packets with optional L2 VLAN tag\n");
    printf("  Without -v: no VLAN tag, with -v <vlan_id>: add VLAN tag\n");
    printf("  Peer MAC resolved automatically via ARP\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -l\n", prog);
    printf("  %s -s -p 9999                # without VLAN\n", prog);
    printf("  %s -s -p 9999 -v 100         # with VLAN 100\n", prog);
    printf("  %s -c 192.168.1.100:9999     # without VLAN\n", prog);
    printf("  %s -c 192.168.1.100:9999 -v 100   # with VLAN 100\n", prog);
    printf("  %s -c 192.168.1.100:9999 -t -b 100M -d 30\n", prog);
    printf("  %s -c 192.168.1.100:9999 -t -b 1G -v 100\n", prog);
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

/*=======================================================================
 * Main function
 *=====================================================================*/

int main(int argc, char *argv[])
{
    pcap_if_t *alldevs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *adapter_name = NULL;
    char *server_ip_port = NULL;
    char *listen_ip_str = NULL;

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
        if (strcmp(argv[arg_idx], "-l") == 0 || strcmp(argv[arg_idx], "--list") == 0) {
            if (pcap_findalldevs(&alldevs, errbuf) == -1) {
                fprintf(stderr, "Error: pcap_findalldevs: %s\n", errbuf);
                return 1;
            }
            printf("Available adapters:\n");
            list_adapters(alldevs);
            pcap_freealldevs(alldevs);
            return 0;
        } else if (strcmp(argv[arg_idx], "-s") == 0) {
            g_mode = MODE_SERVER;
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "-c") == 0) {
            g_mode = MODE_CLIENT;
            arg_idx++;
            if (arg_idx < argc && argv[arg_idx][0] != '-') {
                server_ip_port = argv[arg_idx];
                arg_idx++;
            }
        } else if (strcmp(argv[arg_idx], "-i") == 0) {
            g_interactive = 1;
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "-t") == 0) {
            g_test_mode = 1;
            g_interactive = 0;
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "-p") == 0 && arg_idx + 1 < argc) {
            g_listen_port = (uint16_t)atoi(argv[arg_idx + 1]);
            arg_idx += 2;
        } else if (strcmp(argv[arg_idx], "-a") == 0 && arg_idx + 1 < argc) {
            listen_ip_str = argv[arg_idx + 1];
            arg_idx += 2;
        } else if (strcmp(argv[arg_idx], "-v") == 0 && arg_idx + 1 < argc) {
            g_vlan_id = (uint16_t)atoi(argv[arg_idx + 1]);
            if (g_vlan_id < 1 || g_vlan_id > 4094) {
                fprintf(stderr, "Error: VLAN ID must be between 1-4094\n");
                return 1;
            }
            arg_idx += 2;
        } else if (strcmp(argv[arg_idx], "-b") == 0 && arg_idx + 1 < argc) {
            g_target_bps = parse_bandwidth(argv[arg_idx + 1]);
            arg_idx += 2;
        } else if (strcmp(argv[arg_idx], "-d") == 0 && arg_idx + 1 < argc) {
            g_test_duration = atoi(argv[arg_idx + 1]);
            if (g_test_duration < 1 || g_test_duration > 3600) {
                fprintf(stderr, "Error: duration must be between 1-3600\n");
                return 1;
            }
            arg_idx += 2;
        } else if (strcmp(argv[arg_idx], "-l") == 0 && arg_idx + 1 < argc) {
            g_pkt_size = atoi(argv[arg_idx + 1]);
            if (g_pkt_size < 64 || g_pkt_size > 1472) {
                fprintf(stderr, "Error: length must be between 64-1472\n");
                return 1;
            }
            arg_idx += 2;
        } else if (adapter_name == NULL && argv[arg_idx][0] != '-') {
            adapter_name = argv[arg_idx];
            arg_idx++;
        } else {
            fprintf(stderr, "Error: Unknown argument: %s\n", argv[arg_idx]);
            usage(argv[0]);
            return 1;
        }
    }

    (void)listen_ip_str; /* reserved for future bind-IP feature */

    if (g_mode == MODE_NONE) {
        fprintf(stderr, "Error: Please use -s (server) or -c (client) to specify mode\n\n");
        usage(argv[0]);
        return 1;
    }

    if (g_mode == MODE_CLIENT && server_ip_port == NULL) {
        fprintf(stderr, "Error: Client mode requires server IP:port\n\n");
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
    printf(" Port      : %u\n", g_listen_port);
    if (g_test_mode) {
        printf(" Test Mode : iperf\n");
        if (g_target_bps > 0) {
            char bw_str[32];
            format_bps(g_target_bps, bw_str, sizeof(bw_str));
            printf(" Target BW : %s\n", bw_str);
        } else {
            printf(" Target BW : Unlimited\n");
        }
        printf(" Duration  : %d sec\n", g_test_duration);
        printf(" Pkt Size  : %d bytes\n", g_pkt_size);
    }
    printf("========================================\n");

    if (g_mode == MODE_CLIENT) {
        if (parse_ip_port(server_ip_port, g_peer_ip, &g_listen_port) < 0) {
            fprintf(stderr, "Error: Invalid IP:port format: %s\n", server_ip_port);
            pcap_close(g_handle);
            pcap_freealldevs(alldevs);
            return 1;
        }
        print_ip("Peer IP", g_peer_ip);
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

    if (g_test_mode) {
        if (g_mode == MODE_CLIENT) {
            iperf_client_test();
        } else {
            iperf_server_test();
        }
    } else if (g_interactive) {
        if (g_mode == MODE_SERVER) {
            server_interactive_loop();
        } else {
            client_interactive_loop();
        }
    }

    printf("\nStopped.\n");
    pcap_close(g_handle);
    pcap_freealldevs(alldevs);
    return 0;
}
