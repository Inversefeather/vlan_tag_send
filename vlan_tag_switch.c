/*
 * vlan_tag_switch.c - iperf-like bandwidth test tool for Windows
 *
 * Two modes:
 *   Socket mode (default): Standard TCP/UDP sockets, works end-to-end like iperf
 *   Raw mode (--raw): Raw Ethernet frames with optional VLAN tag (requires WinPcap)
 *
 * Build (socket mode only - no WinPcap needed):
 *   gcc -Wall -O2 -o vlan_tag_switch.exe vlan_tag_switch.c -lws2_32 -liphlpapi
 *
 * Build (with raw/VLAN mode support):
 *   gcc -Wall -O2 -DUSE_WINPCAP -IC:\WpdPack\Include -o vlan_tag_switch.exe ^
 *       vlan_tag_switch.c -LC:\WpdPack\Lib\x64 -lwpcap -lPacket -lws2_32 -liphlpapi
 *
 * Usage:
 *   Server: vlan_tag_switch.exe -s [-p <port>] [-u] [-T <timeout>]
 *   Client: vlan_tag_switch.exe -c <server_ip> [-p <port>] [-u] [-b <bw>] [-t <sec>] [-l <len>]
 *
 * Socket mode examples:
 *   vlan_tag_switch.exe -s -p 9999                    # TCP server
 *   vlan_tag_switch.exe -s -p 9999 -u                 # UDP server
 *   vlan_tag_switch.exe -c 192.168.1.100 -p 9999       # TCP client, 10 sec
 *   vlan_tag_switch.exe -c 192.168.1.100 -p 9999 -b 100M -t 30
 *   vlan_tag_switch.exe -c 192.168.1.100 -p 9999 -u -b 1G
 *
 * Raw mode examples (with VLAN tag):
 *   vlan_tag_switch.exe -s -p 9999 --raw -V 100
 *   vlan_tag_switch.exe -c 192.168.1.100 -p 9999 --raw -V 100 -b 100M
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mmsystem.h>
#include <iphlpapi.h>
#include <conio.h>

#ifdef USE_WINPCAP
/* WinPcap SDK needs these POSIX types - define before including pcap.h */
typedef unsigned int   u_int;
typedef unsigned short u_short;
typedef unsigned char  u_char;
typedef unsigned long  u_long;
#include <pcap.h>
#endif

/* Constants */
#define DEFAULT_PORT        9999
#define DEFAULT_DURATION    10
#define DEFAULT_BUFSIZE_TCP 65536   /* Large buffer = fewer syscalls for TCP */
#define DEFAULT_BUFSIZE_UDP 1472    /* Max unfragmented UDP: 1500 - 20 IP - 8 UDP */
#define DEFAULT_INTERVAL    1
#define MAX_BUFSIZE         65536

/* Protocol */
#define PROTO_TCP  0
#define PROTO_UDP  1

/* Mode */
#define MODE_NONE   0
#define MODE_SERVER 1
#define MODE_CLIENT 2

#ifdef USE_WINPCAP
/* VLAN constants */
#define VLAN_VID_MASK    0x0FFF
#define VLAN_PCP_SHIFT   13
#define ETH_HDR_LEN      14
#define VLAN_TAG_LEN     4
#define VLAN_ETH_HDR_LEN (ETH_HDR_LEN + VLAN_TAG_LEN)
#define IP_HDR_LEN       20
#define UDP_HDR_LEN      8
#define TCP_HDR_LEN      20
#define ETHERTYPE_VLAN   0x8100
#define ETHERTYPE_IP     0x0800
#define ETHERTYPE_ARP    0x0806
#define IP_PROTOCOL_UDP  17
#define IP_PROTOCOL_TCP  6
#define ARP_HW_TYPE_ETH  0x0001
#define ARP_OP_REQUEST   0x0001
#define ARP_OP_REPLY     0x0002
#define ARP_TIMEOUT_MS   3000
#endif

#ifdef USE_WINPCAP
/* Ethernet header */
typedef struct eth_header_s {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
} eth_header_t;

/* IPv4 header (no options) */
typedef struct ip_header_s {
    uint8_t  ver_ihl;       /* version << 4 | ihl */
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src[4];
    uint8_t  dst[4];
} ip_header_t;

/* UDP header */
typedef struct udp_header_s {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} udp_header_t;

/* ARP header */
typedef struct arp_header_s {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  src_mac[6];
    uint8_t  src_ip[4];
    uint8_t  dst_mac[6];
    uint8_t  dst_ip[4];
} arp_header_t;

#define RAW_MAX_PAYLOAD   1472   /* 1500 - 20 IP - 8 UDP (no VLAN) */
#define RAW_FRAME_SIZE    (ETH_HDR_LEN + 4 + IP_HDR_LEN + UDP_HDR_LEN + RAW_MAX_PAYLOAD)

static uint8_t  g_raw_frame[RAW_FRAME_SIZE];   /* static: must NOT be on stack */
static int      g_raw_payload_len = RAW_MAX_PAYLOAD;
#endif

/* Thread-safe stop flag (ctrl_handler runs on a dedicated system thread) */
static LONG g_stop = 0;
static int g_mode = MODE_NONE;
static int g_protocol = PROTO_TCP;
static int g_port = DEFAULT_PORT;
static int g_duration = DEFAULT_DURATION;
static int g_bufsize = 0;  /* 0 = not set, choose based on protocol */
static int g_report_interval = DEFAULT_INTERVAL;
static double g_target_bps = 0;
static uint64_t g_nbytes = 0;
static int g_use_raw = 0;
static char g_server_ip[64] = {0};
static int g_silence_timeout = 3;
static int g_interactive = 0;

#ifdef USE_WINPCAP
/* Raw mode globals */
static pcap_t *g_handle = NULL;
static uint8_t g_my_mac[6] = {0};
static uint8_t g_my_ip[4] = {0};
static uint8_t g_peer_mac[6] = {0};
static uint8_t g_peer_ip[4] = {0};
static uint16_t g_vlan_id = 0;
static uint8_t g_pcp = 0;
#endif

/*=======================================================================
 * Utility functions
 *=====================================================================*/

static BOOL WINAPI ctrl_handler(DWORD ctrl_type)
{
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        InterlockedExchange(&g_stop, 1);
#ifdef USE_WINPCAP
        if (g_handle) pcap_breakloop(g_handle);
#endif
        return TRUE;
    }
    return FALSE;
}

static void format_bps(double bps, char *buf, int buf_size)
{
    if (bps >= 1e9)
        snprintf(buf, buf_size, "%.2f Gbits/sec", bps / 1e9);
    else if (bps >= 1e6)
        snprintf(buf, buf_size, "%.2f Mbits/sec", bps / 1e6);
    else if (bps >= 1e3)
        snprintf(buf, buf_size, "%.2f Kbits/sec", bps / 1e3);
    else
        snprintf(buf, buf_size, "%.2f bits/sec", bps);
}

static void format_bytes(uint64_t bytes, char *buf, int buf_size)
{
    if (bytes >= 1024ULL * 1024 * 1024)
        snprintf(buf, buf_size, "%.2f GBytes", (double)bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024 * 1024)
        snprintf(buf, buf_size, "%.2f MBytes", (double)bytes / (1024.0 * 1024));
    else if (bytes >= 1024)
        snprintf(buf, buf_size, "%.2f KBytes", (double)bytes / 1024.0);
    else
        snprintf(buf, buf_size, "%llu Bytes", (unsigned long long)bytes);
}

static double parse_bandwidth(const char *str)
{
    double value;
    char unit[16] = {0};
    if (sscanf(str, "%lf%15s", &value, unit) < 1) return 0;
    if (unit[0] == 'G' || unit[0] == 'g') return value * 1e9;
    if (unit[0] == 'M' || unit[0] == 'm') return value * 1e6;
    if (unit[0] == 'K' || unit[0] == 'k') return value * 1e3;
    return value;
}

static uint64_t parse_bytes(const char *str)
{
    double value;
    char unit[16] = {0};
    if (sscanf(str, "%lf%15s", &value, unit) < 1) return 0;
    if (unit[0] == 'G' || unit[0] == 'g') return (uint64_t)(value * 1073741824.0);
    if (unit[0] == 'M' || unit[0] == 'm') return (uint64_t)(value * 1048576.0);
    if (unit[0] == 'K' || unit[0] == 'k') return (uint64_t)(value * 1024.0);
    return (uint64_t)value;
}

/*=======================================================================
 * Socket mode: TCP client
 *=====================================================================*/

static void tcp_client_test(void)
{
    SOCKET sock;
    uint8_t *buf;
    struct sockaddr_in addr;
    int result;

    buf = (uint8_t *)malloc(g_bufsize);
    if (!buf) {
        fprintf(stderr, "Error: Failed to allocate %d byte buffer\n", g_bufsize);
        return;
    }
    /* Fill with pattern */
    for (int i = 0; i < g_bufsize; i++)
        buf[i] = (uint8_t)(i & 0xFF);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Error: socket() failed: %d\n", WSAGetLastError());
        free(buf);
        return;
    }

    /* Set send buffer size for high bandwidth */
    int sndbuf = 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf, sizeof(sndbuf));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_port);
    inet_pton(AF_INET, g_server_ip, &addr.sin_addr);

    printf("Connecting to %s:%u, TCP\n", g_server_ip, g_port);

    result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (result == SOCKET_ERROR) {
        fprintf(stderr, "Error: connect() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        free(buf);
        return;
    }

    printf("Connected. Sending %d byte buffers", g_bufsize);
    if (g_target_bps > 0) {
        char bw_str[32];
        format_bps(g_target_bps, bw_str, sizeof(bw_str));
        printf(", target bandwidth %s", bw_str);
    }
    printf("...\n\n");
    printf("[ ID] Interval           Transfer     Bandwidth\n");

    uint64_t total_sent = 0;
    uint64_t interval_sent = 0;
    LARGE_INTEGER freq, start, interval_start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    QueryPerformanceCounter(&interval_start);

    while (!g_stop) {
        QueryPerformanceCounter(&now);
        double elapsed_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;

        /* Check stop conditions */
        if (g_nbytes > 0) {
            if (total_sent >= g_nbytes) break;
        } else {
            if (elapsed_sec >= g_duration) break;
        }

        /* Calculate how much to send */
        int to_send = g_bufsize;
        if (g_nbytes > 0 && total_sent + to_send > g_nbytes)
            to_send = (int)(g_nbytes - total_sent);

        /* Send data */
        int sent = send(sock, (char *)buf, to_send, 0);
        if (sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err != WSAECONNRESET && err != WSAECONNABORTED)
                fprintf(stderr, "\nError: send() failed: %d\n", err);
            break;
        }
        if (sent == 0) break;

        total_sent += sent;
        interval_sent += sent;

        /* Report interval */
        QueryPerformanceCounter(&now);
        double interval_sec = (double)(now.QuadPart - interval_start.QuadPart) / freq.QuadPart;
        if (interval_sec >= g_report_interval) {
            double bps = (double)interval_sent * 8 / interval_sec;
            double start_sec = (double)(interval_start.QuadPart - start.QuadPart) / freq.QuadPart;
            char bw_str[32], bytes_str[32];
            format_bps(bps, bw_str, sizeof(bw_str));
            format_bytes(interval_sent, bytes_str, sizeof(bytes_str));
            printf("[  1] %5.2f-%5.2f sec  %s  %s\n",
                   start_sec, start_sec + interval_sec, bytes_str, bw_str);
            interval_sent = 0;
            interval_start = now;
            fflush(stdout);
        }

        /* Pacing: busy-wait until time to send more data */
        if (g_target_bps > 0) {
            double should_have_sent = (double)total_sent * 8.0 / g_target_bps;
            while (!g_stop) {
                QueryPerformanceCounter(&now);
                double elapsed_now = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
                if (elapsed_now >= should_have_sent) break;
                YieldProcessor();  /* Spin-wait, no Sleep() latency */
            }
        }
    }

    QueryPerformanceCounter(&now);
    double total_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
    double avg_bps = (total_sec > 0) ? (double)total_sent * 8 / total_sec : 0;

    char bw_str[32], bytes_str[32];
    format_bps(avg_bps, bw_str, sizeof(bw_str));
    format_bytes(total_sent, bytes_str, sizeof(bytes_str));

    /* Print final summary in iperf format */
    printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("[ ID] Interval           Transfer     Bandwidth\n");
    printf("[  1]  0.00-%5.2f sec  %s  %s                  sender\n",
           total_sec, bytes_str, bw_str);
    printf("[  1]  0.00-%5.2f sec  %s  %s                  receiver\n",
           total_sec, bytes_str, bw_str);
    printf("\nSent %llu bytes in %.2f seconds\n",
           (unsigned long long)total_sent, total_sec);

    closesocket(sock);
    free(buf);
}

/*=======================================================================
 * Socket mode: TCP server
 *=====================================================================*/

static void tcp_server_test(void)
{
    SOCKET listen_sock, client_sock;
    uint8_t *buf;
    struct sockaddr_in addr, client_addr;
    int addr_len;
    int result;

    buf = (uint8_t *)malloc(g_bufsize);
    if (!buf) {
        fprintf(stderr, "Error: Failed to allocate %d byte buffer\n", g_bufsize);
        return;
    }

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        fprintf(stderr, "Error: socket() failed: %d\n", WSAGetLastError());
        free(buf);
        return;
    }

    /* Allow address reuse */
    int reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    result = bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr));
    if (result == SOCKET_ERROR) {
        fprintf(stderr, "Error: bind() failed: %d (port %u in use?)\n",
                WSAGetLastError(), g_port);
        closesocket(listen_sock);
        free(buf);
        return;
    }

    result = listen(listen_sock, 1);
    if (result == SOCKET_ERROR) {
        fprintf(stderr, "Error: listen() failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        free(buf);
        return;
    }

    printf("TCP server listening on port %u\n", g_port);
    printf("Waiting for client connection...\n");

    addr_len = sizeof(client_addr);
    client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock == INVALID_SOCKET) {
        fprintf(stderr, "Error: accept() failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        free(buf);
        return;
    }

    char *client_ip = inet_ntoa(client_addr.sin_addr);
    printf("Client connected from %s:%u\n\n", client_ip, ntohs(client_addr.sin_port));
    printf("[ ID] Interval           Transfer     Bandwidth\n");

    uint64_t total_recv = 0;
    uint64_t interval_recv = 0;
    LARGE_INTEGER freq, start, interval_start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    QueryPerformanceCounter(&interval_start);

    while (!g_stop) {
        int received = recv(client_sock, (char *)buf, g_bufsize, 0);
        QueryPerformanceCounter(&now);

        if (received > 0) {
            total_recv += received;
            interval_recv += received;
        } else if (received == 0) {
            /* Client closed connection */
            printf("\nClient closed connection.\n");
            break;
        } else {
            int err = WSAGetLastError();
            if (err == WSAECONNRESET || err == WSAECONNABORTED) {
                printf("\nConnection reset by client.\n");
            } else {
                fprintf(stderr, "\nError: recv() failed: %d\n", err);
            }
            break;
        }

        /* Report interval */
        double interval_sec = (double)(now.QuadPart - interval_start.QuadPart) / freq.QuadPart;
        if (interval_sec >= g_report_interval && interval_recv > 0) {
            double bps = (double)interval_recv * 8 / interval_sec;
            double elapsed = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
            double start_sec = (double)(interval_start.QuadPart - start.QuadPart) / freq.QuadPart;
            char bw_str[32], bytes_str[32];
            format_bps(bps, bw_str, sizeof(bw_str));
            format_bytes(interval_recv, bytes_str, sizeof(bytes_str));
            printf("[  3] %5.2f-%5.2f sec  %s  %s\n",
                   start_sec, elapsed, bytes_str, bw_str);
            interval_recv = 0;
            interval_start = now;
            fflush(stdout);
        }
    }

    QueryPerformanceCounter(&now);
    double total_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
    double avg_bps = (total_sec > 0) ? (double)total_recv * 8 / total_sec : 0;

    char bw_str[32], bytes_str[32];
    format_bps(avg_bps, bw_str, sizeof(bw_str));
    format_bytes(total_recv, bytes_str, sizeof(bytes_str));

    printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("[ ID] Interval           Transfer     Bandwidth\n");
    printf("[  3]  0.00-%5.2f sec  %s  %s\n",
           total_sec, bytes_str, bw_str);
    printf("\nReceived %llu bytes in %.2f seconds\n",
           (unsigned long long)total_recv, total_sec);

    closesocket(client_sock);
    closesocket(listen_sock);
    free(buf);
}

/*=======================================================================
 * Socket mode: UDP client
 *=====================================================================*/

static void udp_client_test(void)
{
    SOCKET sock;
    uint8_t *buf;
    struct sockaddr_in addr;

    buf = (uint8_t *)malloc(g_bufsize);
    if (!buf) {
        fprintf(stderr, "Error: Failed to allocate %d byte buffer\n", g_bufsize);
        return;
    }
    for (int i = 0; i < g_bufsize; i++)
        buf[i] = (uint8_t)(i & 0xFF);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Error: socket() failed: %d\n", WSAGetLastError());
        free(buf);
        return;
    }

    int sndbuf = 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf, sizeof(sndbuf));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_port);
    inet_pton(AF_INET, g_server_ip, &addr.sin_addr);

    printf("UDP client -> %s:%u, sending %d byte datagrams",
           g_server_ip, g_port, g_bufsize);
    if (g_target_bps > 0) {
        char bw_str[32];
        format_bps(g_target_bps, bw_str, sizeof(bw_str));
        printf(", target bandwidth %s", bw_str);
    }
    printf("...\n\n");
    printf("[ ID] Interval           Transfer     Bandwidth\n");

    uint64_t total_sent = 0;
    uint64_t interval_sent = 0;
    LARGE_INTEGER freq, start, interval_start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    QueryPerformanceCounter(&interval_start);

    /*
     * Pacing: track cumulative bytes we SHOULD have sent by now.
     * If total_sent < should_send → we're behind, send immediately.
     * If total_sent >= should_send → we're ahead, yield briefly.
     * No Sleep(1) bottleneck: Sleep(0) yields without the ~15ms timer granularity.
     */
    while (!g_stop) {
        QueryPerformanceCounter(&now);
        double elapsed_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;

        if (g_nbytes > 0) {
            if (total_sent >= g_nbytes) break;
        } else {
            if (elapsed_sec >= g_duration) break;
        }

        /* How many bytes should we have sent by now? */
        double should_send = (g_target_bps > 0)
            ? elapsed_sec * (g_target_bps / 8.0)
            : (double)UINT64_MAX;  /* unlimited */

        if (total_sent < should_send) {
            /* Behind schedule — send a datagram */
            int to_send = g_bufsize;
            if (g_nbytes > 0 && total_sent + to_send > g_nbytes)
                to_send = (int)(g_nbytes - total_sent);

            int sent = sendto(sock, (char *)buf, to_send, 0,
                              (struct sockaddr *)&addr, sizeof(addr));
            if (sent == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK) {
                    /* Socket buffer full — brief busy-wait then retry */
                    for (int spin = 0; spin < 100 && !g_stop; spin++)
                        YieldProcessor();
                    continue;
                }
                fprintf(stderr, "\nError: sendto() failed: %d\n", err);
                InterlockedExchange(&g_stop, 1);
                break;
            }

            total_sent += sent;
            interval_sent += sent;
        } else {
            /* Ahead of schedule — busy-wait for accurate pacing */
            YieldProcessor();
        }

        /* Report interval */
        QueryPerformanceCounter(&now);
        double interval_sec = (double)(now.QuadPart - interval_start.QuadPart) / freq.QuadPart;
        if (interval_sec >= g_report_interval) {
            double bps = (double)interval_sent * 8 / interval_sec;
            double start_sec = (double)(interval_start.QuadPart - start.QuadPart) / freq.QuadPart;
            char bw_str[32], bytes_str[32];
            format_bps(bps, bw_str, sizeof(bw_str));
            format_bytes(interval_sent, bytes_str, sizeof(bytes_str));
            printf("[  1] %5.2f-%5.2f sec  %s  %s\n",
                   start_sec, start_sec + interval_sec, bytes_str, bw_str);
            interval_sent = 0;
            interval_start = now;
            fflush(stdout);
        }
    }

    QueryPerformanceCounter(&now);
    double total_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
    double avg_bps = (total_sec > 0) ? (double)total_sent * 8 / total_sec : 0;

    char bw_str[32], bytes_str[32];
    format_bps(avg_bps, bw_str, sizeof(bw_str));
    format_bytes(total_sent, bytes_str, sizeof(bytes_str));

    printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("[ ID] Interval           Transfer     Bandwidth\n");
    printf("[  1]  0.00-%5.2f sec  %s  %s                  sender\n",
           total_sec, bytes_str, bw_str);
    printf("[  1]  0.00-%5.2f sec  %s  %s                  receiver\n",
           total_sec, bytes_str, bw_str);
    printf("\nSent %llu bytes in %.2f seconds\n",
           (unsigned long long)total_sent, total_sec);

    closesocket(sock);
    free(buf);
}

/*=======================================================================
 * Socket mode: UDP server
 *=====================================================================*/

static void udp_server_test(void)
{
    SOCKET sock;
    uint8_t *buf;
    struct sockaddr_in addr, client_addr;
    int addr_len;
    int result;

    buf = (uint8_t *)malloc(g_bufsize);
    if (!buf) {
        fprintf(stderr, "Error: Failed to allocate %d byte buffer\n", g_bufsize);
        return;
    }

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Error: socket() failed: %d\n", WSAGetLastError());
        free(buf);
        return;
    }

    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, sizeof(rcvbuf));

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    result = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (result == SOCKET_ERROR) {
        fprintf(stderr, "Error: bind() failed: %d (port %u in use?)\n",
                WSAGetLastError(), g_port);
        closesocket(sock);
        free(buf);
        return;
    }

    printf("UDP server listening on port %u\n", g_port);
    printf("Waiting for datagrams...\n\n");
    printf("[ ID] Interval           Transfer     Bandwidth\n");

    uint64_t total_recv = 0;
    uint64_t interval_recv = 0;
    LARGE_INTEGER freq, start, interval_start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    QueryPerformanceCounter(&interval_start);
    LARGE_INTEGER last_data_time = start;
    int has_client = 0;
    int silence_ms = g_silence_timeout * 1000;

    while (!g_stop) {
        /* Set recv timeout for silence detection */
        DWORD timeout = 100;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

        addr_len = sizeof(client_addr);
        int received = recvfrom(sock, (char *)buf, g_bufsize, 0,
                                (struct sockaddr *)&client_addr, &addr_len);
        QueryPerformanceCounter(&now);

        if (received > 0) {
            if (!has_client) {
                has_client = 1;
                char *client_ip = inet_ntoa(client_addr.sin_addr);
                printf("Client datagram from %s:%u\n", client_ip, ntohs(client_addr.sin_port));
                start = now;
                interval_start = now;
            }
            total_recv += received;
            interval_recv += received;
            last_data_time = now;
        } else {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK && err != WSAETIMEDOUT) {
                fprintf(stderr, "\nError: recvfrom() failed: %d\n", err);
                break;
            }
        }

        /* Check silence timeout */
        if (has_client) {
            double silence_elapsed = (double)(now.QuadPart - last_data_time.QuadPart) * 1000.0 / freq.QuadPart;
            if (silence_elapsed >= silence_ms) {
                printf("\nNo data received for %d seconds, stopping.\n", g_silence_timeout);
                break;
            }
        }

        /* Report interval */
        double interval_sec = (double)(now.QuadPart - interval_start.QuadPart) / freq.QuadPart;
        if (interval_sec >= g_report_interval && interval_recv > 0) {
            double bps = (double)interval_recv * 8 / interval_sec;
            double elapsed = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
            double start_sec = (double)(interval_start.QuadPart - start.QuadPart) / freq.QuadPart;
            char bw_str[32], bytes_str[32];
            format_bps(bps, bw_str, sizeof(bw_str));
            format_bytes(interval_recv, bytes_str, sizeof(bytes_str));
            printf("[  3] %5.2f-%5.2f sec  %s  %s\n",
                   start_sec, elapsed, bytes_str, bw_str);
            interval_recv = 0;
            interval_start = now;
            fflush(stdout);
        }
    }

    QueryPerformanceCounter(&now);
    double total_sec = (has_client) ?
        (double)(now.QuadPart - start.QuadPart) / freq.QuadPart : 0;
    double avg_bps = (total_sec > 0) ? (double)total_recv * 8 / total_sec : 0;

    char bw_str[32], bytes_str[32];
    format_bps(avg_bps, bw_str, sizeof(bw_str));
    format_bytes(total_recv, bytes_str, sizeof(bytes_str));

    printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("[ ID] Interval           Transfer     Bandwidth\n");
    printf("[  3]  0.00-%5.2f sec  %s  %s\n",
           total_sec, bytes_str, bw_str);
    printf("\nReceived %llu bytes in %.2f seconds\n",
           (unsigned long long)total_recv, total_sec);

    closesocket(sock);
    free(buf);
}

/*=======================================================================
 * Interactive mode (socket-based)
 *=====================================================================*/

static void server_interactive_loop(void)
{
    SOCKET listen_sock, client_sock;
    char input[1024];
    uint8_t buf[MAX_BUFSIZE];
    struct sockaddr_in addr, client_addr;
    int addr_len;
    int has_client = 0;

    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        fprintf(stderr, "Error: socket() failed: %d\n", WSAGetLastError());
        return;
    }

    int reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Error: bind() failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        return;
    }

    listen(listen_sock, 1);
    printf("\n--- Server Interactive Mode ---\n");
    printf("--- Listening on port %u ---\n", g_port);
    printf("--- Type messages to send to client (quit to exit) ---\n\n");

    /* Set non-blocking for accept */
    u_long nonblock = 1;
    ioctlsocket(listen_sock, FIONBIO, &nonblock);

    while (!g_stop) {
        /* Try to accept client */
        if (!has_client) {
            addr_len = sizeof(client_addr);
            client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
            if (client_sock != INVALID_SOCKET) {
                has_client = 1;
                char *client_ip = inet_ntoa(client_addr.sin_addr);
                printf("Client connected from %s:%u\n", client_ip, ntohs(client_addr.sin_port));
            }
        }

        /* Try to receive data */
        if (has_client) {
            int received = recv(client_sock, (char *)buf, sizeof(buf) - 1, 0);
            if (received > 0) {
                buf[received] = '\0';
                SYSTEMTIME st;
                GetLocalTime(&st);
                printf("\n[%02d:%02d:%02d.%03d] From client: %.*s\n",
                       st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                       received, buf);
                fflush(stdout);
            } else if (received == 0) {
                printf("Client disconnected.\n");
                closesocket(client_sock);
                has_client = 0;
            } else {
                int err = WSAGetLastError();
                if (err != WSAEWOULDBLOCK) {
                    printf("Client error: %d\n", err);
                    closesocket(client_sock);
                    has_client = 0;
                }
            }
        }

        /* Check for keyboard input */
        if (_kbhit()) {
            if (fgets(input, sizeof(input), stdin)) {
                int len = (int)strlen(input);
                while (len > 0 && (input[len-1] == '\n' || input[len-1] == '\r'))
                    input[--len] = '\0';

                if (len == 0) continue;
                if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0)
                    break;

                if (!has_client) {
                    printf("  [Hint] No client connected yet.\n");
                    continue;
                }

                SYSTEMTIME st;
                GetLocalTime(&st);
                char msg[1200];
                int msg_len = sprintf(msg, "[%02d:%02d:%02d.%03d] SERVER: %s",
                                      st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, input);
                send(client_sock, msg, msg_len, 0);
                printf("  -> Sent %d bytes\n", msg_len);
            }
        }

        Sleep(10);
    }

    if (has_client) closesocket(client_sock);
    closesocket(listen_sock);
}

static void client_interactive_loop(void)
{
    SOCKET sock;
    char input[1024];
    uint8_t buf[MAX_BUFSIZE];
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Error: socket() failed: %d\n", WSAGetLastError());
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)g_port);
    inet_pton(AF_INET, g_server_ip, &addr.sin_addr);

    printf("\n--- Client Interactive Mode ---\n");
    printf("--- Connecting to %s:%u ---\n", g_server_ip, g_port);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Error: connect() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        return;
    }

    printf("--- Connected. Type messages (quit to exit) ---\n\n");

    /* Set non-blocking */
    u_long nonblock = 1;
    ioctlsocket(sock, FIONBIO, &nonblock);

    while (!g_stop) {
        int received = recv(sock, (char *)buf, sizeof(buf) - 1, 0);
        if (received > 0) {
            buf[received] = '\0';
            SYSTEMTIME st;
            GetLocalTime(&st);
            printf("\n[%02d:%02d:%02d.%03d] From server: %.*s\n",
                   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                   received, buf);
            fflush(stdout);
        } else if (received == 0) {
            printf("Server closed connection.\n");
            break;
        } else {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                printf("Connection error: %d\n", err);
                break;
            }
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
                send(sock, msg, msg_len, 0);
                printf("  -> Sent %d bytes\n", msg_len);
            }
        }

        Sleep(10);
    }

    closesocket(sock);
}

#ifdef USE_WINPCAP
/*=======================================================================
 * Raw mode (WinPcap/Npcap) - VLAN tagged traffic generator
 * Sends forged raw Ethernet frames: Eth | VLAN | IP | UDP | payload
 * NOTE: no kernel callbacks, no Npcap timer storm -> no BSOD path.
 *=====================================================================*/

/* One's complement checksum (RFC 1071) */
static uint16_t raw_checksum(const void *data, int len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;
    int words = len >> 1;

    for (int i = 0; i < words; i++) {
        sum += p[i];
        if (sum & 0xFFFF0000) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    if (len & 1)
        sum += (uint16_t)(*((const uint8_t *)data + len - 1) << 8);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFF);
}

/* UDP pseudo-header checksum */
static uint16_t raw_udp_checksum(const uint8_t *src_ip, const uint8_t *dst_ip,
                                 const void *udp_hdr, int udp_len)
{
    uint32_t sum = 0;

    /* pseudo-header */
    for (int i = 0; i < 4; i += 2)
        sum += ((uint16_t)src_ip[i] << 8) | src_ip[i + 1];
    for (int i = 0; i < 4; i += 2)
        sum += ((uint16_t)dst_ip[i] << 8) | dst_ip[i + 1];
    sum += IP_PROTOCOL_UDP;
    sum += (uint16_t)udp_len;

    /* UDP header + payload, padded to even length */
    int even_len = (udp_len + 1) & ~1;
    uint8_t *tmp = (uint8_t *)malloc(even_len);
    if (!tmp) return 0;
    memcpy(tmp, udp_hdr, udp_len);
    tmp[udp_len] = 0;

    for (int i = 0; i < even_len; i += 2) {
        sum += ((uint16_t)tmp[i] << 8) | tmp[i + 1];
        if (sum & 0xFFFF0000)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }
    free(tmp);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    uint16_t c = (uint16_t)(~sum & 0xFFFF);
    return c ? c : 0xFFFF;   /* checksum 0x0000 must be sent as 0xFFFF */
}

/*
 * Maximum payload that fits in one untagged Ethernet frame.
 * VLAN mode: 4 bytes less (VLAN tag sits inside the Ethernet header).
 */
static int raw_max_payload(void)
{
    int payload = 1500 - IP_HDR_LEN - UDP_HDR_LEN;
    if (g_vlan_id > 0)
        payload -= VLAN_TAG_LEN;
    return payload;           /* 1472 untagged / 1468 tagged */
}

/*
 * Build one raw frame.
 * Layout (tagged): DMAC(6) | SMAC(6) | TPID 8100(2) | TCI(2) | EtherType 0800(2)
 *                  | IP(20) | UDP(8) | payload
 */
static int raw_build_frame(const uint8_t *dst_mac, const uint8_t *src_mac,
                           const uint8_t *dst_ip, const uint8_t *src_ip,
                           uint16_t sport, uint16_t dport,
                           const void *payload, int payload_len,
                           uint8_t *out, int *out_len)
{
    const int max_pl = raw_max_payload();
    if (payload_len < 0 || payload_len > max_pl) {
        fprintf(stderr, "Error: payload %d exceeds %d bytes (one frame, no fragmentation)\n",
                payload_len, max_pl);
        return -1;
    }

    eth_header_t *eth = (eth_header_t *)out;
    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, src_mac, 6);

    uint8_t *p = out + ETH_HDR_LEN;
    int eth_payload_off;

    if (g_vlan_id > 0) {
        *((uint16_t *)(p + 0)) = htons(ETHERTYPE_VLAN);          /* TPID */
        *((uint16_t *)(p + 2)) = htons(((uint16_t)(g_pcp & 7) << VLAN_PCP_SHIFT)
                                       | (g_vlan_id & VLAN_VID_MASK));  /* TCI */
        *((uint16_t *)(p + 4)) = htons(ETHERTYPE_IP);            /* inner type */
        eth_payload_off = ETH_HDR_LEN + VLAN_TAG_LEN;
    } else {
        eth->ethertype = htons(ETHERTYPE_IP);
        eth_payload_off = ETH_HDR_LEN;
    }

    ip_header_t *ip = (ip_header_t *)(out + eth_payload_off);
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl    = 0x45;
    ip->tos        = 0;
    ip->total_len  = htons(sizeof(ip_header_t) + UDP_HDR_LEN + payload_len);
    ip->id         = htons((uint16_t)(GetTickCount() & 0xFFFF));
    ip->frag_off   = 0;
    ip->ttl        = 64;
    ip->protocol   = IP_PROTOCOL_UDP;
    memcpy(ip->src, src_ip, 4);
    memcpy(ip->dst, dst_ip, 4);
    ip->checksum   = raw_checksum(ip, sizeof(*ip));

    udp_header_t *udp = (udp_header_t *)((uint8_t *)ip + sizeof(*ip));
    udp->src_port = htons(sport);
    udp->dst_port = htons(dport);
    udp->len      = htons((uint16_t)(UDP_HDR_LEN + payload_len));
    udp->checksum = 0;

    if (payload && payload_len > 0)
        memcpy((uint8_t *)udp + UDP_HDR_LEN, payload, payload_len);

    udp->checksum = raw_udp_checksum(src_ip, dst_ip, udp, UDP_HDR_LEN + payload_len);

    *out_len = eth_payload_off + sizeof(*ip) + UDP_HDR_LEN + payload_len;
    return 0;
}

/* Find the pcap device whose IPv4 address matches target_ip */
static int raw_find_device(const char *target_ip, char *dev_buf, int dev_buf_len)
{
    pcap_if_t *alldevs = NULL, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error: pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    struct in_addr target;
    if (inet_pton(AF_INET, target_ip, &target) != 1) {
        fprintf(stderr, "Error: cannot parse IP %s\n", target_ip);
        pcap_freealldevs(alldevs);
        return -1;
    }

    int found = 0;
    for (d = alldevs; d; d = d->next) {
        pcap_addr_t *a;
        for (a = d->addresses; a; a = a->next) {
            if (!a->addr || a->addr->sa_family != AF_INET) continue;
            struct sockaddr_in *s = (struct sockaddr_in *)a->addr;
            if (s->sin_addr.s_addr == target.s_addr) {
                found = 1;
                break;
            }
        }
        if (found) break;
    }

    if (found) {
        snprintf(dev_buf, dev_buf_len, "%s", d->name);
    } else {
        /* fallback: first device with any IPv4 address */
        for (d = alldevs; d; d = d->next) {
            for (pcap_addr_t *a = d->addresses; a; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    snprintf(dev_buf, dev_buf_len, "%s", d->name);
                    found = 1;
                    goto out;
                }
            }
        }
    }
out:
    pcap_freealldevs(alldevs);
    return found ? 0 : -1;
}

/* Open the adapter and learn our own MAC + IP */
static int raw_open(const char *target_ip)
{
    char dev_name[1024];
    char errbuf[PCAP_ERRBUF_SIZE];

    if (raw_find_device(target_ip, dev_name, sizeof(dev_name)) != 0) {
        fprintf(stderr, "Error: no suitable pcap device for %s\n", target_ip);
        return -1;
    }

    /*
     * timeout = 100 ms (NOT 1 ms).
     * 1 ms makes Npcap's internal timer fire continuously and is the
     * classic BSOD trigger on Windows 7 x64.
     */
    g_handle = pcap_open_live(dev_name, 65536, 1, 100, errbuf);
    if (!g_handle) {
        fprintf(stderr, "Error: pcap_open_live(%s) failed: %s\n", dev_name, errbuf);
        return -1;
    }

    if (pcap_datalink(g_handle) != DLT_EN10MB) {
        fprintf(stderr, "Error: not an Ethernet adapter\n");
        return -1;
    }

    /* Pull MAC + IP from pcap device info */
    pcap_if_t *alldevs = NULL;
    pcap_addr_t *a;
    uint8_t *mac = NULL;
    uint8_t *ip  = NULL;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            if (strcmp(d->name, dev_name) != 0) continue;
            if (d->flags & PCAP_IF_LOOPBACK) {
                fprintf(stderr, "Error: %s is a loopback device, raw frames not supported\n",
                        dev_name);
                pcap_freealldevs(alldevs);
                return -1;
            }
            for (a = d->addresses; a; a = a->next) {
                if (!a->addr || a->addr->sa_family != AF_INET) continue;
                struct sockaddr_in *s = (struct sockaddr_in *)a->addr;
                memcpy(g_my_ip, &s->sin_addr.s_addr, 4);
                ip = g_my_ip;

                /* MAC lives in ->addr of AF_PACKET on WinPcap, else get it via GetAdaptersInfo */
                if (a->addr && a->addr->sa_family == AF_INET) {
                    /* not available here on Windows; fetch below */
                }
            }
        }
        pcap_freealldevs(alldevs);
    }

    /* Get MAC via IP Helper API */
    {
        IP_ADAPTER_INFO *info = NULL, *p;
        ULONG buf_len = 0;
        if (GetAdaptersInfo(NULL, &buf_len) == ERROR_BUFFER_OVERFLOW) {
            info = (IP_ADAPTER_INFO *)malloc(buf_len);
            if (info && GetAdaptersInfo(info, &buf_len) == NO_ERROR) {
                for (p = info; p; p = p->Next) {
                    struct in_addr ia;
                    ia.s_addr = *(uint32_t *)&p->IpAddressList.IpAddress.String;
                    /* compare as uint32 */
                    uint32_t have = *(uint32_t *)g_my_ip;
                    if (have != 0 && memcmp(&ia.s_addr, g_my_ip, 4) == 0) {
                        for (int i = 0; i < 6; i++)
                            g_my_mac[i] = (uint8_t)p->Address[i];
                        mac = g_my_mac;
                        break;
                    }
                }
            }
            free(info);
        }
    }

    if (!mac || memcmp(g_my_mac, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
        fprintf(stderr, "Error: cannot determine local MAC for %s\n", dev_name);
        return -1;
    }
    if (!ip || *(uint32_t *)g_my_ip == 0) {
        fprintf(stderr, "Error: %s has no IPv4 address configured\n", dev_name);
        return -1;
    }

    printf("Raw mode: device=%s MAC=%02X:%02X:%02X:%02X:%02X:%02X IP=%u.%u.%u.%u\n",
           dev_name,
           g_my_mac[0], g_my_mac[1], g_my_mac[2],
           g_my_mac[3], g_my_mac[4], g_my_mac[5],
           g_my_ip[0], g_my_ip[1], g_my_ip[2], g_my_ip[3]);

    return 0;
}

/* Resolve dst_ip -> dst_mac via ARP */
static int raw_arp_resolve(const uint8_t *dst_ip, uint8_t *dst_mac)
{
    uint8_t req[42];
    eth_header_t *eth = (eth_header_t *)req;
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, g_my_mac, 6);
    eth->ethertype = htons(ETHERTYPE_ARP);

    arp_header_t *arp = (arp_header_t *)(req + ETH_HDR_LEN);
    arp->hw_type   = htons(ARP_HW_TYPE_ETH);
    arp->proto_type = htons(ETHERTYPE_IP);
    arp->hw_len    = 6;
    arp->proto_len = 4;
    arp->opcode    = htons(ARP_OP_REQUEST);
    memcpy(arp->src_mac, g_my_mac, 6);
    memcpy(arp->src_ip, g_my_ip, 4);
    memset(arp->dst_mac, 0x00, 6);
    memcpy(arp->dst_ip, dst_ip, 4);

    if (pcap_sendpacket(g_handle, req, sizeof(req)) != 0) {
        fprintf(stderr, "Error: ARP request send failed: %s\n", pcap_geterr(g_handle));
        return -1;
    }
    printf("ARP request sent for %u.%u.%u.%u, waiting %d ms...\n",
           dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], ARP_TIMEOUT_MS);

    int deadline = GetTickCount() + ARP_TIMEOUT_MS;
    struct pcap_pkthdr *hdr;
    const uint8_t *pkt;

    while ((int)(GetTickCount() - deadline) < 0 && !g_stop) {
        int r = pcap_next_ex(g_handle, &hdr, &pkt);
        if (r == 1 && hdr->len >= 42) {
            eth = (eth_header_t *)pkt;
            if (ntohs(eth->ethertype) != ETHERTYPE_ARP) continue;
            arp = (arp_header_t *)(pkt + ETH_HDR_LEN);
            if (ntohs(arp->opcode) != ARP_OP_REPLY) continue;
            if (memcmp(arp->src_ip, dst_ip, 4) != 0) continue;
            memcpy(dst_mac, arp->src_mac, 6);
            printf("ARP resolved: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   dst_mac[0], dst_mac[1], dst_mac[2],
                   dst_mac[3], dst_mac[4], dst_mac[5]);
            return 0;
        } else if (r == -1) {
            fprintf(stderr, "Error: pcap_next_ex: %s\n", pcap_geterr(g_handle));
            return -1;
        }
    }
    fprintf(stderr, "Error: ARP timeout (target not on local link?)\n");
    return -1;
}

/* Raw mode CLIENT: blast VLAN/UDP frames */
static void raw_client_test(void)
{
    if (raw_open(g_server_ip) != 0) return;

    memcpy(g_peer_ip, g_my_ip, 4);   /* keep own IP */
    /* peer = target host parsed from g_server_ip */
    struct in_addr ia;
    if (inet_pton(AF_INET, g_server_ip, &ia) == 1)
        memcpy(g_peer_ip, &ia.s_addr, 4);

    if (raw_arp_resolve(g_peer_ip, g_peer_mac) != 0) {
        pcap_close(g_handle);
        g_handle = NULL;
        return;
    }

    /* payload content (static buffer, survives the call) */
    g_raw_payload_len = raw_max_payload();
    if (g_bufsize > 0 && g_bufsize <= g_raw_payload_len)
        g_raw_payload_len = g_bufsize;
    uint8_t *payload = (uint8_t *)malloc(g_raw_payload_len);
    if (!payload) {
        fprintf(stderr, "Error: malloc payload failed\n");
        pcap_close(g_handle);
        g_handle = NULL;
        return;
    }
    for (int i = 0; i < g_raw_payload_len; i++)
        payload[i] = (uint8_t)(i & 0xFF);

    int frame_len = 0;
    if (raw_build_frame(g_peer_mac, g_my_mac, g_peer_ip, g_my_ip,
                        5001, (uint16_t)g_port,
                        payload, g_raw_payload_len,
                        g_raw_frame, &frame_len) != 0) {
        free(payload);
        pcap_close(g_handle);
        g_handle = NULL;
        return;
    }

    printf("Raw client: VLAN %u PCP %u payload %d bytes target %s\n",
           g_vlan_id, g_pcp,
           g_raw_payload_len,
           g_target_bps > 0 ? "" : "(unlimited)");
    if (g_target_bps > 0) {
        char bw_str[32];
        format_bps(g_target_bps, bw_str, sizeof(bw_str));
        printf("Target BW: %s\n", bw_str);
    }
    printf("[ ID] Interval           Transfer     Bandwidth\n");

    uint64_t total_sent = 0;
    uint64_t interval_sent = 0;
    LARGE_INTEGER freq, start, interval_start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    QueryPerformanceCounter(&interval_start);

    while (!g_stop) {
        QueryPerformanceCounter(&now);
        double elapsed_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;

        if (g_nbytes > 0) {
            if (total_sent >= g_nbytes) break;
        } else {
            if (elapsed_sec >= g_duration) break;
        }

        if (pcap_sendpacket(g_handle, g_raw_frame, frame_len) != 0) {
            fprintf(stderr, "\nError: pcap_sendpacket: %s\n", pcap_geterr(g_handle));
            break;
        }
        total_sent += g_raw_payload_len;
        interval_sent += g_raw_payload_len;

        /* pacing */
        if (g_target_bps > 0) {
            double should_send = elapsed_sec * (g_target_bps / 8.0);
            if ((double)total_sent >= should_send) {
                /* ahead -> short yield, do NOT Sleep(1) */
                for (int spin = 0; spin < 50 && !g_stop; spin++)
                    YieldProcessor();
            }
        }

        QueryPerformanceCounter(&now);
        double interval_sec = (double)(now.QuadPart - interval_start.QuadPart) / freq.QuadPart;
        if (interval_sec >= g_report_interval) {
            double bps = (double)interval_sent * 8 / interval_sec;
            double start_sec = (double)(interval_start.QuadPart - start.QuadPart) / freq.QuadPart;
            char bw_str[32], bytes_str[32];
            format_bps(bps, bw_str, sizeof(bw_str));
            format_bytes(interval_sent, bytes_str, sizeof(bytes_str));
            printf("[  1] %5.2f-%5.2f sec  %s  %s\n",
                   start_sec, start_sec + interval_sec, bytes_str, bw_str);
            interval_sent = 0;
            interval_start = now;
            fflush(stdout);
        }
    }

    QueryPerformanceCounter(&now);
    double total_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
    double avg_bps = (total_sec > 0) ? (double)total_sent * 8 / total_sec : 0;
    char bw_str[32], bytes_str[32];
    format_bps(avg_bps, bw_str, sizeof(bw_str));
    format_bytes(total_sent, bytes_str, sizeof(bytes_str));
    printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("[  1]  0.00-%5.2f sec  %s  %s                  sender\n",
           total_sec, bytes_str, bw_str);
    printf("Sent %llu bytes in %.2f seconds\n",
           (unsigned long long)total_sent, total_sec);

    free(payload);
    pcap_close(g_handle);
    g_handle = NULL;
}

/* Open the first non-loopback Ethernet adapter (for server mode) */
static int raw_open_first_device(void)
{
    pcap_if_t *alldevs = NULL, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error: pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    /* Find first non-loopback device with an IPv4 address */
    for (d = alldevs; d; d = d->next) {
        if (d->flags & PCAP_IF_LOOPBACK) continue;

        pcap_addr_t *a;
        for (a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                /* Found candidate */
                char dev_name[1024];
                snprintf(dev_name, sizeof(dev_name), "%s", d->name);

                g_handle = pcap_open_live(dev_name, 65536, 1, 100, errbuf);
                if (!g_handle) {
                    fprintf(stderr, "Error: pcap_open_live(%s) failed: %s\n", dev_name, errbuf);
                    continue;
                }

                if (pcap_datalink(g_handle) != DLT_EN10MB) {
                    pcap_close(g_handle);
                    g_handle = NULL;
                    continue;
                }

                /* Get IP + MAC */
                struct sockaddr_in *s = (struct sockaddr_in *)a->addr;
                memcpy(g_my_ip, &s->sin_addr.s_addr, 4);

                /* Get MAC via IP Helper */
                IP_ADAPTER_INFO *info = NULL, *p;
                ULONG buf_len = 0;
                if (GetAdaptersInfo(NULL, &buf_len) == ERROR_BUFFER_OVERFLOW) {
                    info = (IP_ADAPTER_INFO *)malloc(buf_len);
                    if (info && GetAdaptersInfo(info, &buf_len) == NO_ERROR) {
                        for (p = info; p; p = p->Next) {
                            uint32_t ip = 0;
                            inet_pton(AF_INET, p->IpAddressList.IpAddress.String, &ip);
                            if (ip != 0 && memcmp(&ip, g_my_ip, 4) == 0) {
                                memcpy(g_my_mac, p->Address, min(p->AddressLength, 6));
                                break;
                            }
                        }
                    }
                    free(info);
                }

                if (memcmp(g_my_mac, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
                    fprintf(stderr, "Warning: cannot determine MAC for %s, using zeros\n", dev_name);
                }

                printf("Raw mode: device=%s MAC=%02X:%02X:%02X:%02X:%02X:%02X IP=%u.%u.%u.%u\n",
                       dev_name,
                       g_my_mac[0], g_my_mac[1], g_my_mac[2],
                       g_my_mac[3], g_my_mac[4], g_my_mac[5],
                       g_my_ip[0], g_my_ip[1], g_my_ip[2], g_my_ip[3]);

                pcap_freealldevs(alldevs);
                return 0;
            }
        }
    }

    pcap_freealldevs(alldevs);
    fprintf(stderr, "Error: no suitable non-loopback Ethernet adapter found\n");
    return -1;
}

/* Raw mode SERVER: count incoming raw frames (VLAN or plain) */
static void raw_server_test(void)
{
    if (raw_open_first_device() != 0) {
        return;
    }

    printf("Raw server: listening for frames%s\n",
           g_vlan_id > 0 ? " (VLAN tag expected)" : "");
    printf("NOTE: receive-only. Source addresses are forged; server cannot echo back.\n");
    printf("[ ID] Interval           Transfer     Bandwidth\n");

    uint64_t total_recv = 0;
    uint64_t interval_recv = 0;
    LARGE_INTEGER freq, start, interval_start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    QueryPerformanceCounter(&interval_start);
    int deadline = GetTickCount() + g_silence_timeout * 1000;

    while (!g_stop) {
        struct pcap_pkthdr *hdr;
        const uint8_t *pkt;
        int r = pcap_next_ex(g_handle, &hdr, &pkt);

        if (r == 1 && hdr->len >= ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN) {
            eth_header_t *eth = (eth_header_t *)pkt;
            uint16_t et = ntohs(eth->ethertype);
            uint8_t *ip_pkt;

            if (et == ETHERTYPE_VLAN) {
                if (g_vlan_id == 0 || hdr->len < VLAN_ETH_HDR_LEN + IP_HDR_LEN) continue;
                uint16_t tci = ntohs(*(uint16_t *)(pkt + ETH_HDR_LEN + 2));
                if ((tci & VLAN_VID_MASK) != g_vlan_id) continue;
                ip_pkt = (uint8_t *)eth + VLAN_ETH_HDR_LEN;
            } else if (et == ETHERTYPE_IP) {
                if (g_vlan_id > 0) continue;   /* strict: expect tagged */
                ip_pkt = (uint8_t *)eth + ETH_HDR_LEN;
            } else {
                continue;
            }

            ip_header_t *ip = (ip_header_t *)ip_pkt;
            if (ip->protocol != IP_PROTOCOL_UDP) continue;
            udp_header_t *udp = (udp_header_t *)(ip_pkt + IP_HDR_LEN);
            if (ntohs(udp->dst_port) != (uint16_t)g_port) continue;

            int plen = ntohs(ip->total_len) - IP_HDR_LEN - UDP_HDR_LEN;
            total_recv += (plen > 0) ? plen : 0;
            interval_recv += (plen > 0) ? plen : 0;
            deadline = GetTickCount() + g_silence_timeout * 1000;

            QueryPerformanceCounter(&now);
            double interval_sec = (double)(now.QuadPart - interval_start.QuadPart) / freq.QuadPart;
            if (interval_sec >= g_report_interval && interval_recv > 0) {
                double bps = (double)interval_recv * 8 / interval_sec;
                double elapsed = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
                char bw_str[32], bytes_str[32];
                format_bps(bps, bw_str, sizeof(bw_str));
                format_bytes(interval_recv, bytes_str, sizeof(bytes_str));
                printf("[  3] %5.2f-%5.2f sec  %s  %s\n",
                       (double)(interval_start.QuadPart - start.QuadPart) / freq.QuadPart,
                       elapsed, bytes_str, bw_str);
                interval_recv = 0;
                interval_start = now;
                fflush(stdout);
            }
        } else if (r == -1) {
            fprintf(stderr, "\nError: pcap_next_ex: %s\n", pcap_geterr(g_handle));
            break;
        }

        if ((int)(GetTickCount() - deadline) >= 0) {
            printf("\nNo frames for %d seconds, stopping.\n", g_silence_timeout);
            break;
        }
    }

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    double total_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
    double avg_bps = (total_sec > 0) ? (double)total_recv * 8 / total_sec : 0;
    char bw_str[32], bytes_str[32];
    format_bps(avg_bps, bw_str, sizeof(bw_str));
    format_bytes(total_recv, bytes_str, sizeof(bytes_str));
    printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("[  3]  0.00-%5.2f sec  %s  %s\n", total_sec, bytes_str, bw_str);

    pcap_close(g_handle);
    g_handle = NULL;
}
#endif /* USE_WINPCAP */

/*=======================================================================
 * Usage
 *=====================================================================*/

static void usage(const char *prog)
{
    printf("iperf-like bandwidth test tool for Windows\n");
    printf("Supports TCP and UDP, socket mode (default) and raw mode (--raw with WinPcap)\n");
    printf("\n");
    printf("Usage:\n");
    printf("  %s -s [options]                      Server mode\n", prog);
    printf("  %s -c <host> [options]               Client mode\n", prog);
    printf("\n");
    printf("Server options:\n");
    printf("  -s, --server              Run in server mode\n");
    printf("  -p, --port      #         Port to listen on/connect to (default %d)\n", DEFAULT_PORT);
    printf("  -u, --udp                 Use UDP (default is TCP)\n");
    printf("  -T, --timeout     #       Auto-stop after N seconds of silence (default 3)\n");
    printf("\n");
    printf("Client options:\n");
    printf("  -c, --client    <host>    Run in client mode, connecting to <host>\n");
    printf("  -b, --bandwidth #[KMG]    Target bandwidth in bits/sec (default unlimited)\n");
    printf("  -t, --time      #         Time in seconds to transmit (default %d)\n", DEFAULT_DURATION);
    printf("  -n, --bytes     #[KMG]    Number of bytes to transmit (instead of -t)\n");
    printf("  -l, --len       #         Buffer size (TCP default %d, UDP default %d, max %d)\n",
           DEFAULT_BUFSIZE_TCP, DEFAULT_BUFSIZE_UDP, MAX_BUFSIZE);
    printf("  -i, --interval  #         Seconds between bandwidth reports (default %d)\n", DEFAULT_INTERVAL);
    printf("      --interactive         Interactive mode (chat-like)\n");
    printf("\n");
#ifdef USE_WINPCAP
    printf("Raw mode options (require WinPcap):\n");
    printf("      --raw                 Use raw Ethernet frames (for VLAN testing)\n");
    printf("  -V, --vlan      #         VLAN ID (1-4094, only with --raw)\n");
    printf("\n");
#endif
    printf("[KMG] suffix: K=kilo, M=mega, G=giga\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -s -p 9999                    # TCP server\n", prog);
    printf("  %s -s -p 9999 -u                 # UDP server\n", prog);
    printf("  %s -c 192.168.1.100 -p 9999       # TCP client, 10 sec\n", prog);
    printf("  %s -c 192.168.1.100 -p 9999 -b 100M -t 30\n", prog);
    printf("  %s -c 192.168.1.100 -p 9999 -u -b 1G\n", prog);
    printf("  %s -c 192.168.1.100 -p 9999 --interactive\n", prog);
#ifdef USE_WINPCAP
    printf("  %s -s -p 9999 --raw -V 100       # Raw mode with VLAN 100\n", prog);
    printf("  %s -c 192.168.1.100 -p 9999 --raw -V 100 -b 100M\n", prog);
#endif
}

/*=======================================================================
 * Main function
 *=====================================================================*/

int main(int argc, char *argv[])
{
    char *server_ip_port = NULL;
    WSADATA wsaData;
    int result;

    /* Initialize Winsock */
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        fprintf(stderr, "Error: WSAStartup failed: %d\n", result);
        return 1;
    }

    /* Parse arguments */
    int arg_idx = 1;
    while (arg_idx < argc) {
        if (strcmp(argv[arg_idx], "-h") == 0 || strcmp(argv[arg_idx], "--help") == 0) {
            usage(argv[0]);
            WSACleanup();
            return 0;
        } else if (strcmp(argv[arg_idx], "-v") == 0 || strcmp(argv[arg_idx], "--version") == 0) {
            printf("vlan_tag_switch (iperf-like) version 2.0.0\n");
            WSACleanup();
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
                g_port = atoi(argv[arg_idx + 1]);
                if (g_port <= 0 || g_port > 65535) {
                    fprintf(stderr, "Error: Invalid port number\n");
                    WSACleanup();
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -p requires a port number\n");
                WSACleanup();
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
                WSACleanup();
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-t") == 0 || strcmp(argv[arg_idx], "--time") == 0) {
            if (arg_idx + 1 < argc) {
                g_duration = atoi(argv[arg_idx + 1]);
                if (g_duration < 1 || g_duration > 3600) {
                    fprintf(stderr, "Error: time must be between 1-3600\n");
                    WSACleanup();
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -t requires a time value\n");
                WSACleanup();
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-n") == 0 || strcmp(argv[arg_idx], "--bytes") == 0) {
            if (arg_idx + 1 < argc) {
                g_nbytes = parse_bytes(argv[arg_idx + 1]);
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -n requires a byte count\n");
                WSACleanup();
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-l") == 0 || strcmp(argv[arg_idx], "--len") == 0) {
            if (arg_idx + 1 < argc) {
                g_bufsize = atoi(argv[arg_idx + 1]);
                if (g_bufsize < 64 || g_bufsize > MAX_BUFSIZE) {
                    fprintf(stderr, "Error: length must be between 64-%d\n", MAX_BUFSIZE);
                    WSACleanup();
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -l requires a length value\n");
                WSACleanup();
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-i") == 0 || strcmp(argv[arg_idx], "--interval") == 0) {
            if (arg_idx + 1 < argc) {
                g_report_interval = atoi(argv[arg_idx + 1]);
                if (g_report_interval < 1 || g_report_interval > 60) {
                    fprintf(stderr, "Error: interval must be between 1-60\n");
                    WSACleanup();
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -i requires an interval value\n");
                WSACleanup();
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "-T") == 0 || strcmp(argv[arg_idx], "--timeout") == 0) {
            if (arg_idx + 1 < argc) {
                g_silence_timeout = atoi(argv[arg_idx + 1]);
                if (g_silence_timeout < 1 || g_silence_timeout > 300) {
                    fprintf(stderr, "Error: timeout must be between 1-300\n");
                    WSACleanup();
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -T requires a timeout value\n");
                WSACleanup();
                return 1;
            }
        } else if (strcmp(argv[arg_idx], "--interactive") == 0) {
            g_interactive = 1;
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "--raw") == 0) {
            g_use_raw = 1;
            arg_idx++;
#ifdef USE_WINPCAP
        } else if (strcmp(argv[arg_idx], "-V") == 0 || strcmp(argv[arg_idx], "--vlan") == 0) {
            if (arg_idx + 1 < argc) {
                g_vlan_id = (uint16_t)atoi(argv[arg_idx + 1]);
                if (g_vlan_id < 1 || g_vlan_id > 4094) {
                    fprintf(stderr, "Error: VLAN ID must be between 1-4094\n");
                    WSACleanup();
                    return 1;
                }
                arg_idx += 2;
            } else {
                fprintf(stderr, "Error: -V requires a VLAN ID\n");
                WSACleanup();
                return 1;
            }
#else
        } else if (strcmp(argv[arg_idx], "-V") == 0 || strcmp(argv[arg_idx], "--vlan") == 0) {
            fprintf(stderr, "Error: VLAN support requires WinPcap. Rebuild with -DUSE_WINPCAP\n");
            WSACleanup();
            return 1;
#endif
        } else {
            fprintf(stderr, "Error: Unknown argument: %s\n", argv[arg_idx]);
            usage(argv[0]);
            WSACleanup();
            return 1;
        }
    }

    if (g_mode == MODE_NONE) {
        fprintf(stderr, "Error: Please use -s (server) or -c (client) to specify mode\n\n");
        usage(argv[0]);
        WSACleanup();
        return 1;
    }

    if (g_mode == MODE_CLIENT && server_ip_port == NULL) {
        fprintf(stderr, "Error: Client mode requires server host address\n\n");
        usage(argv[0]);
        WSACleanup();
        return 1;
    }

    /* Parse server IP (and optional port) */
    if (server_ip_port) {
        strncpy(g_server_ip, server_ip_port, sizeof(g_server_ip) - 1);
        g_server_ip[sizeof(g_server_ip) - 1] = '\0';

        char *colon = strrchr(g_server_ip, ':');
        if (colon) {
            *colon = '\0';
            int port = atoi(colon + 1);
            if (port > 0 && port <= 65535) {
                g_port = port;
            }
        }
    }

    /* VLAN requires raw mode (socket mode cannot set VLAN tag) */
    if (g_vlan_id > 0 && !g_use_raw) {
        printf("NOTE: VLAN %u requested without --raw. Auto-enabling raw mode.\n\n", g_vlan_id);
        g_use_raw = 1;
    }

    /* Raw mode only supports UDP (TCP handshake not feasible with raw frames) */
    if (g_use_raw && g_protocol == PROTO_TCP) {
        printf("NOTE: raw mode uses UDP only (manual TCP handshake not implemented). Forcing UDP.\n\n");
        g_protocol = PROTO_UDP;
    }

    /* Set Ctrl+C handler */
    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    /* Print header */
    printf("========================================\n");
    printf(" iperf-like Bandwidth Test Tool v2.0\n");
    printf("========================================\n");
    printf(" Mode      : %s\n", g_mode == MODE_SERVER ? "Server (-s)" : "Client (-c)");
    printf(" Protocol  : %s\n", g_protocol == PROTO_TCP ? "TCP" : "UDP");
    printf(" Port      : %u\n", g_port);
    if (g_mode == MODE_CLIENT) {
        printf(" Server    : %s\n", g_server_ip);
        if (g_target_bps > 0) {
            char bw_str[32];
            format_bps(g_target_bps, bw_str, sizeof(bw_str));
            printf(" Target BW : %s\n", bw_str);
        }
        if (g_nbytes > 0) {
            char bytes_str[32];
            format_bytes(g_nbytes, bytes_str, sizeof(bytes_str));
            printf(" Bytes     : %s\n", bytes_str);
        } else {
            printf(" Duration  : %d sec\n", g_duration);
        }
    } else {
        printf(" Timeout   : %d sec (auto-stop)\n", g_silence_timeout);
    }
    /* Choose default buffer size based on protocol if not set by user */
    if (g_bufsize <= 0) {
        g_bufsize = (g_protocol == PROTO_TCP) ? DEFAULT_BUFSIZE_TCP : DEFAULT_BUFSIZE_UDP;
    }
    if (g_bufsize > MAX_BUFSIZE) g_bufsize = MAX_BUFSIZE;

    printf(" Buf Size  : %d bytes\n", g_bufsize);
    printf(" Interval  : %d sec (report interval)\n", g_report_interval);
    printf("========================================\n");

    /* Improve Windows timer resolution for accurate pacing */
    timeBeginPeriod(1);

    /* Run test */
    if (g_interactive) {
        if (g_mode == MODE_SERVER) {
            server_interactive_loop();
        } else {
            client_interactive_loop();
        }
    } else {
        if (g_mode == MODE_CLIENT) {
            if (g_protocol == PROTO_TCP) {
                tcp_client_test();
            } else {
#ifdef USE_WINPCAP
                if (g_use_raw) {
                    raw_client_test();
                } else
#endif
                udp_client_test();
            }
        } else {
            if (g_protocol == PROTO_TCP) {
                tcp_server_test();
            } else {
#ifdef USE_WINPCAP
                if (g_use_raw) {
                    raw_server_test();
                } else
#endif
                udp_server_test();
            }
        }
    }

    printf("\nStopped.\n");
    timeEndPeriod(1);
    WSACleanup();
    return 0;
}
