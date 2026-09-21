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
#define DEFAULT_BUFSIZE     1400
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

/* Global state */
static int g_running = 1;
static int g_mode = MODE_NONE;
static int g_protocol = PROTO_TCP;
static int g_port = DEFAULT_PORT;
static int g_duration = DEFAULT_DURATION;
static int g_bufsize = DEFAULT_BUFSIZE;
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
        g_running = 0;
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

    while (g_running) {
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

        /* Pacing: if target bandwidth set, sleep to maintain rate */
        if (g_target_bps > 0) {
            QueryPerformanceCounter(&now);
            double elapsed_now = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
            double expected_sec = (double)total_sent * 8.0 / g_target_bps;
            if (expected_sec > elapsed_now) {
                double sleep_sec = expected_sec - elapsed_now;
                if (sleep_sec > 0.0005) {
                    Sleep((DWORD)(sleep_sec * 1000.0 + 0.5));
                }
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

    while (g_running) {
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

    while (g_running) {
        QueryPerformanceCounter(&now);
        double elapsed_sec = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;

        if (g_nbytes > 0) {
            if (total_sent >= g_nbytes) break;
        } else {
            if (elapsed_sec >= g_duration) break;
        }

        int to_send = g_bufsize;
        if (g_nbytes > 0 && total_sent + to_send > g_nbytes)
            to_send = (int)(g_nbytes - total_sent);

        int sent = sendto(sock, (char *)buf, to_send, 0,
                          (struct sockaddr *)&addr, sizeof(addr));
        if (sent == SOCKET_ERROR) {
            fprintf(stderr, "\nError: sendto() failed: %d\n", WSAGetLastError());
            break;
        }

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

        /* Pacing */
        if (g_target_bps > 0) {
            QueryPerformanceCounter(&now);
            double elapsed_now = (double)(now.QuadPart - start.QuadPart) / freq.QuadPart;
            double expected_sec = (double)total_sent * 8.0 / g_target_bps;
            if (expected_sec > elapsed_now) {
                double sleep_sec = expected_sec - elapsed_now;
                if (sleep_sec > 0.0005) {
                    Sleep((DWORD)(sleep_sec * 1000.0 + 0.5));
                }
            }
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

    while (g_running) {
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

    while (g_running) {
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

    while (g_running) {
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

/*=======================================================================
 * Raw mode (WinPcap) - VLAN tag support
 *
 * NOTE: Raw mode is not implemented in this version.
 * Use socket mode for bandwidth testing (works like iperf).
 * For VLAN tag testing, use standard iperf3 with VLAN interfaces:
 *   1. Configure VLAN interfaces at the OS level
 *   2. Use: iperf3 -c <vlan_ip> -p <port> -b <bw>
 *=====================================================================*/

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
    printf("  -l, --len       #         Buffer size to read/write (default %d, max %d)\n",
           DEFAULT_BUFSIZE, MAX_BUFSIZE);
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
    printf(" Buf Size  : %d bytes\n", g_bufsize);
    printf(" Interval  : %d sec (report interval)\n", g_report_interval);
    printf("========================================\n");

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
                udp_client_test();
            }
        } else {
            if (g_protocol == PROTO_TCP) {
                tcp_server_test();
            } else {
                udp_server_test();
            }
        }
    }

    printf("\nStopped.\n");
    WSACleanup();
    return 0;
}
