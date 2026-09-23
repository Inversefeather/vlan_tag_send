/*
 * iperf.c - System TCP/UDP throughput test via Winsock
 *
 * This is the "--mode iperf" backend.  It uses the OS kernel TCP/UDP stack
 * via standard BSD-style sockets -- no Npcap, no hand-built frames, no FSM.
 *
 * Two sub-backends selected by cfg->iperf3:
 *   0 (default): built-in send/receive loop
 *   1:           system("iperf3 ...") call
 *
 * The built-in backend supports:
 *   - TCP and UDP (-u)
 *   - Client (-c host) and server (-s) modes
 *   - Parallel streams (-P N)
 *   - Bandwidth throttling (-b N)
 *   - Optional source bind (-B ip / --bind)
 *   - JSON output (-J)
 *   - Interval reports (-i N)
 */
#include "iperf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mmsystem.h>

/* ---------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------*/
#define IPERF_BUFSIZE    131072   /* 128 KB send/recv buffer */
#define IPERF_UDP_SIZE   1470    /* ~MTU - IP(20) - UDP(8) */

/* Per-stream state */
typedef struct {
    SOCKET      sock;
    uint64_t    bytes;          /* bytes sent (client) or received (server) */
    uint64_t    interval_bytes; /* bytes in current report interval */
    int         id;
} iperf_stream_t;

/* ---------------------------------------------------------------------
 * High-resolution time
 * -------------------------------------------------------------------*/
static uint64_t now_ms(void)
{
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    return (uint64_t)(cnt.QuadPart * 1000.0 / freq.QuadPart);
}

/* Sub-millisecond time in seconds (for rate limiter precision).
 * QPC frequency is cached so busy-wait loops don't pay for a syscall
 * per call. */
static double now_sec(void)
{
    static double freq = 0.0;
    LARGE_INTEGER cnt;
    if (freq == 0.0) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        freq = (double)f.QuadPart;
    }
    QueryPerformanceCounter(&cnt);
    return (double)cnt.QuadPart / freq;
}

/* ---------------------------------------------------------------------
 * Bandwidth rate limiter (time-based)
 *
 * Instead of a token bucket (which needs sub-μs precision that busy-
 * wait loops can't provide), we track when the next packet may be sent.
 * For 10 Mbit/s and 1470-byte packets that's ~1.18 ms apart -- well
 * above the QPC resolution (~100 ns).
 * -------------------------------------------------------------------*/
typedef struct {
    double   rate_bps;      /* target rate, 0 = unlimited */
    double   interval_sec;  /* seconds per packet */
    double   next_sec;      /* when next packet may fire */
    int      pktsize;
} rate_limiter_t;

static void rl_init(rate_limiter_t *rl, double bps, int pktsize)
{
    rl->rate_bps = bps;
    rl->pktsize = pktsize;
    rl->interval_sec = (bps > 0) ? (double)pktsize * 8.0 / bps : 0;
    rl->next_sec = 0;
}

/* Call before each send.  Busy-wait until the rate window opens. */
static void rl_wait(rate_limiter_t *rl)
{
    if (rl->rate_bps <= 0) return;
    double now = now_sec();
    if (rl->next_sec == 0.0)
        rl->next_sec = now + rl->interval_sec;
    if (now < rl->next_sec) {
        while (now_sec() < rl->next_sec) { /* spin */ }
    }
    rl->next_sec += rl->interval_sec;
}

/* ---------------------------------------------------------------------
 * Format bytes as human-readable
 * -------------------------------------------------------------------*/
static void fmt_bytes(uint64_t b, char *buf, int bufsz)
{
    double v = (double)b;
    const char *unit = "Bytes";
    if (v >= 1e9) { v /= 1e9; unit = "GBytes"; }
    else if (v >= 1e6) { v /= 1e6; unit = "MBytes"; }
    else if (v >= 1e3) { v /= 1e3; unit = "KBytes"; }
    snprintf(buf, bufsz, "%.2f %s", v, unit);
}

static void fmt_bps(uint64_t bytes, double sec, char *buf, int bufsz)
{
    double bps = (sec > 0) ? (double)bytes * 8.0 / sec : 0;
    double v = bps;
    const char *unit = "bits/sec";
    if (v >= 1e9) { v /= 1e9; unit = "Gbits/sec"; }
    else if (v >= 1e6) { v /= 1e6; unit = "Mbits/sec"; }
    else if (v >= 1e3) { v /= 1e3; unit = "Kbits/sec"; }
    snprintf(buf, bufsz, "%.2f %s", v, unit);
}

/* ---------------------------------------------------------------------
 * TCP client
 * -------------------------------------------------------------------*/
static int tcp_client(const cli_config_t *cfg, uint32_t remote_ip)
{
    iperf_stream_t *streams = (iperf_stream_t *)calloc(cfg->streams, sizeof(iperf_stream_t));
    if (!streams) return -1;

    int bufsize = cfg->bufsize > 0 ? cfg->bufsize : IPERF_BUFSIZE;
    uint8_t *buf = (uint8_t *)malloc(bufsize);
    if (!buf) { free(streams); return -1; }
    /* fill with pattern */
    for (int i = 0; i < bufsize; i++) buf[i] = (uint8_t)(i & 0xFF);

    rate_limiter_t *rls = NULL;
    if (cfg->target_bps > 0) {
        rls = (rate_limiter_t *)calloc(cfg->streams, sizeof(rate_limiter_t));
        if (!rls) { free(streams); free(buf); return -1; }
        for (int i = 0; i < cfg->streams; i++)
            rl_init(&rls[i], cfg->target_bps / cfg->streams, bufsize);
    }

    printf("iperf TCP client: %d stream(s) -> %u.%u.%u.%u:%u  buf=%d\n",
           cfg->streams,
           remote_ip&0xFF,(remote_ip>>8)&0xFF,(remote_ip>>16)&0xFF,(remote_ip>>24)&0xFF,
           cfg->port, bufsize);

    /* connect all streams */
    for (int i = 0; i < cfg->streams; i++) {
        streams[i].sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (streams[i].sock == INVALID_SOCKET) {
            fprintf(stderr, "Error: socket() failed: %d\n", WSAGetLastError());
            for (int j = 0; j < i; j++) closesocket(streams[j].sock);
            free(streams); free(buf); return -1;
        }
        /* optional source bind */
        if (cfg->bind_ip != 0) {
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = cfg->bind_ip;
            sa.sin_port = 0;  /* ephemeral */
            bind(streams[i].sock, (struct sockaddr *)&sa, sizeof(sa));
        }
        struct sockaddr_in da;
        memset(&da, 0, sizeof(da));
        da.sin_family = AF_INET;
        da.sin_addr.s_addr = remote_ip;
        da.sin_port = htons((uint16_t)cfg->port);
        if (connect(streams[i].sock, (struct sockaddr *)&da, sizeof(da)) != 0) {
            fprintf(stderr, "Error: connect() failed: %d\n", WSAGetLastError());
            for (int j = 0; j <= i; j++) closesocket(streams[j].sock);
            free(streams); free(buf); return -1;
        }
        unsigned long nb = 1;
        ioctlsocket(streams[i].sock, FIONBIO, &nb);  /* non-blocking send loop */
    }

    uint64_t start_ms = now_ms();
    uint64_t stop_ms = start_ms + (uint64_t)cfg->duration * 1000;
    uint64_t report_ms = start_ms;
    if (!cfg->json) {
        printf("[ ID] Interval       Transfer     Bandwidth\n");
    }

    for (;;) {
        uint64_t now = now_ms();
        if (now >= stop_ms) break;

        /* each stream sends as fast as rate limiter allows */
        for (int i = 0; i < cfg->streams; i++) {
            if (rls) rl_wait(&rls[i]);
            int allow = bufsize;
            int n = send(streams[i].sock, (const char *)buf, allow, 0);
            if (n > 0) {
                streams[i].bytes += n;
                streams[i].interval_bytes += n;
            } else {
                int e = WSAGetLastError();
                if (e != WSAEWOULDBLOCK && e != WSAEINTR) {
                    fprintf(stderr, "send error: %d\n", e);
                    goto done;
                }
            }
        }

        /* interval report */
        if (now - report_ms >= (uint64_t)cfg->report_interval * 1000) {
            uint64_t total = 0;
            for (int i = 0; i < cfg->streams; i++) total += streams[i].interval_bytes;
            double sec = (double)(now - report_ms) / 1000.0;
            char tb[32], bb[32];
            fmt_bytes(total, tb, sizeof(tb));
            fmt_bps(total, sec, bb, sizeof(bb));
            if (!cfg->json) {
                printf("[SUM] %6.2f-%6.2f sec  %s  %s\n",
                       (double)(report_ms - start_ms) / 1000.0,
                       (double)(now - start_ms) / 1000.0, tb, bb);
            }
            for (int i = 0; i < cfg->streams; i++) streams[i].interval_bytes = 0;
            report_ms = now;
        }
        if (rls == NULL) Sleep(1);
    }

done: {
    double total_sec = (double)(now_ms() - start_ms) / 1000.0;
    uint64_t total_bytes = 0;
    for (int i = 0; i < cfg->streams; i++) total_bytes += streams[i].bytes;

    char tb[32], bb[32];
    fmt_bytes(total_bytes, tb, sizeof(tb));
    fmt_bps(total_bytes, total_sec, bb, sizeof(bb));

    if (cfg->json) {
        printf("{\"start\":0,\"end\":%.2f,\"bytes\":%llu,\"bits_per_second\":%.2f}\n",
               total_sec, (unsigned long long)total_bytes,
               total_sec > 0 ? (double)total_bytes * 8.0 / total_sec : 0);
    } else {
        printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
        printf("[SUM]  0.00-%5.2f sec  %s  %s\n", total_sec, tb, bb);
    }

    for (int i = 0; i < cfg->streams; i++) closesocket(streams[i].sock);
    free(streams);
    free(buf);
    free(rls);
    return 0;
    }  /* done: block */
    return 0;  /* unreachable */
}

/* ---------------------------------------------------------------------
 * TCP server
 * -------------------------------------------------------------------*/
static int tcp_server(const cli_config_t *cfg)
{
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        fprintf(stderr, "Error: socket() failed: %d\n", WSAGetLastError());
        return -1;
    }
    int yes = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = cfg->bind_ip;  /* 0 = INADDR_ANY */
    sa.sin_port = htons((uint16_t)cfg->port);
    if (bind(listener, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        fprintf(stderr, "Error: bind() failed: %d\n", WSAGetLastError());
        closesocket(listener);
        return -1;
    }
    if (listen(listener, cfg->streams + 2) != 0) {
        fprintf(stderr, "Error: listen() failed: %d\n", WSAGetLastError());
        closesocket(listener);
        return -1;
    }

    printf("iperf TCP server: port=%u bind=%u.%u.%u.%u (listening...)\n",
           cfg->port,
           (unsigned int)(ntohl(cfg->bind_ip)&0xFF),
           (unsigned int)((ntohl(cfg->bind_ip)>>8)&0xFF),
           (unsigned int)((ntohl(cfg->bind_ip)>>16)&0xFF),
           (unsigned int)((ntohl(cfg->bind_ip)>>24)&0xFF));

    uint8_t *buf = (uint8_t *)malloc(IPERF_BUFSIZE);
    if (!buf) { closesocket(listener); return -1; }

    /* Parallel-stream handling via select(): the listener + all accepted
     * client sockets go into one fd_set, so we recv from whichever has
     * data instead of blocking on a single connection. */
    SOCKET clients[256];
    uint64_t client_bytes[256];
    int num_clients = 0;

    uint64_t total_bytes = 0;
    uint64_t start_ms = now_ms();
    uint64_t report_ms = start_ms;

    if (!cfg->json) {
        printf("[ ID] Interval       Transfer     Bandwidth\n");
    }

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listener, &rfds);
        SOCKET max_sock = listener;
        for (int i = 0; i < num_clients; i++) {
            FD_SET(clients[i], &rfds);
            if (clients[i] > max_sock) max_sock = clients[i];
        }

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000;  /* 10ms timeout for responsive interval reports */

        int ret = select((int)(max_sock + 1), &rfds, NULL, NULL, &tv);
        if (ret == SOCKET_ERROR) break;

        /* New connection */
        if (FD_ISSET(listener, &rfds)) {
            struct sockaddr_in cli;
            int clen = sizeof(cli);
            SOCKET s = accept(listener, (struct sockaddr *)&cli, &clen);
            if (s != INVALID_SOCKET && num_clients < 256) {
                char cip[32];
                snprintf(cip, sizeof(cip), "%u.%u.%u.%u",
                         (unsigned int)(cli.sin_addr.s_addr&0xFF),
                         (unsigned int)((cli.sin_addr.s_addr>>8)&0xFF),
                         (unsigned int)((cli.sin_addr.s_addr>>16)&0xFF),
                         (unsigned int)((cli.sin_addr.s_addr>>24)&0xFF));
                if (!cfg->json)
                    printf("Accepted from %s:%u\n", cip, ntohs(cli.sin_port));
                clients[num_clients] = s;
                client_bytes[num_clients] = 0;
                num_clients++;
            }
        }

        /* Data on existing connections */
        for (int i = 0; i < num_clients; i++) {
            if (FD_ISSET(clients[i], &rfds)) {
                int n = recv(clients[i], (char *)buf, IPERF_BUFSIZE, 0);
                if (n > 0) {
                    client_bytes[i] += n;
                    total_bytes += n;
                } else {
                    /* Connection closed */
                    closesocket(clients[i]);
                    clients[i] = clients[num_clients - 1];
                    client_bytes[i] = client_bytes[num_clients - 1];
                    num_clients--;
                    i--;
                }
            }
        }

        /* Interval report */
        uint64_t now = now_ms();
        if (now - report_ms >= (uint64_t)cfg->report_interval * 1000) {
            char tb[32], bb[32];
            fmt_bytes(total_bytes, tb, sizeof(tb));
            fmt_bps(total_bytes, (double)(now - start_ms) / 1000.0, bb, sizeof(bb));
            if (!cfg->json) {
                printf("[SUM] %6.2f-%6.2f sec  %s  %s\n",
                       (double)(report_ms - start_ms) / 1000.0,
                       (double)(now - start_ms) / 1000.0, tb, bb);
            }
            report_ms = now;
        }

        /* Duration limit */
        if (cfg->duration > 0 && now - start_ms >= (uint64_t)cfg->duration * 1000)
            break;
    }

    double total_sec = (double)(now_ms() - start_ms) / 1000.0;
    char tb[32], bb[32];
    fmt_bytes(total_bytes, tb, sizeof(tb));
    fmt_bps(total_bytes, total_sec, bb, sizeof(bb));
    if (cfg->json) {
        printf("{\"start\":0,\"end\":%.2f,\"bytes\":%llu,\"bits_per_second\":%.2f}\n",
               total_sec, (unsigned long long)total_bytes,
               total_sec > 0 ? (double)total_bytes * 8.0 / total_sec : 0);
    } else {
        printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
        printf("[SUM]  0.00-%5.2f sec  %s  %s\n", total_sec, tb, bb);
    }

    for (int i = 0; i < num_clients; i++) closesocket(clients[i]);
    closesocket(listener);
    free(buf);
    return 0;
}

/* ---------------------------------------------------------------------
 * UDP client
 * -------------------------------------------------------------------*/
static int udp_client(const cli_config_t *cfg, uint32_t remote_ip)
{
    iperf_stream_t *streams = (iperf_stream_t *)calloc(cfg->streams, sizeof(iperf_stream_t));
    if (!streams) return -1;

    int pktsize = cfg->bufsize > 0 ? (cfg->bufsize > IPERF_UDP_SIZE ? IPERF_UDP_SIZE : cfg->bufsize) : IPERF_UDP_SIZE;
    uint8_t *buf = (uint8_t *)malloc(pktsize);
    if (!buf) { free(streams); return -1; }
    for (int i = 0; i < pktsize; i++) buf[i] = (uint8_t)(i & 0xFF);

    /* One rate limiter per stream so parallel streams don't starve each other */
    rate_limiter_t *rls = NULL;
    if (cfg->target_bps > 0) {
        rls = (rate_limiter_t *)calloc(cfg->streams, sizeof(rate_limiter_t));
        if (!rls) { free(streams); free(buf); return -1; }
        for (int i = 0; i < cfg->streams; i++)
            rl_init(&rls[i], cfg->target_bps / cfg->streams, pktsize);
    }

    printf("iperf UDP client: %d stream(s) -> %u.%u.%u.%u:%u  pkt=%d\n",
           cfg->streams,
           remote_ip&0xFF,(remote_ip>>8)&0xFF,(remote_ip>>16)&0xFF,(remote_ip>>24)&0xFF,
           cfg->port, pktsize);

    struct sockaddr_in da;
    memset(&da, 0, sizeof(da));
    da.sin_family = AF_INET;
    da.sin_addr.s_addr = remote_ip;
    da.sin_port = htons((uint16_t)cfg->port);

    for (int i = 0; i < cfg->streams; i++) {
        streams[i].sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (streams[i].sock == INVALID_SOCKET) {
            fprintf(stderr, "Error: socket() failed: %d\n", WSAGetLastError());
            for (int j = 0; j < i; j++) closesocket(streams[j].sock);
            free(streams); free(buf); return -1;
        }
        if (cfg->bind_ip != 0) {
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = cfg->bind_ip;
            sa.sin_port = 0;
            bind(streams[i].sock, (struct sockaddr *)&sa, sizeof(sa));
        }
        connect(streams[i].sock, (struct sockaddr *)&da, sizeof(da));
    }

    uint64_t start_ms = now_ms();
    uint64_t stop_ms = start_ms + (uint64_t)cfg->duration * 1000;
    uint64_t report_ms = start_ms;

    if (!cfg->json) printf("[ ID] Interval       Transfer     Bandwidth\n");

    for (;;) {
        uint64_t now = now_ms();
        if (now >= stop_ms) break;

        for (int i = 0; i < cfg->streams; i++) {
            if (rls) {
                /* Rate limited: wait for one packet slot, send one packet */
                rl_wait(&rls[i]);
                int n = send(streams[i].sock, (const char *)buf, pktsize, 0);
                if (n > 0) {
                    streams[i].bytes += n;
                    streams[i].interval_bytes += n;
                }
            } else {
                /* Unlimited: blast as many packets as the socket accepts */
                int budget = pktsize * 1000;
                while (budget >= pktsize) {
                    int n = send(streams[i].sock, (const char *)buf, pktsize, 0);
                    if (n > 0) {
                        streams[i].bytes += n;
                        streams[i].interval_bytes += n;
                        budget -= pktsize;
                    } else break;
                }
            }
        }

        if (now - report_ms >= (uint64_t)cfg->report_interval * 1000) {
            uint64_t total = 0;
            for (int i = 0; i < cfg->streams; i++) total += streams[i].interval_bytes;
            double sec = (double)(now - report_ms) / 1000.0;
            char tb[32], bb[32];
            fmt_bytes(total, tb, sizeof(tb));
            fmt_bps(total, sec, bb, sizeof(bb));
            if (!cfg->json) {
                printf("[SUM] %6.2f-%6.2f sec  %s  %s\n",
                       (double)(report_ms - start_ms) / 1000.0,
                       (double)(now - start_ms) / 1000.0, tb, bb);
            }
            for (int i = 0; i < cfg->streams; i++) streams[i].interval_bytes = 0;
            report_ms = now;
        }
        /* Rate limiter busy-waits via rl_wait; without a limit, yield CPU. */
        if (rls == NULL) Sleep(1);
    }

    double total_sec = (double)(now_ms() - start_ms) / 1000.0;
    uint64_t total_bytes = 0;
    for (int i = 0; i < cfg->streams; i++) total_bytes += streams[i].bytes;
    char tb[32], bb[32];
    fmt_bytes(total_bytes, tb, sizeof(tb));
    fmt_bps(total_bytes, total_sec, bb, sizeof(bb));
    if (cfg->json) {
        printf("{\"start\":0,\"end\":%.2f,\"bytes\":%llu,\"bits_per_second\":%.2f}\n",
               total_sec, (unsigned long long)total_bytes,
               total_sec > 0 ? (double)total_bytes * 8.0 / total_sec : 0);
    } else {
        printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
        printf("[SUM]  0.00-%5.2f sec  %s  %s\n", total_sec, tb, bb);
    }

    for (int i = 0; i < cfg->streams; i++) closesocket(streams[i].sock);
    free(streams); free(buf); free(rls);
    return 0;
}

/* ---------------------------------------------------------------------
 * UDP server
 * -------------------------------------------------------------------*/
static int udp_server(const cli_config_t *cfg)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "Error: socket() failed: %d\n", WSAGetLastError());
        return -1;
    }
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = cfg->bind_ip;
    sa.sin_port = htons((uint16_t)cfg->port);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        fprintf(stderr, "Error: bind() failed: %d\n", WSAGetLastError());
        closesocket(s); return -1;
    }

    printf("iperf UDP server: port=%u bind=%u.%u.%u.%u (listening...)\n",
           cfg->port,
           (unsigned int)(ntohl(cfg->bind_ip)&0xFF),
           (unsigned int)((ntohl(cfg->bind_ip)>>8)&0xFF),
           (unsigned int)((ntohl(cfg->bind_ip)>>16)&0xFF),
           (unsigned int)((ntohl(cfg->bind_ip)>>24)&0xFF));

    uint8_t *buf = (uint8_t *)malloc(IPERF_UDP_SIZE + 64);
    if (!buf) { closesocket(s); return -1; }

    uint64_t total_bytes = 0;
    uint64_t start_ms = now_ms();
    uint64_t report_ms = start_ms;

    if (!cfg->json) printf("[ ID] Interval       Transfer     Bandwidth\n");

    for (;;) {
        struct sockaddr_in from;
        int fromlen = sizeof(from);
        int n = recvfrom(s, (char *)buf, IPERF_UDP_SIZE + 64, 0,
                         (struct sockaddr *)&from, &fromlen);
        if (n > 0) total_bytes += n;

        uint64_t now = now_ms();
        if (now - report_ms >= (uint64_t)cfg->report_interval * 1000) {
            char tb[32], bb[32];
            fmt_bytes(total_bytes, tb, sizeof(tb));
            fmt_bps(total_bytes, (double)(now - start_ms) / 1000.0, bb, sizeof(bb));
            if (!cfg->json) {
                printf("[SUM] %6.2f-%6.2f sec  %s  %s\n",
                       (double)(report_ms - start_ms) / 1000.0,
                       (double)(now - start_ms) / 1000.0, tb, bb);
            }
            report_ms = now;
        }
        if (cfg->duration > 0 && now - start_ms >= (uint64_t)cfg->duration * 1000)
            break;
    }

    double total_sec = (double)(now_ms() - start_ms) / 1000.0;
    char tb[32], bb[32];
    fmt_bytes(total_bytes, tb, sizeof(tb));
    fmt_bps(total_bytes, total_sec, bb, sizeof(bb));
    if (cfg->json) {
        printf("{\"start\":0,\"end\":%.2f,\"bytes\":%llu,\"bits_per_second\":%.2f}\n",
               total_sec, (unsigned long long)total_bytes,
               total_sec > 0 ? (double)total_bytes * 8.0 / total_sec : 0);
    } else {
        printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
        printf("[SUM]  0.00-%5.2f sec  %s  %s\n", total_sec, tb, bb);
    }

    closesocket(s);
    free(buf);
    return 0;
}

/* ---------------------------------------------------------------------
 * Entry point
 * -------------------------------------------------------------------*/
int iperf_run(const cli_config_t *cfg)
{
    /* Resolve remote host for client mode */
    uint32_t remote_ip = 0;
    if (!cfg->is_server) {
        struct in_addr a;
        if (inet_pton(AF_INET, cfg->host, &a) == 1) {
            remote_ip = a.s_addr;
        } else {
            struct hostent *h = gethostbyname(cfg->host);
            if (!h) {
                fprintf(stderr, "Error: cannot resolve %s\n", cfg->host);
                return 1;
            }
            memcpy(&remote_ip, h->h_addr, 4);
        }
        if (!cfg->json) {
            printf("iperf %s: %s -> %u.%u.%u.%u:%u\n",
                   cfg->proto ? "UDP" : "TCP",
                   cfg->is_server ? "server" : "client",
                   remote_ip&0xFF,(remote_ip>>8)&0xFF,(remote_ip>>16)&0xFF,(remote_ip>>24)&0xFF,
                   cfg->port);
        }
    }

    if (cfg->proto == 0) {
        return cfg->is_server ? tcp_server(cfg) : tcp_client(cfg, remote_ip);
    } else {
        return cfg->is_server ? udp_server(cfg) : udp_client(cfg, remote_ip);
    }
}
