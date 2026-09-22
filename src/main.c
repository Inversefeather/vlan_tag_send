/*
 * main.c - CLI / Parser + event-driven main loop
 *
 * This is the top of the stack:
 *   CLI/Parser -> Flow Engine (event loop) -> TCP FSM / UDP -> Platform (pcap)
 *
 * The main loop is strictly event-driven and non-blocking:
 *   while (!stop) {
 *       now = time_now_ms();
 *       tcp_timer_walk(now);        // RTO + TIME_WAIT
 *       for each TCB: tcp_send_pending(tcb, now);  // pacing
 *       platform_recv_dispatch(...);  // pcap capture -> FSM
 *   }
 *
 * No sleep(1). pcap timeout = 100ms.
 *
 * Features implemented:
 *   - UDP flow engine (client + server)
 *   - TCP parallel streams (-P N, each with independent congestion control)
 *   - TCP/UDP server mode (-s)
 *   - JSON output (-J)
 *   - Optional VLAN (-V, default off)
 */
#include "platform.h"
#include "report.h"
#include <shlwapi.h>  /* StrStrIA */

/* ---------------------------------------------------------------------
 * Config
 * -------------------------------------------------------------------*/
typedef struct {
    int         is_server;
    int         proto;          /* PROTO_TCP or PROTO_UDP */
    int         port;
    char        host[64];
    int         duration;       /* seconds (client) */
    uint64_t    num_bytes;      /* 0 = use duration */
    int         bufsize;
    double      target_bps;     /* 0 = unlimited */
    int         report_interval;
    int         streams;        /* parallel (TCP: N TCBs; UDP: N sockets) */
    uint16_t    vlan_id;
    uint8_t     pcp;
    int         verbose;
    int         silence_timeout;
    int         json;           /* -J */
    uint32_t    bind_ip;        /* 0 = 0.0.0.0 (all interfaces / first adapter) */
    char        bind_name[128]; /* adapter name/description substring match */
} cli_config_t;

static cli_config_t g_cfg;

/* ---------------------------------------------------------------------
 * Forward declarations
 * -------------------------------------------------------------------*/
static double parse_bw(const char *s);
static uint64_t parse_bytes(const char *s);
static int parse_args(int argc, char **argv);
static void usage(const char *p);

#ifdef USE_WINPCAP
static int resolve_arp(uint32_t local_ip, uint32_t remote_ip, uint8_t *peer_mac,
                       const char *host);
static void tcp_client_flow(uint32_t local_ip, uint8_t *local_mac,
                            const char *adapter_name,
                            uint32_t remote_ip, const char *remote_host,
                            cli_config_t *cfg);
static void udp_client_flow(uint32_t local_ip, uint8_t *local_mac,
                            const char *adapter_name,
                            uint32_t remote_ip, cli_config_t *cfg);
static void udp_server_flow(uint32_t bind_ip, const char *adapter_name,
                            uint8_t *local_mac, cli_config_t *cfg);
static void tcp_server_flow(uint32_t bind_ip, const char *adapter_name,
                            uint8_t *local_mac, cli_config_t *cfg);
#endif

/* ---------------------------------------------------------------------
 * CLI
 * -------------------------------------------------------------------*/
static void usage(const char *p)
{
    printf("Raw TCP/UDP bandwidth test with optional VLAN tag\n");
    printf("All traffic = raw Ethernet frames via pcap (no OS TCP stack)\n\n");
    printf("Usage:\n");
    printf("  %s -s [options]                 server\n", p);
    printf("  %s -c <host> [options]          client\n", p);
    printf("\nOptions:\n");
    printf("  -p, --port       #       port (default 9999)\n");
    printf("  -u, --udp                UDP mode (default TCP)\n");
    printf("  -b, --bandwidth #[KMG]   target bits/sec\n");
    printf("  -t, --time       #       duration sec (default 10)\n");
    printf("  -n, --bytes      #[KMG]   bytes to send\n");
    printf("  -l, --len        #       buffer size\n");
    printf("  -i, --interval   #       report interval (default 1)\n");
    printf("  -P, --parallel   #        parallel streams (default 1)\n");
    printf("  -V, --vlan       #        VLAN ID 1-4094 (default off)\n");
    printf("      --pcp        #        PCP 0-7 (default 0)\n");
    printf("  -T, --timeout    #        server silence timeout (default 3)\n");
    printf("  -B, --bind       addr   bind IP or adapter name (default: first NIC)\n");
    printf("  -J, --json               JSON output\n");
    printf("  -v, --verbose            verbose\n\n");
    printf("Examples:\n");
    printf("  %s -s -p 9999                     TCP server\n", p);
    printf("  %s -c 192.168.1.100 -b 100M       TCP client\n", p);
    printf("  %s -c 192.168.1.100 -u -b 1G      UDP client\n", p);
    printf("  %s -c 192.168.1.100 -V 100 -b 1G  VLAN client\n", p);
    printf("  %s -c 192.168.1.100 -P 4 -b 1G    4 parallel streams\n", p);
    printf("  %s -s -P 8                        multi-stream server\n", p);
    printf("  %s -c 192.168.1.100 -J            JSON output\n", p);
}

static double parse_bw(const char *s)
{
    double v; char u[16] = {0};
    if (sscanf(s, "%lf%15s", &v, u) < 1) return 0;
    if (u[0]=='G'||u[0]=='g') return v*1e9;
    if (u[0]=='M'||u[0]=='m') return v*1e6;
    if (u[0]=='K'||u[0]=='k') return v*1e3;
    return v;
}
static uint64_t parse_bytes(const char *s)
{
    double v; char u[16] = {0};
    if (sscanf(s, "%lf%15s", &v, u) < 1) return 0;
    if (u[0]=='G'||u[0]=='g') return (uint64_t)(v*1073741824.0);
    if (u[0]=='M'||u[0]=='m') return (uint64_t)(v*1048576.0);
    if (u[0]=='K'||u[0]=='k') return (uint64_t)(v*1024.0);
    return (uint64_t)v;
}

static int parse_args(int argc, char **argv)
{
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.port = 9999;
    g_cfg.duration = 10;
    g_cfg.report_interval = 1;
    g_cfg.streams = 1;
    g_cfg.silence_timeout = 3;
    g_cfg.proto = 0; /* TCP */
    g_cfg.bufsize = 0;

    for (int i = 1; i < argc; i++) {
        char *a = argv[i];
        if (!strcmp(a,"-h")||!strcmp(a,"--help")) { usage(argv[0]); exit(0); }
        else if (!strcmp(a,"-s")||!strcmp(a,"--server")) g_cfg.is_server = 1;
        else if (!strcmp(a,"-c")||!strcmp(a,"--client")) {
            g_cfg.is_server = 0;
            if (i+1<argc && argv[i+1][0]!='-') strncpy(g_cfg.host, argv[++i], 63);
        }
        else if (!strcmp(a,"-p")||!strcmp(a,"--port")) { if(i+1<argc) g_cfg.port=atoi(argv[++i]); }
        else if (!strcmp(a,"-u")||!strcmp(a,"--udp")) g_cfg.proto = 1;
        else if (!strcmp(a,"-b")||!strcmp(a,"--bandwidth")) { if(i+1<argc) g_cfg.target_bps=parse_bw(argv[++i]); }
        else if (!strcmp(a,"-t")||!strcmp(a,"--time")) { if(i+1<argc) g_cfg.duration=atoi(argv[++i]); }
        else if (!strcmp(a,"-n")||!strcmp(a,"--bytes")) { if(i+1<argc) g_cfg.num_bytes=parse_bytes(argv[++i]); }
        else if (!strcmp(a,"-l")||!strcmp(a,"--len")) { if(i+1<argc) g_cfg.bufsize=atoi(argv[++i]); }
        else if (!strcmp(a,"-i")||!strcmp(a,"--interval")) { if(i+1<argc) g_cfg.report_interval=atoi(argv[++i]); }
        else if (!strcmp(a,"-P")||!strcmp(a,"--parallel")) { if(i+1<argc) g_cfg.streams=atoi(argv[++i]); }
        else if (!strcmp(a,"-V")||!strcmp(a,"--vlan")) { if(i+1<argc){int v=atoi(argv[++i]); if(v>=1&&v<=4094)g_cfg.vlan_id=(uint16_t)v;} }
        else if (!strcmp(a,"--pcp")) { if(i+1<argc) g_cfg.pcp=(uint8_t)(atoi(argv[++i])&7); }
        else if (!strcmp(a,"-T")||!strcmp(a,"--timeout")) { if(i+1<argc) g_cfg.silence_timeout=atoi(argv[++i]); }
        else if (!strcmp(a,"-B")||!strcmp(a,"--bind")) {
            if (i+1<argc) {
                struct in_addr addr;
                if (inet_pton(AF_INET, argv[++i], &addr) == 1)
                    g_cfg.bind_ip = addr.s_addr;
                else {
                    /* not an IP: treat as adapter name/description substring */
                    strncpy(g_cfg.bind_name, argv[i], sizeof(g_cfg.bind_name) - 1);
                }
            }
        }
        else if (!strcmp(a,"-J")||!strcmp(a,"--json")) g_cfg.json = 1;
        else if (!strcmp(a,"-v")||!strcmp(a,"--verbose")) g_cfg.verbose = 1;
        else { fprintf(stderr,"Unknown: %s\n", a); return -1; }
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * ARP resolve helper (opens a temp pcap, sends request, waits for reply)
 * -------------------------------------------------------------------*/
#ifdef USE_WINPCAP
static int resolve_arp(uint32_t local_ip, uint32_t remote_ip, uint8_t *peer_mac,
                       const char *host)
{
    pcap_if_t *alldevs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char dev_name[1024] = {0};
    pcap_t *arp_pcap = NULL;

    printf("Resolving %s via ARP...\n", host);
    if (pcap_findalldevs(&alldevs, errbuf) != -1) {
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            if (d->flags & PCAP_IF_LOOPBACK) continue;
            for (pcap_addr_t *a = d->addresses; a; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    if (((struct sockaddr_in *)a->addr)->sin_addr.s_addr == local_ip) {
                        snprintf(dev_name, sizeof(dev_name), "%s", d->name);
                        break;
                    }
                }
            }
            if (dev_name[0]) break;
        }
        pcap_freealldevs(alldevs);
    }
    if (!dev_name[0]) { fprintf(stderr, "Error: no adapter for ARP\n"); return -1; }

    arp_pcap = pcap_open_live(dev_name, 2048, 1, 100, errbuf);
    if (!arp_pcap) { fprintf(stderr, "Error: %s\n", errbuf); return -1; }

    /* send ARP request */
    uint8_t req[60];
    eth_header_t *eth = (eth_header_t *)req;
    memset(eth->dst, 0xFF, 6);
    uint8_t my_mac[6];
    get_mac_for_ip(local_ip, my_mac);
    memcpy(eth->src, my_mac, 6);
    eth->ethertype = htons(ETHERTYPE_ARP);
    uint8_t *arp = req + ETH_HDR_LEN;
    memset(arp, 0, 28);
    arp[0]=0; arp[1]=1; arp[2]=8; arp[3]=0; arp[4]=6; arp[5]=4; arp[6]=0; arp[7]=1;
    memcpy(arp+8, my_mac, 6);
    memcpy(arp+14, &local_ip, 4);
    memcpy(arp+24, &remote_ip, 4);
    pcap_sendpacket(arp_pcap, req, 60);

    int deadline = GetTickCount() + ARP_TIMEOUT_MS;
    while (!g_stop && (int)(GetTickCount()-deadline) < 0) {
        struct pcap_pkthdr *hdr; const uint8_t *pkt;
        int r = pcap_next_ex(arp_pcap, &hdr, &pkt);
        if (r == 1 && hdr->len >= 42) {
            eth_header_t *re = (eth_header_t *)pkt;
            if (ntohs(re->ethertype) != ETHERTYPE_ARP) continue;
            uint8_t *ra = (uint8_t *)pkt + ETH_HDR_LEN;
            if (ra[6]||ra[7]!=2) continue;
            uint32_t sip; memcpy(&sip, ra+14, 4);
            if (sip != remote_ip) continue;
            memcpy(peer_mac, ra+8, 6);
            printf("ARP: %s -> %02X:%02X:%02X:%02X:%02X:%02X\n", host,
                   peer_mac[0],peer_mac[1],peer_mac[2],peer_mac[3],peer_mac[4],peer_mac[5]);
            break;
        }
    }
    pcap_close(arp_pcap);
    return (memcmp(peer_mac, "\x00\x00\x00\x00\x00\x00", 6) != 0) ? 0 : -1;
}

/* ---------------------------------------------------------------------
 * TCP client flow engine (single stream)
 * -------------------------------------------------------------------*/
static void tcp_client_flow(uint32_t local_ip, uint8_t *local_mac,
                            const char *adapter_name,
                            uint32_t remote_ip, const char *remote_host,
                            cli_config_t *cfg)
{
    uint8_t peer_mac[6] = {0};
    if (resolve_arp(local_ip, remote_ip, peer_mac, remote_host) != 0) {
        fprintf(stderr, "Error: ARP resolve failed for %s\n", remote_host);
        return;
    }

    platform_open_sniffer(local_ip, adapter_name);

    /* auto bufsize: account for VLAN tag */
    if (cfg->bufsize <= 0)
        cfg->bufsize = cfg->vlan_id > 0 ? MSS_VLAN : MSS_DEFAULT;
    if (cfg->bufsize > MSS_DEFAULT) cfg->bufsize = MSS_DEFAULT;

    /* create N parallel TCBs */
    int n = cfg->streams;
    tcb_t **tcbs = (tcb_t **)calloc(n, sizeof(tcb_t *));
    uint64_t *stream_bytes = (uint64_t *)calloc(n, sizeof(uint64_t));
    uint64_t *stream_retrans = (uint64_t *)calloc(n, sizeof(uint64_t));

    for (int i = 0; i < n; i++) {
        uint16_t sport = 49152 + ((uint16_t)(GetCurrentProcessId() & 0x0FFF) + i * 7) % 16384;
        tcbs[i] = tcp_active_open(local_ip, local_mac, remote_ip, peer_mac,
                                   sport, (uint16_t)cfg->port,
                                   cfg->vlan_id, cfg->pcp);
        if (!tcbs[i]) { fprintf(stderr, "Error: tcp_active_open stream %d failed\n", i+1); return; }
    }

    printf("TCP client: %d stream(s) -> %s:%u VLAN=%u buf=%d\n",
           n, remote_host, cfg->port, cfg->vlan_id, cfg->bufsize);

    uint8_t *pattern = (uint8_t *)malloc(cfg->bufsize);
    for (int i = 0; i < cfg->bufsize; i++) pattern[i] = (uint8_t)(i & 0xFF);

    uint64_t start_ms = time_now_ms();
    uint64_t stop_ms = start_ms + (uint64_t)cfg->duration * 1000;
    uint64_t report_ms = start_ms;
    uint64_t interval_total = 0;
    uint64_t prev_total = 0;

    if (!cfg->json) report_print_header();

    while (!g_stop) {
        uint64_t now = time_now_ms();

        if (cfg->num_bytes > 0) {
            uint64_t total = 0;
            for (int i = 0; i < n; i++) total += stream_bytes[i];
            if (total >= cfg->num_bytes) break;
        } else if (now >= stop_ms) {
            break;
        }

        tcp_timer_walk(now);

        /* pump each stream */
        for (int i = 0; i < n; i++) {
            if (!tcbs[i] || tcbs[i]->state < TCP_SYN_SENT) continue;

            if (tcbs[i]->state == TCP_ESTABLISHED) {
                tcp_app_write(tcbs[i], pattern, cfg->bufsize);

                if (cfg->target_bps > 0) {
                    double per_stream_bps = cfg->target_bps / n;
                    double should = (double)(now - start_ms) / 1000.0 * (per_stream_bps / 8.0);
                    if ((double)stream_bytes[i] < should) {
                        tcp_send_pending(tcbs[i], now);
                        if (tcp_snd_buf_empty(tcbs[i]))
                            tcp_app_write(tcbs[i], pattern, cfg->bufsize);
                    }
                    /* yield to RX. If far behind schedule, skip the thread-yield:
                     * the outer loop's blocking platform_recv_dispatch will pace us. */
                    platform_recv_dispatch(NULL, NULL);
                    if ((double)stream_bytes[i] < should * 0.95) {  /* >5% behind: yield */
                        SwitchToThread();  /* burst but yield CPU */
                        continue;
                    }
                    /* caught up: no yield, keep pumping */
                } else {
                    tcp_send_pending(tcbs[i], now);
                }
            }

            stream_bytes[i] = tcbs[i]->bytes_acked;
            stream_retrans[i] = tcbs[i]->retrans_bytes;

            /* close when done */
            if (tcbs[i]->state == TCP_ESTABLISHED && cfg->num_bytes > 0) {
                uint64_t per_stream = cfg->num_bytes / n;
                if (stream_bytes[i] >= per_stream)
                    tcp_app_close(tcbs[i]);
            }
        }

        platform_recv_dispatch(NULL, NULL);

        /* interval report */
        if (now - report_ms >= (uint64_t)cfg->report_interval * 1000) {
            uint64_t total = 0;
            for (int i = 0; i < n; i++) total += stream_bytes[i];
            interval_total = total - prev_total;
            prev_total = total;

            if (!cfg->json) {
                if (n == 1) {
                    double start_s = (double)(report_ms - start_ms) / 1000.0;
                    double intv_s = (double)(now - report_ms) / 1000.0;
                    report_print_interval(1, start_s, intv_s, interval_total);
                } else {
                    /* per-stream + SUM */
                    for (int i = 0; i < n; i++) {
                        double start_s = (double)(report_ms - start_ms) / 1000.0;
                        double intv_s = (double)(now - report_ms) / 1000.0;
                        report_print_interval(i+1, start_s, intv_s, stream_bytes[i]);
                    }
                    printf("[SUM] %5.2f-%5.2f sec  %llu bytes  (%.2f Mbits/sec)\n",
                           0.0, (double)(now - start_ms) / 1000.0,
                           (unsigned long long)interval_total,
                           (double)interval_total * 8.0 / ((now - report_ms) * 1000.0));
                }
            }
            report_ms = now;
        }
    }

    /* final summary */
    double total_sec = (double)(time_now_ms() - start_ms) / 1000.0;
    uint64_t total_bytes = 0;
    for (int i = 0; i < n; i++) total_bytes += stream_bytes[i];

    if (cfg->json) {
        report_json_start();
        for (int i = 0; i < n; i++) {
            if (i > 0) report_json_stream_sep();
            report_print_json(i+1, total_sec, stream_bytes[i], 1, stream_retrans[i]);
        }
        report_json_end();
    } else {
        printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
        for (int i = 0; i < n; i++) {
            report_print_summary(i+1, total_sec, stream_bytes[i], 1);
        }
        if (n > 1) {
            printf("[SUM]  0.00-%5.2f sec  %llu bytes  %.2f Mbits/sec\n",
                   total_sec, (unsigned long long)total_bytes,
                   total_sec > 0 ? (double)total_bytes * 8.0 / total_sec / 1e6 : 0);
        }
    }

    free(pattern);
    free(tcbs);
    free(stream_bytes);
    free(stream_retrans);
}

/* ---------------------------------------------------------------------
 * UDP client flow engine
 * -------------------------------------------------------------------*/
typedef struct {
    uint64_t total_bytes;
    uint64_t interval_bytes;
    uint64_t packets;
    uint64_t start_ms;
    uint64_t report_ms;
    uint16_t vlan_id;
} udp_stats_t;

static void udp_client_flow(uint32_t local_ip, uint8_t *local_mac,
                            const char *adapter_name,
                            uint32_t remote_ip, cli_config_t *cfg)
{
    uint8_t peer_mac[6] = {0};
    if (resolve_arp(local_ip, remote_ip, peer_mac, cfg->host) != 0) {
        fprintf(stderr, "Error: ARP resolve failed\n");
        return;
    }

    platform_open_sniffer(local_ip, adapter_name);

    int bufsize = cfg->bufsize > 0 ? cfg->bufsize : (cfg->vlan_id > 0 ? MSS_VLAN : MSS_DEFAULT);
    if (bufsize > MSS_DEFAULT) bufsize = MSS_DEFAULT;

    uint8_t *pattern = (uint8_t *)malloc(bufsize);
    for (int i = 0; i < bufsize; i++) pattern[i] = (uint8_t)(i & 0xFF);

    udp_stats_t st = {0};
    st.start_ms = st.report_ms = time_now_ms();
    uint64_t stop_ms = st.start_ms + (uint64_t)cfg->duration * 1000;

    printf("UDP client: -> %s:%u VLAN=%u buf=%d\n", cfg->host, cfg->port, cfg->vlan_id, bufsize);

    if (!cfg->json) report_print_header();

    uint16_t sport = 49152 + (uint16_t)(GetCurrentProcessId() & 0x3FFF);

    while (!g_stop) {
        uint64_t now = time_now_ms();
        if (now >= stop_ms) break;

        /* send a datagram */
        raw_send_udp(local_ip, local_mac, remote_ip, peer_mac,
                     sport, (uint16_t)cfg->port, pattern, bufsize,
                     cfg->vlan_id, cfg->pcp);
        st.total_bytes += bufsize;
        st.interval_bytes += bufsize;
        st.packets++;

        /* pacing: send a bounded batch to catch up, then yield to RX */
        if (cfg->target_bps > 0) {
            double should = (double)(now - st.start_ms) / 1000.0 * (cfg->target_bps / 8.0);
            /* send at most 64 datagrams per iteration (bounded batch) */
            for (int burst = 0; burst < 64 && (double)st.total_bytes < should; burst++) {
                if (g_stop || now >= stop_ms) break;
                raw_send_udp(local_ip, local_mac, remote_ip, peer_mac,
                             sport, (uint16_t)cfg->port, pattern, bufsize,
                             cfg->vlan_id, cfg->pcp);
                st.total_bytes += bufsize;
                st.interval_bytes += bufsize;
                st.packets++;
            }
        }

        /* capture (drain any replies) */
        platform_recv_dispatch(NULL, NULL);

        /* interval report */
        if (now - st.report_ms >= (uint64_t)cfg->report_interval * 1000) {
            double start_s = (double)(st.report_ms - st.start_ms) / 1000.0;
            double intv_s = (double)(now - st.report_ms) / 1000.0;
            if (!cfg->json)
                report_print_interval(1, start_s, intv_s, st.interval_bytes);
            st.interval_bytes = 0;
            st.report_ms = now;
        }
    }

    double total_sec = (double)(time_now_ms() - st.start_ms) / 1000.0;
    if (cfg->json) {
        report_json_start();
        report_print_json(1, total_sec, st.total_bytes, 1, 0);
        report_json_end();
    } else {
        printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
        report_print_summary(1, total_sec, st.total_bytes, 1);
        printf("UDP: %llu packets sent\n", (unsigned long long)st.packets);
    }
    free(pattern);
}

/* ---------------------------------------------------------------------
 * UDP server flow engine (sniff & count)
 * -------------------------------------------------------------------*/
static void udp_rx_callback(const uint8_t *pkt, int len, void *ctx)
{
    (void)pkt;
    udp_stats_t *st = (udp_stats_t *)ctx;
    /* rough: count bytes from UDP payload */
    if (len > ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN) {
        int udp_payload = len - ETH_HDR_LEN - IPV4_HDR_LEN - UDP_HDR_LEN;
        if (st->vlan_id) udp_payload -= VLAN_TAG_LEN;
        st->total_bytes += udp_payload;
        st->interval_bytes += udp_payload;
        st->packets++;
    }
}

static void udp_server_flow(uint32_t bind_ip, const char *adapter_name,
                            uint8_t *local_mac, cli_config_t *cfg)
{
    (void)local_mac;
    /* open sniffer on the adapter owning bind_ip (0 = first non-loopback) */
    platform_open_sniffer(bind_ip, adapter_name);

    udp_stats_t st = {0};
    st.vlan_id = cfg->vlan_id;
    st.start_ms = st.report_ms = time_now_ms();

    printf("UDP server: port=%u VLAN=%u bind=%s (sniffing...)\n",
           cfg->port, cfg->vlan_id,
           bind_ip ? "specific" : "0.0.0.0");
    if (!cfg->json) report_print_header();

    int silence_ms = cfg->silence_timeout * 1000;
    uint64_t last_data = st.start_ms;

    while (!g_stop) {
        uint64_t now = time_now_ms();
        int r = platform_recv_dispatch(udp_rx_callback, &st);
        if (r > 0) last_data = now;

        /* silence timeout */
        if (now - last_data >= (uint64_t)silence_ms && st.packets > 0) {
            printf("\nNo data for %d sec, stopping.\n", cfg->silence_timeout);
            break;
        }

        /* interval report */
        if (now - st.report_ms >= (uint64_t)cfg->report_interval * 1000 && st.interval_bytes > 0) {
            double start_s = (double)(st.report_ms - st.start_ms) / 1000.0;
            double intv_s = (double)(now - st.report_ms) / 1000.0;
            if (!cfg->json)
                report_print_interval(1, start_s, intv_s, st.interval_bytes);
            st.interval_bytes = 0;
            st.report_ms = now;
        }
    }

    double total_sec = (double)(time_now_ms() - st.start_ms) / 1000.0;
    if (cfg->json) {
        report_json_start();
        report_print_json(1, total_sec, st.total_bytes, 0, 0);
        report_json_end();
    } else {
        printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
        report_print_summary(1, total_sec, st.total_bytes, 0);
        printf("UDP: %llu packets received\n", (unsigned long long)st.packets);
    }
}

/* ---------------------------------------------------------------------
 * TCP server flow engine (listen + accept + drain)
 * -------------------------------------------------------------------*/
static void tcp_server_flow(uint32_t bind_ip, const char *adapter_name,
                            uint8_t *local_mac, cli_config_t *cfg)
{
    /* open sniffer on the adapter owning bind_ip (0 = first non-loopback) */
    platform_open_sniffer(bind_ip, adapter_name);

    /*
     * create a listening TCB with local_ip = 0 (wildcard).
     * The listener accepts SYN destined to ANY IP on this adapter.
     * The child TCB created on accept gets the real dst_ip from the SYN.
     */
    tcb_t *listener = tcp_passive_open(0, local_mac, (uint16_t)cfg->port,
                                        cfg->vlan_id, cfg->pcp);
    if (!listener) { fprintf(stderr, "Error: tcp_passive_open failed\n"); return; }

    printf("TCP server: port=%u VLAN=%u bind=%s (listening...)\n",
           cfg->port, cfg->vlan_id,
           bind_ip ? "specific" : "0.0.0.0");

    uint64_t start_ms = time_now_ms();
    uint64_t report_ms = start_ms;
    uint64_t total_bytes = 0;          /* monotonic: only grows, survives TCB free */
    uint64_t prev_sum = 0;             /* last seen sum of live TCBs' bytes_recv */
    uint64_t last_interval_total = 0;  /* total_bytes at last report */
    int established = 0;

    if (!cfg->json) report_print_header();

    while (!g_stop) {
        uint64_t now = time_now_ms();
        tcp_timer_walk(now);

        /* check if listener got a connection */
        if (listener->state == TCP_SYN_RECEIVED || listener->state == TCP_ESTABLISHED) {
            established = 1;
        }

        /* capture & dispatch */
        platform_recv_dispatch(NULL, NULL);

        /* sum bytes_recv from currently-live TCBs.
         * When a TCB is freed (TIME_WAIT), its bytes_recv disappears from this sum.
         * To keep total_bytes monotonic, only add the positive delta. */
        uint64_t current_sum = 0;
        for (tcb_t *t = tcb_list_head(); t; t = t->next) {
            if (t == listener) continue;
            if (t->state >= TCP_ESTABLISHED) current_sum += t->bytes_recv;
        }
        if (current_sum > prev_sum) {
            total_bytes += (current_sum - prev_sum);
        }
        prev_sum = current_sum;

        /* interval report */
        if (established && now - report_ms >= (uint64_t)cfg->report_interval * 1000) {
            uint64_t interval_bytes = total_bytes - last_interval_total;
            last_interval_total = total_bytes;
            double start_s = (double)(report_ms - start_ms) / 1000.0;
            double intv_s = (double)(now - report_ms) / 1000.0;
            if (!cfg->json)
                report_print_interval(1, start_s, intv_s, interval_bytes);
            report_ms = now;
        }
    }

    double total_sec = (double)(time_now_ms() - start_ms) / 1000.0;
    if (cfg->json) {
        report_json_start();
        report_print_json(1, total_sec, total_bytes, 0, 0);
        report_json_end();
    } else {
        printf("\n- - - - - - - - - - - - - - - - - - - - - - - - -\n");
        report_print_summary(1, total_sec, total_bytes, 0);
    }
}
#endif /* USE_WINPCAP */

/* ---------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------*/
int main(int argc, char **argv)
{
    if (platform_init() != 0) return 1;
    if (parse_args(argc, argv) != 0) { usage(argv[0]); platform_cleanup(); return 1; }

    if (!g_cfg.is_server && g_cfg.host[0] == '\0') {
        fprintf(stderr, "Error: client needs -c <host>\n");
        usage(argv[0]); platform_cleanup(); return 1;
    }

    platform_set_timer_resolution();
    platform_install_ctrl_handler();

    /* determine local IP / MAC: by IP, by name substring, or default */
    uint32_t local_ip = 0;
    uint8_t local_mac[6] = {0};
    adapter_info_t adapters[32];
    int n = platform_enum_adapters(adapters, 32);

    if (g_cfg.bind_ip != 0) {
        /* match by IP address */
        for (int i = 0; i < n; i++) {
            if (adapters[i].ip == g_cfg.bind_ip) {
                local_ip = adapters[i].ip;
                memcpy(local_mac, adapters[i].mac, 6);
                break;
            }
        }
        if (!local_ip) {
            fprintf(stderr, "Error: no adapter with IP %u.%u.%u.%u\n",
                    g_cfg.bind_ip&0xFF,(g_cfg.bind_ip>>8)&0xFF,
                    (g_cfg.bind_ip>>16)&0xFF,(g_cfg.bind_ip>>24)&0xFF);
            platform_cleanup(); return 1;
        }
    } else if (g_cfg.bind_name[0] != '\0') {
        /* match by adapter name/description substring (case-insensitive) */
        for (int i = 0; i < n; i++) {
            if (adapters[i].is_loopback) continue;
            /* check desc first, then name */
            if (StrStrIA(adapters[i].desc, g_cfg.bind_name) ||
                StrStrIA(adapters[i].name, g_cfg.bind_name)) {
                local_ip = adapters[i].ip;
                memcpy(local_mac, adapters[i].mac, 6);
                break;
            }
        }
        if (!local_ip) {
            fprintf(stderr, "Error: no adapter matching '%s'\n", g_cfg.bind_name);
            platform_cleanup(); return 1;
        }
    } else {
        /* default: first non-loopback adapter */
        for (int i = 0; i < n; i++) {
            if (!adapters[i].is_loopback && adapters[i].ip) {
                local_ip = adapters[i].ip;
                memcpy(local_mac, adapters[i].mac, 6);
                break;
            }
        }
        if (!local_ip) {
            fprintf(stderr, "Error: no suitable adapter\n");
            platform_cleanup(); return 1;
        }
    }

    /* get the pcap device name for the selected adapter (reliable matching) */
    char adapter_name[1024] = {0};
    get_adapter_name_by_ip(local_ip, adapter_name, sizeof(adapter_name));

    printf("Bind: %u.%u.%u.%u  MAC=%02X:%02X:%02X:%02X:%02X:%02X  VLAN=%u\n",
           local_ip&0xFF,(local_ip>>8)&0xFF,(local_ip>>16)&0xFF,(local_ip>>24)&0xFF,
           local_mac[0],local_mac[1],local_mac[2],local_mac[3],local_mac[4],local_mac[5],
           g_cfg.vlan_id);

    /* show available adapters */
    {
        adapter_info_t list[32];
        int cnt = platform_enum_adapters(list, 32);
        printf("Available adapters:\n");
        for (int i = 0; i < cnt; i++) {
            printf("  [%d] %s  %u.%u.%u.%u  %02X:%02X:%02X:%02X:%02X:%02X  %s\n", i,
                   list[i].desc,
                   list[i].ip&0xFF,(list[i].ip>>8)&0xFF,(list[i].ip>>16)&0xFF,(list[i].ip>>24)&0xFF,
                   list[i].mac[0],list[i].mac[1],list[i].mac[2],list[i].mac[3],list[i].mac[4],list[i].mac[5],
                   list[i].is_loopback ? "(loopback)" : "");
        }
    }

#ifdef USE_WINPCAP
    if (g_cfg.proto == 0) {
        /* TCP mode */
        uint32_t remote_ip;
        if (!g_cfg.is_server) {
            if (inet_pton(AF_INET, g_cfg.host, &remote_ip) != 1) {
                struct hostent *h = gethostbyname(g_cfg.host);
                if (!h) { fprintf(stderr,"Error: cannot resolve %s\n", g_cfg.host); return 1; }
                memcpy(&remote_ip, h->h_addr, 4);
            }
            tcp_client_flow(local_ip, local_mac, adapter_name, remote_ip, g_cfg.host, &g_cfg);
        } else {
            tcp_server_flow(g_cfg.bind_ip, adapter_name, local_mac, &g_cfg);
        }
    } else {
        /* UDP mode */
        if (!g_cfg.is_server) {
            uint32_t remote_ip;
            if (inet_pton(AF_INET, g_cfg.host, &remote_ip) != 1) {
                struct hostent *h = gethostbyname(g_cfg.host);
                if (!h) { fprintf(stderr,"Error: cannot resolve %s\n", g_cfg.host); return 1; }
                memcpy(&remote_ip, h->h_addr, 4);
            }
            udp_client_flow(local_ip, local_mac, adapter_name, remote_ip, &g_cfg);
        } else {
            udp_server_flow(g_cfg.bind_ip, adapter_name, local_mac, &g_cfg);
        }
    }
#else
    fprintf(stderr, "Error: this build needs -DUSE_WINPCAP to run\n");
#endif

    platform_restore_timer_resolution();
    platform_cleanup();
    return 0;
}
