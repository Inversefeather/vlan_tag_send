/*
 * net.h - Core data structures, protocol constants, frame building/parsing
 *
 * This is the foundation layer shared by every other module.
 * It defines the TCB, segment descriptors, packet buffer, and the
 * layered frame construction / dissection primitives (Eth, VLAN, IPv4, TCP, UDP).
 *
 * Design rules (from the architecture spec):
 *   - ALL TCP packets = hand-built frames sent via pcap. No OS TCP stack.
 *   - ALL TCP receive = pcap capture, hand-parsed.
 *   - VLAN tag is a first-class citizen of the frame, not an add-on.
 */
#ifndef NET_H
#define NET_H

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mmsystem.h>
#include <iphlpapi.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#ifdef USE_WINPCAP
typedef unsigned int   u_int;
typedef unsigned short u_short;
typedef unsigned char  u_char;
typedef unsigned long  u_long;
#include <pcap.h>
#endif

/* ---------------------------------------------------------------------
 * Protocol constants
 * -------------------------------------------------------------------*/

#define ETH_ADDR_LEN     6
#define ETH_HDR_LEN      14
#define VLAN_TAG_LEN     4
#define IPV4_HDR_LEN     20
#define TCP_HDR_LEN      20
#define UDP_HDR_LEN      8
#define PSEUDO_HDR_LEN   12

#define ETHERTYPE_VLAN   0x8100
#define ETHERTYPE_IP     0x0800
#define ETHERTYPE_ARP    0x0806
/* IP protocol values for the two TCP modes:
 *   IPPROTO_TCP (6) = real TCP — OS kernel sees it, may RST (needs WinDivert)
 *   IP_PROTO_PRIV (250) = experimental — kernel ignores it, no RST */
#include <ws2tcpip.h>  /* pulls in IPPROTO_TCP (6) */
#define IP_PROTO_PRIV    250
#define IP_PROTOCOL_UDP  17
#define IP_FRAG_DF       0x4000

/* TCP operating mode: real (proto 6) or pseudo (proto 250) */
typedef enum {
    MODE_REAL_TCP = 0,      /* IP proto = 6, kernel may RST, needs WinDivert */
    MODE_PSEUDO_TCP = 1     /* IP proto = 250, kernel ignores, no RST */
} tcp_mode_t;

/* Global mode selector (defined in net.c). Default: MODE_PSEUDO_TCP. */
extern tcp_mode_t g_tcp_mode;

#define VLAN_VID_MASK    0x0FFF
#define VLAN_PCP_SHIFT   13

#define TCP_HDR_WORDS    5
#define TCP_HDR_MIN_LEN  (TCP_HDR_WORDS * 4)

/* TCP flags */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

/* MSS: 1500 - IP(20) - TCP(20) [ - VLAN(4) ] */
#define MSS_DEFAULT       1460
#define MSS_VLAN          1456
#define DEFAULT_SND_WND   65535
#define DEFAULT_RCV_WND   65535
#define TIME_WAIT_MS      2000       /* 2 MSL (conservative for a test tool) */
#define RTO_MIN_MS        200        /* RFC 6298 minimum */
#define RTO_MAX_MS        60000
#define ARP_TIMEOUT_MS    3000
#define MAX_RETRANS       10         /* give up after N retries */
#define SND_QUEUE_SIZE    (4 * 1024 * 1024)   /* 4 MB send buffer */
_Static_assert((SND_QUEUE_SIZE & (SND_QUEUE_SIZE - 1)) == 0,
               "SND_QUEUE_SIZE must be a power of 2");

/* Max frame we will ever build (tagged + headers + MSS) */
#define FRAME_BUF_SIZE    (ETH_HDR_LEN + VLAN_TAG_LEN + IPV4_HDR_LEN + TCP_HDR_LEN + MSS_VLAN + 16)

/* ---------------------------------------------------------------------
 * Sequence number comparisons (handle 32-bit wraparound, RFC 1323 style)
 * -------------------------------------------------------------------*/
#define SEQ_LT(a, b)   ((int32_t)((a) - (b)) < 0)
#define SEQ_LEQ(a, b)  ((int32_t)((a) - (b)) <= 0)
#define SEQ_GT(a, b)   ((int32_t)((a) - (b)) > 0)
#define SEQ_GEQ(a, b)  ((int32_t)((a) - (b)) >= 0)

/* Convenience */
#define MIN(a, b)      ((a) < (b) ? (a) : (b))
#define MAX(a, b)      ((a) > (b) ? (a) : (b))

/* ---------------------------------------------------------------------
 * Frame structures (packed wire format)
 * -------------------------------------------------------------------*/

#pragma pack(push, 1)

typedef struct eth_header_s {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
} eth_header_t;

typedef struct ipv4_header_s {
    uint8_t  ver_ihl;       /* version(4) | ihl(4) */
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} ipv4_header_t;

typedef struct tcp_header_s {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  data_off;      /* high 4 bits = data offset in 32-bit words */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} tcp_header_t;

typedef struct udp_header_s {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
} udp_header_t;

#pragma pack(pop)

/* ---------------------------------------------------------------------
 * TCP states (RFC 793)
 * -------------------------------------------------------------------*/

typedef enum {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
} tcp_state_t;

/* ---------------------------------------------------------------------
 * Segment descriptor (retransmission queue node)
 * -------------------------------------------------------------------*/

typedef struct tcp_seg_s {
    uint32_t   seq;          /* first sequence number of this segment */
    uint32_t   len;          /* payload length (0 for pure SYN/FIN) */
    uint8_t    flags;        /* TCP flags used when sent */
    uint8_t    times_sent;   /* how many times we've transmitted it */
    uint64_t   send_ms;      /* wall-clock time of last transmit (for RTT) */
    uint8_t    payload[];    /* flexible: actual data follows */
} tcp_seg_t;

/* ---------------------------------------------------------------------
 * TCP Control Block (TCB) -- the heart of the stack
 * -------------------------------------------------------------------*/

typedef struct tcb {
    /* 5-tuple */
    uint8_t  local_mac[6];
    uint8_t  remote_mac[6];
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;

    /* VLAN (first-class citizen) */
    uint16_t vlan_id;
    uint8_t  vlan_pcp;

    /* FSM state */
    tcp_state_t state;

    /* Sequence numbers */
    uint32_t snd_una;       /* oldest unacknowledged */
    uint32_t snd_nxt;       /* next to send */
    uint32_t snd_wnd;       /* peer's receive window */
    uint32_t rcv_nxt;       /* next expected from peer */
    uint32_t rcv_wnd;       /* our receive window */
    uint32_t iss;           /* initial send sequence */
    uint32_t irs;           /* initial recv sequence */

    /* RTT / RTO (RFC 6298) */
    uint32_t srtt;          /* smoothed RTT (ms) */
    uint32_t rttvar;        /* RTT variance (ms) */
    uint32_t rto;           /* current retransmission timeout (ms) */
    uint32_t rto_backoff;   /* exponential backoff counter (RFC 2988) */
    int      rtt_pending;   /* waiting for an RTT sample */

    /* Retransmission queue (ordered by seq) */
    tcp_seg_t *retrans_q;
    uint32_t   retrans_count;

    /* Send buffer (ring) */
    uint8_t  *snd_buf;
    uint32_t  snd_head;     /* app writes here */
    uint32_t  snd_tail;     /* stack reads from here */
    uint32_t  snd_cap;

    /* Receive buffer (ring) */
    uint8_t  *rcv_buf;
    uint32_t  rcv_head;     /* stack writes here */
    uint32_t  rcv_tail;     /* app reads from here */
    uint32_t  rcv_cap;

    /* Congestion control (Reno) */
    uint32_t cwnd;
    uint32_t ssthresh;
    uint32_t dupack_count;
    uint32_t recover;       /* Reno fast-recovery seq ceiling */

    /* Timers */
    uint64_t rto_expire;
    uint64_t time_wait_expire;

    /* Flags */
    int      app_closed;    /* application called close */
    int      fin_acked;     /* our FIN has been acked */

    /* Statistics */
    uint64_t bytes_sent;
    uint64_t bytes_acked;
    uint64_t bytes_recv;     /* received data bytes (separate from sent) */
    uint64_t retrans_bytes;

    /* Linked list of all TCBs (for the event loop) */
    struct tcb *next;
} tcb_t;

/* ---------------------------------------------------------------------
 * Parsed frame (result of receive pipeline)
 * -------------------------------------------------------------------*/

typedef struct parsed_tcp_s {
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    int      has_vlan;
    uint16_t vlan_id;           /* VLAN ID (0 if untagged) */
    uint8_t  vlan_pcp;          /* PCP priority (0-7) */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  flags;
    uint16_t window;
    uint8_t  *payload;
    int      payload_len;
} parsed_tcp_t;

/* ---------------------------------------------------------------------
 * Utility (implemented in net.c)
 * -------------------------------------------------------------------*/

uint16_t inet_checksum(const void *data, int len);
uint16_t tcp_udp_checksum(uint32_t src_ip, uint32_t dst_ip,
                          uint8_t protocol, const void *data, int len);

uint32_t alloc_iss(void);

/* Debug: hex dump a buffer to stdout. prefix may be NULL. */
void hex_dump(const uint8_t *data, int len, const char *prefix);

#endif /* NET_H */
