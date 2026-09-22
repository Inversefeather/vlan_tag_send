/*
 * tcp_fsm.c - TCP Finite State Machine (RFC 793 + RFC 1122)
 *
 * Strict state transitions driven by the receive pipeline.
 * The TCB list is a linked list; lookup is linear on the 5-tuple + VLAN.
 *
 * Send path: app_write() -> snd_buf -> tcp_send_pending() segments by MSS,
 * fills TCP header, hands frame to platform layer. ACK processing updates
 * snd_una, RTT estimate (RFC 6298), and congestion window (Reno).
 */
#include "tcp_fsm.h"
#include "platform.h"

/* platform send (defined in platform.c) */
extern int raw_send_segment(const tcb_t *tcb, const uint8_t *tcp_payload,
                            int payload_len, uint8_t flags);
extern int g_platform_verbose;
extern const char *fmt_ip(uint32_t ip);

static const char *tcp_state_name(tcp_state_t s)
{
    switch (s) {
    case TCP_CLOSED:       return "CLOSED";
    case TCP_LISTEN:       return "LISTEN";
    case TCP_SYN_SENT:     return "SYN_SENT";
    case TCP_SYN_RECEIVED: return "SYN_RECEIVED";
    case TCP_ESTABLISHED:  return "ESTABLISHED";
    case TCP_FIN_WAIT_1:   return "FIN_WAIT_1";
    case TCP_FIN_WAIT_2:   return "FIN_WAIT_2";
    case TCP_CLOSE_WAIT:   return "CLOSE_WAIT";
    case TCP_CLOSING:      return "CLOSING";
    case TCP_LAST_ACK:     return "LAST_ACK";
    case TCP_TIME_WAIT:    return "TIME_WAIT";
    }
    return "?";
}

/* ---------------------------------------------------------------------
 * Fast recovery state
 * -------------------------------------------------------------------*/
#define RECOVER_ACTIVE(t) ((t)->recover != 0)
#define RECOVER_ENTER(t)  ((t)->recover = (t)->snd_nxt)
#define RECOVER_EXIT(t)   ((t)->recover = 0)

/* ---------------------------------------------------------------------
 * TCB list
 * -------------------------------------------------------------------*/
static tcb_t *g_tcb_list = NULL;
tcb_t *tcb_list_head(void) { return g_tcb_list; }

/* ---------------------------------------------------------------------
 * Allocation / free
 * -------------------------------------------------------------------*/
static uint16_t g_next_port = 49152;

tcb_t *tcb_alloc(void)
{
    tcb_t *t = (tcb_t *)calloc(1, sizeof(tcb_t));
    if (!t) return NULL;
    t->snd_cap = SND_QUEUE_SIZE;
    t->snd_buf = (uint8_t *)malloc(t->snd_cap);
    t->rcv_cap = DEFAULT_RCV_WND;      /* match rcv_wnd exactly */
    t->rcv_buf = (uint8_t *)malloc(t->rcv_cap);
    if (!t->snd_buf || !t->rcv_buf) {
        free(t->snd_buf); free(t->rcv_buf); free(t); return NULL;
    }
    t->state    = TCP_CLOSED;
    t->snd_wnd  = DEFAULT_SND_WND;
    t->rcv_wnd  = DEFAULT_RCV_WND;
    t->cwnd     = 2 * MSS_DEFAULT;
    t->ssthresh = 0xFFFFFFFF;
    t->rto          = 1000;
    t->rto_backoff  = 0;
    t->local_port   = g_next_port++;
    RECOVER_EXIT(t);
    return t;
}

void tcb_free(tcb_t *t)
{
    if (!t) return;
    tcp_seg_t *s = t->retrans_q;
    while (s) {
        tcp_seg_t *next = *(tcp_seg_t **)(s->payload + s->len);
        free(s);
        s = next;
    }
    free(t->snd_buf); free(t->rcv_buf); free(t);
}

static void tcb_unlink(tcb_t *t)
{
    tcb_t **pp = &g_tcb_list;
    while (*pp) {
        if (*pp == t) { *pp = t->next; t->next = NULL; return; }
        pp = &(*pp)->next;
    }
}

/* ---------------------------------------------------------------------
 * Lookup (5-tuple + VLAN). reverse swaps src<->dst.
 * -------------------------------------------------------------------*/
tcb_t *tcb_lookup(uint32_t src_ip, uint32_t dst_ip,
                  uint16_t sport, uint16_t dport,
                  uint16_t vlan_id, int reverse)
{
    for (tcb_t *t = g_tcb_list; t; t = t->next) {
        /* VLAN is always part of the key: different VLAN = different TCB */
        if (t->vlan_id != vlan_id) continue;
        if (reverse) {
            if (t->local_ip == src_ip && t->remote_ip == dst_ip &&
                t->local_port == sport && t->remote_port == dport)
                return t;
        } else {
            /* local_ip == 0 means wildcard (listen on any IP) */
            if (t->remote_ip == src_ip &&
                (t->local_ip == 0 || t->local_ip == dst_ip) &&
                t->remote_port == sport && t->local_port == dport)
                return t;
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------------
 * Open
 * -------------------------------------------------------------------*/
tcb_t *tcp_active_open(uint32_t local_ip, const uint8_t *local_mac,
                       uint32_t remote_ip, const uint8_t *remote_mac,
                       uint16_t local_port, uint16_t remote_port,
                       uint16_t vlan_id, uint8_t vlan_pcp)
{
    tcb_t *t = tcb_alloc();
    if (!t) return NULL;
    memcpy(t->local_mac, local_mac, 6);
    memcpy(t->remote_mac, remote_mac, 6);
    t->local_ip    = local_ip;
    t->remote_ip   = remote_ip;
    t->local_port  = local_port;
    t->remote_port = remote_port;
    t->vlan_id     = vlan_id;
    t->vlan_pcp    = vlan_pcp;
    t->iss         = alloc_iss();
    t->snd_una     = t->iss;
    t->snd_nxt     = t->iss;
    t->state       = TCP_SYN_SENT;

    raw_send_segment(t, NULL, 0, TCP_SYN);
    t->snd_nxt    = t->iss + 1;
    t->rto_expire  = time_now_ms() + t->rto;
    t->rtt_pending = 1;

    t->next = g_tcb_list; g_tcb_list = t;
    return t;
}

tcb_t *tcp_passive_open(uint32_t local_ip, const uint8_t *local_mac,
                        uint16_t local_port, uint16_t vlan_id, uint8_t vlan_pcp)
{
    tcb_t *t = tcb_alloc();
    if (!t) return NULL;
    memcpy(t->local_mac, local_mac, 6);
    t->local_ip   = local_ip;
    t->local_port = local_port;
    t->vlan_id    = vlan_id;
    t->vlan_pcp   = vlan_pcp;
    t->state      = TCP_LISTEN;
    t->iss        = alloc_iss();
    t->next = g_tcb_list; g_tcb_list = t;
    return t;
}

/* ---------------------------------------------------------------------
 * Send bare control segment
 * -------------------------------------------------------------------*/
static void send_flags(tcb_t *t, uint8_t flags)
{
    raw_send_segment(t, NULL, 0, flags);
}
static void send_ack(tcb_t *t) { send_flags(t, TCP_ACK); }

/* ---------------------------------------------------------------------
 * RFC 6298 RTT update
 * -------------------------------------------------------------------*/
static void update_rtt(tcb_t *t, uint32_t rtt_ms)
{
    if (t->srtt == 0) {
        t->srtt   = rtt_ms;
        t->rttvar = rtt_ms / 2;
    } else {
        int32_t delta = (int32_t)(rtt_ms - t->srtt);
        if (delta < 0) delta = -delta;
        t->rttvar = (3 * t->rttvar + delta) / 4;
        t->srtt   = (7 * t->srtt + rtt_ms) / 8;
    }
    t->rto = t->srtt + MAX(10, 4 * t->rttvar);
    if (t->rto < RTO_MIN_MS) t->rto = RTO_MIN_MS;
    if (t->rto > RTO_MAX_MS) t->rto = RTO_MAX_MS;
    t->rto_backoff = 0;  /* RTT sample OK → path healthy, reset backoff */
    t->rtt_pending = 0;
}

/* ---------------------------------------------------------------------
 * Reno congestion control
 * -------------------------------------------------------------------*/
static void reno_newack(tcb_t *t, uint32_t acked_bytes)
{
    (void)acked_bytes;
    if (t->cwnd < t->ssthresh) {
        t->cwnd += MSS_DEFAULT;
        if (t->cwnd > t->ssthresh) t->cwnd = t->ssthresh;
    } else {
        t->cwnd += MSS_DEFAULT * MSS_DEFAULT / t->cwnd;
    }
    t->dupack_count = 0;
}

static void reno_fast_retransmit(tcb_t *t, uint64_t now_ms)
{
    t->ssthresh = MAX(t->cwnd / 2, 2 * MSS_DEFAULT);
    t->cwnd = t->ssthresh + 3 * MSS_DEFAULT;
    RECOVER_ENTER(t);
    tcp_timeout_retransmit(t, now_ms);
}

static void reno_timeout(tcb_t *t)
{
    t->ssthresh = MAX(t->cwnd / 2, 2 * MSS_DEFAULT);
    t->cwnd = MSS_DEFAULT;
    t->dupack_count = 0;
}

/* ---------------------------------------------------------------------
 * Send buffer helpers
 * -------------------------------------------------------------------*/
static uint32_t snd_mask(tcb_t *t) { return t->snd_cap - 1; }
static uint32_t snd_buffered(tcb_t *t) { return (t->snd_head - t->snd_tail) & snd_mask(t); }
static uint32_t snd_space(tcb_t *t) { return t->snd_cap - 1 - snd_buffered(t); }

int tcp_snd_buf_empty(tcb_t *t) { return t->snd_head == t->snd_tail; }

int tcp_app_write(tcb_t *t, const uint8_t *buf, int len)
{
    if (t->state != TCP_ESTABLISHED && t->state != TCP_CLOSE_WAIT)
        return -1;
    uint32_t space = snd_space(t);
    if (len > (int)space) len = (int)space;
    for (int i = 0; i < len; i++) {
        t->snd_buf[t->snd_head] = buf[i];
        t->snd_head = (t->snd_head + 1) & snd_mask(t);
    }
    return len;
}

/* ---------------------------------------------------------------------
 * Retransmission queue: embedded next pointer at payload[len]
 * -------------------------------------------------------------------*/
static tcp_seg_t **seg_next_ptr(tcp_seg_t *s)
{
    return (tcp_seg_t **)(s->payload + s->len);
}

/* ---------------------------------------------------------------------
 * tcp_send_pending: drain snd_buf into segments within cwnd & peer wnd
 * -------------------------------------------------------------------*/
void tcp_send_pending(tcb_t *t, uint64_t now_ms)
{
    if (t->state < TCP_ESTABLISHED) return;

    for (;;) {
        uint32_t flight = t->snd_nxt - t->snd_una;
        uint32_t win = MIN(t->cwnd, t->snd_wnd);
        if (flight >= win) break;

        uint32_t can_send = win - flight;
        uint32_t queued = snd_buffered(t);
        if (queued == 0) break;
        uint32_t want = MIN(MIN(can_send, queued), MSS_DEFAULT);
        if (want == 0) break;

        tcp_seg_t *seg = (tcp_seg_t *)malloc(sizeof(tcp_seg_t) + want + sizeof(tcp_seg_t *));
        if (!seg) break;
        seg->seq        = t->snd_nxt;
        seg->len        = want;
        seg->flags      = TCP_PSH | TCP_ACK;
        seg->times_sent = 1;
        seg->send_ms    = now_ms;
        *seg_next_ptr(seg) = NULL;

        for (uint32_t i = 0; i < want; i++) {
            seg->payload[i] = t->snd_buf[t->snd_tail];
            t->snd_tail = (t->snd_tail + 1) & snd_mask(t);
        }

        /* append to retransmission queue tail */
        tcp_seg_t **pp = &t->retrans_q;
        while (*pp) pp = seg_next_ptr(*pp);
        *pp = seg;

        raw_send_segment(t, seg->payload, (int)want, TCP_PSH | TCP_ACK);
        t->snd_nxt    += want;
        t->bytes_sent += want;
        t->rto_expire  = now_ms + t->rto;
        t->rtt_pending = 1;
    }

    /* teardown: app closed, all data drained & acked -> send FIN (once).
     * retrans_q == NULL guarantees every sent segment has been ACK'd
     * ( snd_una == snd_nxt alone can race with in-flight ACKs ). */
    if (t->app_closed && snd_buffered(t) == 0 &&
        t->snd_una == t->snd_nxt &&
        t->retrans_q == NULL &&
        (t->state == TCP_ESTABLISHED || t->state == TCP_CLOSE_WAIT)) {
        if (t->state != TCP_FIN_WAIT_1 && t->state != TCP_FIN_WAIT_2 &&
            t->state != TCP_CLOSING && t->state != TCP_LAST_ACK) {
            send_flags(t, TCP_FIN | TCP_ACK);
            t->snd_nxt   += 1;
            RECOVER_ENTER(t);  /* FIN consumes a seq# — keep recover in sync */
            t->state      = (t->state == TCP_CLOSE_WAIT) ? TCP_LAST_ACK : TCP_FIN_WAIT_1;
            t->rto_expire = time_now_ms() + t->rto;
        }
    }
}

void tcp_app_close(tcb_t *t) { t->app_closed = 1; }

/* ---------------------------------------------------------------------
 * Retransmission
 * -------------------------------------------------------------------*/
void tcp_timeout_retransmit(tcb_t *t, uint64_t now_ms)
{
    if (!t->retrans_q) return;

    /* RFC 5681 §3.2: RTO MUST exit Fast Recovery unconditionally.
     * Any RTO means the network is congested enough that even the
     * retransmit timer fired — fast recovery is no longer valid.
     * Reset cwnd to 1 MSS and clear the recovery state. */
    if (RECOVER_ACTIVE(t)) {
        RECOVER_EXIT(t);
        t->dupack_count = 0;
    }
    reno_timeout(t);

    tcp_seg_t *seg = t->retrans_q;

    /* RFC 2988 §5.5: RTO = min(RTO * 2, RTO_MAX) per retransmission */
    uint32_t prev_rto = t->rto;
    if (prev_rto < RTO_MIN_MS) prev_rto = RTO_MIN_MS;
    t->rto = prev_rto << 1;
    if (t->rto > RTO_MAX_MS) t->rto = RTO_MAX_MS;
    if (t->rto_backoff < 12) t->rto_backoff++;

    raw_send_segment(t, seg->payload, (int)seg->len, seg->flags);
    t->retrans_bytes += seg->len;
    t->retrans_count++;
    seg->times_sent++;
    seg->send_ms = now_ms;
    t->rto_expire = now_ms + t->rto;
}

/* ---------------------------------------------------------------------
 * Timer walk
 * -------------------------------------------------------------------*/
void tcp_timer_walk(uint64_t now_ms)
{
    for (tcb_t *t = g_tcb_list; t; ) {
        tcb_t *next = t->next;

        if (t->state == TCP_TIME_WAIT && now_ms >= t->time_wait_expire) {
            tcb_unlink(t); tcb_free(t); t = next; continue;
        }
        if (t->state >= TCP_SYN_SENT && now_ms >= t->rto_expire) {
            if (t->retrans_count >= MAX_RETRANS) {
                tcb_unlink(t); tcb_free(t); t = next; continue;
            }
            tcp_timeout_retransmit(t, now_ms);
        }
        t = next;
    }
}

/* ---------------------------------------------------------------------
 * FSM input -- dispatch a parsed segment
 * -------------------------------------------------------------------*/
static void emit_rst(const parsed_tcp_t *pkt, const uint8_t *src_mac, uint32_t ack_seq)
{
    tcb_t rst;
    memset(&rst, 0, sizeof(rst));
    rst.local_ip    = pkt->dst_ip;
    rst.remote_ip   = pkt->src_ip;
    rst.local_port  = pkt->dport;
    rst.remote_port = pkt->sport;
    rst.vlan_id     = pkt->vlan_id;
    rst.snd_nxt     = ack_seq;
    rst.rcv_wnd     = DEFAULT_RCV_WND;  /* RST should advertise full window */
    memcpy(rst.local_mac, pkt->dst_mac, 6);
    memcpy(rst.remote_mac, src_mac, 6);
    raw_send_segment(&rst, NULL, 0, TCP_RST | TCP_ACK);
}

/* advance rcv_nxt over in-order data + FIN.
 * For a test-tool server we discard data immediately: advance rcv_tail
 * to match rcv_head so the receive buffer never fills and rcv_wnd
 * stays at full capacity. Without consumption the buffer would wrap
 * and the peer would see a false zero-window. */
static void deliver_data(tcb_t *t, const parsed_tcp_t *pkt)
{
    if (pkt->payload_len <= 0) return;
    if (SEQ_LT(pkt->seq + pkt->payload_len, t->rcv_nxt)) return; /* old */
    t->rcv_nxt = pkt->seq + pkt->payload_len;
    t->bytes_recv += pkt->payload_len; /* rx byte count */
    /* discard: keep the buffer empty, window always open */
    t->rcv_head = t->rcv_tail;
    t->rcv_wnd = t->rcv_cap;  /* full window, no off-by-one */
}

static void process_ack(tcb_t *t, const parsed_tcp_t *pkt, uint64_t now_ms)
{
    if (SEQ_GT(pkt->ack_seq, t->snd_una)) {
        /* Exit fast recovery: ACK advanced past the recovery point */
        if (RECOVER_ACTIVE(t) && SEQ_GEQ(pkt->ack_seq, t->recover)) {
            t->cwnd = t->ssthresh;   /* deflate window */
            RECOVER_EXIT(t);
            t->dupack_count = 0;
        }

        uint32_t acked = pkt->ack_seq - t->snd_una;
        t->snd_una = pkt->ack_seq;
        while (t->retrans_q && SEQ_LEQ(t->retrans_q->seq + t->retrans_q->len, t->snd_una)) {
            if (t->rtt_pending) {
                uint32_t rtt = (uint32_t)(now_ms - t->retrans_q->send_ms);
                update_rtt(t, rtt);
            }
            tcp_seg_t *done = t->retrans_q;
            t->retrans_q = *seg_next_ptr(done);
            free(done);
        }
        reno_newack(t, acked);
        /* Only advance FIN-related state when the ACK covers snd_nxt
         * (which was incremented by 1 when the FIN was sent).
         * A pure data ACK (ack_seq < snd_nxt) must NOT transition
         * out of FIN_WAIT_1, or the FIN would never be retransmitted. */
        if (SEQ_GEQ(pkt->ack_seq, t->snd_nxt)) {
            /* Force set: FIN retransmission may have already advanced snd_nxt,
             * and a prior data ACK may have cleared fin_acked incorrectly. */
            t->fin_acked = 1;
            if (t->state == TCP_FIN_WAIT_1) t->state = TCP_FIN_WAIT_2;
            else if (t->state == TCP_LAST_ACK) { tcb_unlink(t); tcb_free(t); return; }
            else if (t->state == TCP_CLOSING) {
                t->state = TCP_TIME_WAIT;
                t->time_wait_expire = now_ms + TIME_WAIT_MS;
            }
        }
    } else {
        /* duplicate ACK */
        /* RFC 5681: only trigger fast retransmit if in recovery */
        if (RECOVER_ACTIVE(t)) {
            t->dupack_count++;
            if (t->dupack_count >= 3) reno_fast_retransmit(t, now_ms);
        }
        /* else: not in recovery, ignore dupacks */
    }
}

void tcp_fsm_input(const parsed_tcp_t *pkt, const uint8_t *src_mac)
{
    uint64_t now_ms = time_now_ms();

    /* RST: immediate teardown */
    if (pkt->flags & TCP_RST) {
        tcb_t *t = tcb_lookup(pkt->src_ip, pkt->dst_ip, pkt->sport, pkt->dport,
                              pkt->vlan_id, 0);
        if (t) { tcb_unlink(t); tcb_free(t); }
        return;
    }

    /* --- pure SYN (active open arriving at a listener) --- */
    if ((pkt->flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
        if (g_platform_verbose)
            printf("[FSM] SYN %s:%u -> %s:%u vlan=%u\n",
                   fmt_ip(pkt->src_ip), pkt->sport,
                   fmt_ip(pkt->dst_ip), pkt->dport, pkt->vlan_id);
        for (tcb_t *l = g_tcb_list; l; l = l->next) {
            if (l->state != TCP_LISTEN) continue;
            if (l->vlan_id != (pkt->vlan_id)) continue;
            if (l->local_port != pkt->dport) continue;
            if (l->local_ip != 0 && l->local_ip != pkt->dst_ip) continue;

            tcb_t *c = tcb_alloc();
            if (!c) return;
            memcpy(c->local_mac, l->local_mac, 6);
            memcpy(c->remote_mac, src_mac, 6);
            c->local_ip    = l->local_ip ? l->local_ip : pkt->dst_ip;
            c->remote_ip   = pkt->src_ip;
            c->local_port  = l->local_port;
            c->remote_port = pkt->sport;
            c->vlan_id     = l->vlan_id;
            c->vlan_pcp    = l->vlan_pcp;
            c->irs         = pkt->seq;
            c->rcv_nxt     = pkt->seq + 1;
            c->iss         = alloc_iss();
            c->snd_una     = c->iss;
            c->snd_nxt     = c->iss;
            c->state       = TCP_SYN_RECEIVED;

            raw_send_segment(c, NULL, 0, TCP_SYN | TCP_ACK);
            c->snd_nxt    = c->iss + 1;
            c->rto_expire  = now_ms + c->rto;
            c->rtt_pending = 1;

            c->next = g_tcb_list; g_tcb_list = c;
            return;
        }
        emit_rst(pkt, src_mac, pkt->seq + 1);
        return;
    }

    /* --- SYN+ACK (response to our active open) --- */
    if ((pkt->flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
        tcb_t *t = tcb_lookup(pkt->src_ip, pkt->dst_ip, pkt->sport, pkt->dport,
                              pkt->vlan_id, 0);
        if (!t) { emit_rst(pkt, src_mac, pkt->seq + 1); return; }
        if (t->state == TCP_SYN_SENT) {
            t->irs     = pkt->seq;
            t->rcv_nxt = pkt->seq + 1;
            t->snd_una = pkt->ack_seq;
            t->snd_wnd = pkt->window;
            if (g_platform_verbose)
                printf("[FSM] %s:%u -> SYN-ACK received, %s -> ESTABLISHED\n",
                       fmt_ip(t->remote_ip), t->remote_port,
                       tcp_state_name(t->state));
            t->state   = TCP_ESTABLISHED;
            uint32_t rtt = (uint32_t)(now_ms - (t->rto_expire - 1000));
            update_rtt(t, rtt);
            /* Preemptive ACK burst: Windows OS stack may see this SYN-ACK
             * and send a RST (no matching socket). Flood the peer with ACKs
             * to win the race — the first one that arrives establishes the
             * connection before the RST can kill it. No recv_dispatch() in
             * between, so nothing delays us. */
            send_ack(t);
            send_ack(t);
            send_ack(t);
        } else if (t->state == TCP_SYN_RECEIVED) {
            send_flags(t, TCP_SYN | TCP_ACK);   /* duplicate SYN */
        }
        return;
    }

    /* --- FIN+ACK or pure FIN --- */
    if (pkt->flags & TCP_FIN) {
        tcb_t *t = tcb_lookup(pkt->src_ip, pkt->dst_ip, pkt->sport, pkt->dport,
                              pkt->vlan_id, 0);
        if (!t) { emit_rst(pkt, src_mac, pkt->ack_seq); return; }

        deliver_data(t, pkt);

        if (pkt->flags & TCP_ACK) process_ack(t, pkt, now_ms);

        /* advance over the FIN */
        if (SEQ_LT(t->rcv_nxt, pkt->seq + 1) && SEQ_GEQ(pkt->seq, t->rcv_nxt - 1)) {
            t->rcv_nxt = pkt->seq + 1;
            send_ack(t);
            switch (t->state) {
            case TCP_ESTABLISHED:     t->state = TCP_CLOSE_WAIT; break;
            case TCP_FIN_WAIT_1:      t->state = TCP_CLOSING;
                if (t->snd_una >= t->snd_nxt) {
                    t->state = TCP_TIME_WAIT;
                    t->time_wait_expire = now_ms + TIME_WAIT_MS;
                }
                break;
            case TCP_FIN_WAIT_2:
                t->state = TCP_TIME_WAIT;
                t->time_wait_expire = now_ms + TIME_WAIT_MS;
                break;
            default: break;
            }
        }
        return;
    }

    /* --- pure ACK (data + ACK) --- */
    {
        tcb_t *t = tcb_lookup(pkt->src_ip, pkt->dst_ip, pkt->sport, pkt->dport,
                              pkt->vlan_id, 0);
        if (!t) { emit_rst(pkt, src_mac, pkt->ack_seq); return; }

        /* SYN_RECEIVED + ACK -> ESTABLISHED */
        if (t->state == TCP_SYN_RECEIVED && (pkt->flags & TCP_ACK)) {
            t->snd_una = pkt->ack_seq;
            t->snd_wnd = pkt->window;
            if (g_platform_verbose)
                printf("[FSM] %s:%u SYN_RECEIVED -> ESTABLISHED (peer ACK received)\n",
                       fmt_ip(t->remote_ip), t->remote_port);
            t->state   = TCP_ESTABLISHED;
            send_ack(t);
        }

        process_ack(t, pkt, now_ms);

        deliver_data(t, pkt);
        if (pkt->payload_len > 0 && t->state == TCP_ESTABLISHED) send_ack(t);
    }
}
