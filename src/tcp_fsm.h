/*
 * tcp_fsm.h - TCP Finite State Machine (RFC 793 + RFC 1122)
 *
 * Strict state transitions driven by events from the receive pipeline
 * and the application layer. This module owns the TCB list and the
 * 5-tuple lookup that includes the VLAN ID as a discriminator.
 */
#ifndef TCP_FSM_H
#define TCP_FSM_H

#include "net.h"

/* ---------------------------------------------------------------------
 * TCB lifecycle
 * -------------------------------------------------------------------*/

/* Allocate a fresh TCB (caller fills 5-tuple + VLAN). */
tcb_t *tcb_alloc(void);

/* Free a TCB and all its queued segments / buffers. */
void tcb_free(tcb_t *tcb);

/*
 * Active open (client): create a TCB in SYN_SENT and emit a SYN.
 * Returns the new TCB, or NULL on allocation failure.
 */
tcb_t *tcp_active_open(uint32_t local_ip, const uint8_t *local_mac,
                       uint32_t remote_ip, const uint8_t *remote_mac,
                       uint16_t local_port, uint16_t remote_port,
                       uint16_t vlan_id, uint8_t vlan_pcp);

/*
 * Passive open (server): create a listening TCB in TCP_LISTEN.
 */
tcb_t *tcp_passive_open(uint32_t local_ip, const uint8_t *local_mac,
                        uint16_t local_port,
                        uint16_t vlan_id, uint8_t vlan_pcp);

/*
 * Look up a TCB by the 5-tuple + VLAN ID on an incoming segment.
 * VLAN is always part of the key: the same 5-tuple on different VLANs
 * maps to different TCBs (no conditional compilation).
 * 'reverse' = 1 means match the reverse direction (for SYN handling).
 */
tcb_t *tcb_lookup(uint32_t src_ip, uint32_t dst_ip,
                  uint16_t sport, uint16_t dport,
                  uint16_t vlan_id, int reverse);

/* ---------------------------------------------------------------------
 * FSM event processing
 * -------------------------------------------------------------------*/

/*
 * Process a parsed incoming TCP segment against the TCB list.
 * This is the entry point from the receive pipeline.
 * It dispatches to the appropriate state handler.
 */
void tcp_fsm_input(const parsed_tcp_t *pkt, const uint8_t *src_mac);

/*
 * Application close: initiate teardown from ESTABLISHED.
 * Sends a FIN and moves to FIN_WAIT_1.
 */
void tcp_app_close(tcb_t *tcb);

/* Application write: copy data into the send ring buffer. */
int tcp_app_write(tcb_t *tcb, const uint8_t *buf, int len);

/* Check if the send ring buffer is empty. */
int tcp_snd_buf_empty(tcb_t *tcb);

/*
 * Drain the send buffer: build & queue segments that fit in the
 * congestion window and peer window. Called from the event loop.
 */
void tcp_send_pending(tcb_t *tcb, uint64_t now_ms);

/*
 * Retransmission timeout. Retransmits the oldest unacked segment,
 * applies exponential backoff + Reno congestion control.
 */
void tcp_timeout_retransmit(tcb_t *tcb, uint64_t now_ms);

/*
 * Walk every TCB and fire expired timers (RTO, TIME_WAIT).
 * Called once per event-loop tick.
 */
void tcp_timer_walk(uint64_t now_ms);

/*
 * Iterate all TCBs (for the main loop). Returns head of list.
 */
tcb_t *tcb_list_head(void);

#endif /* TCP_FSM_H */
