/*
 * platform.h - Platform Layer
 *
 * Owns the pcap adapter handle, adapter info, high-resolution timing,
 * the send pipeline (Eth -> VLAN -> IPv4 -> TCP/UDP), the receive
 * pipeline (parse + dispatch to TCP FSM), and Ctrl-C handling.
 *
 * Everything above this layer is network-API-agnostic.
 */
#ifndef PLATFORM_H
#define PLATFORM_H

#include "net.h"
#include "tcp_fsm.h"

/* ---------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------*/

/* Initialize Winsock + timer. Call once. */
int  platform_init(void);
void platform_cleanup(void);

void platform_set_timer_resolution(void);
void platform_restore_timer_resolution(void);

/* Install Ctrl-C / Ctrl-Break handler. */
int  platform_install_ctrl_handler(void);

/* Atomic stop flag (set by ctrl handler). */
extern volatile LONG g_stop;

/* High-resolution time (milliseconds). */
uint64_t time_now_ms(void);

/* ---------------------------------------------------------------------
 * Adapter
 * -------------------------------------------------------------------*/

typedef struct adapter_info_s {
    char     name[512];
    char     desc[256];
    uint32_t ip;           /* network order */
    uint8_t  mac[6];
    int      is_loopback;
} adapter_info_t;

int  platform_enum_adapters(adapter_info_t *out, int cap);
int  platform_find_adapter_by_ip(uint32_t ip);

/* Get MAC address for a local IP. Returns 0 on success. */
int  get_mac_for_ip(uint32_t ip, uint8_t *mac);

/*
 * Get the MAC address for a bind address.
 *   bind_ip : 0 = first non-loopback adapter; otherwise the adapter owning that IP
 * Returns 0 on success, -1 on failure.
 */
int  get_mac_for_bind(uint32_t bind_ip, uint8_t *mac);

/*
 * Get the pcap device name for an adapter with the given IP.
 * Uses the Windows IP Helper API (same source as get_mac_for_ip).
 * Returns 0 on success, -1 on failure.
 */
int  get_adapter_name_by_ip(uint32_t ip, char *name, int name_len);

/* ---------------------------------------------------------------------
 * Send pipeline
 *
 * raw_send_segment() builds a complete frame from a TCB + payload and
 * hands it to pcap_sendpacket(). This is the ONLY way TCP/UDP segments
 * leave the stack -- no OS sockets.
 * -------------------------------------------------------------------*/

/*
 * Build and transmit one segment.
 *   tcb         : the owning control block (provides 5-tuple + VLAN)
 *   tcp_payload : UDP/TCP payload bytes (NULL for pure control)
 *   payload_len : length of payload
 *   flags       : TCP flags (SYN/ACK/FIN/RST/PSH)
 *
 * The frame is built layer by layer:
 *   tcp_build() -> ipv4_build() -> [vlan_build()] -> eth_build() -> pcap_sendpacket()
 *
 * Returns 0 on success, -1 on failure.
 */
int raw_send_segment(const tcb_t *tcb, const uint8_t *tcp_payload,
                     int payload_len, uint8_t flags);

/*
 * Send a raw UDP datagram (no TCP state machine). Used for UDP test mode.
 * Builds: Eth [VLAN] IPv4 UDP payload -> pcap_sendpacket().
 */
int raw_send_udp(uint32_t src_ip, const uint8_t *src_mac,
                 uint32_t dst_ip, const uint8_t *dst_mac,
                 uint16_t sport, uint16_t dport,
                 const uint8_t *payload, int payload_len,
                 uint16_t vlan_id, uint8_t vlan_pcp);

/* ---------------------------------------------------------------------
 * Receive pipeline
 *
 * platform_open_sniffer() opens an adapter for capture.
 * platform_recv_dispatch() captures one frame and dispatches it:
 *   eth_parse() -> ipv4_parse() -> tcp_parse() -> tcp_fsm_input()
 *
 * For UDP test mode, the dispatch calls a user callback instead.
 * -------------------------------------------------------------------*/

#ifdef USE_WINPCAP
typedef void (*udp_rx_cb_t)(const uint8_t *pkt, int len, void *ctx);

/*
 * Open a sniffer on the adapter that owns 'bind_ip' (or default adapter).
 * If 'name' is non-NULL, use it directly as the pcap device name (most reliable).
 * Returns 0 on success.
 */
int platform_open_sniffer(uint32_t bind_ip, const char *name);

/*
 * Capture & dispatch one frame (non-blocking with 100ms pcap timeout).
 * For TCP mode this feeds the FSM; for UDP mode it calls 'cb'.
 * Returns:  1 = a frame was dispatched
 *           0 = timeout / no frame
 *          -1 = error
 */
int platform_recv_dispatch(udp_rx_cb_t cb, void *ctx);

/* Close the sniffer. */
void platform_close_sniffer(void);

/* Break out of pcap loop (called from ctrl handler). */
void platform_breakloop(void);
#endif /* USE_WINPCAP */

#endif /* PLATFORM_H */
