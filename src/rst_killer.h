/*
 * rst_killer.h - WinDivert-based outbound RST blocker (client side)
 *
 * When the client uses EtherType 0x0800 (standard IPv4), the Windows
 * kernel TCP stack on the CLIENT machine sees the server's SYN-ACK (no
 * socket bound to that ephemeral source port) and immediately emits an
 * outbound RST,ACK back to the server. That kernel RST races against our
 * userspace ACK burst and kills the connection before ESTABLISHED.
 *
 * This module opens a WFP handle via WinDivert and drops any outbound
 * TCP RST whose (dst_ip, dst_port) matches our test server. The kernel
 * RST never reaches the wire, so the server only ever sees our ACKs.
 *
 * Loaded dynamically (LoadLibrary) so the tool still builds & runs on
 * machines without WinDivert.dll -- rst_killer_start() simply returns 0
 * ("nothing to do") in that case.
 */
#ifndef RST_KILLER_H
#define RST_KILLER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Start the RST killer thread.
 *   src_port : the port our userspace is listening on (host order).
 *              The kernel RSTs SYN arriving at this port (no kernel socket),
 *              so we drop outbound RST with this source port.
 *   dst_ip   : destination IP to filter on (network order), or 0 to match
 *              any destination (port-only filter).
 *
 * Two typical usages:
 *   - Server side: rst_killer_start(port, 0)  -- drop RST from our port
 *   - Client side: rst_killer_start(0, server_ip, server_port) -- drop RST to server
 *
 * Returns 0 on success (or if WinDivert is unavailable), -1 on failure.
 */
int rst_killer_start(uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);

/* Stop the RST killer thread and release resources. Safe if never started. */
void rst_killer_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* RST_KILLER_H */
