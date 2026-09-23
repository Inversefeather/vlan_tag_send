/*
 * iperf.h - System TCP/UDP throughput test (Winsock-based)
 *
 * This is the "--mode iperf" backend.  It implements an iperf-like
 * bandwidth test using the OS kernel TCP/UDP stack via standard
 * Winsock sockets -- no Npcap, no hand-built frames, no FSM.
 *
 * Features:
 *   - TCP and UDP
 *   - Client and server modes
 *   - Parallel streams (-P N)
 *   - Bandwidth throttling (-b)
 *   - Optional source bind (-B)
 *   - JSON output (-J)
 */
#ifndef IPERF_H
#define IPERF_H

#include "main.h"  /* for cli_config_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Run the iperf backend for the given config.
 * Returns 0 on success, non-zero on failure. */
int iperf_run(const cli_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* IPERF_H */
