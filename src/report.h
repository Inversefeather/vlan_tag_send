/*
 * report.h - Report / Stats (iperf-format + optional JSON output)
 *
 * Prints interval and summary lines in iperf style:
 *   [ ID] Interval           Transfer     Bandwidth
 *   [  3] 0.00- 1.00 sec  112 MBytes   941 Mbits/sec
 *
 * With -J, emits a machine-readable JSON summary at the end.
 */
#ifndef REPORT_H
#define REPORT_H

#include "net.h"

/* Print the iperf column header. */
void report_print_header(void);

/*
 * Print one interval line for a stream.
 *   stream_id : 1-based
 *   start_sec : interval start relative to stream start
 *   interval  : interval width (seconds)
 *   bytes     : bytes transferred in this interval
 */
void report_print_interval(int stream_id, double start_sec, double interval,
                           uint64_t bytes);

/*
 * Print the final summary line.
 *   stream_id : 1-based
 *   total_sec : total elapsed time
 *   bytes     : total bytes
 *   is_sender : 1 = sender, 0 = receiver
 */
void report_print_summary(int stream_id, double total_sec, uint64_t bytes,
                          int is_sender);

/* Format helpers (also used by main). */
void format_bps(double bps, char *buf, int cap);
void format_bytes(uint64_t bytes, char *buf, int cap);

/* ---------------------------------------------------------------------
 * JSON output (-J)
 * -------------------------------------------------------------------*/

/*
 * Print a JSON summary for one stream. Call after the test completes.
 * Example output (appended to a JSON array by the caller):
 *   {
 *     "stream": 1,
 *     "sender": true,
 *     "seconds": 10.00,
 *     "bytes": 125000000,
 *     "bits_per_second": 100000000.00,
 *     "retransmits": 0
 *   }
 */
void report_print_json(int stream_id, double total_sec, uint64_t bytes,
                       int is_sender, uint64_t retransmits);

/* Print the opening JSON structure (call once before streams). */
void report_json_start(void);

/* Print the closing JSON structure (call once after streams). */
void report_json_end(void);

/* Comma separator between JSON stream objects. */
void report_json_stream_sep(void);

#endif /* REPORT_H */
