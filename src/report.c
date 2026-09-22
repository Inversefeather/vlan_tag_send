/*
 * report.c - iperf-format output
 */
#include "report.h"

void format_bps(double bps, char *buf, int cap)
{
    if (bps >= 1e9)
        snprintf(buf, cap, "%.2f Gbits/sec", bps / 1e9);
    else if (bps >= 1e6)
        snprintf(buf, cap, "%.2f Mbits/sec", bps / 1e6);
    else if (bps >= 1e3)
        snprintf(buf, cap, "%.2f Kbits/sec", bps / 1e3);
    else
        snprintf(buf, cap, "%.2f bits/sec", bps);
}

void format_bytes(uint64_t bytes, char *buf, int cap)
{
    if (bytes >= 1024ULL * 1024 * 1024)
        snprintf(buf, cap, "%.2f GBytes", (double)bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024 * 1024)
        snprintf(buf, cap, "%.2f MBytes", (double)bytes / (1024.0 * 1024));
    else if (bytes >= 1024)
        snprintf(buf, cap, "%.2f KBytes", (double)bytes / 1024.0);
    else
        snprintf(buf, cap, "%llu Bytes", (unsigned long long)bytes);
}

void report_print_header(void)
{
    printf("[ ID] Interval           Transfer     Bandwidth\n");
}

void report_print_interval(int stream_id, double start_sec, double interval,
                           uint64_t bytes)
{
    double bps = (interval > 0) ? (double)bytes * 8.0 / interval : 0;
    char bw[32], tb[32];
    format_bps(bps, bw, sizeof(bw));
    format_bytes(bytes, tb, sizeof(tb));
    printf("[%3d] %5.2f-%5.2f sec  %s  %s\n",
           stream_id, start_sec, start_sec + interval, tb, bw);
    fflush(stdout);
}

void report_print_summary(int stream_id, double total_sec, uint64_t bytes,
                          int is_sender)
{
    double bps = (total_sec > 0) ? (double)bytes * 8.0 / total_sec : 0;
    char bw[32], tb[32];
    format_bps(bps, bw, sizeof(bw));
    format_bytes(bytes, tb, sizeof(tb));
    printf("[%3d]  0.00-%5.2f sec  %s  %s                  %s\n",
           stream_id, total_sec, tb, bw,
           is_sender ? "sender" : "receiver");
    fflush(stdout);
}

/* ---------------------------------------------------------------------
 * JSON output (-J)
 * -------------------------------------------------------------------*/

void report_json_start(void)
{
    printf("{\n  \"start\": {\n    \"timestamp\": %llu\n  },\n  \"intervals\": [],\n  \"end\": {\n    \"streams\": [\n",
           (unsigned long long)time(NULL));
}

void report_json_end(void)
{
    printf("    ]\n  }\n}\n");
    fflush(stdout);
}

void report_print_json(int stream_id, double total_sec, uint64_t bytes,
                       int is_sender, uint64_t retransmits)
{
    double bps = (total_sec > 0) ? (double)bytes * 8.0 / total_sec : 0;
    printf("      {\n");
    printf("        \"stream\": %d,\n", stream_id);
    printf("        \"sender\": %s,\n", is_sender ? "true" : "false");
    printf("        \"seconds\": %.2f,\n", total_sec);
    printf("        \"bytes\": %llu,\n", (unsigned long long)bytes);
    printf("        \"bits_per_second\": %.2f,\n", bps);
    printf("        \"retransmits\": %llu\n", (unsigned long long)retransmits);
    printf("      }");
    fflush(stdout);
}

/* comma-separate JSON stream objects */
void report_json_stream_sep(void)
{
    printf(",\n");
}
