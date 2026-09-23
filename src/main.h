/*
 * main.h - Shared CLI config struct + mode enum
 *
 * Both backends (--mode iperf and --mode vlan) receive a pointer to
 * cli_config_t after main.c has finished parsing.  Keeping the struct
 * definition here (instead of in main.c) lets both backends see it
 * without a circular include.
 */
#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Operating mode: which backend to run */
typedef enum {
    MODE_VLAN = 0,      /* Npcap hand-crafted frames + FSM (default) */
    MODE_IPERF = 1      /* System TCP/UDP via Winsock */
} run_mode_t;

/* CLI-parsed configuration, shared by both backends */
typedef struct {
    int         is_server;
    int         proto;          /* 0 = TCP, 1 = UDP */
    int         port;
    char        host[64];
    int         duration;       /* seconds (client) */
    uint64_t    num_bytes;      /* 0 = use duration */
    int         bufsize;
    double      target_bps;     /* 0 = unlimited */
    int         report_interval;
    int         streams;        /* parallel */
    uint16_t    vlan_id;
    uint8_t     pcp;
    int         verbose;
    int         silence_timeout;
    int         json;           /* -J */
    uint32_t    bind_ip;        /* network order, 0 = wildcard */
    char        bind_name[128]; /* adapter name/description substring */
    int         windivert;      /* --windivert */
    run_mode_t  mode;           /* --mode iperf | vlan */
} cli_config_t;

#ifdef __cplusplus
}
#endif

#endif /* MAIN_H */
