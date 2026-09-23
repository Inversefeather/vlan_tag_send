/*
 * rst_killer.c - WinDivert-based outbound RST blocker
 *
 * When using EtherType 0x0800 (standard IPv4), the Windows kernel TCP
 * stack on the machine sees unexpected SYN/SYN-ACK packets (because our
 * userspace stack, not a kernel socket, is handling them) and emits an
 * outbound RST that races/kills our connection.
 *
 * This module opens a WFP handle via WinDivert and drops that kernel RST
 * before it reaches the wire.
 *
 * Two modes (selected by which parameters are non-zero):
 *   Server mode: src_port != 0
 *       Kernel RSTs SYN arriving at our listening port. Filter on
 *       tcp.SrcPort == <src_port>.
 *   Client mode: src_port == 0, dst_ip/dst_port set
 *       Kernel RSTs the server's SYN-ACK. Filter on ip.DstAddr == <dst_ip>
 *       and tcp.DstPort == <dst_port>.
 *
 * Build modes (compile-time):
 *   - WINDIVERT_STATIC: WinDivert is compiled into the exe (via
 *     windivert_static.c).  We call WinDivertOpen() directly.
 *   - otherwise:        dynamic-load WinDivert.dll at runtime; if the
 *     DLL/driver is missing, rst_killer_start() returns 0 and the tool
 *     runs without RST protection.
 */
#include "rst_killer.h"
#include "net.h"  /* for g_tcp_mode */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/* g_platform_verbose is defined in platform.c */
extern int g_platform_verbose;

/* ---------------------------------------------------------------------
 * Static build: WinDivert is compiled into the exe
 * -------------------------------------------------------------------*/
#ifdef WINDIVERT_STATIC

#include "windivert_static.h"

static HANDLE    g_handle = NULL;
static HANDLE    g_thread = NULL;
static volatile LONG g_stop_flag = 0;

static DWORD WINAPI rk_thread(LPVOID arg)
{
    (void)arg;
    unsigned char pkt[2048];
    UINT pkt_len;
    WINDIVERT_ADDRESS addr;

    while (!g_stop_flag) {
        BOOL ok = WinDivertRecv(g_handle, pkt, sizeof(pkt), &pkt_len, &addr);
        if (!ok) {
            DWORD e = GetLastError();
            if (e == ERROR_INVALID_HANDLE || e == ERROR_OPERATION_ABORTED)
                break;
            Sleep(1);
            continue;
        }
        /* Drop: do NOT call WinDivertSend to reinject. */
        if (g_platform_verbose) {
            printf("[rst_killer] dropped outbound RST (len=%u, outbound=%u)\n",
                   pkt_len, addr.Outbound);
        }
    }
    return 0;
}

int rst_killer_start(uint16_t src_port, uint32_t dst_ip, uint16_t dst_port)
{
    /* Pseudo-TCP mode: kernel never sees TCP, never RSTs -- skip WinDivert */
    if (g_tcp_mode == MODE_PSEUDO_TCP)
        return 0;

    char filter[256];

    if (src_port != 0) {
        /* Server mode: kernel RSTs SYN arriving at our listening port.
         * Filter by source port only. */
        snprintf(filter, sizeof(filter),
                 "outbound and tcp.Rst and tcp.SrcPort == %u", src_port);
        printf("[rst_killer] protecting port %u from kernel RST (server mode)\n",
               src_port);
    } else {
        /* Client mode: kernel RSTs the server's SYN-ACK.
         * Filter by destination IP + port. */
        char ipstr[64];
        uint32_t h = ntohl(dst_ip);
        snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u",
                 (h >> 24) & 0xFF, (h >> 16) & 0xFF,
                 (h >> 8) & 0xFF, h & 0xFF);
        snprintf(filter, sizeof(filter),
                 "outbound and tcp.Rst and ip.DstAddr == %s and tcp.DstPort == %u",
                 ipstr, dst_port);
        printf("[rst_killer] protecting %s:%u from kernel RST (client mode)\n",
               ipstr, dst_port);
    }

    if (g_platform_verbose)
        printf("[rst_killer] filter: \"%s\"\n", filter);

    g_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (!g_handle || g_handle == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        fprintf(stderr, "[rst_killer] WinDivertOpen failed (err=%lu). "
                "Is the WinDivert driver installed & are you running as admin?\n", e);
        return -1;
    }

    g_stop_flag = 0;
    g_thread = CreateThread(NULL, 0, rk_thread, NULL, 0, NULL);
    if (!g_thread) {
        fprintf(stderr, "[rst_killer] CreateThread failed\n");
        WinDivertClose(g_handle);
        g_handle = NULL;
        return -1;
    }

    return 0;
}

void rst_killer_stop(void)
{
    if (!g_handle)
        return;

    g_stop_flag = 1;
    WinDivertShutdown(g_handle, WINDIVERT_SHUTDOWN_RECV);

    if (g_thread) {
        WaitForSingleObject(g_thread, 3000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }

    WinDivertClose(g_handle);
    g_handle = NULL;
}

/* ---------------------------------------------------------------------
 * Dynamic build: load WinDivert.dll at runtime
 * -------------------------------------------------------------------*/
#else

#include <windows.h>

typedef enum {
    WINDIVERT_LAYER_NETWORK = 0,
} WINDIVERT_LAYER;

typedef enum {
    WINDIVERT_SHUTDOWN_RECV = 0x1,
} WINDIVERT_SHUTDOWN;

typedef struct {
    INT64  Timestamp;
    UINT32 Layer:8;
    UINT32 Event:8;
    UINT32 Sniffed:1;
    UINT32 Outbound:1;
    UINT32 Loopback:1;
    UINT32 Impostor:1;
    UINT32 IPv6:1;
    UINT32 IPChecksum:1;
    UINT32 TCPChecksum:1;
    UINT32 UDPChecksum:1;
    UINT32 Reserved1:8;
    UINT32 Reserved2;
    UINT8  Reserved3[64];
} WINDIVERT_ADDRESS;

typedef HANDLE (WINAPI *pfnWinDivertOpen)(const char *, WINDIVERT_LAYER, INT16, UINT64);
typedef BOOL (WINAPI *pfnWinDivertRecv)(HANDLE, VOID *, UINT, UINT *, WINDIVERT_ADDRESS *);
typedef BOOL (WINAPI *pfnWinDivertShutdown)(HANDLE, WINDIVERT_SHUTDOWN);
typedef BOOL (WINAPI *pfnWinDivertClose)(HANDLE);

static struct {
    HMODULE dll;
    pfnWinDivertOpen fnOpen;
    pfnWinDivertRecv fnRecv;
    pfnWinDivertShutdown fnShutdown;
    pfnWinDivertClose fnClose;

    HANDLE    handle;
    HANDLE    thread;
    volatile LONG stop_flag;
} g_rk = { 0 };

static int load_windivert(void)
{
    if (g_rk.dll) return 0;

    g_rk.dll = LoadLibraryA("WinDivert.dll");
    if (!g_rk.dll)
        g_rk.dll = LoadLibraryA("WinDivert64.dll");
    if (!g_rk.dll) {
        fprintf(stderr, "[rst_killer] WinDivert.dll not found -- RST protection disabled.\n");
        return -1;
    }

#define RK_GETPROC(name) do { \
    g_rk.fn##name = (pfnWinDivert##name)GetProcAddress(g_rk.dll, "WinDivert" #name); \
    if (!g_rk.fn##name) { fprintf(stderr, "[rst_killer] missing WinDivert" #name "\n"); goto fail; } \
} while (0)

    RK_GETPROC(Open);
    RK_GETPROC(Recv);
    RK_GETPROC(Shutdown);
    RK_GETPROC(Close);
#undef RK_GETPROC

    return 0;

fail:
    FreeLibrary(g_rk.dll);
    g_rk.dll = NULL;
    return -1;
}

static DWORD WINAPI rk_thread(LPVOID arg)
{
    (void)arg;
    unsigned char pkt[2048];
    UINT pkt_len;
    WINDIVERT_ADDRESS addr;

    while (!g_rk.stop_flag) {
        BOOL ok = g_rk.fnRecv(g_rk.handle, pkt, sizeof(pkt), &pkt_len, &addr);
        if (!ok) {
            DWORD e = GetLastError();
            if (e == ERROR_INVALID_HANDLE || e == ERROR_OPERATION_ABORTED)
                break;
            Sleep(1);
            continue;
        }
        if (g_platform_verbose) {
            printf("[rst_killer] dropped outbound RST (len=%u, outbound=%u)\n",
                   pkt_len, addr.Outbound);
        }
    }
    return 0;
}

int rst_killer_start(uint16_t src_port, uint32_t dst_ip, uint16_t dst_port)
{
    /* Pseudo-TCP mode: kernel never sees TCP, never RSTs -- skip WinDivert */
    if (g_tcp_mode == MODE_PSEUDO_TCP)
        return 0;

    char filter[256];

    if (load_windivert() != 0)
        return 0;

    if (src_port != 0) {
        snprintf(filter, sizeof(filter),
                 "outbound and tcp.Rst and tcp.SrcPort == %u", src_port);
        printf("[rst_killer] protecting port %u from kernel RST (server mode)\n",
               src_port);
    } else {
        char ipstr[64];
        uint32_t h = ntohl(dst_ip);
        snprintf(ipstr, sizeof(ipstr), "%u.%u.%u.%u",
                 (h >> 24) & 0xFF, (h >> 16) & 0xFF,
                 (h >> 8) & 0xFF, h & 0xFF);
        snprintf(filter, sizeof(filter),
                 "outbound and tcp.Rst and ip.DstAddr == %s and tcp.DstPort == %u",
                 ipstr, dst_port);
        printf("[rst_killer] protecting %s:%u from kernel RST (client mode)\n",
               ipstr, dst_port);
    }

    if (g_platform_verbose)
        printf("[rst_killer] filter: \"%s\"\n", filter);

    g_rk.handle = g_rk.fnOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (!g_rk.handle || g_rk.handle == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        fprintf(stderr, "[rst_killer] WinDivertOpen failed (err=%lu). "
                "Is the WinDivert driver installed & are you running as admin?\n", e);
        return -1;
    }

    g_rk.stop_flag = 0;
    g_rk.thread = CreateThread(NULL, 0, rk_thread, NULL, 0, NULL);
    if (!g_rk.thread) {
        fprintf(stderr, "[rst_killer] CreateThread failed\n");
        g_rk.fnClose(g_rk.handle);
        g_rk.handle = NULL;
        return -1;
    }

    return 0;
}

void rst_killer_stop(void)
{
    if (!g_rk.handle)
        return;

    g_rk.stop_flag = 1;
    g_rk.fnShutdown(g_rk.handle, WINDIVERT_SHUTDOWN_RECV);

    if (g_rk.thread) {
        WaitForSingleObject(g_rk.thread, 3000);
        CloseHandle(g_rk.thread);
        g_rk.thread = NULL;
    }

    g_rk.fnClose(g_rk.handle);
    g_rk.handle = NULL;
}

#endif /* WINDIVERT_STATIC */
