/*
 * net.c - Core utilities: checksums, ISS allocation, frame build/parse
 *
 * All checksums are software-computed (IP header checksum + TCP/UDP
 * pseudo-header checksum). No OS TCP stack is used anywhere.
 */
#include "net.h"
#include <assert.h>

/* ---------------------------------------------------------------------
 * Global TCP mode selector (used by send + receive paths).
 * Default: pseudo-TCP (proto 250) so the kernel never interferes.
 * main.c sets MODE_REAL_TCP when --real-tcp is passed.
 * -------------------------------------------------------------------*/
tcp_mode_t g_tcp_mode = MODE_PSEUDO_TCP;

/* ---------------------------------------------------------------------
 * One's complement checksum (RFC 1071)
 * -------------------------------------------------------------------*/

uint16_t inet_checksum(const void *data, int len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;
    int words = len >> 1;

    for (int i = 0; i < words; i++) {
        sum += p[i];
        if (sum & 0xFFFF0000u)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (len & 1)
        sum += (uint16_t)(((const uint8_t *)data)[len - 1] << 8);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFF);
}

/*
 * TCP/UDP checksum including the IPv4 pseudo-header.
 *   src_ip, dst_ip : network order
 *   protocol       : IP_PROTOCOL_TCP or IP_PROTOCOL_UDP
 *   data           : the TCP/UDP header followed by payload
 *   len            : length of data (header + payload)
 */
uint16_t tcp_udp_checksum(uint32_t src_ip, uint32_t dst_ip,
                          uint8_t protocol, const void *data, int len)
{
    /* TCP/UDP length field in pseudo-header is 16-bit; truncate would
     * silently corrupt the checksum. Today MSS≤1460 so this never fires,
     * but future GSO support could push a segment past 65535 bytes. */
    assert(len >= 0 && len <= 65535);
    /* Pseudo-header (12 bytes) */
    uint8_t pseudo[PSEUDO_HDR_LEN];
    uint32_t sum = 0;

    memcpy(pseudo + 0, &src_ip, 4);
    memcpy(pseudo + 4, &dst_ip, 4);
    pseudo[8] = 0;
    pseudo[9] = protocol;
    pseudo[10] = (uint8_t)(len >> 8);
    pseudo[11] = (uint8_t)(len & 0xFF);

    /* fold pseudo-header */
    for (int i = 0; i < PSEUDO_HDR_LEN; i += 2) {
        sum += ((uint16_t)pseudo[i] << 8) | pseudo[i + 1];
        if (sum & 0xFFFF0000u)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /* fold the segment (padded to even length on stack) */
    uint8_t tmp[FRAME_BUF_SIZE];  /* enough for any frame we build */
    memcpy(tmp, data, len);
    if (len & 1) tmp[len] = 0;  /* zero-pad odd byte */
    int even_len = (len + 1) & ~1;

    for (int i = 0; i < even_len; i += 2) {
        sum += ((uint16_t)tmp[i] << 8) | tmp[i + 1];
        if (sum & 0xFFFF0000u)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    uint16_t c = (uint16_t)(~sum & 0xFFFF);
    return c ? c : 0xFFFF;   /* 0 means "no checksum" -> transmit 0xFFFF */
}

/* ---------------------------------------------------------------------
 * Hex dump (debug aid)
 * -------------------------------------------------------------------*/
void hex_dump(const uint8_t *data, int len, const char *prefix)
{
    for (int i = 0; i < len; i += 16) {
        if (prefix) printf("%s", prefix);
        printf("%04x: ", i);
        int n = len - i;
        if (n > 16) n = 16;
        for (int j = 0; j < 16; j++) {
            if (j < n) printf("%02x ", data[i + j]);
            else printf("   ");
        }
        printf(" ");
        for (int j = 0; j < n; j++) {
            uint8_t c = data[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("\n");
    }
}

/* ---------------------------------------------------------------------
 * Initial Sequence Number (time-based, RFC 793)
 * -------------------------------------------------------------------*/

static uint32_t g_iss_counter = 0;

uint32_t alloc_iss(void)
{
    /* 250 kHz clock, like many stacks: 4 us per tick */
    uint64_t t = GetTickCount64();
    if (g_iss_counter == 0)
        g_iss_counter = (uint32_t)(t * 250) + 1;
    return g_iss_counter += (uint32_t)(t & 0xFFFF) + 1;
}
