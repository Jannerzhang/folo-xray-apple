/*
 ============================================================================
 Name        : hev-tunnel.h
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2023 - 2025 hev
 Description : Tunnel
 ============================================================================
 */

#ifndef __HEV_TUNNEL_H__
#define __HEV_TUNNEL_H__

#include <netinet/in.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <lwip/pbuf.h>

#if defined(__linux__)
#include "hev-tunnel-linux.h"
#endif /* __linux__ */

#if defined(__FreeBSD__)
#include "hev-tunnel-freebsd.h"
#endif /* __FreeBSD__ */

#if defined(__NetBSD__)
#include "hev-tunnel-netbsd.h"
#endif /* __NetBSD__ */

#if defined(__APPLE__) || defined(__MACH__)
#include "hev-tunnel-macos.h"
#endif /* __APPLE__ || __MACH__ */

#if defined(__MSYS__)
#include "hev-tunnel-windows.h"
#endif /* __MSYS__ */

#if defined(HEV_TUNNEL_PACKETFLOW)
static inline int
hev_packetflow_read_exact (int fd, void *data, size_t length,
                           HevTaskIOYielder yielder, void *yielder_data)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t res = hev_task_io_read ((fd), (uint8_t *)data + offset,
                                        length - offset, yielder,
                                        yielder_data);
        if (res <= 0)
            return -1;
        offset += (size_t)res;
    }

    return 0;
}

static inline int
hev_packetflow_write_exact (int fd, const void *data, size_t length,
                            HevTaskIOYielder yielder, void *yielder_data)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t res = hev_task_io_write ((fd), (const uint8_t *)data + offset,
                                         length - offset, yielder,
                                         yielder_data);
        if (res <= 0)
            return -1;
        offset += (size_t)res;
    }

    return 0;
}

static inline int
hev_packetflow_header (const struct pbuf *buf, uint8_t header[12])
{
    uint8_t ip_header[40] = { 0 };
    uint16_t packet_length;
    uint8_t family;
    uint8_t protocol;

    if (!buf || !buf->tot_len || buf->tot_len > UINT16_MAX ||
        pbuf_copy_partial ((struct pbuf *)buf, ip_header,
                           (u16_t)((buf->tot_len < sizeof (ip_header))
                                       ? buf->tot_len : sizeof (ip_header)),
                           0) == 0)
        return -1;

    packet_length = buf->tot_len;
    switch (ip_header[0] >> 4) {
    case 4:
        if (packet_length < 20 || (ip_header[0] & 0x0f) < 5 ||
            (uint16_t)((ip_header[0] & 0x0f) * 4) > packet_length ||
            (uint16_t)(((uint16_t)ip_header[2] << 8) | ip_header[3]) !=
                packet_length)
            return -1;
        family = 4;
        protocol = ip_header[9];
        break;
    case 6:
        if (packet_length < 40 ||
            (uint16_t)(40 + (((uint16_t)ip_header[4] << 8) | ip_header[5])) !=
                packet_length)
            return -1;
        family = 6;
        protocol = ip_header[6];
        break;
    default:
        return -1;
    }

    header[0] = 0x46;
    header[1] = 0x50;
    header[2] = 1;
    header[3] = family;
    header[4] = protocol;
    header[5] = 0;
    header[6] = 0;
    header[7] = 0;
    header[8] = (uint8_t)(packet_length >> 8);
    header[9] = (uint8_t)packet_length;
    header[10] = 0;
    header[11] = 0;

    return 0;
}

static inline struct pbuf *
hev_tunnel_read (int fd, int mtu, HevTaskIOYielder yielder, void *yielder_data)
{
    uint8_t header[12];
    struct pbuf *buf, *p;
    uint8_t expected[12];
    uint32_t packet_length;

    if (hev_packetflow_read_exact (fd, header, sizeof (header), yielder,
                                   yielder_data) < 0)
        return NULL;

    packet_length = ((uint32_t)header[6] << 24) |
                    ((uint32_t)header[7] << 16) |
                    ((uint32_t)header[8] << 8) | header[9];
    if (header[0] != 0x46 || header[1] != 0x50 || header[2] != 1 ||
        (header[3] != 4 && header[3] != 6) || header[5] || header[10] ||
        header[11] || !packet_length || packet_length > UINT16_MAX ||
        (mtu > 0 && packet_length > (uint32_t)mtu))
        return NULL;

    buf = pbuf_alloc (PBUF_RAW, (u16_t)packet_length, PBUF_RAM);
    if (!buf)
        return NULL;

    for (p = buf; p; p = p->next) {
        if (hev_packetflow_read_exact (fd, p->payload, p->len, yielder,
                                       yielder_data) < 0) {
            pbuf_free (buf);
            return NULL;
        }
    }

    if (hev_packetflow_header (buf, expected) < 0 ||
        memcmp (expected, header, sizeof (header)) != 0) {
        pbuf_free (buf);
        return NULL;
    }

    return buf;
}

static inline ssize_t
hev_tunnel_write (int fd, struct pbuf *buf, HevTaskIOYielder yielder,
                  void *yielder_data)
{
    uint8_t header[12];
    struct pbuf *p;

    if (hev_packetflow_header (buf, header) < 0 ||
        hev_packetflow_write_exact (fd, header, sizeof (header), yielder,
                                    yielder_data) < 0)
        return -1;

    for (p = buf; p; p = p->next) {
        if (hev_packetflow_write_exact (fd, p->payload, p->len, yielder,
                                        yielder_data) < 0)
            return -1;
    }

    return buf->tot_len;
}

#elif defined(HEV_TUNNEL_GENERIC_HEAD)
static inline struct pbuf *
hev_tunnel_read (int fd, int mtu, HevTaskIOYielder yielder, void *yielder_data)
{
    struct iovec iov[2];
    struct pbuf *buf;
    uint32_t type;
    ssize_t s;

    buf = pbuf_alloc (PBUF_RAW, mtu, PBUF_RAM);
    if (!buf)
        return NULL;

    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof (type);
    iov[1].iov_base = buf->payload;
    iov[1].iov_len = buf->len;

    s = hev_task_io_readv (fd, iov, 2, yielder, yielder_data);
    if (s <= (ssize_t)sizeof (type)) {
        pbuf_free (buf);
        return NULL;
    }

    buf->tot_len = s - sizeof (type);
    buf->len = s - sizeof (type);

    return buf;
}

static inline ssize_t
hev_tunnel_write (int fd, struct pbuf *buf)
{
    struct iovec iov[512];
    struct pbuf *p = buf;
    uint32_t type = 0;
    ssize_t res;
    int i;

    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof (type);

    for (i = 1; p && (i < 512); p = p->next) {
        iov[i].iov_base = p->payload;
        iov[i].iov_len = p->len;
        i++;

        if (!type && p->len) {
            if (((*(uint8_t *)p->payload >> 4) & 0xF) == 4)
                type = htonl (AF_INET);
            else
                type = htonl (AF_INET6);
        }
    }

    res = writev (fd, iov, i);
    if (res <= (ssize_t)sizeof (type))
        return -1;

    return res;
}

#elif defined(HEV_TUNNEL_GENERIC)
static inline struct pbuf *
hev_tunnel_read (int fd, int mtu, HevTaskIOYielder yielder, void *yielder_data)
{
    struct pbuf *buf;
    ssize_t s;

    buf = pbuf_alloc (PBUF_RAW, mtu, PBUF_RAM);
    if (!buf)
        return NULL;

    s = hev_task_io_read (fd, buf->payload, buf->len, yielder, yielder_data);
    if (s <= 0) {
        pbuf_free (buf);
        return NULL;
    }

    buf->tot_len = s;
    buf->len = s;

    return buf;
}

static inline ssize_t
hev_tunnel_write (int fd, struct pbuf *buf)
{
    struct iovec iov[512];
    struct pbuf *p = buf;
    int i;

    if (!p->next)
        return write (fd, p->payload, p->len);

    for (i = 0; p && (i < 512); p = p->next) {
        iov[i].iov_base = p->payload;
        iov[i].iov_len = p->len;
        i++;
    }

    return writev (fd, iov, i);
}
#endif /* HEV_TUNNEL_GENERIC */

int hev_tunnel_open (const char *name, int multi_queue);
void hev_tunnel_close (int fd);

int hev_tunnel_set_mtu (int mtu);
int hev_tunnel_set_state (int state);

int hev_tunnel_set_ipv4 (const char *addr, unsigned int prefix);
int hev_tunnel_set_ipv6 (const char *addr, unsigned int prefix);

const char *hev_tunnel_get_name (void);
const char *hev_tunnel_get_index (void);

int hev_tunnel_add_task (int fd, HevTask *task);
void hev_tunnel_del_task (int fd, HevTask *task);

#endif /* __HEV_TUNNEL_H__ */
