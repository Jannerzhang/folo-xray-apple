/*
 * SPDX-License-Identifier: LicenseRef-Folo-Proprietary
 *
 * Public PacketFlow evaluation backend for the MIT-licensed Hev engine.
 *
 * The upstream Apple backend opens and configures a macOS utun control
 * socket. A Packet Tunnel Extension cannot use that private host path. This
 * backend intentionally never opens a tunnel descriptor: the caller adopts a
 * stream endpoint and supplies complete PacketFlow frames to Hev.
 */

#include <unistd.h>
#include <sys/uio.h>

#include <hev-task.h>
#include <hev-task-io.h>

#include "hev-tunnel.h"

static char packetflow_name[] = "folo-packetflow";

int
hev_tunnel_open (const char *name, int multi_queue)
{
    (void)name;
    (void)multi_queue;
    return -1;
}

void
hev_tunnel_close (int fd)
{
    if (fd >= 0)
        close (fd);
}

int
hev_tunnel_set_mtu (int mtu)
{
    (void)mtu;
    return 0;
}

int
hev_tunnel_set_state (int state)
{
    (void)state;
    return 0;
}

int
hev_tunnel_set_ipv4 (const char *addr, unsigned int prefix)
{
    (void)addr;
    (void)prefix;
    return 0;
}

int
hev_tunnel_set_ipv6 (const char *addr, unsigned int prefix)
{
    (void)addr;
    (void)prefix;
    return 0;
}

const char *
hev_tunnel_get_name (void)
{
    return packetflow_name;
}

const char *
hev_tunnel_get_index (void)
{
    return "0";
}

int
hev_tunnel_add_task (int fd, HevTask *task)
{
    return hev_task_add_fd (task, fd, POLLIN);
}

void
hev_tunnel_del_task (int fd, HevTask *task)
{
    hev_task_del_fd (task, fd);
}
