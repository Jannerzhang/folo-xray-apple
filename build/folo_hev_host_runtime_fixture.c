// SPDX-License-Identifier: Apache-2.0

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "folo_hev_packetflow.h"

static const char config[] =
    "tunnel:\n"
    "  name: folo-packetflow\n"
    "  mtu: 8500\n"
    "  ipv4: 198.18.0.1\n"
    "  ipv6: fc00::1\n"
    "socks5:\n"
    "  port: 1\n"
    "  address: 127.0.0.1\n"
    "  udp: 'udp'\n";

static const char invalid_config[] =
    "tunnel:\n"
    "  mtu: [\n";

int
main (void)
{
    int descriptors[2] = { -1, -1 };
    int result = 0;

    if (FoloHevPacketFlowState () != FOLO_HEV_PACKETFLOW_IDLE)
        return 10;
    if (socketpair (AF_UNIX, SOCK_STREAM, 0, descriptors) != 0)
        return 11;

    if (FoloHevPacketFlowStart ((const uint8_t *)invalid_config,
                                strlen (invalid_config), descriptors[0]) !=
        FOLO_HEV_PACKETFLOW_START_FAILED) {
        result = 19;
        goto close_descriptors;
    }
    if (FoloHevPacketFlowState () != FOLO_HEV_PACKETFLOW_IDLE) {
        result = 20;
        goto close_descriptors;
    }

    if (FoloHevPacketFlowStart ((const uint8_t *)config, strlen (config),
                                descriptors[0]) != FOLO_HEV_PACKETFLOW_OK) {
        result = 12;
        goto close_descriptors;
    }
    if (FoloHevPacketFlowState () != FOLO_HEV_PACKETFLOW_RUNNING) {
        result = 13;
        goto stop_wrapper;
    }
    /* The wrapper must duplicate the supplied peer; the caller-owned
     * descriptor remains valid throughout and after the Hev session. */
    if (fcntl (descriptors[0], F_GETFD) < 0) {
        result = 14;
        goto stop_wrapper;
    }
stop_wrapper:
    /* Stop Hev before the caller closes its adopted-stream endpoint. */
    if (FoloHevPacketFlowStop () != FOLO_HEV_PACKETFLOW_OK && result == 0)
        result = 15;
    if (FoloHevPacketFlowState () != FOLO_HEV_PACKETFLOW_IDLE && result == 0)
        result = 16;
    if (result == 0 && fcntl (descriptors[0], F_GETFD) < 0)
        result = 17;
    if (shutdown (descriptors[0], SHUT_RDWR) != 0 && result == 0)
        result = 18;

close_descriptors:
    close (descriptors[0]);
    close (descriptors[1]);
    if (result == 0)
        puts ("hev_host_runtime=pass start=running stop=idle owner=dup");
    return result;
}
