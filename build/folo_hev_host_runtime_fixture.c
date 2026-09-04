// SPDX-License-Identifier: Apache-2.0

#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "folo_hev_packetflow.h"
#include "hev-main.h"

static const char config[] =
    "tunnel:\n"
    "  name: folo-packetflow\n"
    "  mtu: 8500\n"
    "  ipv4: 198.18.0.1\n"
    "  ipv6: fc00::1\n"
    "  icmp: 'reply'\n"
    "socks5:\n"
    "  port: 1\n"
    "  address: 127.0.0.1\n"
    "  udp: 'udp'\n";

static const char invalid_config[] =
    "tunnel:\n"
    "  mtu: [\n";

static uint16_t
checksum (const uint8_t *bytes, size_t length)
{
    uint32_t sum = 0;

    while (length >= 2) {
        sum += ((uint16_t)bytes[0] << 8) | bytes[1];
        bytes += 2;
        length -= 2;
    }
    if (length)
        sum += (uint16_t)bytes[0] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static int
write_all (int fd, const uint8_t *bytes, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write (fd, bytes + offset, length - offset);
        if (written <= 0)
            return -1;
        offset += (size_t)written;
    }
    return 0;
}

static int
read_exact_with_timeout (int fd, uint8_t *bytes, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        struct pollfd descriptor = { .fd = fd, .events = POLLIN };
        ssize_t read_count;
        int ready = poll (&descriptor, 1, 1000);
        if (ready <= 0 || !(descriptor.revents & (POLLIN | POLLHUP)))
            return -1;
        read_count = read (fd, bytes + offset, length - offset);
        if (read_count <= 0)
            return -1;
        offset += (size_t)read_count;
    }
    return 0;
}

static int
run_icmp_roundtrip (int peer_fd)
{
    uint8_t packet[28] = { 0 };
    uint8_t frame[12 + sizeof (packet)] = { 0 };
    uint8_t response[12 + sizeof (packet)] = { 0 };

    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = sizeof (packet);
    packet[8] = 64;
    packet[9] = 1;
    packet[12] = 198;
    packet[13] = 18;
    packet[14] = 0;
    packet[15] = 2;
    packet[16] = 198;
    packet[17] = 18;
    packet[18] = 0;
    packet[19] = 1;
    packet[20] = 8;
    packet[24] = 0x12;
    packet[25] = 0x34;
    packet[27] = 1;
    packet[10] = (uint8_t)(checksum (packet, 20) >> 8);
    packet[11] = (uint8_t)checksum (packet, 20);
    {
        uint16_t icmp_checksum = checksum (packet + 20, 8);
        packet[22] = (uint8_t)(icmp_checksum >> 8);
        packet[23] = (uint8_t)icmp_checksum;
    }

    frame[0] = 0x46;
    frame[1] = 0x50;
    frame[2] = 1;
    frame[3] = 4;
    frame[4] = 1;
    frame[8] = 0;
    frame[9] = sizeof (packet);
    memcpy (frame + 12, packet, sizeof (packet));
    if (write_all (peer_fd, frame, sizeof (frame)) < 0)
        return -1;
    if (read_exact_with_timeout (peer_fd, response, sizeof (response)) < 0)
        return -1;
    if (response[0] != 0x46 || response[1] != 0x50 || response[2] != 1 ||
        response[3] != 4 || response[4] != 1 || response[8] != 0 ||
        response[9] != sizeof (packet) || memcmp (response + 12, packet,
                                                   sizeof (packet)) == 0)
        return -1;
    if (response[12] != 0x45 || response[12 + 20] != 0 ||
        response[12 + 21] != 0 || response[12 + 24] != 0x12 ||
        response[12 + 25] != 0x34 || response[12 + 26] != 0 ||
        response[12 + 27] != 1 || response[12 + 12] != 198 ||
        response[12 + 13] != 18 || response[12 + 14] != 0 ||
        response[12 + 15] != 1 || response[12 + 16] != 198 ||
        response[12 + 17] != 18 || response[12 + 18] != 0 ||
        response[12 + 19] != 2)
        return -1;
    return 0;
}

int
main (void)
{
    int descriptors[2] = { -1, -1 };
    int eof_descriptors[2] = { -1, -1 };
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
    if (run_icmp_roundtrip (descriptors[1]) != 0) {
        result = 14;
        goto stop_wrapper;
    }
    /* The wrapper must duplicate the supplied peer; the caller-owned
     * descriptor remains valid throughout and after the Hev session. */
    if (fcntl (descriptors[0], F_GETFD) < 0) {
        result = 15;
        goto stop_wrapper;
    }
stop_wrapper:
    /* Stop Hev before the caller closes its adopted-stream endpoint. */
    if (FoloHevPacketFlowStop () != FOLO_HEV_PACKETFLOW_OK && result == 0)
        result = 16;
    if (FoloHevPacketFlowState () != FOLO_HEV_PACKETFLOW_IDLE && result == 0)
        result = 17;
    if (result == 0 && fcntl (descriptors[0], F_GETFD) < 0)
        result = 18;

    if (result == 0 &&
        FoloHevPacketFlowStart ((const uint8_t *)config, strlen (config),
                                descriptors[0]) != FOLO_HEV_PACKETFLOW_OK)
        result = 22;
    if (result == 0 && FoloHevPacketFlowState () != FOLO_HEV_PACKETFLOW_RUNNING)
        result = 23;
    if (result == 0)
        hev_socks5_tunnel_quit ();
    for (int attempt = 0; result == 0 && attempt < 100; attempt++) {
        if (FoloHevPacketFlowState () == FOLO_HEV_PACKETFLOW_IDLE)
            break;
        usleep (1000);
    }
    if (result == 0 && FoloHevPacketFlowState () != FOLO_HEV_PACKETFLOW_IDLE)
        result = 24;
    if (FoloHevPacketFlowStop () != FOLO_HEV_PACKETFLOW_OK && result == 0)
        result = 25;
    if (result == 0 && fcntl (descriptors[0], F_GETFD) < 0)
        result = 26;
    if (result != 0)
        goto close_descriptors;

    /* A caller-side shutdown must make the adopted Hev worker exit by
     * itself, rather than leaving the lwIP reader spinning on EOF. */
    if (socketpair (AF_UNIX, SOCK_STREAM, 0, eof_descriptors) != 0) {
        result = 27;
        goto close_descriptors;
    }
    if (FoloHevPacketFlowStart ((const uint8_t *)config, strlen (config),
                                eof_descriptors[0]) != FOLO_HEV_PACKETFLOW_OK) {
        result = 28;
        goto close_eof_descriptors;
    }
    if (FoloHevPacketFlowState () != FOLO_HEV_PACKETFLOW_RUNNING) {
        result = 29;
        goto stop_eof_wrapper;
    }
    if (shutdown (eof_descriptors[0], SHUT_RDWR) != 0) {
        result = 30;
        goto stop_eof_wrapper;
    }
    for (int attempt = 0; attempt < 100; attempt++) {
        if (FoloHevPacketFlowState () == FOLO_HEV_PACKETFLOW_IDLE)
            break;
        usleep (1000);
    }
    if (FoloHevPacketFlowState () != FOLO_HEV_PACKETFLOW_IDLE) {
        result = 31;
        goto stop_eof_wrapper;
    }
stop_eof_wrapper:
    if (FoloHevPacketFlowStop () != FOLO_HEV_PACKETFLOW_OK && result == 0)
        result = 32;
    if (result == 0 && fcntl (eof_descriptors[0], F_GETFD) < 0)
        result = 33;

close_eof_descriptors:
    close (eof_descriptors[0]);
    close (eof_descriptors[1]);

close_descriptors:
    close (descriptors[0]);
    close (descriptors[1]);
    if (result == 0)
        puts ("hev_host_runtime=pass start=running stop=idle owner=dup");
    return result;
}
