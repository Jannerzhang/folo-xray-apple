// SPDX-License-Identifier: Apache-2.0

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "folo_hev_packetflow.h"
#include "hev-main.h"

typedef struct {
    int tcp_listen_fd;
    uint16_t tcp_port;
    int udp_relay_fd;
    uint16_t udp_port;
    int client_tcp_fd;
    volatile int stop;
    pthread_t thread;
} MockSocks5;

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

static uint16_t
calc_transport_checksum (const uint8_t *src_ip, const uint8_t *dst_ip,
                         uint8_t proto, const uint8_t *segment, size_t seg_len)
{
    uint8_t pseudo[12];
    memcpy (pseudo, src_ip, 4);
    memcpy (pseudo + 4, dst_ip, 4);
    pseudo[8] = 0;
    pseudo[9] = proto;
    pseudo[10] = (uint8_t)(seg_len >> 8);
    pseudo[11] = (uint8_t)(seg_len & 0xff);

    uint32_t sum = 0;
    for (size_t i = 0; i < 12; i += 2) {
        sum += ((uint16_t)pseudo[i] << 8) | pseudo[i + 1];
    }
    size_t length = seg_len;
    const uint8_t *bytes = segment;
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
read_framed_packet (int peer_fd, uint8_t *packet_buf, size_t max_buf_len, size_t *out_packet_len)
{
    uint8_t frame[12];
    if (read_exact_with_timeout (peer_fd, frame, 12) < 0)
        return -1;
    if (frame[0] != 0x46 || frame[1] != 0x50 || frame[2] != 1)
        return -1;
    size_t pkt_len = ((size_t)frame[8] << 8) | frame[9];
    if (pkt_len > max_buf_len)
        return -1;
    if (read_exact_with_timeout (peer_fd, packet_buf, pkt_len) < 0)
        return -1;
    *out_packet_len = pkt_len;
    return 0;
}

static void *
mock_socks5_worker (void *arg)
{
    MockSocks5 *server = (MockSocks5 *)arg;

    while (!server->stop) {
        struct pollfd pfds[3];
        int nfds = 2;
        pfds[0].fd = server->tcp_listen_fd;
        pfds[0].events = POLLIN;
        pfds[1].fd = server->udp_relay_fd;
        pfds[1].events = POLLIN;
        if (server->client_tcp_fd >= 0) {
            pfds[2].fd = server->client_tcp_fd;
            pfds[2].events = POLLIN | POLLHUP | POLLERR;
            nfds = 3;
        }

        int r = poll (pfds, nfds, 50);
        if (r <= 0)
            continue;
        if (pfds[0].revents & POLLIN) {
            int client_fd = accept (server->tcp_listen_fd, NULL, NULL);
            if (client_fd >= 0) {
                uint8_t buf[512];
                // Greeting: 0x05, 0x01, 0x00
                if (read_exact_with_timeout (client_fd, buf, 3) == 0 && buf[0] == 5) {
                    uint8_t method_reply[2] = { 5, 0 };
                    write_all (client_fd, method_reply, 2);
                    // Request: 0x05, CMD, 0x00, ATYP
                    if (read_exact_with_timeout (client_fd, buf, 4) == 0 && buf[0] == 5) {
                        uint8_t cmd = buf[1];
                        uint8_t atyp = buf[3];
                        int addr_len = 0;
                        if (atyp == 1) addr_len = 4;
                        else if (atyp == 4) addr_len = 16;
                        else if (atyp == 3) {
                            uint8_t dlen = 0;
                            read_exact_with_timeout (client_fd, &dlen, 1);
                            addr_len = dlen;
                        }
                        uint8_t addr_and_port[256];
                        read_exact_with_timeout (client_fd, addr_and_port, addr_len + 2);

                        if (cmd == 1) { // CONNECT
                            uint8_t reply[10] = { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 };
                            write_all (client_fd, reply, 10);
                            // Read TCP payload
                            ssize_t n = read (client_fd, buf, sizeof (buf));
                            if (n > 0) {
                                write_all (client_fd, (const uint8_t *)"PONG\n", 5);
                            }
                            while (read (client_fd, buf, sizeof (buf)) > 0);
                            close (client_fd);
                        } else if (cmd == 3) { // UDP ASSOCIATE
                            uint8_t reply[10] = {
                                5, 0, 0, 1, 127, 0, 0, 1,
                                (uint8_t)(server->udp_port >> 8),
                                (uint8_t)(server->udp_port & 0xff)
                            };
                            write_all (client_fd, reply, 10);
                            if (server->client_tcp_fd >= 0)
                                close (server->client_tcp_fd);
                            server->client_tcp_fd = client_fd;
                        } else {
                            close (client_fd);
                        }
                    } else {
                        close (client_fd);
                    }
                } else {
                    close (client_fd);
                }
            }
        }
        if (pfds[1].revents & POLLIN) {
            uint8_t ubuf[2048];
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof (client_addr);
            ssize_t n = recvfrom (server->udp_relay_fd, ubuf, sizeof (ubuf), 0,
                                  (struct sockaddr *)&client_addr, &addr_len);
            if (n >= 10 && ubuf[0] == 0 && ubuf[1] == 0 && ubuf[2] == 0 && ubuf[3] == 1) {
                // Header: RSV(2), FRAG(1), ATYP(1), DST(4), PORT(2), DATA
                uint8_t resp[128];
                memcpy (resp, ubuf, 10);
                const char pong[] = "UDP_PONG\n";
                size_t pong_len = strlen (pong);
                memcpy (resp + 10, pong, pong_len);
                sendto (server->udp_relay_fd, resp, 10 + pong_len, 0,
                        (struct sockaddr *)&client_addr, addr_len);
            }
        }
        if (nfds == 3 && (pfds[2].revents & (POLLIN | POLLHUP | POLLERR))) {
            uint8_t dump[64];
            if (read (server->client_tcp_fd, dump, sizeof (dump)) <= 0) {
                close (server->client_tcp_fd);
                server->client_tcp_fd = -1;
            }
        }
    }
    return NULL;
}

static int
mock_socks5_start (MockSocks5 *server)
{
    memset (server, 0, sizeof (*server));
    server->client_tcp_fd = -1;
    server->tcp_listen_fd = socket (AF_INET, SOCK_STREAM, 0);
    if (server->tcp_listen_fd < 0)
        return -1;
    server->udp_relay_fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (server->udp_relay_fd < 0) {
        close (server->tcp_listen_fd);
        return -1;
    }

    int opt = 1;
    setsockopt (server->tcp_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt));

    struct sockaddr_in sin;
    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind (server->tcp_listen_fd, (struct sockaddr *)&sin, sizeof (sin)) < 0 ||
        listen (server->tcp_listen_fd, 5) < 0) {
        close (server->tcp_listen_fd);
        close (server->udp_relay_fd);
        return -1;
    }

    socklen_t slen = sizeof (sin);
    if (getsockname (server->tcp_listen_fd, (struct sockaddr *)&sin, &slen) < 0) {
        close (server->tcp_listen_fd);
        close (server->udp_relay_fd);
        return -1;
    }
    server->tcp_port = ntohs (sin.sin_port);

    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    sin.sin_port = 0;

    if (bind (server->udp_relay_fd, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
        close (server->tcp_listen_fd);
        close (server->udp_relay_fd);
        return -1;
    }

    slen = sizeof (sin);
    if (getsockname (server->udp_relay_fd, (struct sockaddr *)&sin, &slen) < 0) {
        close (server->tcp_listen_fd);
        close (server->udp_relay_fd);
        return -1;
    }
    server->udp_port = ntohs (sin.sin_port);

    if (pthread_create (&server->thread, NULL, mock_socks5_worker, server) != 0) {
        close (server->tcp_listen_fd);
        close (server->udp_relay_fd);
        return -1;
    }
    return 0;
}

static void
mock_socks5_stop (MockSocks5 *server)
{
    server->stop = 1;
    if (server->tcp_listen_fd >= 0) {
        close (server->tcp_listen_fd);
        server->tcp_listen_fd = -1;
    }
    if (server->udp_relay_fd >= 0) {
        close (server->udp_relay_fd);
        server->udp_relay_fd = -1;
    }
    if (server->client_tcp_fd >= 0) {
        close (server->client_tcp_fd);
        server->client_tcp_fd = -1;
    }
    pthread_join (server->thread, NULL);
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

static int
send_tcp_packet (int peer_fd, const uint8_t *src_ip, const uint8_t *dst_ip,
                 uint16_t src_port, uint16_t dst_port,
                 uint32_t seq, uint32_t ack, uint8_t flags,
                 const uint8_t *payload, size_t payload_len)
{
    size_t tcp_len = 20 + payload_len;
    size_t ip_len = 20 + tcp_len;
    uint8_t frame[12 + ip_len];
    memset (frame, 0, sizeof (frame));

    frame[0] = 0x46;
    frame[1] = 0x50;
    frame[2] = 1;
    frame[3] = 4;
    frame[4] = 6;
    frame[8] = (uint8_t)(ip_len >> 8);
    frame[9] = (uint8_t)(ip_len & 0xff);

    uint8_t *ip = frame + 12;
    ip[0] = 0x45;
    ip[2] = (uint8_t)(ip_len >> 8);
    ip[3] = (uint8_t)(ip_len & 0xff);
    ip[4] = 0x12; ip[5] = 0x34;
    ip[6] = 0x40; // DF
    ip[8] = 64;   // TTL
    ip[9] = 6;    // TCP
    memcpy (ip + 12, src_ip, 4);
    memcpy (ip + 16, dst_ip, 4);
    uint16_t ip_ck = checksum (ip, 20);
    ip[10] = (uint8_t)(ip_ck >> 8);
    ip[11] = (uint8_t)(ip_ck & 0xff);

    uint8_t *tcp = ip + 20;
    tcp[0] = (uint8_t)(src_port >> 8);
    tcp[1] = (uint8_t)(src_port & 0xff);
    tcp[2] = (uint8_t)(dst_port >> 8);
    tcp[3] = (uint8_t)(dst_port & 0xff);
    tcp[4] = (uint8_t)(seq >> 24);
    tcp[5] = (uint8_t)(seq >> 16);
    tcp[6] = (uint8_t)(seq >> 8);
    tcp[7] = (uint8_t)(seq & 0xff);
    tcp[8] = (uint8_t)(ack >> 24);
    tcp[9] = (uint8_t)(ack >> 16);
    tcp[10] = (uint8_t)(ack >> 8);
    tcp[11] = (uint8_t)(ack & 0xff);
    tcp[12] = 0x50; // header len 20
    tcp[13] = flags;
    tcp[14] = 0xff; tcp[15] = 0xff; // window 65535
    if (payload && payload_len > 0)
        memcpy (tcp + 20, payload, payload_len);

    uint16_t tcp_ck = calc_transport_checksum (src_ip, dst_ip, 6, tcp, tcp_len);
    tcp[16] = (uint8_t)(tcp_ck >> 8);
    tcp[17] = (uint8_t)(tcp_ck & 0xff);

    return write_all (peer_fd, frame, sizeof (frame));
}

static int
run_tcp_roundtrip (int peer_fd)
{
    const uint8_t client_ip[4] = { 198, 18, 0, 2 };
    const uint8_t server_ip[4] = { 1, 2, 3, 4 };
    uint16_t client_port = 12345;
    uint16_t server_port = 80;
    uint32_t client_seq = 0x10000001;

    // 1. Send SYN
    if (send_tcp_packet (peer_fd, client_ip, server_ip, client_port, server_port,
                         client_seq, 0, 0x02, NULL, 0) < 0)
        return -1;

    // 2. Read SYN-ACK
    uint8_t pkt[1500];
    size_t pkt_len = 0;
    if (read_framed_packet (peer_fd, pkt, sizeof (pkt), &pkt_len) < 0)
        return -1;
    if (pkt_len < 40 || pkt[0] != 0x45 || pkt[9] != 6)
        return -1;
    const uint8_t *tcp = pkt + 20;
    if (tcp[13] != 0x12) // SYN | ACK
        return -1;
    uint32_t server_seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
                          ((uint32_t)tcp[6] << 8) | tcp[7];

    // 3. Send ACK
    client_seq++;
    if (send_tcp_packet (peer_fd, client_ip, server_ip, client_port, server_port,
                         client_seq, server_seq + 1, 0x10, NULL, 0) < 0)
        return -1;

    // 4. Send DATA ("PING\n")
    const char ping[] = "PING\n";
    size_t ping_len = strlen (ping);
    if (send_tcp_packet (peer_fd, client_ip, server_ip, client_port, server_port,
                         client_seq, server_seq + 1, 0x18, (const uint8_t *)ping, ping_len) < 0)
        return -1;

    // 5. Read response packet(s) until we get PONG
    int got_pong = 0;
    for (int attempt = 0; attempt < 10; attempt++) {
        if (read_framed_packet (peer_fd, pkt, sizeof (pkt), &pkt_len) < 0)
            break;
        if (pkt_len < 40 || pkt[0] != 0x45 || pkt[9] != 6)
            continue;
        tcp = pkt + 20;
        size_t tcp_hdr_len = ((tcp[12] >> 4) & 0x0f) * 4;
        if (pkt_len >= 20 + tcp_hdr_len + 5) {
            const uint8_t *data = tcp + tcp_hdr_len;
            if (memcmp (data, "PONG\n", 5) == 0) {
                got_pong = 1;
                server_seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
                             ((uint32_t)tcp[6] << 8) | tcp[7];
                server_seq += (pkt_len - 20 - tcp_hdr_len);
                break;
            }
        }
    }
    if (!got_pong)
        return -1;

    // 6. Send FIN|ACK
    client_seq += ping_len;
    if (send_tcp_packet (peer_fd, client_ip, server_ip, client_port, server_port,
                         client_seq, server_seq, 0x11, NULL, 0) < 0)
        return -1;

    // 7. Read FIN-ACK / ACK
    for (int attempt = 0; attempt < 10; attempt++) {
        if (read_framed_packet (peer_fd, pkt, sizeof (pkt), &pkt_len) < 0)
            break;
        if (pkt_len >= 40 && pkt[0] == 0x45 && pkt[9] == 6) {
            tcp = pkt + 20;
            if (tcp[13] & 0x01) { // FIN received
                server_seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
                             ((uint32_t)tcp[6] << 8) | tcp[7];
                // Final ACK
                send_tcp_packet (peer_fd, client_ip, server_ip, client_port, server_port,
                                 client_seq + 1, server_seq + 1, 0x10, NULL, 0);
                break;
            }
        }
    }

    return 0;
}

static int
run_udp_roundtrip (int peer_fd)
{
    // Drain any leftover TCP frames from previous test
    for (int i = 0; i < 5; i++) {
        struct pollfd pfd = { .fd = peer_fd, .events = POLLIN };
        if (poll (&pfd, 1, 10) <= 0)
            break;
        uint8_t drain[1500];
        size_t dlen = 0;
        if (read_framed_packet (peer_fd, drain, sizeof (drain), &dlen) < 0)
            break;
    }

    const uint8_t client_ip[4] = { 198, 18, 0, 2 };
    const uint8_t server_ip[4] = { 1, 2, 3, 4 };
    uint16_t client_port = 12346;
    uint16_t server_port = 5353;
    const char ping[] = "UDP_PING\n";
    size_t payload_len = strlen (ping);
    size_t udp_len = 8 + payload_len;
    size_t ip_len = 20 + udp_len;

    uint8_t frame[12 + ip_len];
    memset (frame, 0, sizeof (frame));
    frame[0] = 0x46; frame[1] = 0x50; frame[2] = 1; frame[3] = 4; frame[4] = 17;
    frame[8] = (uint8_t)(ip_len >> 8); frame[9] = (uint8_t)(ip_len & 0xff);

    uint8_t *ip = frame + 12;
    ip[0] = 0x45;
    ip[2] = (uint8_t)(ip_len >> 8); ip[3] = (uint8_t)(ip_len & 0xff);
    ip[4] = 0x34; ip[5] = 0x56;
    ip[8] = 64; ip[9] = 17;
    memcpy (ip + 12, client_ip, 4);
    memcpy (ip + 16, server_ip, 4);
    uint16_t ip_ck = checksum (ip, 20);
    ip[10] = (uint8_t)(ip_ck >> 8); ip[11] = (uint8_t)(ip_ck & 0xff);

    uint8_t *udp = ip + 20;
    udp[0] = (uint8_t)(client_port >> 8); udp[1] = (uint8_t)(client_port & 0xff);
    udp[2] = (uint8_t)(server_port >> 8); udp[3] = (uint8_t)(server_port & 0xff);
    udp[4] = (uint8_t)(udp_len >> 8); udp[5] = (uint8_t)(udp_len & 0xff);
    memcpy (udp + 8, ping, payload_len);

    uint16_t udp_ck = calc_transport_checksum (client_ip, server_ip, 17, udp, udp_len);
    udp[6] = (uint8_t)(udp_ck >> 8); udp[7] = (uint8_t)(udp_ck & 0xff);

    if (write_all (peer_fd, frame, sizeof (frame)) < 0)
        return -1;

    uint8_t pkt[1500];
    size_t pkt_len = 0;
    for (int attempt = 0; attempt < 10; attempt++) {
        if (read_framed_packet (peer_fd, pkt, sizeof (pkt), &pkt_len) < 0)
            break;
        if (pkt_len >= 28 && pkt[0] == 0x45 && pkt[9] == 17) {
            const uint8_t *resp_udp = pkt + 20;
            size_t resp_payload_len = pkt_len - 28;
            if (resp_payload_len >= 9 && memcmp (resp_udp + 8, "UDP_PONG\n", 9) == 0) {
                return 0;
            }
        }
    }
    return -1;
}

int
main (void)
{
    int descriptors[2] = { -1, -1 };
    int eof_descriptors[2] = { -1, -1 };
    int result = 0;
    MockSocks5 mock_socks;
    memset (&mock_socks, 0, sizeof (mock_socks));

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

    if (mock_socks5_start (&mock_socks) != 0) {
        result = 21;
        goto close_descriptors;
    }

    char dynamic_config[512];
    snprintf (dynamic_config, sizeof (dynamic_config),
              "tunnel:\n"
              "  name: folo-packetflow\n"
              "  mtu: 8500\n"
              "  ipv4: 198.18.0.1\n"
              "  ipv6: fc00::1\n"
              "  icmp: 'reply'\n"
              "socks5:\n"
              "  port: %u\n"
              "  address: 127.0.0.1\n"
              "  udp: 'udp'\n",
              mock_socks.tcp_port);

    if (FoloHevPacketFlowStart ((const uint8_t *)dynamic_config, strlen (dynamic_config),
                                descriptors[0]) != FOLO_HEV_PACKETFLOW_OK) {
        result = 12;
        goto stop_mock;
    }
    if (FoloHevPacketFlowState () != FOLO_HEV_PACKETFLOW_RUNNING) {
        result = 13;
        goto stop_wrapper;
    }

    // 1. ICMP roundtrip
    if (run_icmp_roundtrip (descriptors[1]) != 0) {
        result = 14;
        goto stop_wrapper;
    }

    // 2. TCP SOCKS5 CONNECT roundtrip
    if (run_tcp_roundtrip (descriptors[1]) != 0) {
        result = 34;
        goto stop_wrapper;
    }

    // 3. UDP SOCKS5 ASSOCIATE roundtrip
    if (run_udp_roundtrip (descriptors[1]) != 0) {
        result = 35;
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
        FoloHevPacketFlowStart ((const uint8_t *)dynamic_config, strlen (dynamic_config),
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

stop_mock:
    mock_socks5_stop (&mock_socks);
    if (result != 0)
        goto close_descriptors;

    /* A caller-side shutdown must make the adopted Hev worker exit by
     * itself, rather than leaving the lwIP reader spinning on EOF. */
    if (socketpair (AF_UNIX, SOCK_STREAM, 0, eof_descriptors) != 0) {
        result = 27;
        goto close_descriptors;
    }
    if (FoloHevPacketFlowStart ((const uint8_t *)dynamic_config, strlen (dynamic_config),
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
        puts ("hev_host_runtime=pass start=running stop=idle owner=dup icmp=pass tcp=pass udp=pass");
    return result;
}
