// SPDX-License-Identifier: MPL-2.0
package router

import (
	"context"
	"fmt"
	"net"
	"time"
)

type DirectDialer struct {
	dialer *net.Dialer
}

func NewDirectDialer() *DirectDialer {
	return &DirectDialer{
		dialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 15 * time.Second,
		},
	}
}

func (d *DirectDialer) DialTCP(ctx context.Context, dest string, port uint16) (net.Conn, error) {
	target := net.JoinHostPort(dest, fmt.Sprintf("%d", port))
	return d.dialer.DialContext(ctx, "tcp", target)
}

func (d *DirectDialer) DialUDP(ctx context.Context, dest string, port uint16) (net.Conn, error) {
	target := net.JoinHostPort(dest, fmt.Sprintf("%d", port))
	return d.dialer.DialContext(ctx, "udp", target)
}
