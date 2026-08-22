// SPDX-License-Identifier: MPL-2.0
//
// Folo's private PacketFlow adapter consumes these two narrow transport
// seams. They deliberately expose only Xray's already-running outbound
// dispatcher; they do not create listeners or accept generic engine JSON.
package folotun

import (
	"context"
	"fmt"
	gonet "net"
	"strings"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

const MaxEndpointAddressLength = 253

// ValidateEndpointAddress accepts an IP literal or an ASCII DNS name. It is
// intentionally stricter than Xray's generic ParseAddress because this is a
// mobile ABI boundary and must not accept an arbitrary address expression.
func ValidateEndpointAddress(address string) error {
	if address == "" || len(address) > MaxEndpointAddressLength || strings.TrimSpace(address) != address {
		return fmt.Errorf("endpoint address is empty, padded, or too long")
	}
	for _, r := range address {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
			return fmt.Errorf("endpoint address contains a forbidden character")
		}
	}
	if gonet.ParseIP(address) != nil {
		return nil
	}
	labels := strings.Split(address, ".")
	if len(labels) == 0 {
		return fmt.Errorf("endpoint address is invalid")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("endpoint address is not a valid DNS name")
		}
		for _, r := range label {
			if !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return fmt.Errorf("endpoint address is not a valid ASCII DNS name")
			}
		}
	}
	return nil
}

func destination(address string, port uint16, network xnet.Network) (xnet.Destination, error) {
	if port == 0 {
		return xnet.Destination{}, fmt.Errorf("endpoint port is zero")
	}
	if err := ValidateEndpointAddress(address); err != nil {
		return xnet.Destination{}, err
	}
	return xnet.Destination{
		Address: xnet.ParseAddress(address),
		Port:    xnet.Port(port),
		Network: network,
	}, nil
}

// DialTCP dispatches one TCP stream through the running Folo Xray instance.
// The caller owns and closes the returned connection.
func DialTCP(ctx context.Context, instance *core.Instance, address string, port uint16) (gonet.Conn, error) {
	if instance == nil {
		return nil, fmt.Errorf("xray instance is nil")
	}
	dest, err := destination(address, port, xnet.Network_TCP)
	if err != nil {
		return nil, err
	}
	return core.Dial(ctx, instance, dest)
}

// DialUDP creates one Xray dispatcher-backed PacketConn. The caller may use
// WriteTo for multiple destinations and must close the returned connection.
func DialUDP(ctx context.Context, instance *core.Instance) (gonet.PacketConn, error) {
	if instance == nil {
		return nil, fmt.Errorf("xray instance is nil")
	}
	return core.DialUDP(ctx, instance)
}
