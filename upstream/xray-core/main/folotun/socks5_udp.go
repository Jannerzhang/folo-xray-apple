// SPDX-License-Identifier: MPL-2.0
//
// RFC 1928 UDP datagrams and a bounded association table for the Folo
// PacketFlow evaluation. This boundary is independent of Hev's private
// UDP-in-TCP behavior and only carries standard SOCKS5 UDP relay metadata.
package folotun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	MaxSocks5UDPDatagramSize = 65_535
	defaultSocks5NATEntries  = 32
	defaultSocks5NATIdle     = 30 * time.Second
)

var errSocks5UDPDatagram = errors.New("SOCKS5 UDP datagram rejected")

// Socks5UDPDatagram is one standard RFC 1928 UDP relay datagram. Payload is
// copied on decode and callers retain ownership of the input/output values.
type Socks5UDPDatagram struct {
	Destination string
	Port        uint16
	Payload     []byte
}

// EncodeSocks5UDPDatagram serializes one SOCKS5 UDP request/response payload.
// Only FRAG=0 is emitted; fragmented UDP is deliberately not implemented.
func EncodeSocks5UDPDatagram(datagram Socks5UDPDatagram) ([]byte, error) {
	if datagram.Port == 0 {
		return nil, errSocks5UDPDatagram
	}
	atyp, address, err := socks5UDPAddress(datagram.Destination)
	if err != nil {
		return nil, err
	}
	if len(datagram.Payload) > MaxSocks5UDPDatagramSize-(4+len(address)+2) {
		return nil, errSocks5UDPDatagram
	}
	frame := make([]byte, 4+len(address)+2+len(datagram.Payload))
	frame[3] = atyp
	offset := 4
	copy(frame[offset:], address)
	offset += len(address)
	binary.BigEndian.PutUint16(frame[offset:offset+2], datagram.Port)
	offset += 2
	copy(frame[offset:], datagram.Payload)
	return frame, nil
}

// DecodeSocks5UDPDatagram validates and copies one standard SOCKS5 UDP frame.
// RSV, FRAG, address type, destination and port are all checked before the
// payload is returned.
func DecodeSocks5UDPDatagram(frame []byte) (Socks5UDPDatagram, error) {
	if len(frame) < 4 || len(frame) > MaxSocks5UDPDatagramSize || frame[0] != 0 || frame[1] != 0 || frame[2] != 0 {
		return Socks5UDPDatagram{}, errSocks5UDPDatagram
	}
	offset := 4
	var destination string
	switch frame[3] {
	case 0x01:
		if len(frame) < offset+4+2 {
			return Socks5UDPDatagram{}, errSocks5UDPDatagram
		}
		destination = net.IP(frame[offset : offset+4]).String()
		offset += 4
	case 0x03:
		if len(frame) < offset+1 {
			return Socks5UDPDatagram{}, errSocks5UDPDatagram
		}
		length := int(frame[offset])
		offset++
		if length == 0 || length > MaxEndpointAddressLength || len(frame) < offset+length+2 {
			return Socks5UDPDatagram{}, errSocks5UDPDatagram
		}
		destination = string(frame[offset : offset+length])
		offset += length
	case 0x04:
		if len(frame) < offset+16+2 {
			return Socks5UDPDatagram{}, errSocks5UDPDatagram
		}
		destination = net.IP(frame[offset : offset+16]).String()
		offset += 16
	default:
		return Socks5UDPDatagram{}, errSocks5UDPDatagram
	}
	if err := ValidateEndpointAddress(destination); err != nil || len(frame) < offset+2 {
		return Socks5UDPDatagram{}, errSocks5UDPDatagram
	}
	port := binary.BigEndian.Uint16(frame[offset : offset+2])
	if port == 0 {
		return Socks5UDPDatagram{}, errSocks5UDPDatagram
	}
	offset += 2
	payload := append([]byte(nil), frame[offset:]...)
	return Socks5UDPDatagram{Destination: destination, Port: port, Payload: payload}, nil
}

func socks5UDPAddress(destination string) (byte, []byte, error) {
	if err := ValidateEndpointAddress(destination); err != nil {
		return 0, nil, errSocks5UDPDatagram
	}
	if ip := net.ParseIP(destination); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return 0x01, append([]byte(nil), ip4...), nil
		}
		if ip16 := ip.To16(); ip16 != nil {
			return 0x04, append([]byte(nil), ip16...), nil
		}
	}
	if len(destination) > 253 {
		return 0, nil, fmt.Errorf("SOCKS5 UDP domain is too long")
	}
	return 0x03, append([]byte{byte(len(destination))}, destination...), nil
}

// Socks5UDPNATTable bounds destination associations for one SOCKS5 UDP
// relay. Entries are refreshed by Admit/Touch and expire after idleTimeout;
// no packet contents or credentials are retained.
type Socks5UDPNATTable struct {
	mu          sync.Mutex
	maxEntries  int
	idleTimeout time.Duration
	entries     map[string]time.Time
	rejected    uint64
	expired     uint64
}

type Socks5UDPNATStats struct {
	Active   int    `json:"active"`
	Max      int    `json:"max"`
	Rejected uint64 `json:"rejected"`
	Expired  uint64 `json:"expired"`
}

func NewSocks5UDPNATTable(maxEntries int, idleTimeout time.Duration) *Socks5UDPNATTable {
	if maxEntries <= 0 {
		maxEntries = defaultSocks5NATEntries
	}
	if idleTimeout <= 0 {
		idleTimeout = defaultSocks5NATIdle
	}
	return &Socks5UDPNATTable{
		maxEntries:  maxEntries,
		idleTimeout: idleTimeout,
		entries:     make(map[string]time.Time),
	}
}

func (t *Socks5UDPNATTable) Admit(destination string, port uint16, now time.Time) bool {
	if port == 0 || ValidateEndpointAddress(destination) != nil {
		t.mu.Lock()
		t.rejected++
		t.mu.Unlock()
		return false
	}
	key := net.JoinHostPort(destination, fmt.Sprintf("%d", port))
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked(now)
	if _, ok := t.entries[key]; ok {
		t.entries[key] = now
		return true
	}
	if len(t.entries) >= t.maxEntries {
		t.rejected++
		return false
	}
	t.entries[key] = now
	return true
}

func (t *Socks5UDPNATTable) Touch(destination string, port uint16, now time.Time) bool {
	if port == 0 {
		return false
	}
	key := net.JoinHostPort(destination, fmt.Sprintf("%d", port))
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expireLocked(now)
	if _, ok := t.entries[key]; !ok {
		return false
	}
	t.entries[key] = now
	return true
}

func (t *Socks5UDPNATTable) Expire(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.expireLocked(now)
}

func (t *Socks5UDPNATTable) Stats() Socks5UDPNATStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Socks5UDPNATStats{
		Active:   len(t.entries),
		Max:      t.maxEntries,
		Rejected: t.rejected,
		Expired:  t.expired,
	}
}

func (t *Socks5UDPNATTable) expireLocked(now time.Time) int {
	removed := 0
	for key, lastSeen := range t.entries {
		if now.Sub(lastSeen) >= t.idleTimeout {
			delete(t.entries, key)
			removed++
		}
	}
	t.expired += uint64(removed)
	return removed
}
