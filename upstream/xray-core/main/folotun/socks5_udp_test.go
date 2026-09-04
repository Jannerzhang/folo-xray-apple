// SPDX-License-Identifier: MPL-2.0
package folotun

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestSocks5UDPDatagramRoundTripsIPv4DomainAndIPv6(t *testing.T) {
	cases := []Socks5UDPDatagram{
		{Destination: "127.0.0.1", Port: 53, Payload: []byte("ipv4")},
		{Destination: "resolver.example.com", Port: 5353, Payload: []byte("domain")},
		{Destination: "2001:db8::1", Port: 443, Payload: []byte("ipv6")},
	}
	for _, original := range cases {
		frame, err := EncodeSocks5UDPDatagram(original)
		if err != nil {
			t.Fatalf("encode %q: %v", original.Destination, err)
		}
		decoded, err := DecodeSocks5UDPDatagram(frame)
		if err != nil {
			t.Fatalf("decode %q: %v", original.Destination, err)
		}
		if decoded.Port != original.Port || !bytes.Equal(decoded.Payload, original.Payload) {
			t.Fatalf("decoded = %+v, original = %+v", decoded, original)
		}
		if net.ParseIP(original.Destination) != nil && net.ParseIP(decoded.Destination) == nil {
			t.Fatalf("decoded IP destination = %q", decoded.Destination)
		}
	}
}

func TestSocks5UDPRejectsFragmentsMalformedMetadataAndInvalidDestination(t *testing.T) {
	frame, err := EncodeSocks5UDPDatagram(Socks5UDPDatagram{
		Destination: "127.0.0.1",
		Port:        53,
		Payload:     []byte("payload"),
	})
	if err != nil {
		t.Fatal(err)
	}
	frame[2] = 1
	if _, err := DecodeSocks5UDPDatagram(frame); err == nil {
		t.Fatal("fragmented datagram was accepted")
	}
	if _, err := EncodeSocks5UDPDatagram(Socks5UDPDatagram{Destination: "bad/name", Port: 53}); err == nil {
		t.Fatal("invalid destination was accepted")
	}
	if _, err := DecodeSocks5UDPDatagram([]byte{0, 0, 0, 3}); err == nil {
		t.Fatal("unsupported address type was accepted")
	}
	if _, err := EncodeSocks5UDPDatagram(Socks5UDPDatagram{
		Destination: "127.0.0.1",
		Port:        53,
		Payload:     make([]byte, MaxSocks5UDPDatagramSize),
	}); err == nil {
		t.Fatal("oversized datagram was accepted")
	}
}

func TestSocks5UDPNATTableBoundsAndIdleExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	table := NewSocks5UDPNATTable(2, 10*time.Second)
	if !table.Admit("127.0.0.1", 53, now) || !table.Admit("198.51.100.1", 443, now) {
		t.Fatal("valid NAT entries were rejected")
	}
	if table.Admit("203.0.113.1", 443, now) {
		t.Fatal("NAT table exceeded its bound")
	}
	if !table.Touch("127.0.0.1", 53, now.Add(8*time.Second)) {
		t.Fatal("existing NAT entry was not refreshed")
	}
	if removed := table.Expire(now.Add(11 * time.Second)); removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	stats := table.Stats()
	if stats.Active != 1 || stats.Rejected != 1 || stats.Expired != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}
