//go:build darwin || ios
// +build darwin ios

// SPDX-License-Identifier: MPL-2.0
package main

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func TestNetstackMemoryTuningContract(t *testing.T) {
	if netstackPacketQueueDepth != 32 {
		t.Fatalf("packet queue depth = %d, want 32", netstackPacketQueueDepth)
	}
	if netstackTCPReceiveWindow != 8*1024 {
		t.Fatalf("TCP receive window = %d, want %d", netstackTCPReceiveWindow, 8*1024)
	}
	if netstackMaxTCPAccepts != 8 {
		t.Fatalf("TCP accept budget = %d, want 8", netstackMaxTCPAccepts)
	}
	if netstackMaxConcurrentTCP != 24 || netstackMaxConcurrentUDP != 24 {
		t.Fatalf("flow budgets = TCP %d, UDP %d; want 24 each", netstackMaxConcurrentTCP, netstackMaxConcurrentUDP)
	}
	if netstackTCPHalfCloseGrace != 2*time.Second {
		t.Fatalf("TCP half-close grace = %s, want 2s", netstackTCPHalfCloseGrace)
	}
	if netstackUDPIdleTimeout != 15*time.Second {
		t.Fatalf("UDP idle timeout = %s, want 15s", netstackUDPIdleTimeout)
	}

	// Keep the explicitly bounded transport resources below the budget that
	// motivated this profile. This intentionally excludes Xray/gVisor object
	// overhead, which is not predictable from this wrapper.
	packetQueueBytes := netstackPacketQueueDepth * netstackMTU
	tcpCopyBytes := 2 * netstackMaxConcurrentTCP * netstackCopyBufferSize
	udpCopyBytes := 2 * netstackMaxConcurrentUDP * netstackCopyBufferSize
	if packetQueueBytes+tcpCopyBytes+udpCopyBytes > 448*1024 {
		t.Fatalf("bounded packet/copy buffers = %d bytes, want <= %d", packetQueueBytes+tcpCopyBytes+udpCopyBytes, 448*1024)
	}
}

func TestReadPacketCopiesPayloadWithoutHeaders(t *testing.T) {
	payload := []byte("packet payload that must not include reserved headers")
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 8,
		Payload:            buffer.MakeWithData(payload),
	})

	runtime := &netstackRuntime{
		link:    channel.New(1, netstackMTU, ""),
		pending: pkt,
	}
	dst := make([]byte, len(payload))
	length, err := runtime.readPacket(dst)
	if err != nil {
		t.Fatalf("readPacket() error = %v", err)
	}
	if length != len(payload) {
		t.Fatalf("readPacket() length = %d, want %d", length, len(payload))
	}
	if !bytes.Equal(dst, payload) {
		t.Fatalf("readPacket() payload = %q, want %q", dst, payload)
	}
	if runtime.pending != nil {
		t.Fatal("readPacket() retained a packet after a successful read")
	}
}

func TestReadPacketRetainsOversizedPacket(t *testing.T) {
	payload := []byte("payload larger than the destination")
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 4,
		Payload:            buffer.MakeWithData(payload),
	})
	runtime := &netstackRuntime{
		link:    channel.New(1, netstackMTU, ""),
		pending: pkt,
	}

	length, err := runtime.readPacket(make([]byte, len(payload)-1))
	if !errors.Is(err, errNetstackPacketTooLarge) {
		t.Fatalf("readPacket() error = %v, want %v", err, errNetstackPacketTooLarge)
	}
	if length != len(payload) {
		t.Fatalf("oversized read length = %d, want %d", length, len(payload))
	}
	if runtime.pending == nil {
		t.Fatal("readPacket() dropped an oversized packet")
	}

	dst := make([]byte, len(payload))
	length, err = runtime.readPacket(dst)
	if err != nil {
		t.Fatalf("retry readPacket() error = %v", err)
	}
	if length != len(payload) || !bytes.Equal(dst, payload) {
		t.Fatalf("retry readPacket() = (%d, %q), want (%d, %q)", length, dst, len(payload), payload)
	}
}
