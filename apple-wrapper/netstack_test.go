//go:build darwin || ios
// +build darwin ios

// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/xtls/xray-core/core"
)

func TestGVisorTCPForwarderChannelEcho(t *testing.T) {
	const (
		serverPort = 18080
		mtu        = 1500
	)
	serverAddr := tcpip.AddrFromSlice([]byte{10, 0, 0, 1})
	clientAddr := tcpip.AddrFromSlice([]byte{10, 0, 0, 2})

	serverLink := channel.New(128, mtu, "")
	clientLink := channel.New(128, mtu, "")
	serverStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	clientStack := newEchoTestStack(t, clientLink, &clientAddr)
	accepted := make(chan struct{})
	forwarder := tcp.NewForwarder(serverStack, netstackTCPReceiveWindow, 1, func(request *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := request.CreateEndpoint(&wq)
		if err != nil {
			request.Complete(true)
			return
		}
		request.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)
		defer conn.Close()
		defer close(accepted)
		_, _ = io.Copy(conn, conn)
	})
	serverStack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
	configureEchoTestNIC(t, serverStack, serverLink, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pumpDone := make(chan struct{}, 2)
	go pumpChannel(ctx, clientLink, serverLink, pumpDone)
	go pumpChannel(ctx, serverLink, clientLink, pumpDone)

	conn, err := gonet.DialContextTCP(ctx, clientStack, tcpip.FullAddress{
		NIC:  netstackNICID,
		Addr: serverAddr,
		Port: serverPort,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialContextTCP failed: %v", err)
	}

	message := []byte("gvisor netstack echo")
	if _, err := conn.Write(message); err != nil {
		conn.Close()
		t.Fatalf("client write failed: %v", err)
	}
	got := make([]byte, len(message))
	if _, err := io.ReadFull(conn, got); err != nil {
		conn.Close()
		t.Fatalf("client read failed: %v", err)
	}
	if string(got) != string(message) {
		conn.Close()
		t.Fatalf("echo mismatch: got %q, want %q", got, message)
	}
	_ = conn.Close()

	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatalf("forwarder echo did not complete: %v", ctx.Err())
	}

	serverStack.Close()
	clientStack.Close()
	serverLink.Close()
	clientLink.Close()
	cancel()
	<-pumpDone
	<-pumpDone
}

func TestNetstackRuntimeReadWouldBlock(t *testing.T) {
	runtime, err := newNetstackRuntime(&core.Instance{})
	if err != nil {
		t.Fatalf("newNetstackRuntime failed: %v", err)
	}
	defer runtime.close()

	_, err = runtime.readPacket(make([]byte, netstackMaxPacketSize))
	if !errors.Is(err, errNetstackWouldBlock) {
		t.Fatalf("readPacket error = %v, want %v", err, errNetstackWouldBlock)
	}
}

func newEchoTestStack(t *testing.T, link *channel.Endpoint, address *tcpip.Address) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	configureEchoTestNIC(t, s, link, address)
	return s
}

func configureEchoTestNIC(t *testing.T, s *stack.Stack, link *channel.Endpoint, address *tcpip.Address) {
	t.Helper()
	if err := s.CreateNIC(netstackNICID, link); err != nil {
		t.Fatalf("CreateNIC failed: %s", err)
	}
	if address != nil {
		if err := s.AddProtocolAddress(netstackNICID, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: address.WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress failed: %s", err)
		}
	} else {
		if err := s.SetPromiscuousMode(netstackNICID, true); err != nil {
			t.Fatalf("SetPromiscuousMode failed: %s", err)
		}
		if err := s.SetSpoofing(netstackNICID, true); err != nil {
			t.Fatalf("SetSpoofing failed: %s", err)
		}
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: netstackNICID}})
}

func pumpChannel(ctx context.Context, source, destination *channel.Endpoint, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	for {
		pkt := source.ReadContext(ctx)
		if pkt == nil {
			return
		}
		protocol := pkt.NetworkProtocolNumber
		inbound := pkt.CloneToInbound()
		destination.InjectInbound(protocol, inbound)
		inbound.DecRef()
		pkt.DecRef()
	}
}
