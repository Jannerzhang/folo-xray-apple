//go:build darwin || ios
// +build darwin ios

// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/main/folotun"
)

const (
	netstackNICID            tcpip.NICID = 1
	netstackMTU                          = 1500
	netstackPacketQueueDepth             = 64
	netstackTCPReceiveWindow             = 16 * 1024
	netstackMaxTCPAccepts                = 16
	netstackMaxPacketSize                = 64 * 1024
	netstackMaxConcurrentTCP             = 64
	netstackMaxConcurrentUDP             = 64
	netstackCopyBufferSize               = 8 * 1024
)

var (
	errNetstackPacketTooLarge = errors.New("netstack packet exceeds the configured limit")
	errNetstackMalformed      = errors.New("netstack packet is malformed")
	errNetstackStopped        = errors.New("netstack is stopped")
	errNetstackWouldBlock     = errors.New("netstack packet queue is empty")
)

type netstackRuntime struct {
	stack    *stack.Stack
	link     *channel.Endpoint
	instance *core.Instance

	ctx    context.Context
	cancel context.CancelFunc

	lifeMu sync.RWMutex
	closed bool

	readMu  sync.Mutex
	pending *stack.PacketBuffer

	work sync.WaitGroup

	notify       *netstackPacketNotification
	notifyHandle *channel.NotificationHandle

	tcpTokens chan struct{}
	udpTokens chan struct{}
}

type netstackPacketNotification struct {
	ready chan struct{}
}

func (n *netstackPacketNotification) WriteNotify() {
	select {
	case n.ready <- struct{}{}:
	default:
	}
}

func newNetstackRuntime(instance *core.Instance) (*netstackRuntime, error) {
	if instance == nil {
		return nil, errors.New("xray instance is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			icmp.NewProtocol4,
			icmp.NewProtocol6,
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	tcpReceiveBuffer := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     2 * 1024,
		Default: netstackTCPReceiveWindow,
		Max:     netstackTCPReceiveWindow,
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpReceiveBuffer); err != nil {
		cancel()
		s.Close()
		return nil, fmt.Errorf("configure TCP receive buffer: %s", err)
	}

	tcpSendBuffer := tcpip.TCPSendBufferSizeRangeOption{
		Min:     2 * 1024,
		Default: netstackTCPReceiveWindow,
		Max:     netstackTCPReceiveWindow,
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpSendBuffer); err != nil {
		cancel()
		s.Close()
		return nil, fmt.Errorf("configure TCP send buffer: %s", err)
	}

	link := channel.New(netstackPacketQueueDepth, netstackMTU, "")
	runtime := &netstackRuntime{
		stack:     s,
		link:      link,
		instance:  instance,
		ctx:       ctx,
		cancel:    cancel,
		tcpTokens: make(chan struct{}, netstackMaxConcurrentTCP),
		udpTokens: make(chan struct{}, netstackMaxConcurrentUDP),
	}
	runtime.notify = &netstackPacketNotification{ready: make(chan struct{}, 1)}

	tcpForwarder := tcp.NewForwarder(s, netstackTCPReceiveWindow, netstackMaxTCPAccepts, runtime.handleTCP)
	udpForwarder := udp.NewForwarder(s, runtime.handleUDP)
	// Register handlers before attaching the NIC. The first injected packet may
	// arrive as soon as Attach returns.
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	if err := s.CreateNIC(netstackNICID, link); err != nil {
		cancel()
		s.Close()
		return nil, fmt.Errorf("create netstack NIC: %s", err)
	}
	runtime.notifyHandle = link.AddNotify(runtime.notify)
	if err := s.SetPromiscuousMode(netstackNICID, true); err != nil {
		cancel()
		s.Close()
		return nil, fmt.Errorf("enable netstack promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(netstackNICID, true); err != nil {
		cancel()
		s.Close()
		return nil, fmt.Errorf("enable netstack spoofing: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: netstackNICID},
		{Destination: header.IPv6EmptySubnet, NIC: netstackNICID},
	})

	return runtime, nil
}

func (n *netstackRuntime) injectPacket(packet []byte) error {
	if len(packet) == 0 || len(packet) > netstackMaxPacketSize {
		return errNetstackPacketTooLarge
	}

	n.lifeMu.RLock()
	defer n.lifeMu.RUnlock()
	if n.closed {
		return errNetstackStopped
	}

	var protocol tcpip.NetworkProtocolNumber
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < header.IPv4MinimumSize {
			return errNetstackMalformed
		}
		protocol = ipv4.ProtocolNumber
	case 6:
		if len(packet) < header.IPv6MinimumSize {
			return errNetstackMalformed
		}
		protocol = ipv6.ProtocolNumber
	default:
		return errNetstackMalformed
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	defer pkt.DecRef()
	n.link.InjectInbound(protocol, pkt)
	return nil
}

func (n *netstackRuntime) readPacket(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, errors.New("read buffer is empty")
	}

	n.lifeMu.RLock()
	defer n.lifeMu.RUnlock()
	n.readMu.Lock()
	defer n.readMu.Unlock()
	if n.closed {
		return 0, errNetstackStopped
	}

	pkt := n.pending
	if pkt == nil {
		pkt = n.link.Read()
	}
	if pkt == nil {
		return 0, errNetstackWouldBlock
	}

	slices := pkt.AsSlices()
	length := 0
	for _, part := range slices {
		length += len(part)
	}
	if length > len(dst) {
		n.pending = pkt
		return length, errNetstackPacketTooLarge
	}

	offset := 0
	for _, part := range slices {
		offset += copy(dst[offset:], part)
	}
	n.pending = nil
	pkt.DecRef()
	return offset, nil
}

var tcpBufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, netstackCopyBufferSize)
		return &b
	},
}

func (n *netstackRuntime) handleTCP(request *tcp.ForwarderRequest) {
	select {
	case n.tcpTokens <- struct{}{}:
	default:
		request.Complete(true)
		return
	}

	id := request.ID()
	var wq waiter.Queue
	ep, err := request.CreateEndpoint(&wq)
	if err != nil {
		<-n.tcpTokens
		request.Complete(true)
		return
	}
	request.Complete(false)

	conn := gonet.NewTCPConn(&wq, ep)
	destination, ok := netstackAddress(id.LocalAddress)
	if !ok || id.LocalPort == 0 {
		<-n.tcpTokens
		_ = conn.Close()
		return
	}

	if !n.startWork(func() {
		defer func() { <-n.tcpTokens }()
		n.proxyTCP(conn, destination, id.LocalPort)
	}) {
		<-n.tcpTokens
		_ = conn.Close()
	}
}

func (n *netstackRuntime) startWork(fn func()) bool {
	n.lifeMu.RLock()
	if n.closed {
		n.lifeMu.RUnlock()
		return false
	}
	n.work.Add(1)
	n.lifeMu.RUnlock()

	go func() {
		defer n.work.Done()
		fn()
	}()
	return true
}

func (n *netstackRuntime) proxyTCP(inbound net.Conn, destination string, port uint16) {
	defer inbound.Close()

	outbound, err := folotun.DialTCP(n.ctx, n.instance, destination, port)
	if err != nil {
		return
	}
	defer outbound.Close()

	copyDone := make(chan struct{}, 2)
	go func() {
		bufPtr := tcpBufferPool.Get().(*[]byte)
		defer tcpBufferPool.Put(bufPtr)
		_, _ = io.CopyBuffer(outbound, inbound, *bufPtr)
		if cw, ok := outbound.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = outbound.Close()
		}
		copyDone <- struct{}{}
	}()
	go func() {
		bufPtr := tcpBufferPool.Get().(*[]byte)
		defer tcpBufferPool.Put(bufPtr)
		_, _ = io.CopyBuffer(inbound, outbound, *bufPtr)
		if cw, ok := inbound.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = inbound.Close()
		}
		copyDone <- struct{}{}
	}()
	<-copyDone
	<-copyDone
}

func (n *netstackRuntime) handleUDP(request *udp.ForwarderRequest) bool {
	select {
	case n.udpTokens <- struct{}{}:
	default:
		return false
	}

	id := request.ID()
	destination, ok := netstackUDPAddress(id.LocalAddress, id.LocalPort)
	if !ok {
		<-n.udpTokens
		return false
	}

	var wq waiter.Queue
	ep, err := request.CreateEndpoint(&wq)
	if err != nil {
		<-n.udpTokens
		return false
	}
	inbound := gonet.NewUDPConn(&wq, ep)
	outbound, dialErr := folotun.DialUDP(n.ctx, n.instance)
	if dialErr != nil {
		<-n.udpTokens
		_ = inbound.Close()
		return true
	}

	if !n.startWork(func() {
		defer func() { <-n.udpTokens }()
		defer inbound.Close()
		defer outbound.Close()
		n.proxyUDP(inbound, outbound, destination)
	}) {
		<-n.udpTokens
		_ = inbound.Close()
		_ = outbound.Close()
	}
	return true
}

var udpBufferPool = sync.Pool{
	New: func() interface{} {
		// Use 4096 instead of 64KB for UDP buffers since internet MTU is normally 1500.
		b := make([]byte, 4096)
		return &b
	},
}

func (n *netstackRuntime) proxyUDP(inbound *gonet.UDPConn, outbound net.PacketConn, destination *net.UDPAddr) {
	copyDone := make(chan struct{}, 2)
	go func() {
		bufPtr := udpBufferPool.Get().(*[]byte)
		buffer := *bufPtr
		defer udpBufferPool.Put(bufPtr)
		for {
			length, _, err := inbound.ReadFrom(buffer)
			if err != nil {
				break
			}
			if _, err := outbound.WriteTo(buffer[:length], destination); err != nil {
				break
			}
		}
		copyDone <- struct{}{}
	}()
	go func() {
		bufPtr := udpBufferPool.Get().(*[]byte)
		buffer := *bufPtr
		defer udpBufferPool.Put(bufPtr)
		for {
			length, _, err := outbound.ReadFrom(buffer)
			if err != nil {
				break
			}
			if _, err := inbound.Write(buffer[:length]); err != nil {
				break
			}
		}
		copyDone <- struct{}{}
	}()
	<-copyDone
	_ = inbound.Close()
	_ = outbound.Close()
	<-copyDone
}

func netstackAddress(address tcpip.Address) (string, bool) {
	if address.Len() != 4 && address.Len() != 16 {
		return "", false
	}
	return net.IP(address.AsSlice()).String(), true
}

func netstackUDPAddress(address tcpip.Address, port uint16) (*net.UDPAddr, bool) {
	value, ok := netstackAddress(address)
	if !ok || port == 0 {
		return nil, false
	}
	return &net.UDPAddr{IP: net.ParseIP(value), Port: int(port)}, true
}

func (n *netstackRuntime) close() {
	n.lifeMu.Lock()
	n.closed = true
	n.lifeMu.Unlock()
	n.cancel()
	if n.notifyHandle != nil {
		n.link.RemoveNotify(n.notifyHandle)
		n.notifyHandle = nil
	}
	n.readMu.Lock()
	if n.pending != nil {
		n.pending.DecRef()
		n.pending = nil
	}
	n.readMu.Unlock()

	n.stack.Close()
	n.link.Close()
	n.work.Wait()
	n.stack.Wait()
}

var netstack = struct {
	sync.Mutex
	runtime *netstackRuntime
}{}

func startNetstack(instance *core.Instance) error {
	netstack.Lock()
	defer netstack.Unlock()
	if netstack.runtime != nil {
		return errors.New("netstack is already running")
	}
	runtime, err := newNetstackRuntime(instance)
	if err != nil {
		return err
	}
	netstack.runtime = runtime
	return nil
}

func stopNetstack() {
	netstack.Lock()
	runtime := netstack.runtime
	netstack.runtime = nil
	netstack.Unlock()
	if runtime != nil {
		runtime.close()
	}
}

func writeNetstackPacket(packet []byte) int32 {
	netstack.Lock()
	runtime := netstack.runtime
	netstack.Unlock()
	if runtime == nil {
		return statusInvalidState
	}
	if err := runtime.injectPacket(packet); err != nil {
		if errors.Is(err, errNetstackPacketTooLarge) {
			return statusResourceLimit
		}
		if errors.Is(err, errNetstackStopped) {
			return statusInvalidState
		}
		return statusInvalidArgument
	}
	return statusOK
}

func readNetstackPacket(buffer []byte) (int, int32) {
	netstack.Lock()
	runtime := netstack.runtime
	netstack.Unlock()
	if runtime == nil {
		return 0, statusInvalidState
	}
	length, err := runtime.readPacket(buffer)
	if err == nil {
		return length, statusOK
	}
	if errors.Is(err, errNetstackWouldBlock) {
		return 0, statusWouldBlock
	}
	if errors.Is(err, errNetstackPacketTooLarge) {
		return length, statusResourceLimit
	}
	if errors.Is(err, errNetstackStopped) {
		return 0, statusInvalidState
	}
	return 0, statusInvalidArgument
}
