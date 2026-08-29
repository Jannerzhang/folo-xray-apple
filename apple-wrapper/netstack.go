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
	"time"

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

	"github.com/Jannerzhang/folo-xray-apple/apple-wrapper/router"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/main/folotun"
)

const (
	netstackNICID             tcpip.NICID = 1
	netstackMTU                           = 1500
	netstackPacketQueueDepth              = 32
	netstackTCPReceiveWindow              = 8 * 1024
	netstackMaxTCPAccepts                 = 8
	netstackMaxPacketSize                 = 64 * 1024
	netstackMaxConcurrentTCP              = 24
	netstackMaxConcurrentUDP              = 24
	netstackCopyBufferSize                = 4 * 1024
	netstackTCPHalfCloseGrace             = 2 * time.Second
	netstackUDPIdleTimeout                = 15 * time.Second
)

var (
	errNetstackPacketTooLarge = errors.New("netstack packet exceeds the configured limit")
	errNetstackMalformed      = errors.New("netstack packet is malformed")
	errNetstackStopped        = errors.New("netstack is stopped")
	errNetstackWouldBlock     = errors.New("netstack packet queue is empty")
)

type netstackRuntime struct {
	stack        *stack.Stack
	link         *channel.Endpoint
	instance     *core.Instance
	router       *router.Router
	directDialer *router.DirectDialer

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

func newNetstackRuntime(instance *core.Instance, r *router.Router) (*netstackRuntime, error) {
	if instance == nil {
		return nil, errors.New("xray instance is nil")
	}
	if r == nil {
		r = router.NewRouter(router.Config{Mode: router.ModeRule})
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
		stack:        s,
		link:         link,
		instance:     instance,
		router:       r,
		directDialer: router.NewDirectDialer(),
		ctx:          ctx,
		cancel:       cancel,
		tcpTokens:    make(chan struct{}, netstackMaxConcurrentTCP),
		udpTokens:    make(chan struct{}, netstackMaxConcurrentUDP),
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

	views, headerOffset := pkt.AsViewList()
	length := 0
	for view := views.Front(); view != nil; view = view.Next() {
		part := view.AsSlice()
		if headerOffset >= len(part) {
			headerOffset -= len(part)
			continue
		}
		length += len(part) - headerOffset
		headerOffset = 0
	}
	if length > len(dst) {
		n.pending = pkt
		return length, errNetstackPacketTooLarge
	}

	offset := 0
	views, headerOffset = pkt.AsViewList()
	for view := views.Front(); view != nil; view = view.Next() {
		part := view.AsSlice()
		if headerOffset >= len(part) {
			headerOffset -= len(part)
			continue
		}
		offset += copy(dst[offset:], part[headerOffset:])
		headerOffset = 0
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
	ctx := n.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Read first packet chunk to sniff TLS SNI or HTTP host
	peekBuf := make([]byte, 2048)
	_ = inbound.SetReadDeadline(time.Now().Add(2 * time.Second))
	nRead, _ := inbound.Read(peekBuf)
	_ = inbound.SetReadDeadline(time.Time{})

	var sniffedDomain string
	if nRead > 0 {
		sniffedDomain = SniffDomain(peekBuf[:nRead])
	}

	// 2. Routing decision
	parsedIP := net.ParseIP(destination)
	action := n.router.Route(sniffedDomain, parsedIP, port)

	if action == router.ActionBlock {
		return
	}

	var outbound net.Conn
	var err error

	if action == router.ActionDirect {
		outbound, err = n.directDialer.DialTCP(n.ctx, destination, port)
	} else {
		target := destination
		if sniffedDomain != "" {
			target = sniffedDomain
		}
		outbound, err = folotun.DialTCP(n.ctx, n.instance, target, port)
	}

	if err != nil {
		return
	}
	defer outbound.Close()

	if nRead > 0 {
		if _, err := outbound.Write(peekBuf[:nRead]); err != nil {
			return
		}
	}

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

	// Wait for the first direction to finish. A half-close is allowed a short
	// grace period for the peer's final response, but it must not retain a flow
	// indefinitely when the other direction stops making progress.
	<-copyDone
	deadline := time.Now().Add(netstackTCPHalfCloseGrace)
	_ = inbound.SetDeadline(deadline)
	_ = outbound.SetDeadline(deadline)

	graceTimer := time.NewTimer(netstackTCPHalfCloseGrace)
	defer graceTimer.Stop()
	select {
	case <-copyDone:
		return
	case <-graceTimer.C:
		// SetDeadline is best-effort for wrapped connections. Close explicitly
		// so the second copy goroutine cannot keep the flow token indefinitely.
	case <-ctx.Done():
		// Stop the data plane immediately during tunnel shutdown.
	}
	_ = inbound.Close()
	_ = outbound.Close()
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

	parsedIP := net.ParseIP(id.LocalAddress.String())
	action := n.router.Route("", parsedIP, id.LocalPort)
	if action == router.ActionBlock {
		<-n.udpTokens
		return true
	}

	var wq waiter.Queue
	ep, err := request.CreateEndpoint(&wq)
	if err != nil {
		<-n.udpTokens
		return false
	}
	inbound := gonet.NewUDPConn(&wq, ep)

	var outbound net.PacketConn
	var dialErr error

	if action == router.ActionDirect {
		var directConn net.Conn
		directConn, dialErr = n.directDialer.DialUDP(n.ctx, destination.IP.String(), id.LocalPort)
		if dialErr == nil {
			if pc, ok := directConn.(net.PacketConn); ok {
				outbound = pc
			} else {
				_ = directConn.Close()
				outbound, dialErr = net.ListenPacket("udp", "")
			}
		}
	} else {
		outbound, dialErr = folotun.DialUDP(n.ctx, n.instance)
	}

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
			_ = inbound.SetReadDeadline(time.Now().Add(netstackUDPIdleTimeout))
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
			_ = outbound.SetReadDeadline(time.Now().Add(netstackUDPIdleTimeout))
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

func startNetstack(instance *core.Instance, r *router.Router) error {
	netstack.Lock()
	defer netstack.Unlock()
	if netstack.runtime != nil {
		return errors.New("netstack is already running")
	}
	runtime, err := newNetstackRuntime(instance, r)
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
