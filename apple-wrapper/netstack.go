//go:build darwin || ios
// +build darwin ios

// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
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
	netstackPacketQueueDepth              = 64
	netstackTCPReceiveWindow              = 16 * 1024
	netstackMaxTCPAccepts                 = 16
	netstackMaxPacketSize                 = 64 * 1024
	netstackMaxConcurrentTCP              = 48
	netstackMaxConcurrentUDP              = 48
	netstackCopyBufferSize                = 4 * 1024
	netstackTCPHalfCloseGrace             = 1 * time.Second
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

	routeMu           sync.RWMutex
	lastRouteDecision *router.RouteDecision

	work sync.WaitGroup

	notify       *netstackPacketNotification
	notifyHandle *channel.NotificationHandle

	tcpTokens chan struct{}
	udpTokens chan struct{}

	tcpActive            atomic.Uint64
	tcpPeak              atomic.Uint64
	tcpRejected          atomic.Uint64
	tcpPendingOpen       atomic.Uint64
	tcpHalfClose         atomic.Uint64
	tcpHalfCloseReleased atomic.Uint64
	tcpTerminated        atomic.Uint64

	udpActive        atomic.Uint64
	udpPeak          atomic.Uint64
	udpRejected      atomic.Uint64
	udpTerminated    atomic.Uint64
	udpIdleReclaimed atomic.Uint64

	queueDrops atomic.Uint64
}

func updatePeak(peak *atomic.Uint64, current uint64) {
	for {
		prev := peak.Load()
		if current <= prev {
			return
		}
		if peak.CompareAndSwap(prev, current) {
			return
		}
	}
}

type NetstackDiagnostics struct {
	TCPActive            uint64                `json:"tcpActive"`
	TCPPeak              uint64                `json:"tcpPeak"`
	TCPRejected          uint64                `json:"tcpRejected"`
	TCPPendingOpen       uint64                `json:"tcpPendingOpen"`
	TCPHalfClose         uint64                `json:"tcpHalfClose"`
	TCPHalfCloseReleased uint64                `json:"tcpHalfCloseReleased"`
	TCPTerminated        uint64                `json:"tcpTerminated"`
	UDPActive            uint64                `json:"udpActive"`
	UDPPeak              uint64                `json:"udpPeak"`
	UDPRejected          uint64                `json:"udpRejected"`
	UDPTerminated        uint64                `json:"udpTerminated"`
	UDPIdleReclaimed     uint64                `json:"udpIdleReclaimed"`
	QueueDrops           uint64                `json:"queueDrops"`
	RouteStats           router.RouteStats     `json:"routeStats"`
	RoutePolicySchema    int                   `json:"routePolicySchemaVersion"`
	RoutePolicyRevision  uint64                `json:"routePolicyRevision"`
	LastRouteDecision    *router.RouteDecision `json:"lastRouteDecision,omitempty"`
	GCCycleCount         uint32                `json:"gcCycleCount"`
	GCPauseTotalNs       uint64                `json:"gcPauseTotalNs"`
	HeapAllocBytes       uint64                `json:"heapAllocBytes"`
	HeapSysBytes         uint64                `json:"heapSysBytes"`
	GoroutineCount       int                   `json:"goroutineCount"`
}

func (n *netstackRuntime) Diagnostics() NetstackDiagnostics {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	var routeStats router.RouteStats
	if n.router != nil {
		routeStats = n.router.Stats()
	}
	policySchema, policyRevision := 0, uint64(0)
	if n.router != nil {
		policySchema, policyRevision = n.router.PolicyIdentity()
	}
	n.routeMu.RLock()
	lastRouteDecision := n.lastRouteDecision
	n.routeMu.RUnlock()

	return NetstackDiagnostics{
		TCPActive:            n.tcpActive.Load(),
		TCPPeak:              n.tcpPeak.Load(),
		TCPRejected:          n.tcpRejected.Load(),
		TCPPendingOpen:       n.tcpPendingOpen.Load(),
		TCPHalfClose:         n.tcpHalfClose.Load(),
		TCPHalfCloseReleased: n.tcpHalfCloseReleased.Load(),
		TCPTerminated:        n.tcpTerminated.Load(),
		UDPActive:            n.udpActive.Load(),
		UDPPeak:              n.udpPeak.Load(),
		UDPRejected:          n.udpRejected.Load(),
		UDPTerminated:        n.udpTerminated.Load(),
		UDPIdleReclaimed:     n.udpIdleReclaimed.Load(),
		QueueDrops:           n.queueDrops.Load(),
		RouteStats:           routeStats,
		RoutePolicySchema:    policySchema,
		RoutePolicyRevision:  policyRevision,
		LastRouteDecision:    lastRouteDecision,
		GCCycleCount:         mem.NumGC,
		GCPauseTotalNs:       mem.PauseTotalNs,
		HeapAllocBytes:       mem.Alloc,
		HeapSysBytes:         mem.Sys,
		GoroutineCount:       runtime.NumGoroutine(),
	}
}

func (n *netstackRuntime) recordRouteDecision(decision router.RouteDecision) {
	n.routeMu.Lock()
	n.lastRouteDecision = &decision
	n.routeMu.Unlock()
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
	if n.link.NumQueued() >= netstackPacketQueueDepth {
		n.queueDrops.Add(1)
	}
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
		n.tcpRejected.Add(1)
		if request != nil {
			func() {
				defer func() { _ = recover() }()
				request.Complete(true)
			}()
		}
		return
	}

	active := n.tcpActive.Add(1)
	updatePeak(&n.tcpPeak, active)

	id := request.ID()
	var wq waiter.Queue
	ep, err := request.CreateEndpoint(&wq)
	if err != nil {
		n.tcpActive.Add(^uint64(0))
		<-n.tcpTokens
		request.Complete(true)
		return
	}
	request.Complete(false)

	conn := gonet.NewTCPConn(&wq, ep)
	destination, ok := netstackAddress(id.LocalAddress)
	if !ok || id.LocalPort == 0 {
		n.tcpActive.Add(^uint64(0))
		<-n.tcpTokens
		n.tcpTerminated.Add(1)
		_ = conn.Close()
		return
	}

	if !n.startWork(func() {
		defer func() {
			n.tcpActive.Add(^uint64(0))
			<-n.tcpTokens
			n.tcpTerminated.Add(1)
		}()
		n.proxyTCP(conn, destination, id.LocalPort)
	}) {
		n.tcpActive.Add(^uint64(0))
		<-n.tcpTokens
		n.tcpTerminated.Add(1)
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
	decision := n.router.RouteWithContext(router.RouteContext{
		Domain:     sniffedDomain,
		IP:         parsedIP,
		Port:       port,
		Network:    "tcp",
		Provenance: router.ProvenanceSniffed,
	})
	n.recordRouteDecision(decision)
	action := decision.Action

	if action == router.ActionBlock {
		return
	}

	var outbound net.Conn
	var err error

	n.tcpPendingOpen.Add(1)
	if action == router.ActionDirect {
		outbound, err = n.directDialer.DialTCP(n.ctx, destination, port)
	} else {
		target := destination
		if sniffedDomain != "" {
			target = sniffedDomain
		}
		outbound, err = folotun.DialTCP(n.ctx, n.instance, target, port)
	}
	n.tcpPendingOpen.Add(^uint64(0))

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

	// Wait for the first direction to finish
	<-copyDone
	n.tcpHalfClose.Add(1)
	// Unblock and cleanly terminate the other direction after grace period to avoid token exhaustion
	_ = inbound.SetDeadline(time.Now().Add(netstackTCPHalfCloseGrace))
	_ = outbound.SetDeadline(time.Now().Add(netstackTCPHalfCloseGrace))
	<-copyDone
	n.tcpHalfClose.Add(^uint64(0))
	n.tcpHalfCloseReleased.Add(1)
}

func (n *netstackRuntime) handleUDP(request *udp.ForwarderRequest) bool {
	select {
	case n.udpTokens <- struct{}{}:
	default:
		n.udpRejected.Add(1)
		return false
	}

	active := n.udpActive.Add(1)
	updatePeak(&n.udpPeak, active)

	id := request.ID()
	destination, ok := netstackUDPAddress(id.LocalAddress, id.LocalPort)
	if !ok {
		n.udpActive.Add(^uint64(0))
		<-n.udpTokens
		n.udpTerminated.Add(1)
		return false
	}

	parsedIP := net.ParseIP(id.LocalAddress.String())
	decision := n.router.RouteWithContext(router.RouteContext{
		IP:         parsedIP,
		Port:       id.LocalPort,
		Network:    "udp",
		Provenance: router.ProvenanceIPSet,
	})
	n.recordRouteDecision(decision)
	action := decision.Action
	if action == router.ActionBlock {
		n.udpActive.Add(^uint64(0))
		<-n.udpTokens
		n.udpTerminated.Add(1)
		return true
	}

	var wq waiter.Queue
	ep, err := request.CreateEndpoint(&wq)
	if err != nil {
		n.udpActive.Add(^uint64(0))
		<-n.udpTokens
		n.udpTerminated.Add(1)
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
		n.udpActive.Add(^uint64(0))
		<-n.udpTokens
		n.udpTerminated.Add(1)
		_ = inbound.Close()
		return true
	}

	if !n.startWork(func() {
		defer func() {
			n.udpActive.Add(^uint64(0))
			<-n.udpTokens
			n.udpTerminated.Add(1)
		}()
		defer inbound.Close()
		defer outbound.Close()
		n.proxyUDP(inbound, outbound, destination)
	}) {
		n.udpActive.Add(^uint64(0))
		<-n.udpTokens
		n.udpTerminated.Add(1)
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
			_ = inbound.SetReadDeadline(time.Now().Add(30 * time.Second))
			length, _, err := inbound.ReadFrom(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					n.udpIdleReclaimed.Add(1)
				}
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
			_ = outbound.SetReadDeadline(time.Now().Add(30 * time.Second))
			length, _, err := outbound.ReadFrom(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					n.udpIdleReclaimed.Add(1)
				}
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

func getNetstackDiagnosticsJSON() string {
	netstack.Lock()
	runtime := netstack.runtime
	netstack.Unlock()
	if runtime == nil {
		return `{"state":0,"error":"netstack not running"}`
	}
	diag := runtime.Diagnostics()
	payload, err := json.Marshal(diag)
	if err != nil {
		return `{"state":0,"error":"marshal failed"}`
	}
	return string(payload)
}
