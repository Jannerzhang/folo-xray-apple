// SPDX-License-Identifier: MPL-2.0
//
// A deliberately narrow loopback SOCKS5 CONNECT boundary for the Folo
// PacketFlow evaluation. It dispatches destinations through the already
// running Xray instance and never accepts a listener address from profile
// JSON. UDP ASSOCIATE, BIND, authentication and arbitrary SOCKS options are
// intentionally outside this stage.
package folotun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/core"
)

const (
	maxSocks5Connections = 16
	socks5HandshakeLimit = 5 * time.Second
	socks5DialTimeout    = 10 * time.Second
	socks5DrainTimeout   = 5 * time.Second
)

var (
	errSocks5Protocol = errors.New("SOCKS5 protocol request rejected")
)

// Socks5OutboundStats is intentionally data-free. It records only bounded
// lifecycle/socket counters and never includes addresses or credentials.
type Socks5OutboundStats struct {
	AcceptedConnections  uint64 `json:"accepted_connections"`
	RejectedConnections  uint64 `json:"rejected_connections"`
	ActiveConnections    uint64 `json:"active_connections"`
	PeakConnections      uint64 `json:"peak_connections"`
	CompletedConnections uint64 `json:"completed_connections"`
	DialFailures         uint64 `json:"dial_failures"`
}

// Socks5OutboundServer provides a fixed loopback endpoint backed by
// folotun.DialTCP. It is suitable for the Hev evaluation only; it is not a
// general-purpose public SOCKS server.
type Socks5OutboundServer struct {
	instance       *core.Instance
	maxConnections int

	mu          sync.Mutex
	running     bool
	listener    net.Listener
	cancel      context.CancelFunc
	acceptDone  chan struct{}
	connections map[net.Conn]struct{}
	workers     sync.WaitGroup

	acceptedConnections  atomic.Uint64
	rejectedConnections  atomic.Uint64
	activeConnections    atomic.Uint64
	peakConnections      atomic.Uint64
	completedConnections atomic.Uint64
	dialFailures         atomic.Uint64
}

func NewSocks5OutboundServer(instance *core.Instance) (*Socks5OutboundServer, error) {
	if instance == nil {
		return nil, errors.New("xray instance is nil")
	}
	return &Socks5OutboundServer{
		instance:       instance,
		maxConnections: maxSocks5Connections,
		connections:    make(map[net.Conn]struct{}),
	}, nil
}

// Start binds only the IPv4 loopback address and lets the kernel select a
// port. A dynamic port prevents collisions while keeping the endpoint local.
func (s *Socks5OutboundServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("SOCKS5 server is already running")
	}
	s.mu.Unlock()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen on loopback failed: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		cancel()
		_ = listener.Close()
		return errors.New("SOCKS5 server is already running")
	}
	s.running = true
	s.listener = listener
	s.cancel = cancel
	s.acceptDone = make(chan struct{})
	s.connections = make(map[net.Conn]struct{})
	s.mu.Unlock()

	go s.acceptLoop(ctx, listener, s.acceptDone)
	return nil
}

// Addr returns the controlled loopback address, or nil before Start/after
// Stop. The returned net.Addr is owned by the caller as a value-only view.
func (s *Socks5OutboundServer) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Socks5OutboundServer) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Stop closes the listener and every accepted connection before waiting for
// workers. Closing tracked connections is what makes cancellation bounded even
// while a peer is idle in a copy loop.
func (s *Socks5OutboundServer) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	listener := s.listener
	cancel := s.cancel
	acceptDone := s.acceptDone
	connections := make([]net.Conn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.listener = nil
	s.cancel = nil
	s.acceptDone = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if listener != nil {
		_ = listener.Close()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	if acceptDone != nil {
		<-acceptDone
	}
	s.workers.Wait()
	return nil
}

func (s *Socks5OutboundServer) Stats() Socks5OutboundStats {
	return Socks5OutboundStats{
		AcceptedConnections:  s.acceptedConnections.Load(),
		RejectedConnections:  s.rejectedConnections.Load(),
		ActiveConnections:    s.activeConnections.Load(),
		PeakConnections:      s.peakConnections.Load(),
		CompletedConnections: s.completedConnections.Load(),
		DialFailures:         s.dialFailures.Load(),
	}
}

func (s *Socks5OutboundServer) acceptLoop(ctx context.Context, listener net.Listener, acceptDone chan struct{}) {
	defer close(acceptDone)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		if !s.trackConnection(conn) {
			s.rejectedConnections.Add(1)
			_ = conn.Close()
			continue
		}
		if !s.reserveConnection() {
			s.untrackConnection(conn)
			s.rejectedConnections.Add(1)
			_ = conn.Close()
			continue
		}
		s.acceptedConnections.Add(1)
		s.workers.Add(1)
		go func() {
			defer s.workers.Done()
			defer s.releaseConnection(conn)
			s.serve(ctx, conn)
		}()
	}
}

func (s *Socks5OutboundServer) trackConnection(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return false
	}
	s.connections[conn] = struct{}{}
	return true
}

func (s *Socks5OutboundServer) untrackConnection(conn net.Conn) {
	s.mu.Lock()
	delete(s.connections, conn)
	s.mu.Unlock()
}

func (s *Socks5OutboundServer) reserveConnection() bool {
	for {
		current := s.activeConnections.Load()
		if current >= uint64(s.maxConnections) {
			return false
		}
		if s.activeConnections.CompareAndSwap(current, current+1) {
			setAtomicMax(&s.peakConnections, current+1)
			return true
		}
	}
}

func (s *Socks5OutboundServer) releaseConnection(conn net.Conn) {
	s.untrackConnection(conn)
	s.activeConnections.Add(^uint64(0))
	s.completedConnections.Add(1)
	_ = conn.Close()
}

func (s *Socks5OutboundServer) serve(ctx context.Context, client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(socks5HandshakeLimit))
	reader := make([]byte, 257)
	if err := socks5Handshake(client, reader); err != nil {
		return
	}
	target, port, err := readSocks5ConnectRequest(client, reader)
	if err != nil {
		writeSocks5Reply(client, 0x08)
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, socks5DialTimeout)
	remote, err := DialTCP(dialCtx, s.instance, target, port)
	if err != nil {
		cancel()
		s.dialFailures.Add(1)
		writeSocks5Reply(client, 0x01)
		return
	}
	// Xray's dispatcher keeps the returned connection tied to its context;
	// keep the context alive for the full copy loop and release it on exit.
	defer cancel()
	if !s.trackConnection(remote) {
		_ = remote.Close()
		return
	}
	defer s.untrackConnection(remote)
	defer remote.Close()

	if err := writeSocks5Reply(client, 0x00); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})
	proxyBidirectional(client, remote)
}

func socks5Handshake(conn net.Conn, scratch []byte) error {
	if _, err := io.ReadFull(conn, scratch[:2]); err != nil {
		return err
	}
	if scratch[0] != 0x05 || scratch[1] == 0 {
		return errSocks5Protocol
	}
	nmethods := int(scratch[1])
	if _, err := io.ReadFull(conn, scratch[:nmethods]); err != nil {
		return err
	}
	method := byte(0xff)
	for _, candidate := range scratch[:nmethods] {
		if candidate == 0x00 {
			method = 0x00
			break
		}
	}
	if _, err := conn.Write([]byte{0x05, method}); err != nil {
		return err
	}
	if method == 0xff {
		return errSocks5Protocol
	}
	return nil
}

func readSocks5ConnectRequest(conn net.Conn, scratch []byte) (string, uint16, error) {
	if _, err := io.ReadFull(conn, scratch[:4]); err != nil {
		return "", 0, err
	}
	if scratch[0] != 0x05 || scratch[1] != 0x01 || scratch[2] != 0x00 {
		return "", 0, errSocks5Protocol
	}
	var address string
	switch scratch[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, scratch[:4]); err != nil {
			return "", 0, err
		}
		address = net.IP(scratch[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(conn, scratch[:1]); err != nil {
			return "", 0, err
		}
		length := int(scratch[0])
		if length == 0 || length > MaxEndpointAddressLength || len(scratch) < length+2 {
			return "", 0, errSocks5Protocol
		}
		if _, err := io.ReadFull(conn, scratch[:length]); err != nil {
			return "", 0, err
		}
		address = string(scratch[:length])
	case 0x04:
		if _, err := io.ReadFull(conn, scratch[:16]); err != nil {
			return "", 0, err
		}
		address = net.IP(scratch[:16]).String()
	default:
		return "", 0, errSocks5Protocol
	}
	if err := ValidateEndpointAddress(address); err != nil {
		return "", 0, err
	}
	if _, err := io.ReadFull(conn, scratch[:2]); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(scratch[:2])
	if port == 0 {
		return "", 0, errSocks5Protocol
	}
	return address, port, nil
}

func writeSocks5Reply(conn net.Conn, code byte) error {
	// The bind address is intentionally unspecified: this server only exposes
	// CONNECT and does not claim a remotely routable bind endpoint.
	_, err := conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func proxyBidirectional(left, right net.Conn) {
	done := make(chan struct{}, 2)
	copyDirection := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if halfCloser, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = halfCloser.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyDirection(right, left)
	go copyDirection(left, right)
	<-done
	_ = left.SetDeadline(time.Now().Add(socks5DrainTimeout))
	_ = right.SetDeadline(time.Now().Add(socks5DrainTimeout))
	<-done
}

func setAtomicMax(value *atomic.Uint64, candidate uint64) {
	for {
		current := value.Load()
		if candidate <= current || value.CompareAndSwap(current, candidate) {
			return
		}
	}
}
