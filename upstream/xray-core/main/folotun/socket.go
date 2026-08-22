// SPDX-License-Identifier: MPL-2.0
package folotun

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
)

// PacketSocket owns the duplicated descriptor returned by net.FileConn. The
// caller transfers the passed descriptor to this function and must not use it
// after a successful attach. Close is idempotent and is the only close path
// for the owned Go connection.
type PacketSocket struct {
	conn      net.Conn
	closeOnce sync.Once
}

// NewPacketSocketFromFD adopts a POSIX stream-socket descriptor. It never
// scans process descriptors and never relies on private Network Extension API.
func NewPacketSocketFromFD(fd int) (*PacketSocket, error) {
	if fd < 0 {
		return nil, fmt.Errorf("packet socket descriptor is invalid")
	}
	file := os.NewFile(uintptr(fd), "folo-packet-socket")
	if file == nil {
		return nil, fmt.Errorf("packet socket descriptor could not be wrapped")
	}
	conn, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil {
		if closeErr != nil {
			return nil, fmt.Errorf("packet socket descriptor is not a stream socket and close failed: %w", closeErr)
		}
		return nil, fmt.Errorf("packet socket descriptor is not a stream socket: %w", err)
	}
	if closeErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("packet socket descriptor close failed: %w", closeErr)
	}
	return &PacketSocket{conn: conn}, nil
}

// ReadPacket reads one complete framed packet.
func (s *PacketSocket) ReadPacket() (Packet, error) {
	return ReadFrame(s.conn)
}

// WritePacket writes one complete framed packet.
func (s *PacketSocket) WritePacket(payload []byte) error {
	return WriteFrame(s.conn, payload)
}

// Echo runs the stage-10 loopback pump. It is a transport PoC only: the
// callback is intentionally explicit so later stages can replace the echo
// handler with a real PacketFlow/TUN data-plane adapter without changing the
// framing or close contract.
func (s *PacketSocket) Echo(ctx context.Context, callback func(Packet) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		packet, err := s.ReadPacket()
		if err != nil {
			return err
		}
		if err := callback(packet); err != nil {
			return err
		}
	}
}

// Close is safe to call from the cancellation path and the goroutine exit
// path. Closing the connection unblocks a pending ReadFrame.
func (s *PacketSocket) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.conn.Close()
	})
	return err
}
