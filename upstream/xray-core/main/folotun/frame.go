// SPDX-License-Identifier: MPL-2.0
//
// Folo PacketFlow framing is deliberately independent of Xray's generic
// listener/config packages. It carries complete IPv4/IPv6 packets over a
// stream socket; it does not parse DNS, route rules or proxy protocols.
package folotun

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	Magic0        byte = 0x46 // F
	Magic1        byte = 0x50 // P
	Version       byte = 1
	HeaderSize         = 12
	MaxPacketSize      = 65535
	IPv4Family    byte = 4
	IPv6Family    byte = 6
)

// Packet is one complete IP packet. Payload owns its byte slice and always
// includes the IP header.
type Packet struct {
	Family   byte
	Protocol byte
	Payload  []byte
}

// InspectPacket validates an IPv4 or IPv6 packet and extracts the framing
// metadata. It rejects truncated packets and packets with a mismatched IP
// length field so a stream read can never silently split or merge packets.
func InspectPacket(payload []byte) (Packet, error) {
	if len(payload) == 0 || len(payload) > MaxPacketSize {
		return Packet{}, fmt.Errorf("packet length out of range: %d", len(payload))
	}

	switch payload[0] >> 4 {
	case IPv4Family:
		if len(payload) < 20 {
			return Packet{}, fmt.Errorf("IPv4 packet is shorter than the header")
		}
		headerSize := int(payload[0]&0x0f) * 4
		if headerSize < 20 || headerSize > len(payload) {
			return Packet{}, fmt.Errorf("invalid IPv4 header length")
		}
		totalSize := int(binary.BigEndian.Uint16(payload[2:4]))
		if totalSize != len(payload) {
			return Packet{}, fmt.Errorf("IPv4 length %d does not match payload %d", totalSize, len(payload))
		}
		return Packet{Family: IPv4Family, Protocol: payload[9], Payload: payload}, nil
	case IPv6Family:
		if len(payload) < 40 {
			return Packet{}, fmt.Errorf("IPv6 packet is shorter than the header")
		}
		payloadSize := int(binary.BigEndian.Uint16(payload[4:6]))
		if payloadSize+40 != len(payload) {
			return Packet{}, fmt.Errorf("IPv6 length %d does not match payload %d", payloadSize+40, len(payload))
		}
		return Packet{Family: IPv6Family, Protocol: payload[6], Payload: payload}, nil
	default:
		return Packet{}, fmt.Errorf("unsupported IP version")
	}
}

// EncodeFrame returns one complete stream frame for a complete IP packet.
func EncodeFrame(payload []byte) ([]byte, error) {
	packet, err := InspectPacket(payload)
	if err != nil {
		return nil, err
	}

	frame := make([]byte, HeaderSize+len(packet.Payload))
	frame[0] = Magic0
	frame[1] = Magic1
	frame[2] = Version
	frame[3] = packet.Family
	frame[4] = packet.Protocol
	// frame[5] is reserved flags and must remain zero in v1.
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(packet.Payload)))
	// frame[10:12] is reserved for a future sequence extension.
	copy(frame[HeaderSize:], packet.Payload)
	return frame, nil
}

// WriteFrame writes one frame with full-write semantics. A stream write may
// be partial; callers must not substitute a single Write call.
func WriteFrame(writer io.Writer, payload []byte) error {
	frame, err := EncodeFrame(payload)
	if err != nil {
		return err
	}
	return writeAll(writer, frame)
}

// ReadFrame reads exactly one frame from a stream and validates both framing
// metadata and the embedded IP packet.
func ReadFrame(reader io.Reader) (Packet, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return Packet{}, err
	}
	if header[0] != Magic0 || header[1] != Magic1 {
		return Packet{}, fmt.Errorf("invalid PacketFlow frame magic")
	}
	if header[2] != Version {
		return Packet{}, fmt.Errorf("unsupported PacketFlow frame version: %d", header[2])
	}
	if header[5] != 0 || header[10] != 0 || header[11] != 0 {
		return Packet{}, fmt.Errorf("PacketFlow frame reserved fields are non-zero")
	}
	length := binary.BigEndian.Uint32(header[6:10])
	if length == 0 || length > MaxPacketSize {
		return Packet{}, fmt.Errorf("PacketFlow frame length out of range: %d", length)
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Packet{}, err
	}
	packet, err := InspectPacket(payload)
	if err != nil {
		return Packet{}, err
	}
	if packet.Family != header[3] || packet.Protocol != header[4] {
		return Packet{}, fmt.Errorf("PacketFlow metadata does not match packet")
	}
	return packet, nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if written < 0 || written > len(payload) {
			return fmt.Errorf("invalid stream write count: %d", written)
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
