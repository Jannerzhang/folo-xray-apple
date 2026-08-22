// SPDX-License-Identifier: MPL-2.0
package folotun

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestFrameRoundTripIPv4WithShortReadsAndWrites(t *testing.T) {
	payload := ipv4Packet(6, 37)
	writer := &chunkWriter{max: 3}
	if err := WriteFrame(writer, payload); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	packet, err := ReadFrame(&chunkReader{reader: bytes.NewReader(writer.Bytes()), max: 2})
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if packet.Family != IPv4Family || packet.Protocol != 6 || !bytes.Equal(packet.Payload, payload) {
		t.Fatalf("round-trip packet mismatch: %+v", packet)
	}
}

func TestFrameRoundTripIPv6(t *testing.T) {
	payload := ipv6Packet(17, 53)
	frame, err := EncodeFrame(payload)
	if err != nil {
		t.Fatalf("EncodeFrame() error = %v", err)
	}
	packet, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if packet.Family != IPv6Family || packet.Protocol != 17 || !bytes.Equal(packet.Payload, payload) {
		t.Fatalf("round-trip packet mismatch: %+v", packet)
	}
}

func TestReadFrameRejectsMergedOrTruncatedMetadata(t *testing.T) {
	frame, err := EncodeFrame(ipv4Packet(6, 10))
	if err != nil {
		t.Fatalf("EncodeFrame() error = %v", err)
	}
	frame[6]++
	if _, err := ReadFrame(bytes.NewReader(frame)); err == nil {
		t.Fatal("ReadFrame() accepted a mismatched payload length")
	}

	frame, err = EncodeFrame(ipv4Packet(6, 10))
	if err != nil {
		t.Fatalf("EncodeFrame() error = %v", err)
	}
	frame = frame[:len(frame)-1]
	if _, err := ReadFrame(bytes.NewReader(frame)); err == nil {
		t.Fatal("ReadFrame() accepted a truncated packet")
	}
}

func TestInspectPacketRejectsMalformedIP(t *testing.T) {
	if _, err := InspectPacket([]byte{0x40, 0, 0}); err == nil {
		t.Fatal("InspectPacket() accepted a truncated IPv4 packet")
	}
	if _, err := InspectPacket([]byte{0x60, 0, 0, 0, 0, 0, 17}); err == nil {
		t.Fatal("InspectPacket() accepted a truncated IPv6 packet")
	}
}

func ipv4Packet(protocol byte, payloadSize int) []byte {
	packet := make([]byte, 20+payloadSize)
	packet[0] = 0x45
	packet[2] = byte(len(packet) >> 8)
	packet[3] = byte(len(packet))
	packet[8] = 64
	packet[9] = protocol
	packet[12] = 192
	packet[13] = 0
	packet[14] = 2
	packet[15] = 1
	packet[16] = 198
	packet[17] = 51
	packet[18] = 100
	packet[19] = 2
	for i := 20; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	return packet
}

func ipv6Packet(nextHeader byte, payloadSize int) []byte {
	packet := make([]byte, 40+payloadSize)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(payloadSize))
	packet[6] = nextHeader
	packet[7] = 64
	packet[8] = 0x20
	packet[9] = 0x01
	packet[10] = 0x0d
	packet[11] = 0xb8
	packet[24] = 0x20
	packet[25] = 0x01
	packet[26] = 0x0d
	packet[27] = 0xb8
	for i := 40; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	return packet
}

type chunkWriter struct {
	bytes.Buffer
	max int
}

func (w *chunkWriter) Write(payload []byte) (int, error) {
	if len(payload) > w.max {
		payload = payload[:w.max]
	}
	return w.Buffer.Write(payload)
}

type chunkReader struct {
	reader io.Reader
	max    int
}

func (r *chunkReader) Read(payload []byte) (int, error) {
	if len(payload) > r.max {
		payload = payload[:r.max]
	}
	return r.reader.Read(payload)
}
