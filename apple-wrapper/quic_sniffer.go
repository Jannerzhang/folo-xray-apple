//go:build darwin || ios
// +build darwin ios

// SPDX-License-Identifier: MPL-2.0
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	quicVersionV1              = uint32(1)
	quicInitialMaxCryptoBytes  = 16 * 1024
	quicInitialMaxFragments    = 64
	quicInitialReassemblyLimit = 200 * time.Millisecond
)

var quicV1InitialSalt = [20]byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a,
	0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

type quicSNIReassemblyStatus uint8

const (
	quicSNIReassemblyPending quicSNIReassemblyStatus = iota
	quicSNIReassemblyFound
	quicSNIReassemblyInvalid
	quicSNIReassemblyExpired
	quicSNIReassemblyLimitExceeded
)

type quicSNIReassemblyResult struct {
	status quicSNIReassemblyStatus
	domain string
	seen   bool
}

type quicInitialSNIReassembler struct {
	data         []byte
	received     []bool
	ranges       [][2]int
	startedAt    time.Time
	maxFragments int
	timeout      time.Duration
	terminal     *quicSNIReassemblyResult
}

func newQUICInitialSNIReassembler(startedAt time.Time) *quicInitialSNIReassembler {
	return &quicInitialSNIReassembler{
		data:         make([]byte, quicInitialMaxCryptoBytes),
		received:     make([]bool, quicInitialMaxCryptoBytes),
		startedAt:    startedAt,
		maxFragments: quicInitialMaxFragments,
		timeout:      quicInitialReassemblyLimit,
	}
}

func (r *quicInitialSNIReassembler) push(packet []byte, now time.Time) quicSNIReassemblyResult {
	if r.terminal != nil {
		return *r.terminal
	}
	if now.Sub(r.startedAt) > r.timeout {
		return r.finish(quicSNIReassemblyResult{status: quicSNIReassemblyExpired})
	}

	plaintext, ok := decryptQUICInitial(packet)
	if !ok {
		return r.finish(quicSNIReassemblyResult{status: quicSNIReassemblyInvalid})
	}
	fragments, ok := collectQUICCryptoFragments(plaintext)
	if !ok {
		return r.finish(quicSNIReassemblyResult{status: quicSNIReassemblyInvalid, seen: true})
	}
	seen := true
	for _, fragment := range fragments {
		if !r.insert(fragment.offset, fragment.data) {
			return r.finish(quicSNIReassemblyResult{
				status: quicSNIReassemblyLimitExceeded,
				seen:   seen,
			})
		}
	}
	end := r.contiguousEnd()
	if end > 0 {
		if domain := sniffTLSHandshakeSNI(r.data[:end]); domain != "" {
			return r.finish(quicSNIReassemblyResult{
				status: quicSNIReassemblyFound,
				domain: domain,
				seen:   seen,
			})
		}
	}
	return quicSNIReassemblyResult{status: quicSNIReassemblyPending, seen: seen}
}

func (r *quicInitialSNIReassembler) finish(result quicSNIReassemblyResult) quicSNIReassemblyResult {
	r.terminal = &result
	return result
}

func (r *quicInitialSNIReassembler) insert(offset int, data []byte) bool {
	if offset < 0 || offset > len(r.data) || len(data) > len(r.data)-offset {
		return false
	}
	end := offset + len(data)
	for index, value := range data {
		position := offset + index
		if r.received[position] && r.data[position] != value {
			return false
		}
	}
	for index, value := range data {
		position := offset + index
		r.data[position] = value
		r.received[position] = true
	}

	start, stop := offset, end
	merged := make([][2]int, 0, len(r.ranges)+1)
	for _, current := range r.ranges {
		if current[1] < start || current[0] > stop {
			merged = append(merged, current)
			continue
		}
		if current[0] < start {
			start = current[0]
		}
		if current[1] > stop {
			stop = current[1]
		}
	}
	merged = append(merged, [2]int{start, stop})
	for index := 1; index < len(merged); index++ {
		current := merged[index]
		position := index - 1
		for position >= 0 && merged[position][0] > current[0] {
			merged[position+1] = merged[position]
			position--
		}
		merged[position+1] = current
	}
	if len(merged) > r.maxFragments {
		return false
	}
	r.ranges = merged
	return true
}

func (r *quicInitialSNIReassembler) contiguousEnd() int {
	for index, received := range r.received {
		if !received {
			return index
		}
	}
	return len(r.received)
}

type quicCryptoFragment struct {
	offset int
	data   []byte
}

func sniffQUICInitialSNI(packet []byte) string {
	now := time.Now()
	result := newQUICInitialSNIReassembler(now).push(packet, now)
	return result.domain
}

func decryptQUICInitial(packet []byte) ([]byte, bool) {
	if len(packet) < 6 || packet[0]&0x80 == 0 || binary.BigEndian.Uint32(packet[1:5]) != quicVersionV1 || packet[0]&0x30 != 0 {
		return nil, false
	}
	offset := 5
	if offset >= len(packet) {
		return nil, false
	}
	dcidLength := int(packet[offset])
	offset++
	if dcidLength > len(packet)-offset {
		return nil, false
	}
	dcid := packet[offset : offset+dcidLength]
	offset += dcidLength
	if offset >= len(packet) {
		return nil, false
	}
	scidLength := int(packet[offset])
	offset++
	if scidLength > len(packet)-offset {
		return nil, false
	}
	offset += scidLength
	tokenLength, used, ok := readQUICVarint(packet, offset)
	if !ok {
		return nil, false
	}
	offset += used
	if tokenLength > uint64(len(packet)-offset) {
		return nil, false
	}
	offset += int(tokenLength)
	length, used, ok := readQUICVarint(packet, offset)
	if !ok || length > uint64(len(packet)-offset-used) {
		return nil, false
	}
	offset += used
	packetLength := int(length)
	if packetLength <= 16 || packetLength > len(packet)-offset {
		return nil, false
	}
	payloadEnd := offset + packetLength
	if offset+4+16 > payloadEnd {
		return nil, false
	}

	secret := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt[:])
	key, ok := quicHKDFExpand(secret, []byte("quic key"), 16)
	if !ok {
		return nil, false
	}
	iv, ok := quicHKDFExpand(secret, []byte("quic iv"), 12)
	if !ok {
		return nil, false
	}
	hp, ok := quicHKDFExpand(secret, []byte("quic hp"), 16)
	if !ok {
		return nil, false
	}
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, false
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], packet[offset+4:offset+4+16])
	first := packet[0] ^ (mask[0] & 0x0f)
	packetNumberLength := int(first&0x03) + 1
	if packetNumberLength+16 > packetLength {
		return nil, false
	}
	packetNumberEnd := offset + packetNumberLength
	if packetNumberEnd > payloadEnd {
		return nil, false
	}
	aad := append([]byte(nil), packet[:packetNumberEnd]...)
	aad[0] = first
	var packetNumber uint64
	for index := 0; index < packetNumberLength; index++ {
		value := packet[offset+index] ^ mask[index+1]
		aad[offset+index] = value
		packetNumber = packetNumber<<8 | uint64(value)
	}
	nonce := append([]byte(nil), iv...)
	for index, value := range uint64Bytes(packetNumber) {
		nonce[4+index] ^= value
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	plaintext, err := aead.Open(nil, nonce, packet[packetNumberEnd:payloadEnd], aad)
	if err != nil {
		return nil, false
	}
	return plaintext, true
}

func quicHKDFExpand(secret, label []byte, size int) ([]byte, bool) {
	info := make([]byte, 0, 2+1+6+len(label)+1)
	info = append(info, byte(size>>8), byte(size), byte(6+len(label)))
	info = append(info, []byte("tls13 ")...)
	info = append(info, label...)
	info = append(info, 0)
	output := make([]byte, size)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), output); err != nil {
		return nil, false
	}
	return output, true
}

func uint64Bytes(value uint64) []byte {
	var output [8]byte
	binary.BigEndian.PutUint64(output[:], value)
	return output[:]
}

func collectQUICCryptoFragments(plaintext []byte) ([]quicCryptoFragment, bool) {
	fragments := make([]quicCryptoFragment, 0, 2)
	for offset := 0; offset < len(plaintext); {
		frameType := plaintext[offset]
		offset++
		switch frameType {
		case 0x00, 0x01:
		case 0x02, 0x03:
			var ok bool
			offset, ok = skipQUICAck(plaintext, offset, frameType == 0x03)
			if !ok {
				return nil, false
			}
		case 0x06:
			cryptoOffset, used, ok := readQUICVarint(plaintext, offset)
			if !ok {
				return nil, false
			}
			offset += used
			cryptoLength, used, ok := readQUICVarint(plaintext, offset)
			if !ok || cryptoLength > uint64(len(plaintext)-offset-used) {
				return nil, false
			}
			offset += used
			if cryptoOffset > uint64(quicInitialMaxCryptoBytes) || cryptoLength > uint64(quicInitialMaxCryptoBytes)-cryptoOffset {
				return nil, false
			}
			end := offset + int(cryptoLength)
			fragments = append(fragments, quicCryptoFragment{
				offset: int(cryptoOffset),
				data:   append([]byte(nil), plaintext[offset:end]...),
			})
			offset = end
		default:
			return nil, false
		}
	}
	return fragments, true
}

func skipQUICAck(data []byte, offset int, hasECN bool) (int, bool) {
	for index := 0; index < 4; index++ {
		_, used, ok := readQUICVarint(data, offset)
		if !ok {
			return 0, false
		}
		offset += used
		if index == 2 {
			// The range count determines two additional values per range.
			count, _, _ := readQUICVarint(data, offset-used)
			for rangeIndex := uint64(0); rangeIndex < count; rangeIndex++ {
				for valueIndex := 0; valueIndex < 2; valueIndex++ {
					_, used, ok = readQUICVarint(data, offset)
					if !ok {
						return 0, false
					}
					offset += used
				}
			}
		}
	}
	if hasECN {
		for index := 0; index < 3; index++ {
			_, used, ok := readQUICVarint(data, offset)
			if !ok {
				return 0, false
			}
			offset += used
		}
	}
	return offset, true
}

func readQUICVarint(data []byte, offset int) (uint64, int, bool) {
	if offset < 0 || offset >= len(data) {
		return 0, 0, false
	}
	length := 1 << (data[offset] >> 6)
	if length > len(data)-offset {
		return 0, 0, false
	}
	value := uint64(data[offset] & 0x3f)
	for _, valueByte := range data[offset+1 : offset+length] {
		value = value<<8 | uint64(valueByte)
	}
	return value, length, true
}

func sniffTLSHandshakeSNI(handshake []byte) string {
	if len(handshake) < 4 || handshake[0] != 1 {
		return ""
	}
	length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if length > len(handshake)-4 {
		return ""
	}
	body := handshake[4 : 4+length]
	offset := 2 + 32
	if offset >= len(body) {
		return ""
	}
	sessionIDLength := int(body[offset])
	offset++
	if sessionIDLength > len(body)-offset {
		return ""
	}
	offset += sessionIDLength
	if offset+2 > len(body) {
		return ""
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if cipherSuitesLength > len(body)-offset {
		return ""
	}
	offset += cipherSuitesLength
	if offset >= len(body) {
		return ""
	}
	compressionLength := int(body[offset])
	offset++
	if compressionLength > len(body)-offset {
		return ""
	}
	offset += compressionLength
	if offset+2 > len(body) {
		return ""
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if extensionsLength > len(body)-offset {
		return ""
	}
	end := offset + extensionsLength
	for offset+4 <= end {
		extensionType := binary.BigEndian.Uint16(body[offset : offset+2])
		extensionLength := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4
		if extensionLength > end-offset {
			return ""
		}
		if extensionType == 0 {
			if extensionLength < 2 {
				return ""
			}
			listLength := int(binary.BigEndian.Uint16(body[offset : offset+2]))
			if listLength > extensionLength-2 {
				return ""
			}
			listEnd := offset + 2 + listLength
			for nameOffset := offset + 2; nameOffset+3 <= listEnd; {
				nameType := body[nameOffset]
				nameLength := int(binary.BigEndian.Uint16(body[nameOffset+1 : nameOffset+3]))
				nameOffset += 3
				if nameLength > listEnd-nameOffset {
					return ""
				}
				if nameType == 0 {
					return normalizeQUICHost(string(body[nameOffset : nameOffset+nameLength]))
				}
				nameOffset += nameLength
			}
			return ""
		}
		offset += extensionLength
	}
	return ""
}

func normalizeQUICHost(host string) string {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || strings.IndexFunc(host, func(r rune) bool { return r == '/' || r == ':' || r == '\\' || r <= ' ' }) >= 0 || net.ParseIP(host) != nil || len(host) > 253 {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}
	}
	return strings.ToLower(host)
}
