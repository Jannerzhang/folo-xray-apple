// SPDX-License-Identifier: MPL-2.0
package main

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// SniffDomain attempts to extract a domain name from the initial bytes of a TCP stream.
// It supports TLS SNI (Server Name Indication) and plain HTTP Host headers.
func SniffDomain(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Try TLS ClientHello SNI
	if domain := sniffTLS(data); domain != "" {
		return domain
	}

	// Try HTTP Host
	if domain := sniffHTTP(data); domain != "" {
		return domain
	}

	return ""
}

func sniffTLS(data []byte) string {
	// TLS Handshake Record: Type (0x16), Version (0x03, 0x01..0x03), Length (2 bytes)
	if len(data) < 44 || data[0] != 0x16 || data[1] != 0x03 {
		return ""
	}

	// Handshake type: 0x01 (ClientHello)
	if data[5] != 0x01 {
		return ""
	}

	// Skip: Record Header (5) + Type (1) + Length (3) + Version (2) + Random (32) = 43 bytes
	pos := 43
	if pos >= len(data) {
		return ""
	}

	// Session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return ""
	}

	// Cipher Suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > len(data) {
		return ""
	}

	// Compression Methods
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen
	if pos+2 > len(data) {
		return ""
	}

	// Extensions
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	end := pos + extensionsLen
	if end > len(data) {
		end = len(data)
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0000 { // server_name (SNI)
			if pos+2 <= end {
				// server_name list
				listLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
				sniPos := pos + 2
				sniEnd := sniPos + listLen
				if sniEnd > end {
					sniEnd = end
				}
				for sniPos+3 <= sniEnd {
					nameType := data[sniPos]
					nameLen := int(binary.BigEndian.Uint16(data[sniPos+1 : sniPos+3]))
					sniPos += 3
					if nameType == 0 && sniPos+nameLen <= sniEnd { // host_name
						return strings.ToLower(string(data[sniPos : sniPos+nameLen]))
					}
					sniPos += nameLen
				}
			}
			return ""
		}
		pos += extLen
	}

	return ""
}

func sniffHTTP(data []byte) string {
	// Check HTTP methods
	if !bytes.HasPrefix(data, []byte("GET ")) &&
		!bytes.HasPrefix(data, []byte("POST ")) &&
		!bytes.HasPrefix(data, []byte("HEAD ")) &&
		!bytes.HasPrefix(data, []byte("PUT ")) &&
		!bytes.HasPrefix(data, []byte("DELETE ")) &&
		!bytes.HasPrefix(data, []byte("CONNECT ")) &&
		!bytes.HasPrefix(data, []byte("OPTIONS ")) {
		return ""
	}

	// Search for "\r\nHost: " or "\nHost: "
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("host:")) {
			host := string(bytes.TrimSpace(line[5:]))
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}
			return strings.ToLower(strings.TrimSpace(host))
		}
	}
	return ""
}
