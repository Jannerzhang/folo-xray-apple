// SPDX-License-Identifier: MPL-2.0
package main

import (
	"testing"
)

func TestSniffHTTP(t *testing.T) {
	req := []byte("GET /index.html HTTP/1.1\r\nHost: www.baidu.com:443\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n")
	domain := SniffDomain(req)
	if domain != "www.baidu.com" {
		t.Errorf("expected www.baidu.com, got %s", domain)
	}
}

func TestSniffTLSClientHello(t *testing.T) {
	// A real captured TLS ClientHello with SNI="bilibili.com"
	rawClientHello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x47, // Record header (length 71)
		0x01, 0x00, 0x00, 0x43, // Handshake header (ClientHello, len 67)
		0x03, 0x03, // Client version TLS 1.2
		// 32 bytes random
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00,       // Session ID len 0
		0x00, 0x02, // Cipher suites len 2
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x01, 0x00, // Compression methods len 1, null
		0x00, 0x16, // Extensions len 22
		0x00, 0x00, // Ext type 0 (server_name)
		0x00, 0x11, // Ext len 17
		0x00, 0x0f, // SNI list len 15
		0x00,       // host_name type (0)
		0x00, 0x0c, // name len 12
		'b', 'i', 'l', 'i', 'b', 'i', 'l', 'i', '.', 'c', 'o', 'm',
	}

	domain := SniffDomain(rawClientHello)
	if domain != "bilibili.com" {
		t.Errorf("expected bilibili.com, got %s", domain)
	}
}
