// SPDX-License-Identifier: MPL-2.0
package router

import (
	"net"
	"testing"
)

func TestChinaIPv4Accuracy(t *testing.T) {
	chinaIPs := []string{
		"114.114.114.114", // 114 DNS
		"223.5.5.5",       // Ali DNS
		"223.6.6.6",       // Ali DNS
		"119.29.29.29",   // DNSPod / Tencent
		"180.76.76.76",   // Baidu DNS
		"1.2.4.8",        // CNNIC
		"202.96.128.86",  // Guangdong Telecom
		"210.22.84.3",    // Shanghai Unicom
		"211.136.192.6",  // Beijing Mobile
		"36.152.44.95",   // Baidu
		"183.2.172.42",   // QQ
		"106.11.208.12",  // Taobao
	}

	foreignIPs := []string{
		"8.8.8.8",        // Google DNS
		"8.8.4.4",        // Google DNS
		"1.1.1.1",        // Cloudflare DNS
		"1.0.0.1",        // Cloudflare DNS
		"208.67.222.222", // OpenDNS
		"9.9.9.9",        // Quad9
		"140.82.121.3",   // GitHub
		"151.101.1.69",   // Fastly
		"104.16.132.229", // Cloudflare
	}

	for _, ipStr := range chinaIPs {
		ip := net.ParseIP(ipStr)
		if !IsChinaIP(ip) {
			t.Errorf("Expected %s to be China IP, got false", ipStr)
		}
	}

	for _, ipStr := range foreignIPs {
		ip := net.ParseIP(ipStr)
		if IsChinaIP(ip) {
			t.Errorf("Expected %s to NOT be China IP, got true", ipStr)
		}
	}
}

func BenchmarkIsChinaIPv4(b *testing.B) {
	ip := net.ParseIP("223.5.5.5")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsChinaIP(ip)
	}
}
