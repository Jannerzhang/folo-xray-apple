// SPDX-License-Identifier: MPL-2.0
package router

import (
	"net"
	"testing"
)

func TestDomainMatcher(t *testing.T) {
	dm := NewDomainMatcher()
	dm.AddSuffix("cn", ActionDirect)
	dm.AddSuffix("bilibili.com", ActionDirect)
	dm.AddExact("ad.example.com", ActionBlock)
	dm.AddKeyword("googleadservices", ActionBlock)

	tests := []struct {
		domain   string
		expected RouteAction
		matched  bool
	}{
		{"www.bilibili.com", ActionDirect, true},
		{"api.bilibili.com", ActionDirect, true},
		{"bilibili.com", ActionDirect, true},
		{"baidu.cn", ActionDirect, true},
		{"ad.example.com", ActionBlock, true},
		{"notad.example.com", ActionProxy, false},
		{"page.googleadservices.com", ActionBlock, true},
		{"google.com", ActionProxy, false},
		{"", ActionProxy, false},
	}

	for _, tt := range tests {
		action, ok := dm.Match(tt.domain)
		if ok != tt.matched {
			t.Errorf("domain %s: expected matched=%v, got %v", tt.domain, tt.matched, ok)
		}
		if ok && action != tt.expected {
			t.Errorf("domain %s: expected action=%v, got %v", tt.domain, tt.expected, action)
		}
	}
}

func TestIPMatcher(t *testing.T) {
	im := NewIPMatcher()
	_ = im.AddCIDR("192.168.0.0/16", ActionDirect)
	_ = im.AddCIDR("10.0.0.0/8", ActionDirect)
	_ = im.AddCIDR("1.2.3.4", ActionBlock)

	tests := []struct {
		ip       string
		expected RouteAction
		matched  bool
	}{
		{"192.168.1.1", ActionDirect, true},
		{"10.200.1.5", ActionDirect, true},
		{"1.2.3.4", ActionBlock, true},
		{"8.8.8.8", ActionProxy, false},
	}

	for _, tt := range tests {
		parsedIP := net.ParseIP(tt.ip)
		action, ok := im.Match(parsedIP)
		if ok != tt.matched {
			t.Errorf("ip %s: expected matched=%v, got %v", tt.ip, tt.matched, ok)
		}
		if ok && action != tt.expected {
			t.Errorf("ip %s: expected action=%v, got %v", tt.ip, tt.expected, action)
		}
	}
}

func TestRouterModes(t *testing.T) {
	cfg := Config{
		Mode: ModeRule,
		CustomDirectDomains: []string{"custom-direct.com"},
		CustomBlockDomains:  []string{"custom-block.com"},
	}
	r := NewRouter(cfg)

	// 1. Rule mode:
	// Builtin CN domains -> Direct
	if act := r.Route("www.baidu.com", net.ParseIP("180.101.50.242"), 443); act != ActionDirect {
		t.Errorf("expected baidu.com to be Direct in Rule mode, got %v", act)
	}
	// Apple -> Direct
	if act := r.Route("apple.com", net.ParseIP("17.253.144.10"), 443); act != ActionDirect {
		t.Errorf("expected apple.com to be Direct, got %v", act)
	}
	// Custom direct -> Direct
	if act := r.Route("sub.custom-direct.com", nil, 443); act != ActionDirect {
		t.Errorf("expected custom-direct.com to be Direct, got %v", act)
	}
	// Custom block -> Block
	if act := r.Route("sub.custom-block.com", nil, 443); act != ActionBlock {
		t.Errorf("expected custom-block.com to be Block, got %v", act)
	}
	// Foreign site -> Proxy
	if act := r.Route("google.com", net.ParseIP("142.250.72.206"), 443); act != ActionProxy {
		t.Errorf("expected google.com to be Proxy in Rule mode, got %v", act)
	}
	// Domestic IP (Unknown domain but domestic IP) -> Direct
	if act := r.Route("unknown-domestic.xyz", net.ParseIP("114.114.114.114"), 53); act != ActionDirect {
		t.Errorf("expected unknown domain with 114.114.114.114 to be Direct, got %v", act)
	}
	// Pure domestic IP without domain -> Direct
	if act := r.Route("", net.ParseIP("223.5.5.5"), 443); act != ActionDirect {
		t.Errorf("expected 223.5.5.5 to be Direct, got %v", act)
	}
	// Private IP -> Direct
	if act := r.Route("", net.ParseIP("192.168.1.1"), 80); act != ActionDirect {
		t.Errorf("expected private IP to be Direct, got %v", act)
	}

	// 2. Global mode:
	rGlobal := NewRouter(Config{Mode: ModeGlobal})
	if act := rGlobal.Route("www.baidu.com", net.ParseIP("180.101.50.242"), 443); act != ActionProxy {
		t.Errorf("expected baidu.com to be Proxy in Global mode, got %v", act)
	}

	// 3. Direct mode:
	rDirect := NewRouter(Config{Mode: ModeDirect})
	if act := rDirect.Route("google.com", net.ParseIP("142.250.72.206"), 443); act != ActionDirect {
		t.Errorf("expected google.com to be Direct in Direct mode, got %v", act)
	}
}

func BenchmarkDomainMatching(b *testing.B) {
	r := NewRouter(Config{Mode: ModeRule})
	domains := []string{"www.baidu.com", "google.com", "v.qq.com", "api.github.com", "apple.com"}
	ip := net.ParseIP("1.1.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := domains[i%len(domains)]
		_ = r.Route(d, ip, 443)
	}
}
