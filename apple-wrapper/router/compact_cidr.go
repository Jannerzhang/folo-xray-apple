// SPDX-License-Identifier: MPL-2.0
package router

import (
	"net"
	"sync"
)

type IPMatcher struct {
	mu    sync.RWMutex
	rules []cidrRule
}

type cidrRule struct {
	ipNet  *net.IPNet
	action RouteAction
}

func NewIPMatcher() *IPMatcher {
	return &IPMatcher{
		rules: make([]cidrRule, 0),
	}
}

func (m *IPMatcher) AddCIDR(cidrStr string, action RouteAction) error {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		ip := net.ParseIP(cidrStr)
		if ip == nil {
			return err
		}
		if ip4 := ip.To4(); ip4 != nil {
			ipNet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
		} else {
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = append(m.rules, cidrRule{ipNet: ipNet, action: action})
	return nil
}

func (m *IPMatcher) Match(ip net.IP) (RouteAction, bool) {
	if ip == nil {
		return ActionProxy, false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var best RouteAction
	matched := false
	for _, r := range m.rules {
		if r.ipNet.Contains(ip) {
			if !matched || routeActionPriority(r.action) > routeActionPriority(best) {
				best = r.action
				matched = true
			}
		}
	}
	return best, matched
}

// IsPrivateIP checks if an IP is in RFC1918, loopback, link-local, or private ranges.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Carrier-grade NAT: 100.64.0.0/10
		if ip4[0] == 100 && (ip4[1]&0xC0) == 64 {
			return true
		}
		// Broadcast: 255.255.255.255
		if ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 {
			return true
		}
	}
	return false
}
