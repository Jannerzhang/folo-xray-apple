// SPDX-License-Identifier: MPL-2.0
package router

import (
	"net"
	"strings"
	"sync"
)

type RouteAction int

const (
	ActionProxy  RouteAction = 0
	ActionDirect RouteAction = 1
	ActionBlock  RouteAction = 2
)

func (a RouteAction) String() string {
	switch a {
	case ActionDirect:
		return "direct"
	case ActionBlock:
		return "block"
	default:
		return "proxy"
	}
}

type RouteMode string

const (
	ModeRule   RouteMode = "rule"
	ModeGlobal RouteMode = "global"
	ModeDirect RouteMode = "direct"
)

type Config struct {
	Mode                RouteMode `json:"mode"`
	CustomDirectDomains []string  `json:"customDirectDomains,omitempty"`
	CustomProxyDomains  []string  `json:"customProxyDomains,omitempty"`
	CustomBlockDomains  []string  `json:"customBlockDomains,omitempty"`
	CustomDirectIPs     []string  `json:"customDirectIPs,omitempty"`
	CustomProxyIPs      []string  `json:"customProxyIPs,omitempty"`
	CustomBlockIPs      []string  `json:"customBlockIPs,omitempty"`
}

type Router struct {
	mu            sync.RWMutex
	mode          RouteMode
	domainMatcher *DomainMatcher
	ipMatcher     *IPMatcher
}

func NewRouter(cfg Config) *Router {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeRule
	}

	dm := NewDomainMatcher()
	im := NewIPMatcher()

	// 1. Load Custom Rules
	for _, d := range cfg.CustomBlockDomains {
		dm.AddSuffix(d, ActionBlock)
	}
	for _, d := range cfg.CustomDirectDomains {
		dm.AddSuffix(d, ActionDirect)
	}
	for _, d := range cfg.CustomProxyDomains {
		dm.AddSuffix(d, ActionProxy)
	}

	for _, cidr := range cfg.CustomBlockIPs {
		_ = im.AddCIDR(cidr, ActionBlock)
	}
	for _, cidr := range cfg.CustomDirectIPs {
		_ = im.AddCIDR(cidr, ActionDirect)
	}
	for _, cidr := range cfg.CustomProxyIPs {
		_ = im.AddCIDR(cidr, ActionProxy)
	}

	// 2. Load Builtin Rules for Rule Mode
	if mode == ModeRule {
		for _, d := range BuiltinBlockSuffixes {
			dm.AddSuffix(d, ActionBlock)
		}
		for _, d := range BuiltinDirectSuffixes {
			dm.AddSuffix(d, ActionDirect)
		}
	}

	return &Router{
		mode:          mode,
		domainMatcher: dm,
		ipMatcher:     im,
	}
}

// Route decides the outbound action for a target (domain or IP).
func (r *Router) Route(domain string, ip net.IP, port uint16) RouteAction {
	r.mu.RLock()
	mode := r.mode
	r.mu.RUnlock()

	// Global / Direct mode overrides (except private IPs which are always direct)
	if IsPrivateIP(ip) {
		return ActionDirect
	}

	if mode == ModeGlobal {
		return ActionProxy
	}
	if mode == ModeDirect {
		return ActionDirect
	}

	// 1. Domain match
	cleanDomain := strings.TrimSpace(domain)
	if cleanDomain != "" {
		if action, ok := r.domainMatcher.Match(cleanDomain); ok {
			return action
		}
	}

	// 2. IP match
	if ip != nil {
		if action, ok := r.ipMatcher.Match(ip); ok {
			return action
		}
		// 3. Built-in China IP match (in Rule mode)
		if mode == ModeRule && IsChinaIP(ip) {
			return ActionDirect
		}
	}

	// Default for rule mode is Proxy
	return ActionProxy
}
