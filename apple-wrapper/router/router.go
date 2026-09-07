// SPDX-License-Identifier: MPL-2.0
package router

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
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

type RouteReason int

const (
	ReasonUnknown       RouteReason = 0
	ReasonPrivateIP     RouteReason = 1
	ReasonModeGlobal    RouteReason = 2
	ReasonModeDirect    RouteReason = 3
	ReasonCustomDomain  RouteReason = 4
	ReasonBuiltinDomain RouteReason = 5
	ReasonCustomIP      RouteReason = 6
	ReasonChinaIP       RouteReason = 7
	ReasonDefaultProxy  RouteReason = 8
)

func (r RouteReason) String() string {
	switch r {
	case ReasonPrivateIP:
		return "private_ip"
	case ReasonModeGlobal:
		return "mode_global"
	case ReasonModeDirect:
		return "mode_direct"
	case ReasonCustomDomain:
		return "custom_domain"
	case ReasonBuiltinDomain:
		return "builtin_domain"
	case ReasonCustomIP:
		return "custom_ip"
	case ReasonChinaIP:
		return "china_ip"
	case ReasonDefaultProxy:
		return "default_proxy"
	default:
		return "unknown"
	}
}

type RouteStats struct {
	DirectPrivateIP     uint64 `json:"directPrivateIP"`
	DirectModeDirect    uint64 `json:"directModeDirect"`
	DirectCustomDomain  uint64 `json:"directCustomDomain"`
	DirectBuiltinDomain uint64 `json:"directBuiltinDomain"`
	DirectCustomIP      uint64 `json:"directCustomIP"`
	DirectChinaIP       uint64 `json:"directChinaIP"`
	ProxyModeGlobal     uint64 `json:"proxyModeGlobal"`
	ProxyCustomDomain   uint64 `json:"proxyCustomDomain"`
	ProxyCustomIP       uint64 `json:"proxyCustomIP"`
	ProxyDefault        uint64 `json:"proxyDefault"`
	BlockCustomDomain   uint64 `json:"blockCustomDomain"`
	BlockCustomIP       uint64 `json:"blockCustomIP"`
	BlockBuiltinDomain  uint64 `json:"blockBuiltinDomain"`
	TotalDirect         uint64 `json:"totalDirect"`
	TotalProxy          uint64 `json:"totalProxy"`
	TotalBlock          uint64 `json:"totalBlock"`
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
	mu                   sync.RWMutex
	mode                 RouteMode
	customDomainMatcher  *DomainMatcher
	builtinDomainMatcher *DomainMatcher
	customIPMatcher      *IPMatcher

	directPrivateIP     atomic.Uint64
	directModeDirect    atomic.Uint64
	directCustomDomain  atomic.Uint64
	directBuiltinDomain atomic.Uint64
	directCustomIP      atomic.Uint64
	directChinaIP       atomic.Uint64
	proxyModeGlobal     atomic.Uint64
	proxyCustomDomain   atomic.Uint64
	proxyCustomIP       atomic.Uint64
	proxyDefault        atomic.Uint64
	blockCustomDomain   atomic.Uint64
	blockCustomIP       atomic.Uint64
	blockBuiltinDomain  atomic.Uint64
}

func NewRouter(cfg Config) *Router {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeRule
	}

	customDM := NewDomainMatcher()
	builtinDM := NewDomainMatcher()
	customIM := NewIPMatcher()

	// 1. Load Custom Rules
	for _, d := range cfg.CustomBlockDomains {
		customDM.AddSuffix(d, ActionBlock)
	}
	for _, d := range cfg.CustomDirectDomains {
		customDM.AddSuffix(d, ActionDirect)
	}
	for _, d := range cfg.CustomProxyDomains {
		customDM.AddSuffix(d, ActionProxy)
	}

	for _, cidr := range cfg.CustomBlockIPs {
		_ = customIM.AddCIDR(cidr, ActionBlock)
	}
	for _, cidr := range cfg.CustomDirectIPs {
		_ = customIM.AddCIDR(cidr, ActionDirect)
	}
	for _, cidr := range cfg.CustomProxyIPs {
		_ = customIM.AddCIDR(cidr, ActionProxy)
	}

	// 2. Load Builtin Rules for Rule Mode
	if mode == ModeRule {
		for _, d := range BuiltinBlockSuffixes {
			builtinDM.AddSuffix(d, ActionBlock)
		}
		for _, d := range BuiltinDirectSuffixes {
			builtinDM.AddSuffix(d, ActionDirect)
		}
	}

	return &Router{
		mode:                 mode,
		customDomainMatcher:  customDM,
		builtinDomainMatcher: builtinDM,
		customIPMatcher:      customIM,
	}
}

// Route decides the outbound action for a target (domain or IP).
func (r *Router) Route(domain string, ip net.IP, port uint16) RouteAction {
	action, _ := r.RouteWithReason(domain, ip, port)
	return action
}

// RouteWithReason decides outbound action and records the decision reason and telemetry counters.
func (r *Router) RouteWithReason(domain string, ip net.IP, port uint16) (RouteAction, RouteReason) {
	r.mu.RLock()
	mode := r.mode
	r.mu.RUnlock()

	// Global / Direct mode overrides (except private IPs which are always direct)
	if IsPrivateIP(ip) {
		r.directPrivateIP.Add(1)
		return ActionDirect, ReasonPrivateIP
	}

	if mode == ModeGlobal {
		r.proxyModeGlobal.Add(1)
		return ActionProxy, ReasonModeGlobal
	}
	if mode == ModeDirect {
		r.directModeDirect.Add(1)
		return ActionDirect, ReasonModeDirect
	}

	// 1. Custom Domain match
	cleanDomain := strings.TrimSpace(domain)
	if cleanDomain != "" {
		if action, ok := r.customDomainMatcher.Match(cleanDomain); ok {
			switch action {
			case ActionDirect:
				r.directCustomDomain.Add(1)
			case ActionBlock:
				r.blockCustomDomain.Add(1)
			default:
				r.proxyCustomDomain.Add(1)
			}
			return action, ReasonCustomDomain
		}
	}

	// 2. Builtin Domain match (Rule mode)
	if cleanDomain != "" && mode == ModeRule {
		if action, ok := r.builtinDomainMatcher.Match(cleanDomain); ok {
			switch action {
			case ActionDirect:
				r.directBuiltinDomain.Add(1)
			case ActionBlock:
				r.blockBuiltinDomain.Add(1)
			default:
				r.proxyDefault.Add(1)
			}
			return action, ReasonBuiltinDomain
		}
	}

	// 3. Custom IP match
	if ip != nil {
		if action, ok := r.customIPMatcher.Match(ip); ok {
			switch action {
			case ActionDirect:
				r.directCustomIP.Add(1)
			case ActionBlock:
				r.blockCustomIP.Add(1)
			default:
				r.proxyCustomIP.Add(1)
			}
			return action, ReasonCustomIP
		}
		// 4. Built-in China IP match (in Rule mode)
		if mode == ModeRule && IsChinaIP(ip) {
			r.directChinaIP.Add(1)
			return ActionDirect, ReasonChinaIP
		}
	}

	// Default for rule mode is Proxy
	r.proxyDefault.Add(1)
	return ActionProxy, ReasonDefaultProxy
}

// Stats returns a snapshot of accumulated routing decisions.
func (r *Router) Stats() RouteStats {
	dirPriv := r.directPrivateIP.Load()
	dirMode := r.directModeDirect.Load()
	dirCustDom := r.directCustomDomain.Load()
	dirBltDom := r.directBuiltinDomain.Load()
	dirCustIP := r.directCustomIP.Load()
	dirChina := r.directChinaIP.Load()

	prxMode := r.proxyModeGlobal.Load()
	prxCustDom := r.proxyCustomDomain.Load()
	prxCustIP := r.proxyCustomIP.Load()
	prxDef := r.proxyDefault.Load()

	blkCustDom := r.blockCustomDomain.Load()
	blkCustIP := r.blockCustomIP.Load()
	blkBltDom := r.blockBuiltinDomain.Load()

	return RouteStats{
		DirectPrivateIP:     dirPriv,
		DirectModeDirect:    dirMode,
		DirectCustomDomain:  dirCustDom,
		DirectBuiltinDomain: dirBltDom,
		DirectCustomIP:      dirCustIP,
		DirectChinaIP:       dirChina,
		ProxyModeGlobal:     prxMode,
		ProxyCustomDomain:   prxCustDom,
		ProxyCustomIP:       prxCustIP,
		ProxyDefault:        prxDef,
		BlockCustomDomain:   blkCustDom,
		BlockCustomIP:       blkCustIP,
		BlockBuiltinDomain:  blkBltDom,
		TotalDirect:         dirPriv + dirMode + dirCustDom + dirBltDom + dirCustIP + dirChina,
		TotalProxy:          prxMode + prxCustDom + prxCustIP + prxDef,
		TotalBlock:          blkCustDom + blkCustIP + blkBltDom,
	}
}

