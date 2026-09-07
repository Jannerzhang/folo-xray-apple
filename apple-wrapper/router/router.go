// SPDX-License-Identifier: MPL-2.0
package router

import (
	"encoding/json"
	"fmt"
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
	ReasonSecurityBlock RouteReason = 9
	ReasonDNSMapping    RouteReason = 10
	ReasonSniffedDomain RouteReason = 11
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
	case ReasonSecurityBlock:
		return "security_block"
	case ReasonDNSMapping:
		return "dns_mapping"
	case ReasonSniffedDomain:
		return "sniffed_domain"
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
	BlockSecurity       uint64 `json:"blockSecurity"`
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
	SchemaVersion       int       `json:"schemaVersion,omitempty"`
	Revision            uint64    `json:"revision,omitempty"`
	Mode                RouteMode `json:"mode"`
	CustomDirectDomains []string  `json:"customDirectDomains,omitempty"`
	CustomProxyDomains  []string  `json:"customProxyDomains,omitempty"`
	CustomBlockDomains  []string  `json:"customBlockDomains,omitempty"`
	CustomDirectIPs     []string  `json:"customDirectIPs,omitempty"`
	CustomProxyIPs      []string  `json:"customProxyIPs,omitempty"`
	CustomBlockIPs      []string  `json:"customBlockIPs,omitempty"`
}

func (c Config) Validate() error {
	if c.SchemaVersion != 0 && c.SchemaVersion != 1 {
		return fmt.Errorf("unsupported route policy schema version %d", c.SchemaVersion)
	}
	switch c.Mode {
	case "", ModeRule, ModeGlobal, ModeDirect:
	default:
		return fmt.Errorf("unsupported route policy mode %q", c.Mode)
	}
	for name, domains := range map[string][]string{
		"customDirectDomains": c.CustomDirectDomains,
		"customProxyDomains":  c.CustomProxyDomains,
		"customBlockDomains":  c.CustomBlockDomains,
	} {
		for _, domain := range domains {
			if err := validateDomainRule(domain); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	for name, cidrs := range map[string][]string{
		"customDirectIPs": c.CustomDirectIPs,
		"customProxyIPs":  c.CustomProxyIPs,
		"customBlockIPs":  c.CustomBlockIPs,
	} {
		for _, cidr := range cidrs {
			value := strings.TrimSpace(cidr)
			if value == "" {
				return fmt.Errorf("%s contains an empty CIDR", name)
			}
			if _, _, err := net.ParseCIDR(value); err != nil && net.ParseIP(value) == nil {
				return fmt.Errorf("%s contains invalid IP/CIDR %q", name, cidr)
			}
		}
	}
	return nil
}

func validateDomainRule(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 {
		return fmt.Errorf("invalid domain rule %q", value)
	}
	if prefix, pattern, ok := strings.Cut(value, ":"); ok {
		if pattern == "" || (prefix != "domain" && prefix != "full" && prefix != "keyword") {
			return fmt.Errorf("unsupported domain rule %q", value)
		}
	}
	return nil
}

// RouteProvenance identifies the layer that supplied the domain or IP used by
// a decision. The values are part of the cross-language RoutePolicy contract.
type RouteProvenance string

const (
	ProvenanceExplicit RouteProvenance = "explicit"
	ProvenanceDNS      RouteProvenance = "dns_mapping"
	ProvenanceSniffed  RouteProvenance = "sniffed_domain"
	ProvenanceIPSet    RouteProvenance = "ip_set"
	ProvenanceDefault  RouteProvenance = "default"
)

// DNSAttribution is supplied by a resolver-owned cache. A record is usable
// only when its revision matches the active RoutePolicy revision.
type DNSAttribution struct {
	Domain          string      `json:"domain"`
	Revision        uint64      `json:"revision"`
	PreferredAction RouteAction `json:"preferredAction"`
	SecurityBlock   bool        `json:"securityBlock,omitempty"`
}

// RouteContext carries the complete decision input into the production data
// plane. Provenance must be explicit for sniffed domains; legacy callers can
// continue using Route/RouteWithReason.
type RouteContext struct {
	Domain     string
	IP         net.IP
	Port       uint16
	Network    string
	Provenance RouteProvenance
	DNS        *DNSAttribution
}

// RouteDecision is the stable decision envelope shared by Swift, Go and the
// Rust candidate. Action/reason are kept as typed values in Go and serialized
// as their contract strings.
type RouteDecision struct {
	SchemaVersion int             `json:"schemaVersion"`
	Revision      uint64          `json:"revision"`
	Action        RouteAction     `json:"-"`
	Reason        RouteReason     `json:"-"`
	Provenance    RouteProvenance `json:"provenance"`
	Matched       string          `json:"matched,omitempty"`
}

func (d RouteDecision) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SchemaVersion int             `json:"schemaVersion"`
		Revision      uint64          `json:"revision"`
		Action        string          `json:"action"`
		Reason        string          `json:"reason"`
		Provenance    RouteProvenance `json:"provenance"`
		Matched       string          `json:"matched,omitempty"`
	}{
		SchemaVersion: d.SchemaVersion,
		Revision:      d.Revision,
		Action:        d.Action.String(),
		Reason:        d.Reason.String(),
		Provenance:    d.Provenance,
		Matched:       d.Matched,
	})
}

type Router struct {
	mu                   sync.RWMutex
	mode                 RouteMode
	schemaVersion        int
	revision             uint64
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
	blockSecurity       atomic.Uint64
}

func (r *Router) PolicyIdentity() (schemaVersion int, revision uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.schemaVersion, r.revision
}

func NewRouter(cfg Config) *Router {
	router, err := NewValidatedRouter(cfg)
	if err == nil {
		return router
	}
	// Keep the historical constructor total for tests and compatibility. The
	// production FFI entry point uses NewValidatedRouter and rejects this path.
	safe, _ := NewValidatedRouter(Config{Mode: ModeRule, SchemaVersion: 1, Revision: 1})
	return safe
}

func NewValidatedRouter(cfg Config) (*Router, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	mode := cfg.Mode
	if mode == "" {
		mode = ModeRule
	}
	schemaVersion := cfg.SchemaVersion
	if schemaVersion == 0 {
		schemaVersion = 1
	}
	revision := cfg.Revision
	if revision == 0 {
		revision = 1
	}

	customDM := NewDomainMatcher()
	builtinDM := NewDomainMatcher()
	customIM := NewIPMatcher()

	// Custom rules are compiled into one matcher, which resolves overlapping
	// actions by security block > proxy > direct regardless of insertion order.
	for _, d := range cfg.CustomBlockDomains {
		addDomainRule(customDM, d, ActionBlock)
	}
	for _, d := range cfg.CustomDirectDomains {
		addDomainRule(customDM, d, ActionDirect)
	}
	for _, d := range cfg.CustomProxyDomains {
		addDomainRule(customDM, d, ActionProxy)
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

	// Security block rules are active in every mode. Direct built-ins are only
	// meaningful in rule mode; global/direct mode still cannot bypass blocks.
	for _, d := range BuiltinBlockSuffixes {
		addDomainRule(builtinDM, d, ActionBlock)
	}
	if mode == ModeRule {
		for _, d := range BuiltinDirectSuffixes {
			addDomainRule(builtinDM, d, ActionDirect)
		}
	}

	return &Router{
		mode:                 mode,
		schemaVersion:        schemaVersion,
		revision:             revision,
		customDomainMatcher:  customDM,
		builtinDomainMatcher: builtinDM,
		customIPMatcher:      customIM,
	}, nil
}

func addDomainRule(matcher *DomainMatcher, value string, action RouteAction) {
	value = strings.TrimSpace(strings.ToLower(value))
	if prefix, pattern, ok := strings.Cut(value, ":"); ok {
		switch prefix {
		case "full":
			matcher.AddExact(pattern, action)
		case "keyword":
			matcher.AddKeyword(pattern, action)
		default:
			matcher.AddSuffix(pattern, action)
		}
		return
	}
	matcher.AddSuffix(value, action)
}

// Route decides the outbound action for a target (domain or IP).
func (r *Router) Route(domain string, ip net.IP, port uint16) RouteAction {
	return r.RouteWithContext(RouteContext{
		Domain:     domain,
		IP:         ip,
		Port:       port,
		Provenance: provenanceForLegacyInput(domain, ip),
	}).Action
}

// RouteWithReason keeps the legacy typed return shape while using the same
// priority engine and decision envelope as production RouteWithContext.
func (r *Router) RouteWithReason(domain string, ip net.IP, port uint16) (RouteAction, RouteReason) {
	decision := r.RouteWithContext(RouteContext{
		Domain:     domain,
		IP:         ip,
		Port:       port,
		Provenance: provenanceForLegacyInput(domain, ip),
	})
	return decision.Action, decision.Reason
}

// RouteWithContext evaluates the ordered policy in the production Go netstack
// and exposes revision/action/reason/provenance for cross-core parity.
func (r *Router) RouteWithContext(input RouteContext) RouteDecision {
	r.mu.RLock()
	mode := r.mode
	r.mu.RUnlock()

	domain := strings.TrimSpace(strings.ToLower(input.Domain))
	provenance := input.Provenance
	if provenance == "" {
		provenance = provenanceForLegacyInput(domain, input.IP)
	}
	decision := func(action RouteAction, reason RouteReason, source RouteProvenance, matched string) RouteDecision {
		r.record(action, reason)
		return RouteDecision{
			SchemaVersion: r.schemaVersion,
			Revision:      r.revision,
			Action:        action,
			Reason:        reason,
			Provenance:    source,
			Matched:       matched,
		}
	}

	// Security block always wins, including private IPs and global/direct mode.
	if domain != "" {
		if action, ok := r.customDomainMatcher.Match(domain); ok && action == ActionBlock {
			return decision(ActionBlock, ReasonSecurityBlock, ProvenanceExplicit, domain)
		}
		if action, ok := r.builtinDomainMatcher.Match(domain); ok && action == ActionBlock {
			return decision(ActionBlock, ReasonSecurityBlock, ProvenanceExplicit, domain)
		}
	}
	if input.IP != nil {
		if action, ok := r.customIPMatcher.Match(input.IP); ok && action == ActionBlock {
			return decision(ActionBlock, ReasonSecurityBlock, ProvenanceIPSet, input.IP.String())
		}
	}

	if domain != "" {
		if action, ok := r.customDomainMatcher.Match(domain); ok && action != ActionBlock {
			reason := ReasonCustomDomain
			source := ProvenanceExplicit
			if provenance == ProvenanceSniffed {
				reason = ReasonSniffedDomain
				source = ProvenanceSniffed
			}
			return decision(action, reason, source, domain)
		}
		if action, ok := r.builtinDomainMatcher.Match(domain); ok && action != ActionBlock {
			return decision(action, ReasonBuiltinDomain, ProvenanceExplicit, domain)
		}
	}

	// Explicit DNS attribution is below explicit target rules and above sniffed
	// domains/IP sets. Revision mismatch is intentionally ignored.
	if input.DNS != nil && input.DNS.Revision == r.revision && input.DNS.Domain != "" {
		if input.DNS.SecurityBlock {
			return decision(ActionBlock, ReasonSecurityBlock, ProvenanceDNS, input.DNS.Domain)
		}
		if input.DNS.PreferredAction == ActionProxy || input.DNS.PreferredAction == ActionDirect {
			return decision(input.DNS.PreferredAction, ReasonDNSMapping, ProvenanceDNS, input.DNS.Domain)
		}
	}

	if input.IP != nil {
		if action, ok := r.customIPMatcher.Match(input.IP); ok && action != ActionBlock {
			return decision(action, ReasonCustomIP, ProvenanceIPSet, input.IP.String())
		}
	}

	// Keep established private-IP behavior, but only after block and explicit
	// custom rules have been checked.
	if IsPrivateIP(input.IP) {
		return decision(ActionDirect, ReasonPrivateIP, ProvenanceIPSet, input.IP.String())
	}
	if mode == ModeGlobal {
		return decision(ActionProxy, ReasonModeGlobal, ProvenanceDefault, "")
	}
	if mode == ModeDirect {
		return decision(ActionDirect, ReasonModeDirect, ProvenanceDefault, "")
	}
	if mode == ModeRule && input.IP != nil && IsChinaIP(input.IP) {
		return decision(ActionDirect, ReasonChinaIP, ProvenanceIPSet, input.IP.String())
	}

	return decision(ActionProxy, ReasonDefaultProxy, ProvenanceDefault, "")
}

func provenanceForLegacyInput(domain string, ip net.IP) RouteProvenance {
	if strings.TrimSpace(domain) != "" {
		return ProvenanceExplicit
	}
	if ip != nil {
		return ProvenanceIPSet
	}
	return ProvenanceDefault
}

func (r *Router) record(action RouteAction, reason RouteReason) {
	switch reason {
	case ReasonSecurityBlock:
		r.blockSecurity.Add(1)
	case ReasonCustomDomain:
		switch action {
		case ActionDirect:
			r.directCustomDomain.Add(1)
		case ActionProxy:
			r.proxyCustomDomain.Add(1)
		}
	case ReasonBuiltinDomain:
		switch action {
		case ActionDirect:
			r.directBuiltinDomain.Add(1)
		case ActionBlock:
			r.blockBuiltinDomain.Add(1)
		}
	case ReasonCustomIP:
		switch action {
		case ActionDirect:
			r.directCustomIP.Add(1)
		case ActionProxy:
			r.proxyCustomIP.Add(1)
		}
	case ReasonPrivateIP:
		r.directPrivateIP.Add(1)
	case ReasonChinaIP:
		r.directChinaIP.Add(1)
	case ReasonModeGlobal:
		r.proxyModeGlobal.Add(1)
	case ReasonModeDirect:
		r.directModeDirect.Add(1)
	case ReasonDNSMapping, ReasonSniffedDomain:
		if action == ActionProxy {
			r.proxyCustomDomain.Add(1)
		} else if action == ActionDirect {
			r.directCustomDomain.Add(1)
		}
	case ReasonDefaultProxy:
		r.proxyDefault.Add(1)
	}
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
	blkSecurity := r.blockSecurity.Load()

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
		BlockSecurity:       blkSecurity,
		TotalDirect:         dirPriv + dirMode + dirCustDom + dirBltDom + dirCustIP + dirChina,
		TotalProxy:          prxMode + prxCustDom + prxCustIP + prxDef,
		TotalBlock:          blkCustDom + blkCustIP + blkBltDom + blkSecurity,
	}
}
