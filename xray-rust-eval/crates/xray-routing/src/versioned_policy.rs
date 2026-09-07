// SPDX-License-Identifier: MPL-2.0
use std::sync::{Arc, RwLock};
use std::time::Instant;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    canonicalize_ip,
    decision::{DomainProvenance, RouteAction, RouteDecision, RouteReason},
    dns_cache::DnsAttributionCache,
    Cidr, DomainMatcher, DomainMatcherSet, DomainNameMode, IpRangeSet, Network,
    Target, TargetAddr,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    Rule,
    Global,
    Direct,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy validation failed: {0}")]
    Validation(String),
    #[error("revision exhausted")]
    RevisionExhausted,
}

#[derive(Clone)]
pub struct VersionedRoutingPolicy {
    pub revision: u64,
    pub fingerprint: [u8; 32],
    pub mode: PolicyMode,
    security_block_domains: DomainMatcherSet,
    security_block_ips: IpRangeSet,
    explicit_direct_domains: DomainMatcherSet,
    explicit_proxy_domains: DomainMatcherSet,
    explicit_direct_ips: IpRangeSet,
    explicit_proxy_ips: IpRangeSet,
    china_ips: IpRangeSet,
    private_ips: IpRangeSet,
}

impl VersionedRoutingPolicy {
    pub fn builder(revision: u64, mode: PolicyMode) -> VersionedRoutingPolicyBuilder {
        VersionedRoutingPolicyBuilder::new(revision, mode)
    }

    pub fn route(
        &self,
        network: Network,
        target: &Target,
        sniffed_domain: Option<&str>,
        dns_cache: &mut DnsAttributionCache,
        now: Instant,
    ) -> RouteDecision {
        let (explicit_domain, target_ip) = match &target.addr {
            TargetAddr::Domain(domain) => (Some(domain.as_str()), None),
            TargetAddr::Ip(ip) => (None, Some(canonicalize_ip(*ip))),
        };

        // 1. Security Block (highest priority)
        if let Some(domain) = explicit_domain {
            if self.security_block_domains.matches(domain) {
                return RouteDecision {
                    network,
                    domain_provenance: DomainProvenance::Explicit,
                    ip: target_ip,
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Block,
                    reason: RouteReason::SecurityBlock,
                    matched_pattern: Some(domain.to_string()),
                };
            }
        }
        if let Some(ip) = target_ip {
            if self.security_block_ips.contains(ip) {
                return RouteDecision {
                    network,
                    domain_provenance: DomainProvenance::None,
                    ip: Some(ip),
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Block,
                    reason: RouteReason::SecurityBlock,
                    matched_pattern: Some(ip.to_string()),
                };
            }
        }

        // Fast path for Global or Direct modes
        match self.mode {
            PolicyMode::Global => {
                return RouteDecision {
                    network,
                    domain_provenance: explicit_domain.map_or(DomainProvenance::None, |_| DomainProvenance::Explicit),
                    ip: target_ip,
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Proxy,
                    reason: RouteReason::Default,
                    matched_pattern: None,
                };
            }
            PolicyMode::Direct => {
                return RouteDecision {
                    network,
                    domain_provenance: explicit_domain.map_or(DomainProvenance::None, |_| DomainProvenance::Explicit),
                    ip: target_ip,
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Direct,
                    reason: RouteReason::Default,
                    matched_pattern: None,
                };
            }
            PolicyMode::Rule => {}
        }

        // 2. Explicit proxy / direct domains (for explicit domain targets)
        if let Some(domain) = explicit_domain {
            if self.explicit_proxy_domains.matches(domain) {
                return RouteDecision {
                    network,
                    domain_provenance: DomainProvenance::Explicit,
                    ip: target_ip,
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Proxy,
                    reason: RouteReason::ExplicitProxyDomain,
                    matched_pattern: Some(domain.to_string()),
                };
            }
            if self.explicit_direct_domains.matches(domain) {
                return RouteDecision {
                    network,
                    domain_provenance: DomainProvenance::Explicit,
                    ip: target_ip,
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Direct,
                    reason: RouteReason::ExplicitDirectDomain,
                    matched_pattern: Some(domain.to_string()),
                };
            }
        }

        // 3. DNS-domain mapping (from DNS attribution cache)
        if let Some(ip) = target_ip {
            if let Some(dns_rec) = dns_cache.lookup_ip_for_revision(&ip, None, self.revision, now) {
                if dns_rec.is_security_block {
                    return RouteDecision {
                        network,
                        domain_provenance: DomainProvenance::DnsMapping,
                        ip: Some(ip),
                        port: target.port,
                        rule_revision: self.revision,
                        action: RouteAction::Block,
                        reason: RouteReason::SecurityBlock,
                        matched_pattern: Some(dns_rec.qname_normalized),
                    };
                }
                if dns_rec.is_proxy_preferred || self.explicit_proxy_domains.matches(&dns_rec.qname_normalized) {
                    return RouteDecision {
                        network,
                        domain_provenance: DomainProvenance::DnsMapping,
                        ip: Some(ip),
                        port: target.port,
                        rule_revision: self.revision,
                        action: RouteAction::Proxy,
                        reason: RouteReason::DnsDomainMapping,
                        matched_pattern: Some(dns_rec.qname_normalized),
                    };
                }
                if self.explicit_direct_domains.matches(&dns_rec.qname_normalized) {
                    return RouteDecision {
                        network,
                        domain_provenance: DomainProvenance::DnsMapping,
                        ip: Some(ip),
                        port: target.port,
                        rule_revision: self.revision,
                        action: RouteAction::Direct,
                        reason: RouteReason::DnsDomainMapping,
                        matched_pattern: Some(dns_rec.qname_normalized),
                    };
                }
            }
        }

        // 4. Sniffed domain (from TLS SNI, HTTP Host, QUIC Initial)
        if let Some(sniffed) = sniffed_domain {
            if self.security_block_domains.matches(sniffed) {
                return RouteDecision {
                    network,
                    domain_provenance: DomainProvenance::Sniffed,
                    ip: target_ip,
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Block,
                    reason: RouteReason::SecurityBlock,
                    matched_pattern: Some(sniffed.to_string()),
                };
            }
            if self.explicit_proxy_domains.matches(sniffed) {
                return RouteDecision {
                    network,
                    domain_provenance: DomainProvenance::Sniffed,
                    ip: target_ip,
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Proxy,
                    reason: RouteReason::SniffedDomain,
                    matched_pattern: Some(sniffed.to_string()),
                };
            }
            if self.explicit_direct_domains.matches(sniffed) {
                return RouteDecision {
                    network,
                    domain_provenance: DomainProvenance::Sniffed,
                    ip: target_ip,
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Direct,
                    reason: RouteReason::SniffedDomain,
                    matched_pattern: Some(sniffed.to_string()),
                };
            }
        }

        // 5. IP set (private IP, custom IP, China IP)
        if let Some(ip) = target_ip {
            if self.private_ips.contains(ip) {
                return RouteDecision {
                    network,
                    domain_provenance: DomainProvenance::None,
                    ip: Some(ip),
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Direct,
                    reason: RouteReason::PrivateIp,
                    matched_pattern: Some(ip.to_string()),
                };
            }
            if self.explicit_proxy_ips.contains(ip) {
                return RouteDecision {
                    network,
                    domain_provenance: DomainProvenance::None,
                    ip: Some(ip),
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Proxy,
                    reason: RouteReason::CustomIp,
                    matched_pattern: Some(ip.to_string()),
                };
            }
            if self.explicit_direct_ips.contains(ip) {
                return RouteDecision {
                    network,
                    domain_provenance: DomainProvenance::None,
                    ip: Some(ip),
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Direct,
                    reason: RouteReason::CustomIp,
                    matched_pattern: Some(ip.to_string()),
                };
            }
            if self.china_ips.contains(ip) {
                return RouteDecision {
                    network,
                    domain_provenance: DomainProvenance::None,
                    ip: Some(ip),
                    port: target.port,
                    rule_revision: self.revision,
                    action: RouteAction::Direct,
                    reason: RouteReason::ChinaIp,
                    matched_pattern: Some(ip.to_string()),
                };
            }
        }

        // 6. Default fallback (proxy in Rule mode)
        RouteDecision {
            network,
            domain_provenance: explicit_domain.map_or(DomainProvenance::None, |_| DomainProvenance::Explicit),
            ip: target_ip,
            port: target.port,
            rule_revision: self.revision,
            action: RouteAction::Proxy,
            reason: RouteReason::Default,
            matched_pattern: None,
        }
    }
}

fn domain_matcher_pattern(m: &DomainMatcher) -> &str {
    match m {
        DomainMatcher::Keyword(s) => s.as_str(),
        DomainMatcher::Full(s) => s.as_str(),
        DomainMatcher::Suffix(s) => s.as_str(),
        DomainMatcher::Regex(r) => r.pattern(),
    }
}

fn domain_matcher_kind(m: &DomainMatcher) -> &'static str {
    match m {
        DomainMatcher::Keyword(_) => "keyword",
        DomainMatcher::Full(_) => "full",
        DomainMatcher::Suffix(_) => "suffix",
        DomainMatcher::Regex(_) => "regex",
    }
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn update_matcher_list(hasher: &mut Sha256, name: &[u8], matchers: &[DomainMatcher]) {
    update_length_prefixed(hasher, name);
    let mut values = matchers
        .iter()
        .map(|matcher| format!("{}:{}", domain_matcher_kind(matcher), domain_matcher_pattern(matcher)))
        .collect::<Vec<_>>();
    values.sort_unstable();
    hasher.update((values.len() as u64).to_be_bytes());
    for value in values {
        update_length_prefixed(hasher, value.as_bytes());
    }
}

fn update_cidr_list(hasher: &mut Sha256, name: &[u8], cidrs: &[Cidr]) {
    update_length_prefixed(hasher, name);
    let mut values = cidrs
        .iter()
        .map(|cidr| format!("{}/{}", cidr.network(), cidr.prefix_len()))
        .collect::<Vec<_>>();
    values.sort_unstable();
    hasher.update((values.len() as u64).to_be_bytes());
    for value in values {
        update_length_prefixed(hasher, value.as_bytes());
    }
}

fn policy_mode_tag(mode: PolicyMode) -> &'static [u8] {
    match mode {
        PolicyMode::Rule => b"rule",
        PolicyMode::Global => b"global",
        PolicyMode::Direct => b"direct",
    }
}

pub struct VersionedRoutingPolicyBuilder {
    revision: u64,
    mode: PolicyMode,
    security_block_domains: Vec<DomainMatcher>,
    security_block_cidrs: Vec<Cidr>,
    explicit_direct_domains: Vec<DomainMatcher>,
    explicit_proxy_domains: Vec<DomainMatcher>,
    explicit_direct_cidrs: Vec<Cidr>,
    explicit_proxy_cidrs: Vec<Cidr>,
    china_cidrs: Vec<Cidr>,
}

impl VersionedRoutingPolicyBuilder {
    pub fn new(revision: u64, mode: PolicyMode) -> Self {
        Self {
            revision,
            mode,
            security_block_domains: Vec::new(),
            security_block_cidrs: Vec::new(),
            explicit_direct_domains: Vec::new(),
            explicit_proxy_domains: Vec::new(),
            explicit_direct_cidrs: Vec::new(),
            explicit_proxy_cidrs: Vec::new(),
            china_cidrs: Vec::new(),
        }
    }

    pub fn add_security_block_domain(&mut self, matcher: DomainMatcher) -> &mut Self {
        self.security_block_domains.push(matcher);
        self
    }

    pub fn add_security_block_cidr(&mut self, cidr: Cidr) -> &mut Self {
        self.security_block_cidrs.push(cidr);
        self
    }

    pub fn add_explicit_direct_domain(&mut self, matcher: DomainMatcher) -> &mut Self {
        self.explicit_direct_domains.push(matcher);
        self
    }

    pub fn add_explicit_proxy_domain(&mut self, matcher: DomainMatcher) -> &mut Self {
        self.explicit_proxy_domains.push(matcher);
        self
    }

    pub fn add_explicit_direct_cidr(&mut self, cidr: Cidr) -> &mut Self {
        self.explicit_direct_cidrs.push(cidr);
        self
    }

    pub fn add_explicit_proxy_cidr(&mut self, cidr: Cidr) -> &mut Self {
        self.explicit_proxy_cidrs.push(cidr);
        self
    }

    pub fn add_china_cidr(&mut self, cidr: Cidr) -> &mut Self {
        self.china_cidrs.push(cidr);
        self
    }

    pub fn build(self) -> Result<VersionedRoutingPolicy, PolicyError> {
        let mut hasher = Sha256::new();
        update_length_prefixed(&mut hasher, b"folo-route-policy-v1");
        hasher.update(self.revision.to_be_bytes());
        update_length_prefixed(&mut hasher, policy_mode_tag(self.mode));
        update_matcher_list(
            &mut hasher,
            b"security-block-domains",
            &self.security_block_domains,
        );
        update_cidr_list(
            &mut hasher,
            b"security-block-cidrs",
            &self.security_block_cidrs,
        );
        update_matcher_list(
            &mut hasher,
            b"explicit-direct-domains",
            &self.explicit_direct_domains,
        );
        update_matcher_list(
            &mut hasher,
            b"explicit-proxy-domains",
            &self.explicit_proxy_domains,
        );
        update_cidr_list(
            &mut hasher,
            b"explicit-direct-cidrs",
            &self.explicit_direct_cidrs,
        );
        update_cidr_list(
            &mut hasher,
            b"explicit-proxy-cidrs",
            &self.explicit_proxy_cidrs,
        );
        update_cidr_list(&mut hasher, b"china-cidrs", &self.china_cidrs);

        let fingerprint: [u8; 32] = hasher.finalize().into();

        let security_block_domains = DomainMatcherSet::compile(&self.security_block_domains, DomainNameMode::Routing)
            .map_err(|e| PolicyError::Validation(e.to_string()))?;
        let security_block_ips = build_ip_range_set(&self.security_block_cidrs);

        let explicit_direct_domains = DomainMatcherSet::compile(&self.explicit_direct_domains, DomainNameMode::Routing)
            .map_err(|e| PolicyError::Validation(e.to_string()))?;
        let explicit_proxy_domains = DomainMatcherSet::compile(&self.explicit_proxy_domains, DomainNameMode::Routing)
            .map_err(|e| PolicyError::Validation(e.to_string()))?;

        let explicit_direct_ips = build_ip_range_set(&self.explicit_direct_cidrs);
        let explicit_proxy_ips = build_ip_range_set(&self.explicit_proxy_cidrs);
        let china_ips = build_ip_range_set(&self.china_cidrs);

        let mut pvt_b = IpRangeSet::builder();
        pvt_b.insert_private_networks();
        let private_ips = pvt_b.build();

        Ok(VersionedRoutingPolicy {
            revision: self.revision,
            fingerprint,
            mode: self.mode,
            security_block_domains,
            security_block_ips,
            explicit_direct_domains,
            explicit_proxy_domains,
            explicit_direct_ips,
            explicit_proxy_ips,
            china_ips,
            private_ips,
        })
    }
}

fn build_ip_range_set(cidrs: &[Cidr]) -> IpRangeSet {
    let mut b = IpRangeSet::builder();
    for c in cidrs {
        b.insert_cidr(*c);
    }
    b.build()
}

/// Thread-safe holder of the published routing policy.
/// Guarantees atomic publication and immutable snapshotting.
pub struct AtomicPolicyHolder {
    published: RwLock<Arc<VersionedRoutingPolicy>>,
}

impl AtomicPolicyHolder {
    pub fn new(initial: VersionedRoutingPolicy) -> Self {
        Self {
            published: RwLock::new(Arc::new(initial)),
        }
    }

    /// Snapshot the current active policy. Existing flows hold this Arc
    /// across their lifetime, ensuring immutable rule evaluation.
    pub fn snapshot(&self) -> Arc<VersionedRoutingPolicy> {
        Arc::clone(&self.published.read().unwrap())
    }

    /// Atomically replace the active policy.
    pub fn replace(&self, next: VersionedRoutingPolicy) -> Result<u64, PolicyError> {
        let mut writer = self.published.write().unwrap();
        if next.revision <= writer.revision {
            return Err(PolicyError::Validation(format!(
                "next revision {} not strictly greater than current {}",
                next.revision, writer.revision
            )));
        }
        let rev = next.revision;
        *writer = Arc::new(next);
        Ok(rev)
    }
}
