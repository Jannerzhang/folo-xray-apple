// SPDX-License-Identifier: MPL-2.0
use std::net::IpAddr;
use crate::Network;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainProvenance {
    /// Client explicitly requested this domain (e.g. SOCKS5 domain target or HTTP CONNECT)
    Explicit,
    /// Domain was resolved/attributed via internal DNS mapping cache
    DnsMapping,
    /// Domain was sniffed from payload (TLS SNI, HTTP Host, QUIC Initial)
    Sniffed,
    /// Pure IP target with no domain attribution
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteAction {
    Direct,
    Proxy,
    Block,
}

impl RouteAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Proxy => "proxy",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteReason {
    /// Matched an explicit security block rule (domain or IP)
    SecurityBlock,
    /// Matched an explicit block domain rule
    ExplicitBlockDomain,
    /// Matched an explicit block IP rule
    ExplicitBlockIp,
    /// Matched an explicit proxy domain rule
    ExplicitProxyDomain,
    /// Matched an explicit direct domain rule
    ExplicitDirectDomain,
    /// Matched a DNS-attributed domain mapping
    DnsDomainMapping,
    /// Matched a sniffed domain (TLS SNI / HTTP / QUIC)
    SniffedDomain,
    /// Matched private / loopback IP space
    PrivateIp,
    /// Matched domestic (China) IP routing set
    ChinaIp,
    /// Matched custom IP rule
    CustomIp,
    /// Default fallback rule
    Default,
}

impl RouteReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SecurityBlock => "security_block",
            Self::ExplicitBlockDomain => "explicit_block_domain",
            Self::ExplicitBlockIp => "explicit_block_ip",
            Self::ExplicitProxyDomain => "explicit_proxy_domain",
            Self::ExplicitDirectDomain => "explicit_direct_domain",
            Self::DnsDomainMapping => "dns_domain_mapping",
            Self::SniffedDomain => "sniffed_domain",
            Self::PrivateIp => "private_ip",
            Self::ChinaIp => "china_ip",
            Self::CustomIp => "custom_ip",
            Self::Default => "default",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub network: Network,
    pub domain_provenance: DomainProvenance,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub rule_revision: u64,
    pub action: RouteAction,
    pub reason: RouteReason,
    pub matched_pattern: Option<String>,
}
