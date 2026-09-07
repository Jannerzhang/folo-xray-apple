// SPDX-License-Identifier: MPL-2.0
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// Standard well-known NAT64 prefix (RFC 6052: 64:ff9b::/96)
pub const NAT64_WELL_KNOWN_PREFIX: [u8; 12] = [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAttributionRecord {
    pub client: Option<String>,
    pub qname_normalized: String,
    pub answer_ips: Vec<IpAddr>,
    pub ttl: Duration,
    pub rule_revision: u64,
    pub created_at: Instant,
    pub is_proxy_preferred: bool,
    pub is_security_block: bool,
    pub cname_chain: Vec<String>,
}

impl DnsAttributionRecord {
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) >= self.ttl
    }

    pub fn approximate_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.client.as_ref().map_or(0, |c| c.len())
            + self.qname_normalized.len()
            + self.answer_ips.len() * std::mem::size_of::<IpAddr>()
            + self.cname_chain.iter().map(|s| s.len()).sum::<usize>()
    }
}

#[derive(Debug)]
pub struct DnsAttributionCache {
    records_by_domain: HashMap<String, DnsAttributionRecord>,
    ip_to_domains: HashMap<IpAddr, Vec<String>>,
    lru_order: VecDeque<String>,
    max_byte_ceiling: usize,
    max_entries: usize,
    current_bytes: usize,
}

impl DnsAttributionCache {
    pub fn new(max_byte_ceiling: usize, max_entries: usize) -> Self {
        Self {
            records_by_domain: HashMap::new(),
            ip_to_domains: HashMap::new(),
            lru_order: VecDeque::new(),
            max_byte_ceiling,
            max_entries,
            current_bytes: 0,
        }
    }

    /// Normalizes domain name (ASCII lowercase, trim trailing dot).
    pub fn normalize_domain(domain: &str) -> String {
        let trimmed = domain.trim_end_matches('.');
        trimmed.to_ascii_lowercase()
    }

    /// Checks if an IPv6 address uses the well-known NAT64 prefix (64:ff9b::/96)
    /// and extracts the embedded IPv4 address.
    pub fn extract_nat64_ipv4(ip: &IpAddr) -> Option<IpAddr> {
        if let IpAddr::V6(v6) = ip {
            let octets = v6.octets();
            if octets[..12] == NAT64_WELL_KNOWN_PREFIX {
                return Some(IpAddr::V4(Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                )));
            }
        }
        None
    }

    /// Inserts a DNS attribution record with conflict resolution.
    pub fn insert(
        &mut self,
        client: Option<&str>,
        qname: &str,
        answer_ips: Vec<IpAddr>,
        ttl: Duration,
        rule_revision: u64,
        is_proxy_preferred: bool,
        is_security_block: bool,
        now: Instant,
    ) {
        let norm_name = Self::normalize_domain(qname);
        if norm_name.is_empty() || norm_name.len() > 253 {
            return;
        }

        // Check if updating existing record
        if let Some(existing) = self.records_by_domain.remove(&norm_name) {
            self.current_bytes = self.current_bytes.saturating_sub(existing.approximate_bytes());
            for ip in &existing.answer_ips {
                if let Some(list) = self.ip_to_domains.get_mut(ip) {
                    list.retain(|d| d != &norm_name);
                    if list.is_empty() {
                        self.ip_to_domains.remove(ip);
                    }
                }
            }
        }

        let record = DnsAttributionRecord {
            client: client.map(|s| s.to_string()),
            qname_normalized: norm_name.clone(),
            answer_ips: answer_ips.clone(),
            ttl,
            rule_revision,
            created_at: now,
            is_proxy_preferred,
            is_security_block,
            cname_chain: Vec::new(),
        };

        self.current_bytes += record.approximate_bytes();

        for ip in &answer_ips {
            self.ip_to_domains
                .entry(*ip)
                .or_default()
                .push(norm_name.clone());
        }

        self.records_by_domain.insert(norm_name.clone(), record);
        self.lru_order.push_back(norm_name);

        self.enforce_capacity(now);
    }

    /// Adds a CNAME alias link.
    pub fn insert_cname(
        &mut self,
        alias: &str,
        canonical: &str,
        ttl: Duration,
        rule_revision: u64,
        is_proxy: bool,
        now: Instant,
    ) {
        let norm_alias = Self::normalize_domain(alias);
        let norm_canonical = Self::normalize_domain(canonical);

        // Find canonical IPs if known
        let answer_ips = self
            .records_by_domain
            .get(&norm_canonical)
            .map(|rec| rec.answer_ips.clone())
            .unwrap_or_default();

        let record = DnsAttributionRecord {
            client: None,
            qname_normalized: norm_alias.clone(),
            answer_ips: answer_ips.clone(),
            ttl,
            rule_revision,
            created_at: now,
            is_proxy_preferred: is_proxy,
            is_security_block: false,
            cname_chain: vec![norm_canonical],
        };

        self.current_bytes += record.approximate_bytes();
        for ip in &answer_ips {
            self.ip_to_domains
                .entry(*ip)
                .or_default()
                .push(norm_alias.clone());
        }

        self.records_by_domain.insert(norm_alias.clone(), record);
        self.lru_order.push_back(norm_alias);
        self.enforce_capacity(now);
    }

    /// Look up domain attribution for an IP address.
    /// Handles NAT64 translation and resolves shared CDN IP conflicts by prioritizing
    /// security_block > proxy_preferred > direct.
    pub fn lookup_ip(&self, ip: &IpAddr, now: Instant) -> Option<DnsAttributionRecord> {
        let effective_ip = Self::extract_nat64_ipv4(ip).unwrap_or(*ip);
        let domain_names = self.ip_to_domains.get(&effective_ip)?;

        let mut candidates: Vec<&DnsAttributionRecord> = domain_names
            .iter()
            .filter_map(|d| self.records_by_domain.get(d))
            .filter(|rec| !rec.is_expired(now))
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // Shared IP conflict resolution:
        // 1. Security block has absolute precedence
        // 2. Proxy preferred has second precedence (never accidentally direct-route proxy traffic)
        // 3. Most recently created record
        candidates.sort_by(|a, b| {
            b.is_security_block
                .cmp(&a.is_security_block)
                .then_with(|| b.is_proxy_preferred.cmp(&a.is_proxy_preferred))
                .then_with(|| b.created_at.cmp(&a.created_at))
        });

        candidates.first().map(|rec| (*rec).clone())
    }

    /// Look up record by domain name.
    pub fn lookup_domain(&self, domain: &str, now: Instant) -> Option<DnsAttributionRecord> {
        let norm = Self::normalize_domain(domain);
        let rec = self.records_by_domain.get(&norm)?;
        if rec.is_expired(now) {
            None
        } else {
            Some(rec.clone())
        }
    }

    /// Prune expired entries.
    pub fn prune_expired(&mut self, now: Instant) {
        let expired_domains: Vec<String> = self
            .records_by_domain
            .iter()
            .filter(|(_, rec)| rec.is_expired(now))
            .map(|(d, _)| d.clone())
            .collect();

        for d in expired_domains {
            self.remove_domain(&d);
        }
    }

    /// Invalidate records older than the active revision.
    pub fn invalidate_revisions_older_than(&mut self, min_revision: u64) {
        let old_domains: Vec<String> = self
            .records_by_domain
            .iter()
            .filter(|(_, rec)| rec.rule_revision < min_revision)
            .map(|(d, _)| d.clone())
            .collect();

        for d in old_domains {
            self.remove_domain(&d);
        }
    }

    fn remove_domain(&mut self, domain: &str) {
        if let Some(rec) = self.records_by_domain.remove(domain) {
            self.current_bytes = self.current_bytes.saturating_sub(rec.approximate_bytes());
            for ip in &rec.answer_ips {
                if let Some(list) = self.ip_to_domains.get_mut(ip) {
                    list.retain(|d| d != domain);
                    if list.is_empty() {
                        self.ip_to_domains.remove(ip);
                    }
                }
            }
        }
        self.lru_order.retain(|d| d != domain);
    }

    fn enforce_capacity(&mut self, now: Instant) {
        if self.records_by_domain.len() > self.max_entries
            || self.current_bytes > self.max_byte_ceiling
        {
            self.prune_expired(now);
        }

        while (self.records_by_domain.len() > self.max_entries
            || self.current_bytes > self.max_byte_ceiling)
            && !self.lru_order.is_empty()
        {
            if let Some(oldest) = self.lru_order.pop_front() {
                if let Some(rec) = self.records_by_domain.remove(&oldest) {
                    self.current_bytes = self.current_bytes.saturating_sub(rec.approximate_bytes());
                    for ip in &rec.answer_ips {
                        if let Some(list) = self.ip_to_domains.get_mut(ip) {
                            list.retain(|d| d != &oldest);
                            if list.is_empty() {
                                self.ip_to_domains.remove(ip);
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.records_by_domain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records_by_domain.is_empty()
    }

    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }
}
