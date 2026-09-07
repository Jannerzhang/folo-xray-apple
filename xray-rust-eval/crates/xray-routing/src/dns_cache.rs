// SPDX-License-Identifier: MPL-2.0
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// Standard well-known NAT64 prefix (RFC 6052: 64:ff9b::/96).
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

    /// Conservative entry estimate including owned string/vector capacity.
    /// Container/table overhead is accounted for by `DnsAttributionCache`.
    pub fn approximate_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.client.as_ref().map_or(0, String::capacity)
            + self.qname_normalized.capacity()
            + self.answer_ips.capacity() * std::mem::size_of::<IpAddr>()
            + self.cname_chain.capacity() * std::mem::size_of::<String>()
            + self.cname_chain.iter().map(String::capacity).sum::<usize>()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    client: Option<String>,
    domain: String,
    revision: u64,
}

#[derive(Debug)]
pub struct DnsAttributionCache {
    records_by_key: HashMap<CacheKey, DnsAttributionRecord>,
    ip_to_keys: HashMap<IpAddr, Vec<CacheKey>>,
    domain_to_keys: HashMap<String, Vec<CacheKey>>,
    alias_to_keys: HashMap<String, Vec<CacheKey>>,
    lru_order: VecDeque<CacheKey>,
    max_byte_ceiling: usize,
    max_entries: usize,
    current_bytes: usize,
}

impl DnsAttributionCache {
    pub fn new(max_byte_ceiling: usize, max_entries: usize) -> Self {
        let minimum = Self::fixed_memory_bytes();
        Self {
            records_by_key: HashMap::new(),
            ip_to_keys: HashMap::new(),
            domain_to_keys: HashMap::new(),
            alias_to_keys: HashMap::new(),
            lru_order: VecDeque::new(),
            max_byte_ceiling: max_byte_ceiling.max(minimum),
            max_entries: max_entries.max(1),
            current_bytes: minimum,
        }
    }

    /// Normalizes domain name (ASCII lowercase, trim trailing dot).
    pub fn normalize_domain(domain: &str) -> String {
        let trimmed = domain.trim_end_matches('.');
        trimmed.to_ascii_lowercase()
    }

    /// Checks if an IPv6 address uses the well-known NAT64 prefix and extracts
    /// the embedded IPv4 address.
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
    #[allow(clippy::too_many_arguments)]
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
        if norm_name.is_empty() || norm_name.len() > 253 || rule_revision == 0 {
            return;
        }

        self.prune_expired(now);
        let client = client.map(str::to_owned);
        let key = CacheKey {
            client: client.clone(),
            domain: norm_name.clone(),
            revision: rule_revision,
        };
        self.remove_key(&key);

        let record = DnsAttributionRecord {
            client,
            qname_normalized: norm_name.clone(),
            answer_ips: answer_ips.clone(),
            ttl,
            rule_revision,
            created_at: now,
            is_proxy_preferred,
            is_security_block,
            cname_chain: Vec::new(),
        };
        self.insert_record(key, record);
        self.enforce_capacity(now);
    }

    /// Adds or replaces a CNAME alias link. Replacing an alias removes its old
    /// record and all reverse indexes before the new link is inserted.
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
        if norm_alias.is_empty() || norm_canonical.is_empty() || rule_revision == 0 {
            return;
        }

        self.prune_expired(now);
        let mut alias_keys = self
            .domain_to_keys
            .get(&norm_alias)
            .cloned()
            .unwrap_or_default();
        alias_keys.extend(self.alias_to_keys.get(&norm_alias).cloned().unwrap_or_default());
        alias_keys.sort_by_key(|key| (key.client.clone(), key.revision, key.domain.clone()));
        alias_keys.dedup();
        for key in alias_keys {
            self.remove_key(&key);
        }

        let canonical_key = self
            .records_by_key
            .keys()
            .find(|key| key.domain == norm_canonical && key.revision == rule_revision)
            .cloned();
        let answer_ips = canonical_key
            .and_then(|key| self.records_by_key.get(&key))
            .map(|record| record.answer_ips.clone())
            .unwrap_or_default();

        let key = CacheKey {
            client: None,
            domain: norm_alias.clone(),
            revision: rule_revision,
        };
        let record = DnsAttributionRecord {
            client: None,
            qname_normalized: norm_alias,
            answer_ips,
            ttl,
            rule_revision,
            created_at: now,
            is_proxy_preferred: is_proxy,
            is_security_block: false,
            cname_chain: vec![norm_canonical],
        };
        self.insert_record(key, record);
        self.enforce_capacity(now);
    }

    /// Legacy lookup that selects the newest revision for compatibility.
    /// Production routing must use `lookup_ip_for_revision`.
    pub fn lookup_ip(&mut self, ip: &IpAddr, now: Instant) -> Option<DnsAttributionRecord> {
        let effective_ip = Self::extract_nat64_ipv4(ip).unwrap_or(*ip);
        let revision = self.latest_revision_for_ip(&effective_ip)?;
        self.lookup_ip_for_revision(ip, None, revision, now)
    }

    /// Strict revision/client-aware IP lookup used by production policy code.
    pub fn lookup_ip_for_revision(
        &mut self,
        ip: &IpAddr,
        client: Option<&str>,
        revision: u64,
        now: Instant,
    ) -> Option<DnsAttributionRecord> {
        let effective_ip = Self::extract_nat64_ipv4(ip).unwrap_or(*ip);
        let keys = self.ip_to_keys.get(&effective_ip).cloned().unwrap_or_default();
        self.best_record(keys, client, Some(revision), now)
    }

    /// Legacy lookup by domain selecting the newest revision.
    pub fn lookup_domain(&mut self, domain: &str, now: Instant) -> Option<DnsAttributionRecord> {
        let norm = Self::normalize_domain(domain);
        let mut keys = self.domain_to_keys.get(&norm).cloned().unwrap_or_default();
        keys.extend(self.alias_to_keys.get(&norm).cloned().unwrap_or_default());
        keys.sort_by_key(|key| (key.client.clone(), key.revision, key.domain.clone()));
        keys.dedup();
        self.best_record(keys, None, None, now)
    }

    /// Strict revision/client-aware domain or CNAME lookup.
    pub fn lookup_domain_for_revision(
        &mut self,
        domain: &str,
        client: Option<&str>,
        revision: u64,
        now: Instant,
    ) -> Option<DnsAttributionRecord> {
        let norm = Self::normalize_domain(domain);
        let mut keys = self.domain_to_keys.get(&norm).cloned().unwrap_or_default();
        keys.extend(self.alias_to_keys.get(&norm).cloned().unwrap_or_default());
        keys.sort_by_key(|key| (key.client.clone(), key.revision, key.domain.clone()));
        keys.dedup();
        self.best_record(keys, client, Some(revision), now)
    }

    /// Prune expired entries and all reverse indexes.
    pub fn prune_expired(&mut self, now: Instant) {
        let expired_keys: Vec<CacheKey> = self
            .records_by_key
            .iter()
            .filter(|(_, record)| record.is_expired(now))
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired_keys {
            self.remove_key(&key);
        }
    }

    /// Invalidate records older than the active revision.
    pub fn invalidate_revisions_older_than(&mut self, min_revision: u64) {
        let old_keys: Vec<CacheKey> = self
            .records_by_key
            .keys()
            .filter(|key| key.revision < min_revision)
            .cloned()
            .collect();
        for key in old_keys {
            self.remove_key(&key);
        }
    }

    fn best_record(
        &mut self,
        keys: Vec<CacheKey>,
        client: Option<&str>,
        revision: Option<u64>,
        now: Instant,
    ) -> Option<DnsAttributionRecord> {
        let mut expired = Vec::new();
        let mut candidates: Vec<(CacheKey, DnsAttributionRecord)> = Vec::new();
        for key in keys {
            let Some(record) = self.records_by_key.get(&key) else {
                continue;
            };
            if record.is_expired(now) {
                expired.push(key);
                continue;
            }
            if revision.is_some_and(|wanted| key.revision != wanted)
                || client.is_some_and(|wanted| key.client.as_deref() != Some(wanted))
            {
                continue;
            }
            candidates.push((key, record.clone()));
        }
        for key in expired {
            self.remove_key(&key);
        }

        let (winning_key, record) = candidates.into_iter().max_by(|(_, left), (_, right)| {
            left.is_security_block
                .cmp(&right.is_security_block)
                .then_with(|| left.is_proxy_preferred.cmp(&right.is_proxy_preferred))
                .then_with(|| left.created_at.cmp(&right.created_at))
                .then_with(|| left.qname_normalized.cmp(&right.qname_normalized))
        })?;
        self.touch(&winning_key);
        Some(record)
    }

    fn insert_record(&mut self, key: CacheKey, record: DnsAttributionRecord) {
        for ip in Self::indexed_ips(&record.answer_ips) {
            insert_index(self.ip_to_keys.entry(ip).or_default(), &key);
        }
        insert_index(
            self.domain_to_keys.entry(key.domain.clone()).or_default(),
            &key,
        );
        if !record.cname_chain.is_empty() {
            insert_index(self.alias_to_keys.entry(key.domain.clone()).or_default(), &key);
        }
        self.lru_order.push_back(key.clone());
        self.records_by_key.insert(key, record);
        self.refresh_memory_accounting();
    }

    fn remove_key(&mut self, key: &CacheKey) {
        let Some(record) = self.records_by_key.remove(key) else {
            return;
        };
        for ip in Self::indexed_ips(&record.answer_ips) {
            remove_index(&mut self.ip_to_keys, &ip, key);
        }
        remove_index(&mut self.domain_to_keys, &key.domain, key);
        if !record.cname_chain.is_empty() {
            remove_index(&mut self.alias_to_keys, &key.domain, key);
        }
        self.lru_order.retain(|candidate| candidate != key);
        self.refresh_memory_accounting();
    }

    fn touch(&mut self, key: &CacheKey) {
        self.lru_order.retain(|candidate| candidate != key);
        self.lru_order.push_back(key.clone());
    }

    fn latest_revision_for_ip(&self, ip: &IpAddr) -> Option<u64> {
        self.ip_to_keys.get(ip).and_then(|keys| {
            keys.iter()
                .filter_map(|key| self.records_by_key.contains_key(key).then_some(key.revision))
                .max()
        })
    }

    fn enforce_capacity(&mut self, now: Instant) {
        self.prune_expired(now);
        while (self.records_by_key.len() > self.max_entries
            || self.current_bytes > self.max_byte_ceiling)
            && !self.lru_order.is_empty()
        {
            if let Some(oldest) = self.lru_order.front().cloned() {
                self.remove_key(&oldest);
            }
        }
    }

    fn indexed_ips(answer_ips: &[IpAddr]) -> Vec<IpAddr> {
        let mut indexed = Vec::with_capacity(answer_ips.len() * 2);
        for ip in answer_ips {
            if !indexed.contains(ip) {
                indexed.push(*ip);
            }
            if let Some(nat64) = Self::extract_nat64_ipv4(ip) {
                if !indexed.contains(&nat64) {
                    indexed.push(nat64);
                }
            }
        }
        indexed
    }

    fn refresh_memory_accounting(&mut self) {
        let records = self
            .records_by_key
            .iter()
            .map(|(key, record)| Self::entry_bytes(key, record))
            .sum::<usize>();
        self.current_bytes = Self::fixed_memory_bytes()
            + records
            + Self::hash_map_overhead(self.records_by_key.len(), std::mem::size_of::<(CacheKey, DnsAttributionRecord)>())
            + Self::hash_map_overhead(self.ip_to_keys.len(), std::mem::size_of::<(IpAddr, Vec<CacheKey>)>())
            + Self::hash_map_overhead(self.domain_to_keys.len(), std::mem::size_of::<(String, Vec<CacheKey>)>())
            + Self::hash_map_overhead(self.alias_to_keys.len(), std::mem::size_of::<(String, Vec<CacheKey>)>())
            + self.lru_order.capacity() * std::mem::size_of::<CacheKey>();
    }

    fn entry_bytes(key: &CacheKey, record: &DnsAttributionRecord) -> usize {
        std::mem::size_of::<CacheKey>()
            + key.client.as_ref().map_or(0, String::capacity)
            + key.domain.capacity()
            + record.approximate_bytes()
            + (Self::indexed_ips(&record.answer_ips).len() + record.cname_chain.len() + 1)
                * std::mem::size_of::<CacheKey>()
    }

    fn hash_map_overhead(len: usize, entry_size: usize) -> usize {
        if len == 0 {
            return 0;
        }
        let buckets = len.saturating_mul(2).next_power_of_two();
        buckets.saturating_mul(std::mem::size_of::<usize>() * 2 + entry_size / 4)
    }

    fn fixed_memory_bytes() -> usize {
        std::mem::size_of::<Self>() + 256
    }

    pub fn len(&self) -> usize {
        self.records_by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records_by_key.is_empty()
    }

    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }
}

fn insert_index(index: &mut Vec<CacheKey>, key: &CacheKey) {
    if !index.contains(key) {
        index.push(key.clone());
    }
}

fn remove_index<T>(index: &mut HashMap<T, Vec<CacheKey>>, lookup: &T, key: &CacheKey)
where
    T: Eq + std::hash::Hash,
{
    if let Some(keys) = index.get_mut(lookup) {
        keys.retain(|candidate| candidate != key);
        if keys.is_empty() {
            index.remove(lookup);
        }
    }
}
