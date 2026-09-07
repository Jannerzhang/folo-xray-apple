// SPDX-License-Identifier: MPL-2.0
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use xray_routing::{
    AtomicPolicyHolder, Cidr, DnsAttributionCache, DomainMatcher,
    Network, PolicyMode, RouteAction, RouteReason, Target, TargetAddr,
    VersionedRoutingPolicy,
};

#[test]
fn test_versioned_policy_priority_and_500_fixtures() {
    let now = Instant::now();
    let mut builder = VersionedRoutingPolicy::builder(1, PolicyMode::Rule);

    // 1. Security Block rules
    builder.add_security_block_domain(DomainMatcher::Suffix("malware.com".to_string()));
    builder.add_security_block_domain(DomainMatcher::Full("ad.tracker.org".to_string()));
    builder.add_security_block_cidr(
        Cidr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24).unwrap(),
    );

    // 2. Explicit Direct Domains (Domestic Chinese services)
    let domestic_domains = [
        "baidu.com", "qq.com", "taobao.com", "alipay.com", "douyin.com",
        "xiaohongshu.com", "jd.com", "bilibili.com", "weibo.com", "zhihu.com",
        "163.com", "sohu.com", "sina.com.cn", "meituan.com", "bytedance.com",
        "tmall.com", "youku.com", "iqiyi.com", "kuaishou.com", "dingtalk.com",
        "tencent.com", "alibaba.com", "aliyun.com", "feishu.cn", "ele.me",
    ];
    for d in &domestic_domains {
        builder.add_explicit_direct_domain(DomainMatcher::Suffix(d.to_string()));
    }

    // 3. Explicit Proxy Domains (International services)
    let foreign_domains = [
        "google.com", "youtube.com", "twitter.com", "facebook.com", "github.com",
        "wikipedia.org", "openai.com", "netflix.com", "instagram.com", "reddit.com",
        "cloudflare.com", "amazon.com", "microsoft.com", "apple.com", "dropbox.com",
        "spotify.com", "telegram.org", "medium.com", "twitch.tv", "linkedin.com",
        "discord.gg", "slack.com", "whatsapp.com", "vimeo.com", "duckduckgo.com",
    ];
    for d in &foreign_domains {
        builder.add_explicit_proxy_domain(DomainMatcher::Suffix(d.to_string()));
    }

    // 4. China IP ranges
    let china_cidrs = [
        Cidr::new(IpAddr::V4(Ipv4Addr::new(180, 101, 0, 0)), 16).unwrap(),
        Cidr::new(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 0)), 24).unwrap(),
        Cidr::new(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 0)), 24).unwrap(),
        Cidr::new(IpAddr::V4(Ipv4Addr::new(119, 29, 0, 0)), 16).unwrap(),
        Cidr::new(IpAddr::V4(Ipv4Addr::new(116, 228, 0, 0)), 16).unwrap(),
        Cidr::new(IpAddr::V4(Ipv4Addr::new(202, 96, 0, 0)), 16).unwrap(),
    ];
    for c in &china_cidrs {
        builder.add_china_cidr(*c);
    }

    let policy = builder.build().expect("build policy");
    let mut dns_cache = DnsAttributionCache::new(1024 * 1024, 1000);

    // Populate DNS cache entries
    dns_cache.insert(
        Some("client-1"),
        "api.xiaohongshu.com",
        vec![IpAddr::V4(Ipv4Addr::new(101, 200, 1, 10))],
        Duration::from_secs(300),
        1,
        false,
        false,
        now,
    );
    dns_cache.insert(
        Some("client-1"),
        "api.openai.com",
        vec![IpAddr::V4(Ipv4Addr::new(104, 18, 1, 10))],
        Duration::from_secs(300),
        1,
        true,
        false,
        now,
    );
    dns_cache.insert(
        Some("client-1"),
        "bad-ad.malware.com",
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99))],
        Duration::from_secs(300),
        1,
        false,
        true,
        now,
    );

    // Build and verify 500+ test fixtures
    let mut total_fixtures = 0;
    let mut correct_decisions = 0;

    // A. 150 Direct domain fixtures
    for (_i, base) in domestic_domains.iter().enumerate() {
        for sub in &["www", "api", "static", "img", "m", "video"] {
            total_fixtures += 1;
            let domain = format!("{}.{}", sub, base);
            let target = Target::new(TargetAddr::Domain(domain.clone()), 443, Network::Tcp);
            let decision = policy.route(Network::Tcp, &target, None, &dns_cache, now);
            if decision.action == RouteAction::Direct && decision.reason == RouteReason::ExplicitDirectDomain {
                correct_decisions += 1;
            }
        }
    }

    // B. 150 Proxy domain fixtures
    for (_i, base) in foreign_domains.iter().enumerate() {
        for sub in &["www", "api", "cdn", "assets", "mobile", "auth"] {
            total_fixtures += 1;
            let domain = format!("{}.{}", sub, base);
            let target = Target::new(TargetAddr::Domain(domain.clone()), 443, Network::Tcp);
            let decision = policy.route(Network::Tcp, &target, None, &dns_cache, now);
            if decision.action == RouteAction::Proxy && decision.reason == RouteReason::ExplicitProxyDomain {
                correct_decisions += 1;
            }
        }
    }

    // C. 50 Security block fixtures (domains and IPs)
    for i in 0..25 {
        total_fixtures += 1;
        let domain = format!("sub{}.malware.com", i);
        let target = Target::new(TargetAddr::Domain(domain), 443, Network::Tcp);
        let decision = policy.route(Network::Tcp, &target, None, &dns_cache, now);
        if decision.action == RouteAction::Block && decision.reason == RouteReason::SecurityBlock {
            correct_decisions += 1;
        }
    }
    for i in 1..26 {
        total_fixtures += 1;
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, i));
        let target = Target::new(TargetAddr::Ip(ip), 80, Network::Tcp);
        let decision = policy.route(Network::Tcp, &target, None, &dns_cache, now);
        if decision.action == RouteAction::Block && decision.reason == RouteReason::SecurityBlock {
            correct_decisions += 1;
        }
    }

    // D. 50 Private IP fixtures
    for i in 1..26 {
        total_fixtures += 1;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i));
        let target = Target::new(TargetAddr::Ip(ip), 8080, Network::Tcp);
        let decision = policy.route(Network::Tcp, &target, None, &dns_cache, now);
        if decision.action == RouteAction::Direct && decision.reason == RouteReason::PrivateIp {
            correct_decisions += 1;
        }
    }
    for i in 1..26 {
        total_fixtures += 1;
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        let target = Target::new(TargetAddr::Ip(ip), 53, Network::Udp);
        let decision = policy.route(Network::Udp, &target, None, &dns_cache, now);
        if decision.action == RouteAction::Direct && decision.reason == RouteReason::PrivateIp {
            correct_decisions += 1;
        }
    }

    // E. 50 China IP fixtures
    for i in 1..51 {
        total_fixtures += 1;
        let ip = IpAddr::V4(Ipv4Addr::new(180, 101, (i / 256) as u8, (i % 256) as u8));
        let target = Target::new(TargetAddr::Ip(ip), 443, Network::Tcp);
        let decision = policy.route(Network::Tcp, &target, None, &dns_cache, now);
        if decision.action == RouteAction::Direct && decision.reason == RouteReason::ChinaIp {
            correct_decisions += 1;
        }
    }

    // F. 30 Sniffed domain fixtures
    for i in 0..30 {
        total_fixtures += 1;
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, (i + 1) as u8)); // Non-China IP
        let target = Target::new(TargetAddr::Ip(ip), 443, Network::Tcp);
        let sniffed = format!("video{}.douyin.com", i);
        let decision = policy.route(Network::Tcp, &target, Some(&sniffed), &dns_cache, now);
        if decision.action == RouteAction::Direct && decision.reason == RouteReason::SniffedDomain {
            correct_decisions += 1;
        }
    }

    // G. 30 DNS attribution mapping fixtures
    for _ in 0..15 {
        total_fixtures += 1;
        let ip = IpAddr::V4(Ipv4Addr::new(101, 200, 1, 10));
        let target = Target::new(TargetAddr::Ip(ip), 443, Network::Tcp);
        let decision = policy.route(Network::Tcp, &target, None, &dns_cache, now);
        if decision.action == RouteAction::Direct && decision.reason == RouteReason::DnsDomainMapping {
            correct_decisions += 1;
        }
    }
    for _ in 0..15 {
        total_fixtures += 1;
        let ip = IpAddr::V4(Ipv4Addr::new(104, 18, 1, 10));
        let target = Target::new(TargetAddr::Ip(ip), 443, Network::Tcp);
        let decision = policy.route(Network::Tcp, &target, None, &dns_cache, now);
        if decision.action == RouteAction::Proxy && decision.reason == RouteReason::DnsDomainMapping {
            correct_decisions += 1;
        }
    }

    assert!(
        total_fixtures >= 500,
        "Expected at least 500 fixtures, got {}",
        total_fixtures
    );
    let hit_rate = (correct_decisions as f64) / (total_fixtures as f64);
    assert!(
        hit_rate >= 0.995,
        "Hit rate {:.4} is below 99.5% threshold ({}/{} correct)",
        hit_rate,
        correct_decisions,
        total_fixtures
    );
}

#[test]
fn test_rule_update_preserves_active_flows_and_assigns_new_revision() {
    let now = Instant::now();

    // Generation 1: example.com is Direct
    let mut builder1 = VersionedRoutingPolicy::builder(1, PolicyMode::Rule);
    builder1.add_explicit_direct_domain(DomainMatcher::Suffix("example.com".to_string()));
    let policy1 = builder1.build().unwrap();

    let holder = AtomicPolicyHolder::new(policy1);
    let dns_cache = DnsAttributionCache::new(1024 * 1024, 100);

    // Flow 1 starts and snapshots generation 1
    let flow1_policy = holder.snapshot();
    let target = Target::new(TargetAddr::Domain("test.example.com".to_string()), 443, Network::Tcp);

    let d1 = flow1_policy.route(Network::Tcp, &target, None, &dns_cache, now);
    assert_eq!(d1.rule_revision, 1);
    assert_eq!(d1.action, RouteAction::Direct);

    // Generation 2: example.com changed to Proxy
    let mut builder2 = VersionedRoutingPolicy::builder(2, PolicyMode::Rule);
    builder2.add_explicit_proxy_domain(DomainMatcher::Suffix("example.com".to_string()));
    let policy2 = builder2.build().unwrap();

    let new_rev = holder.replace(policy2).expect("replace policy");
    assert_eq!(new_rev, 2);

    // Flow 1 is still running, still holds flow1_policy: MUST still evaluate to Revision 1 & Direct
    let d1_after = flow1_policy.route(Network::Tcp, &target, None, &dns_cache, now);
    assert_eq!(d1_after.rule_revision, 1);
    assert_eq!(d1_after.action, RouteAction::Direct);

    // New Flow 2 snapshots latest from holder: MUST observe Revision 2 & Proxy
    let flow2_policy = holder.snapshot();
    let d2 = flow2_policy.route(Network::Tcp, &target, None, &dns_cache, now);
    assert_eq!(d2.rule_revision, 2);
    assert_eq!(d2.action, RouteAction::Proxy);
}

#[test]
fn test_error_rule_load_fails_closed_without_reverting_to_direct() {
    let mut builder = VersionedRoutingPolicy::builder(1, PolicyMode::Rule);
    builder.add_explicit_proxy_domain(DomainMatcher::Suffix("important.com".to_string()));
    let initial_policy = builder.build().unwrap();

    let holder = AtomicPolicyHolder::new(initial_policy);

    // Attempt to load policy with older or equal revision (e.g. 1 <= 1)
    let invalid_builder = VersionedRoutingPolicy::builder(1, PolicyMode::Rule);
    let invalid_policy = invalid_builder.build().unwrap();

    let err = holder.replace(invalid_policy).unwrap_err();
    assert!(err.to_string().contains("not strictly greater"));

    // Active policy is unchanged and does NOT fall back to direct
    let active = holder.snapshot();
    let target = Target::new(TargetAddr::Domain("test.important.com".to_string()), 443, Network::Tcp);
    let decision = active.route(Network::Tcp, &target, None, &DnsAttributionCache::new(1024, 10), Instant::now());
    assert_eq!(decision.action, RouteAction::Proxy);
}

#[test]
fn test_dns_attribution_cname_dualstack_nat64_and_shared_cdn_conflict() {
    let now = Instant::now();
    let mut cache = DnsAttributionCache::new(1024 * 1024, 500);

    // 1. Dual stack (IPv4 and IPv6)
    let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    cache.insert(
        Some("client-1"),
        "dualstack.example.com",
        vec![v4, v6],
        Duration::from_secs(60),
        1,
        true,
        false,
        now,
    );

    let rec_v4 = cache.lookup_ip(&v4, now).expect("lookup v4");
    assert_eq!(rec_v4.qname_normalized, "dualstack.example.com");
    assert!(rec_v4.is_proxy_preferred);

    let rec_v6 = cache.lookup_ip(&v6, now).expect("lookup v6");
    assert_eq!(rec_v6.qname_normalized, "dualstack.example.com");

    // 2. NAT64 synthesis translation (RFC 6052 64:ff9b::/96)
    let nat64_v6 = IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0xcb00, 0x7101)); // 64:ff9b::203.0.113.1
    let rec_nat64 = cache.lookup_ip(&nat64_v6, now).expect("lookup nat64");
    assert_eq!(rec_nat64.qname_normalized, "dualstack.example.com");

    // 3. CNAME chain
    cache.insert_cname(
        "alias.example.com",
        "dualstack.example.com",
        Duration::from_secs(60),
        1,
        true,
        now,
    );
    let rec_cname = cache.lookup_domain("alias.example.com", now).expect("lookup alias");
    assert_eq!(rec_cname.cname_chain, vec!["dualstack.example.com"]);

    // 4. Shared CDN IP Conflict:
    // Suppose CDN IP 198.51.100.50 is used by both a proxy domain and a direct domain.
    let shared_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50));
    // Direct domain resolves first
    cache.insert(
        Some("client-1"),
        "domestic-site.cn",
        vec![shared_ip],
        Duration::from_secs(60),
        1,
        false, // Direct
        false,
        now,
    );
    // Proxy domain resolves second to the SAME IP
    cache.insert(
        Some("client-1"),
        "foreign-sensitive.org",
        vec![shared_ip],
        Duration::from_secs(60),
        1,
        true, // Proxy preferred!
        false,
        now,
    );

    // Crucial requirement: "共享 IP 冲突时优先 explicit proxy/security rule，不能凭最后一次 DNS 查询误直连"
    let winning_rec = cache.lookup_ip(&shared_ip, now).expect("lookup shared IP");
    assert!(
        winning_rec.is_proxy_preferred,
        "Shared CDN IP conflict must prioritize proxy over direct!"
    );
    assert_eq!(winning_rec.qname_normalized, "foreign-sensitive.org");
}

#[test]
fn test_dns_cache_capacity_and_ttl_eviction() {
    let now = Instant::now();
    // Tiny capacity cache: max 3 entries
    let mut cache = DnsAttributionCache::new(1024 * 1024, 3);

    cache.insert(None, "d1.com", vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))], Duration::from_secs(10), 1, false, false, now);
    cache.insert(None, "d2.com", vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2))], Duration::from_secs(10), 1, false, false, now);
    cache.insert(None, "d3.com", vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3))], Duration::from_secs(10), 1, false, false, now);
    assert_eq!(cache.len(), 3);

    // Adding 4th entry evicts oldest (d1.com)
    cache.insert(None, "d4.com", vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 4))], Duration::from_secs(10), 1, false, false, now);
    assert_eq!(cache.len(), 3);
    assert!(cache.lookup_domain("d1.com", now).is_none());
    assert!(cache.lookup_domain("d4.com", now).is_some());

    // TTL expiry after 15s
    let future = now + Duration::from_secs(15);
    cache.prune_expired(future);
    assert_eq!(cache.len(), 0);
}
