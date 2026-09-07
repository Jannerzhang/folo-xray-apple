// SPDX-License-Identifier: LicenseRef-Folo-Proprietary

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use tokio::io::AsyncWriteExt;
use xray_config::{InboundSniffingConfig, SniffingDestination};
use xray_core_rs::{
    build_test_quic_initial_packet, should_sniff_udp, sniff_quic_initial_sni_public,
    sniff_udp_initial_payload,
};
use xray_proxy::vless::{
    encode_xudp_keep_packet, encode_xudp_new_packet, read_xudp_packet,
};
use xray_routing::{
    DnsAttributionCache, DomainMatcher, DomainProvenance, Network, PolicyMode, RouteAction,
    RouteReason, Target, TargetAddr, VersionedRoutingPolicyBuilder,
};

#[test]
fn test_quic_initial_sni_sniffing_mainstream_apps() {
    let test_domains = [
        "v.douyin.com",
        "v3-dy-y.ixigua.com",
        "trade.taobao.com",
        "upos-sz-mirrorcos.bilivideo.com",
        "www.youtube.com",
        "quic.google.com",
        "gateway.discord.gg",
    ];

    for domain in test_domains {
        let packet = build_test_quic_initial_packet(domain);
        assert!(!packet.is_empty(), "QUIC initial packet must not be empty");

        let sniffed = sniff_quic_initial_sni_public(&packet)
            .expect("Valid QUIC Initial packet must yield SNI");
        assert_eq!(
            sniffed, domain,
            "Sniffed SNI must match the encoded host"
        );
    }
}

#[test]
fn test_quic_initial_sniffing_rejects_malformed_packets() {
    // Empty packet
    assert!(sniff_quic_initial_sni_public(&[]).is_none());

    // Short packet
    assert!(sniff_quic_initial_sni_public(&[0xc0, 0x00, 0x00, 0x00, 0x01]).is_none());

    // Random noise
    let garbage = vec![0x42; 128];
    assert!(sniff_quic_initial_sni_public(&garbage).is_none());

    // Non-v1 version
    let mut packet = build_test_quic_initial_packet("v.douyin.com");
    packet[1..5].copy_from_slice(&2u32.to_be_bytes());
    assert!(sniff_quic_initial_sni_public(&packet).is_none());
}

#[test]
fn test_udp_quic_split_routing_with_versioned_policy() {
    let now = Instant::now();
    let dns_cache = DnsAttributionCache::new(512, 128 * 1024);

    let mut builder = VersionedRoutingPolicyBuilder::new(1, PolicyMode::Rule);
    builder
        .add_explicit_direct_domain(DomainMatcher::Suffix("douyin.com".to_string()))
        .add_explicit_direct_domain(DomainMatcher::Suffix("taobao.com".to_string()))
        .add_explicit_direct_domain(DomainMatcher::Suffix("bilivideo.com".to_string()))
        .add_explicit_proxy_domain(DomainMatcher::Suffix("youtube.com".to_string()))
        .add_explicit_proxy_domain(DomainMatcher::Suffix("google.com".to_string()))
        .add_security_block_domain(DomainMatcher::Suffix("adservice.google.com".to_string()));
    let policy = builder.build().expect("Valid policy");

    let sniffing_cfg = InboundSniffingConfig {
        enabled: true,
        dest_override: vec![SniffingDestination::Quic],
        metadata_only: false,
        route_only: true,
    };
    assert!(should_sniff_udp(Some(&sniffing_cfg)));

    let dummy_target = Target::new(
        TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(120, 232, 145, 10))),
        443,
        Network::Udp,
    );

    // 1. Domestic Direct app: Douyin
    let dy_packet = build_test_quic_initial_packet("v3-dy-y.douyin.com");
    let dy_sniffed = sniff_udp_initial_payload(&sniffing_cfg, &dummy_target, &dy_packet)
        .expect("Douyin QUIC should be sniffed");
    let dy_domain = match &dy_sniffed.route_target.addr {
        TargetAddr::Domain(d) => d.as_str(),
        _ => panic!("Expected domain target"),
    };
    let decision = policy.route(Network::Udp, &dummy_target, Some(dy_domain), &dns_cache, now);
    assert_eq!(decision.action, RouteAction::Direct);
    assert_eq!(decision.reason, RouteReason::SniffedDomain);
    assert_eq!(decision.domain_provenance, DomainProvenance::Sniffed);

    // 2. Domestic Direct app: Taobao
    let tb_packet = build_test_quic_initial_packet("trade.taobao.com");
    let tb_sniffed = sniff_udp_initial_payload(&sniffing_cfg, &dummy_target, &tb_packet)
        .expect("Taobao QUIC should be sniffed");
    let tb_domain = match &tb_sniffed.route_target.addr {
        TargetAddr::Domain(d) => d.as_str(),
        _ => panic!("Expected domain target"),
    };
    let decision = policy.route(Network::Udp, &dummy_target, Some(tb_domain), &dns_cache, now);
    assert_eq!(decision.action, RouteAction::Direct);
    assert_eq!(decision.reason, RouteReason::SniffedDomain);

    // 3. Foreign Proxy app: YouTube
    let yt_packet = build_test_quic_initial_packet("rr1---sn-4g5ednle.youtube.com");
    let yt_sniffed = sniff_udp_initial_payload(&sniffing_cfg, &dummy_target, &yt_packet)
        .expect("YouTube QUIC should be sniffed");
    let yt_domain = match &yt_sniffed.route_target.addr {
        TargetAddr::Domain(d) => d.as_str(),
        _ => panic!("Expected domain target"),
    };
    let decision = policy.route(Network::Udp, &dummy_target, Some(yt_domain), &dns_cache, now);
    assert_eq!(decision.action, RouteAction::Proxy);
    assert_eq!(decision.reason, RouteReason::SniffedDomain);

    // 4. Security Block app
    let ad_packet = build_test_quic_initial_packet("pagead.adservice.google.com");
    let ad_sniffed = sniff_udp_initial_payload(&sniffing_cfg, &dummy_target, &ad_packet)
        .expect("Ad QUIC should be sniffed");
    let ad_domain = match &ad_sniffed.route_target.addr {
        TargetAddr::Domain(d) => d.as_str(),
        _ => panic!("Expected domain target"),
    };
    let decision = policy.route(Network::Udp, &dummy_target, Some(ad_domain), &dns_cache, now);
    assert_eq!(decision.action, RouteAction::Block);
    assert_eq!(decision.reason, RouteReason::SecurityBlock);
}

#[tokio::test]
async fn test_xudp_framing_and_unpacking_roundtrip() {
    let (mut client_tx, mut server_rx) = tokio::io::duplex(4096);

    let original_payload = b"QUIC datagram payload over XUDP transport";
    let target = Target::new(
        TargetAddr::Domain("quic.video.example.com".to_string()),
        443,
        Network::Udp,
    );
    let global_id = [1, 2, 3, 4, 5, 6, 7, 8];

    // Frame 1: NEW packet
    let new_frame = encode_xudp_new_packet(&target, original_payload, global_id)
        .expect("Encode XUDP new packet");
    client_tx.write_all(&new_frame).await.unwrap();

    // Frame 2: KEEP packet
    let keep_payload = b"Subsequent QUIC datagram in same session";
    let keep_frame = encode_xudp_keep_packet(Some(&target), keep_payload)
        .expect("Encode XUDP keep packet");
    client_tx.write_all(&keep_frame).await.unwrap();

    // Server unpacks Frame 1
    let packet1 = read_xudp_packet(&mut server_rx).await.unwrap();
    assert_eq!(&packet1.payload[..], original_payload);
    let target1 = packet1.source.expect("XUDP new frame carries target");
    assert_eq!(target1.port, 443);
    assert_eq!(
        target1.addr,
        TargetAddr::Domain("quic.video.example.com".to_string())
    );

    // Server unpacks Frame 2
    let packet2 = read_xudp_packet(&mut server_rx).await.unwrap();
    assert_eq!(&packet2.payload[..], keep_payload);
    let target2 = packet2.source.expect("XUDP keep frame carries source target");
    assert_eq!(target2.port, 443);
}

#[test]
fn test_quic_sniffing_latency_benchmark() {
    let host = "hotsoon.douyin.com";
    let packet = build_test_quic_initial_packet(host);

    let iterations = 200;
    let start = Instant::now();
    for _ in 0..iterations {
        let sni = sniff_quic_initial_sni_public(&packet);
        assert_eq!(sni.as_deref(), Some(host));
    }
    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() / iterations as u128;

    // QUIC Initial sniffing must be extremely fast to avoid first-packet stall (< 1000us)
    assert!(
        avg_micros < 1000,
        "Average sniffing latency ({avg_micros}us) must be sub-millisecond"
    );
}
