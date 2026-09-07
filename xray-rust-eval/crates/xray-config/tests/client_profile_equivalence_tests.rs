// SPDX-License-Identifier: LicenseRef-Folo-Proprietary

use std::net::IpAddr;
use xray_config::{
    parse_xray_json, InboundProtocol, Network, OutboundProtocol, OutboundSettings,
    RoutingRuleTarget, StreamSecurity, StreamTransport, TargetAddr,
};

#[test]
fn test_client_profile_vless_reality_vision_tcp_parses_losslessly() {
    let client_rendered_json = include_str!("fixtures/shared_vless_reality_golden.json");
    let parsed = parse_xray_json(client_rendered_json).expect("client rendered config must parse cleanly");
    assert!(parsed.diagnostics.is_empty(), "expected zero diagnostics for valid client config");

    // Verify inbounds
    assert_eq!(parsed.config.inbounds.len(), 1);
    assert_eq!(parsed.config.inbounds[0].tag.as_deref(), Some("tun-in"));
    assert_eq!(parsed.config.inbounds[0].protocol, InboundProtocol::Tun);

    // Verify outbounds
    assert_eq!(parsed.config.outbounds.len(), 3);
    assert_eq!(parsed.config.outbounds[0].tag.as_deref(), Some("proxy"));
    assert_eq!(parsed.config.outbounds[0].settings.protocol(), OutboundProtocol::Vless);

    let OutboundSettings::Vless(vless) = &parsed.config.outbounds[0].settings else {
        panic!("expected vless settings");
    };
    assert_eq!(vless.server, TargetAddr::Domain("edge.example.com".to_string()));
    assert_eq!(vless.port, 443);
    assert_eq!(vless.users.len(), 1);
    assert_eq!(vless.users[0].encryption, "none");
    assert_eq!(vless.users[0].flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(
        vless.users[0].id.to_string(),
        "00000000-0000-0000-0000-000000000001"
    );

    // Verify stream settings
    assert_eq!(parsed.config.outbounds[0].stream.network, Network::Tcp);
    assert_eq!(parsed.config.outbounds[0].stream.transport, StreamTransport::Raw);
    let StreamSecurity::Reality(reality) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected reality stream security");
    };
    assert_eq!(reality.server_name, "www.example.com");
    assert_eq!(reality.fingerprint, "chrome");
    assert_eq!(reality.spider_x, "/");
    assert_eq!(
        reality.short_id.as_slice(),
        &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
    );

    // Verify direct and block outbounds
    assert_eq!(parsed.config.outbounds[1].tag.as_deref(), Some("direct"));
    assert!(matches!(parsed.config.outbounds[1].settings, OutboundSettings::Freedom));
    assert_eq!(parsed.config.outbounds[2].tag.as_deref(), Some("block"));
    assert!(matches!(parsed.config.outbounds[2].settings, OutboundSettings::Blackhole));

    // Verify routing rules (4 rules in golden fixture)
    assert_eq!(parsed.config.routing.rules.len(), 4);
    assert_eq!(parsed.config.routing.rules[0].target, RoutingRuleTarget::Outbound("block".to_string()));
    assert!(parsed.config.routing.rules[0].matches_domain(Some("ads.example")));

    assert_eq!(parsed.config.routing.rules[1].target, RoutingRuleTarget::Outbound("proxy".to_string()));
    assert!(parsed.config.routing.rules[1].matches_domain(Some("sub.example.com")));

    assert_eq!(parsed.config.routing.rules[2].target, RoutingRuleTarget::Outbound("direct".to_string()));
    assert!(parsed.config.routing.rules[2].matches_domain(Some("captive.apple.com")));

    assert_eq!(parsed.config.routing.rules[3].target, RoutingRuleTarget::Outbound("direct".to_string()));
    assert!(parsed.config.routing.rules[3].matches_ip(Some(&"10.1.2.3".parse::<IpAddr>().unwrap())));
    assert!(parsed.config.routing.rules[3].matches_ip(Some(&"192.168.1.1".parse::<IpAddr>().unwrap())));
}

#[test]
fn test_unsupported_client_protocols_and_transports_fail_closed() {
    // 1. VMess outbound must fail or be diagnosed as unsupported
    let vmess_json = r#"{
      "inbounds": [{"tag": "tun-in", "protocol": "tun", "listen": "127.0.0.1", "port": 0, "settings": {}}],
      "outbounds": [
        {
          "tag": "proxy",
          "protocol": "vmess",
          "settings": {
            "vnext": [{"address": "1.2.3.4", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000001"}]}]
          }
        }
      ]
    }"#;
    let res = parse_xray_json(vmess_json);
    assert!(res.is_err() || res.unwrap().diagnostics.iter().any(|d| d.severity == xray_config::DiagnosticSeverity::Error));

    // 2. Trojan outbound must fail
    let trojan_json = r#"{
      "inbounds": [{"tag": "tun-in", "protocol": "tun", "listen": "127.0.0.1", "port": 0, "settings": {}}],
      "outbounds": [
        {
          "tag": "proxy",
          "protocol": "trojan",
          "settings": {
            "servers": [{"address": "1.2.3.4", "port": 443, "password": "pass"}]
          }
        }
      ]
    }"#;
    let res = parse_xray_json(trojan_json);
    assert!(res.is_err() || res.unwrap().diagnostics.iter().any(|d| d.severity == xray_config::DiagnosticSeverity::Error));
}

#[test]
fn test_routing_ip_and_cidr_validation_rejects_malformed_values() {
    let config = |value: &str| {
        format!(
            r#"{{
              "inbounds": [{{"tag":"tun-in","protocol":"tun","listen":"127.0.0.1","port":0,"settings":{{}}}}],
              "outbounds": [{{"tag":"direct","protocol":"freedom"}}],
              "routing": {{"rules":[{{"type":"field","ip":["{value}"],"outboundTag":"direct"}}]}}
            }}"#
        )
    };

    for value in ["not-a-cidr", "10.0.0.0/33", "2001:db8::/129", "10.0.0.999/24"] {
        let parsed = parse_xray_json(&config(value));
        assert!(
            parsed.is_err()
                || parsed
                    .as_ref()
                    .expect("successful parser result")
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.severity == xray_config::DiagnosticSeverity::Error),
            "malformed routing matcher must fail closed: {value}"
        );
    }

    let mixed = config("10.0.0.0/8");
    assert!(parse_xray_json(&mixed).is_ok());
    let mixed_ipv6 = config("2001:db8::/32");
    assert!(parse_xray_json(&mixed_ipv6).is_ok());
}
