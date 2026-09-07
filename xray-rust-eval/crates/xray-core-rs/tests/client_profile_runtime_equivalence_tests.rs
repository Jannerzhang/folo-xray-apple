use std::sync::Arc;

use xray_config::parse_xray_json;
use xray_core_rs::Core;
use xray_transport::{SystemDnsResolver, TransportDialer};

const SHARED_GOLDEN: &str =
    include_str!("../../xray-config/tests/fixtures/shared_vless_reality_golden.json");

#[tokio::test]
async fn shared_profile_fixture_reaches_the_rust_runtime_without_rewrite() {
    let parsed = parse_xray_json(SHARED_GOLDEN).expect("shared fixture must parse");
    assert!(parsed.diagnostics.is_empty());

    let mut core = Core::with_runtime_dependencies(
        parsed.config,
        Arc::new(SystemDnsResolver),
        Arc::new(TransportDialer::system().expect("system transport dialer")),
    )
    .expect("Rust runtime must accept the shared App-rendered fixture");

    core.start().await.expect("Rust runtime must start");
    assert_eq!(core.tun().mtu(), 1500);
    core.stop().await.expect("Rust runtime must stop");
}
