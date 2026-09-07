// SPDX-License-Identifier: LicenseRef-Folo-Proprietary

use std::ffi::CString;
use std::time::{Duration, Instant};

use xray_ffi::{
    xray_core_free, xray_core_load_config_json, xray_core_new,
    xray_core_set_tun_runtime_profile, xray_core_start, xray_core_stop,
    xray_tun_poll_packets, xray_tun_push_packets, xray_tun_stats, XrayStatus,
    XrayTunRuntimeProfile, XrayTunStats,
};

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(u32::from(word));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_icmp_echo_request(
    source: [u8; 4],
    destination: [u8; 4],
    ident: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = 20 + icmp_len;
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 1; // ICMP
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let icmp = &mut packet[20..];
    icmp[0] = 8; // Echo request
    icmp[4..6].copy_from_slice(&ident.to_be_bytes());
    icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
    icmp[8..].copy_from_slice(payload);
    let icmp_checksum = internet_checksum(icmp);
    icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());

    packet
}

fn tun_config_minimal() -> String {
    r#"{
      "inbounds": [
        {
          "tag": "tun-in",
          "protocol": "tun",
          "settings": { "userLevel": 0 }
        }
      ],
      "outbounds": [
        { "tag": "direct", "protocol": "freedom" }
      ]
    }"#
    .to_string()
}

#[test]
fn test_throughput_burst_and_soak_memory_stability() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let profile_status = unsafe {
        xray_core_set_tun_runtime_profile(
            core,
            XrayTunRuntimeProfile::FoloIos as i32,
            &mut err,
        )
    };
    assert_eq!(profile_status, XrayStatus::Ok);

    let config_c = CString::new(tun_config_minimal()).unwrap();
    let load_status = unsafe { xray_core_load_config_json(core, config_c.as_ptr(), &mut err) };
    assert_eq!(load_status, XrayStatus::Ok);

    let start_status = unsafe { xray_core_start(core, &mut err) };
    assert_eq!(start_status, XrayStatus::Ok);

    // Soak test: Push 10 batches of 16 packets each while polling replies
    const BATCH_SIZE: usize = 16;
    let packets_batch: Vec<Vec<u8>> = (0..BATCH_SIZE)
        .map(|i| ipv4_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 0x4321, i as u16, b"soak-test-payload"))
        .collect();

    let ptrs: Vec<*const u8> = packets_batch.iter().map(|p| p.as_ptr()).collect();
    let lengths: Vec<usize> = packets_batch.iter().map(|p| p.len()).collect();

    let mut poll_buffer = vec![0u8; 1500 * BATCH_SIZE];
    let mut packet_lengths = vec![0usize; BATCH_SIZE];
    let mut total_pushed = 0usize;

    let start_time = Instant::now();
    for _ in 0..10 {
        let mut pushed = 0usize;
        let push_res = unsafe {
            xray_tun_push_packets(
                core,
                ptrs.as_ptr(),
                lengths.as_ptr(),
                ptrs.len(),
                &mut pushed,
                &mut err,
            )
        };
        assert_eq!(push_res, XrayStatus::Ok);
        assert_eq!(pushed, BATCH_SIZE);
        total_pushed += pushed;

        // Drain / poll so the queue never overflows
        let mut polled_in_call = 0usize;
        let _ = unsafe {
            xray_tun_poll_packets(
                core,
                poll_buffer.as_mut_ptr(),
                poll_buffer.len(),
                packet_lengths.as_mut_ptr(),
                packet_lengths.len(),
                &mut polled_in_call,
                5, // 5ms non-blocking drain
                &mut err,
            )
        };
    }
    let elapsed = start_time.elapsed();
    assert!(elapsed < Duration::from_secs(3), "Burst push and drain should complete quickly");

    // Inspect statistics
    let mut stats = XrayTunStats {
        struct_size: std::mem::size_of::<XrayTunStats>(),
        ..Default::default()
    };
    let stats_status = unsafe { xray_tun_stats(core, &mut stats, &mut err) };
    assert_eq!(stats_status, XrayStatus::Ok);
    assert_eq!(stats.inbound_packets, total_pushed as u64);

    // Teardown
    let stop_status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(stop_status, XrayStatus::Ok);
    unsafe { xray_core_free(core) };
}
