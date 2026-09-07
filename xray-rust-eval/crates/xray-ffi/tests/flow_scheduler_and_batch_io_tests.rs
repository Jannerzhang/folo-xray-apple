use std::ffi::CString;
use std::time::{Duration, Instant};

use xray_ffi::{
    xray_core_free, xray_core_load_config_json, xray_core_new, xray_core_set_tun_runtime_profile,
    xray_core_start, xray_core_stop, xray_error_free, xray_tun_poll_packets, xray_tun_push_packets,
    XrayStatus, XrayTunRuntimeProfile,
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

fn is_ipv4_icmp_echo_reply(packet: &[u8]) -> bool {
    packet.len() >= 28 && packet[0] >> 4 == 4 && packet[9] == 1 && packet[20] == 0
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
    .to_owned()
}

#[test]
fn test_batch_push_and_poll_roundtrip_with_folo_ios_profile() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    assert!(err.is_null());

    let status = unsafe {
        xray_core_set_tun_runtime_profile(core, XrayTunRuntimeProfile::FoloIos as i32, &mut err)
    };
    assert_eq!(status, XrayStatus::Ok);

    let config_json = CString::new(tun_config_minimal()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, config_json.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);

    let status = unsafe { xray_core_start(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);

    // Prepare a batch of 32 ICMP packets
    const BATCH_SIZE: usize = 32;
    let mut packets_data = Vec::with_capacity(BATCH_SIZE);
    for i in 0..BATCH_SIZE {
        let pkt = ipv4_icmp_echo_request(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            0x1234,
            i as u16,
            b"batch-pump-payload",
        );
        packets_data.push(pkt);
    }

    let packet_ptrs: Vec<*const u8> = packets_data.iter().map(|p| p.as_ptr()).collect();
    let packet_lens: Vec<usize> = packets_data.iter().map(|p| p.len()).collect();
    let mut pushed_count = 0usize;

    let status = unsafe {
        xray_tun_push_packets(
            core,
            packet_ptrs.as_ptr(),
            packet_lens.as_ptr(),
            BATCH_SIZE,
            &mut pushed_count,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);
    assert_eq!(pushed_count, BATCH_SIZE);

    // Contiguous arena for batch poll
    let mut poll_buffer = vec![0u8; 1500 * BATCH_SIZE];
    let mut packet_lengths = vec![0usize; BATCH_SIZE];
    let mut total_replies = 0usize;

    let start = Instant::now();
    while total_replies < BATCH_SIZE && start.elapsed() < Duration::from_secs(3) {
        let mut polled_in_call = 0usize;
        let status = unsafe {
            xray_tun_poll_packets(
                core,
                poll_buffer.as_mut_ptr(),
                poll_buffer.len(),
                packet_lengths.as_mut_ptr(),
                packet_lengths.len(),
                &mut polled_in_call,
                100, // 100ms timeout
                &mut err,
            )
        };
        assert_eq!(status, XrayStatus::Ok);
        let mut offset = 0usize;
        for i in 0..polled_in_call {
            let pkt_len = packet_lengths[i];
            if pkt_len > 0 && offset + pkt_len <= poll_buffer.len() {
                let reply = &poll_buffer[offset..offset + pkt_len];
                assert!(is_ipv4_icmp_echo_reply(reply));
                total_replies += 1;
                offset += pkt_len;
            }
        }
    }

    assert!(
        total_replies >= 1,
        "expected at least 1 reply, got {total_replies}"
    );

    let status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    unsafe { xray_core_free(core) };
    if !err.is_null() {
        unsafe { xray_error_free(err) };
    }
}

#[test]
fn test_batch_io_argument_validation() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let dummy_ptr = 0x1234 as *const u8;
    let dummy_len = 64usize;
    let mut pushed_count = 0usize;

    // Null core
    let status = unsafe {
        xray_tun_push_packets(
            std::ptr::null_mut(),
            &dummy_ptr,
            &dummy_len,
            1,
            &mut pushed_count,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);

    // Null packets array
    let status = unsafe {
        xray_tun_push_packets(
            core,
            std::ptr::null(),
            &dummy_len,
            1,
            &mut pushed_count,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);

    // Null lengths array
    let status = unsafe {
        xray_tun_push_packets(
            core,
            &dummy_ptr,
            std::ptr::null(),
            1,
            &mut pushed_count,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);

    // Null pushed_count
    let status = unsafe {
        xray_tun_push_packets(
            core,
            &dummy_ptr,
            &dummy_len,
            1,
            std::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);

    // Zero count succeeds with 0 pushed
    let status = unsafe {
        xray_tun_push_packets(
            core,
            &dummy_ptr,
            &dummy_len,
            0,
            &mut pushed_count,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);
    assert_eq!(pushed_count, 0);

    unsafe { xray_core_free(core) };
    if !err.is_null() {
        unsafe { xray_error_free(err) };
    }
}
