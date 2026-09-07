use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use xray_ffi::{
    xray_core_cancel_tun_poll, xray_core_free, xray_core_load_config_json, xray_core_new,
    xray_core_set_tun_runtime_profile, xray_core_start, xray_core_stop,
    xray_error_free, xray_ffi_capabilities, xray_ffi_version_major, xray_ffi_version_minor,
    xray_tun_poll_packets, xray_tun_push_packets, XrayStatus, XrayTunRuntimeProfile,
    XRAY_FFI_ABI_MAJOR, XRAY_FFI_ABI_MINOR, XRAY_FFI_CAPABILITY_TUN_BATCH_POLL,
    XRAY_FFI_CAPABILITY_TUN_BATCH_PUSH,
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
fn abi_v2_reports_major_2_and_negotiation() {
    assert_eq!(xray_ffi_version_major(), 2);
    assert_eq!(xray_ffi_version_minor(), 0);
    assert_eq!(XRAY_FFI_ABI_MAJOR, 2);
    assert_eq!(XRAY_FFI_ABI_MINOR, 0);

    let caps = xray_ffi_capabilities();
    assert_ne!(caps & XRAY_FFI_CAPABILITY_TUN_BATCH_PUSH, 0);
    assert_ne!(caps & XRAY_FFI_CAPABILITY_TUN_BATCH_POLL, 0);
}

#[test]
fn abi_v2_folo_ios_runtime_profile_setting() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    assert!(err.is_null());

    let status = unsafe {
        xray_core_set_tun_runtime_profile(
            core,
            XrayTunRuntimeProfile::FoloIos as libc::c_int,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);
    assert!(err.is_null());

    let raw = CString::new(tun_config_minimal()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);

    // After load, profile cannot be changed
    let status = unsafe {
        xray_core_set_tun_runtime_profile(
            core,
            XrayTunRuntimeProfile::FoloIos as libc::c_int,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::RuntimeError);
    if !err.is_null() {
        unsafe { xray_error_free(err) };
    }

    unsafe { xray_core_free(core) };
}

#[test]
fn abi_v2_tun_push_packets_argument_validation() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let packet = ipv4_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 1, 1, b"hello");
    let packet_ptrs = [packet.as_ptr()];
    let packet_lens = [packet.len()];
    let mut pushed_count = 0usize;

    // Null handle
    let status = unsafe {
        xray_tun_push_packets(
            std::ptr::null_mut(),
            packet_ptrs.as_ptr(),
            packet_lens.as_ptr(),
            1,
            &mut pushed_count,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);
    if !err.is_null() {
        unsafe { xray_error_free(err) };
        err = std::ptr::null_mut();
    }

    // Null packets array
    let status = unsafe {
        xray_tun_push_packets(
            core,
            std::ptr::null(),
            packet_lens.as_ptr(),
            1,
            &mut pushed_count,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);
    if !err.is_null() {
        unsafe { xray_error_free(err) };
        err = std::ptr::null_mut();
    }

    // Null lengths array
    let status = unsafe {
        xray_tun_push_packets(
            core,
            packet_ptrs.as_ptr(),
            std::ptr::null(),
            1,
            &mut pushed_count,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);
    if !err.is_null() {
        unsafe { xray_error_free(err) };
        err = std::ptr::null_mut();
    }

    // Null pushed_count pointer
    let status = unsafe {
        xray_tun_push_packets(
            core,
            packet_ptrs.as_ptr(),
            packet_lens.as_ptr(),
            1,
            std::ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::NullArgument);
    if !err.is_null() {
        unsafe { xray_error_free(err) };
        err = std::ptr::null_mut();
    }

    // Count 0 is valid no-op
    pushed_count = 99;
    let status = unsafe {
        xray_tun_push_packets(
            core,
            packet_ptrs.as_ptr(),
            packet_lens.as_ptr(),
            0,
            &mut pushed_count,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);
    assert_eq!(pushed_count, 0);

    unsafe { xray_core_free(core) };
}

#[test]
fn abi_v2_tun_batch_push_and_batch_poll_flow() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let status = unsafe {
        xray_core_set_tun_runtime_profile(
            core,
            XrayTunRuntimeProfile::FoloIos as libc::c_int,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);

    let raw = CString::new(tun_config_minimal()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);

    let status = unsafe { xray_core_start(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);

    // Prepare 3 ICMP echo request packets
    let p1 = ipv4_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 100, 1, b"pkt1");
    let p2 = ipv4_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 100, 2, b"pkt2");
    let p3 = ipv4_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], 100, 3, b"pkt3");

    let ptrs = [p1.as_ptr(), p2.as_ptr(), p3.as_ptr()];
    let lens = [p1.len(), p2.len(), p3.len()];
    let mut pushed_count = 0usize;

    let status =
        unsafe { xray_tun_push_packets(core, ptrs.as_ptr(), lens.as_ptr(), 3, &mut pushed_count, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    assert_eq!(pushed_count, 3);

    // Poll replies via batch poll
    let mut poll_buffer = vec![0u8; 1500 * 8];
    let mut packet_lengths = [0usize; 8];
    let mut packet_count = 0usize;

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut replies_found = 0usize;

    while Instant::now() < deadline && replies_found < 3 {
        let status = unsafe {
            xray_tun_poll_packets(
                core,
                poll_buffer.as_mut_ptr(),
                poll_buffer.len(),
                packet_lengths.as_mut_ptr(),
                packet_lengths.len(),
                &mut packet_count,
                100, // 100ms timeout
                &mut err,
            )
        };
        assert_eq!(status, XrayStatus::Ok);
        let mut offset = 0usize;
        for i in 0..packet_count {
            let pkt_len = packet_lengths[i];
            let pkt_slice = &poll_buffer[offset..offset + pkt_len];
            if is_ipv4_icmp_echo_reply(pkt_slice) {
                replies_found += 1;
            }
            offset += pkt_len;
        }
    }

    assert!(
        replies_found >= 1,
        "expected at least one echo reply, found {replies_found}"
    );

    let status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    unsafe { xray_core_free(core) };
}

#[test]
fn abi_v2_cancel_tun_poll_wakes_waiting_poller_immediately() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let status = unsafe {
        xray_core_set_tun_runtime_profile(
            core,
            XrayTunRuntimeProfile::FoloIos as libc::c_int,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);

    let raw = CString::new(tun_config_minimal()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);

    let status = unsafe { xray_core_start(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);

    // Poller thread with long timeout (5000ms)
    let core_addr = core as usize;
    let poller_done = Arc::new(AtomicBool::new(false));
    let poller_done_clone = poller_done.clone();

    let poller_thread = thread::spawn(move || {
        let core = core_addr as *mut xray_ffi::XrayCoreHandle;
        let mut local_err = std::ptr::null_mut();
        let mut buffer = vec![0u8; 1500];
        let mut packet_lengths = [0usize; 1];
        let mut packet_count = 0usize;

        let start = Instant::now();
        let status = unsafe {
            xray_tun_poll_packets(
                core,
                buffer.as_mut_ptr(),
                buffer.len(),
                packet_lengths.as_mut_ptr(),
                packet_lengths.len(),
                &mut packet_count,
                5000, // 5 seconds wait
                &mut local_err,
            )
        };
        let elapsed = start.elapsed();
        poller_done_clone.store(true, Ordering::SeqCst);
        (status, packet_count, elapsed)
    });

    // Wait 50ms then trigger cancel
    thread::sleep(Duration::from_millis(50));
    let cancel_start = Instant::now();
    let cancel_status = unsafe { xray_core_cancel_tun_poll(core, &mut err) };
    assert_eq!(cancel_status, XrayStatus::Ok);

    let (status, count, elapsed) = poller_thread.join().expect("poller thread failed");
    let cancel_elapsed = cancel_start.elapsed();

    assert_eq!(status, XrayStatus::NoPacket);
    assert_eq!(count, 0);
    assert!(
        cancel_elapsed < Duration::from_millis(500),
        "cancel took too long: {cancel_elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1000),
        "poller did not wake up promptly: {elapsed:?}"
    );

    let status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);
    unsafe { xray_core_free(core) };
}

#[test]
fn abi_v2_stop_automatically_wakes_waiting_poller() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let status = unsafe {
        xray_core_set_tun_runtime_profile(
            core,
            XrayTunRuntimeProfile::FoloIos as libc::c_int,
            &mut err,
        )
    };
    assert_eq!(status, XrayStatus::Ok);

    let raw = CString::new(tun_config_minimal()).unwrap();
    let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
    assert_eq!(status, XrayStatus::Ok);

    let status = unsafe { xray_core_start(core, &mut err) };
    assert_eq!(status, XrayStatus::Ok);

    let core_addr = core as usize;
    let poller_thread = thread::spawn(move || {
        let core = core_addr as *mut xray_ffi::XrayCoreHandle;
        let mut local_err = std::ptr::null_mut();
        let mut buffer = vec![0u8; 1500];
        let mut packet_lengths = [0usize; 1];
        let mut packet_count = 0usize;

        let start = Instant::now();
        let status = unsafe {
            xray_tun_poll_packets(
                core,
                buffer.as_mut_ptr(),
                buffer.len(),
                packet_lengths.as_mut_ptr(),
                packet_lengths.len(),
                &mut packet_count,
                5000,
                &mut local_err,
            )
        };
        let elapsed = start.elapsed();
        (status, packet_count, elapsed)
    });

    thread::sleep(Duration::from_millis(50));
    let stop_start = Instant::now();
    let stop_status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(stop_status, XrayStatus::Ok);

    let (_status, _count, elapsed) = poller_thread.join().expect("poller thread failed");
    let stop_elapsed = stop_start.elapsed();

    assert!(
        stop_elapsed < Duration::from_millis(500),
        "stop took too long: {stop_elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1000),
        "poller did not wake up promptly on stop: {elapsed:?}"
    );

    unsafe { xray_core_free(core) };
}

#[test]
fn abi_v2_rapid_lifecycle_endurance() {
    for i in 0..25 {
        let mut err = std::ptr::null_mut();
        let core = unsafe { xray_core_new(&mut err) };
        assert!(!core.is_null(), "cycle {i} core_new failed");

        let status = unsafe {
            xray_core_set_tun_runtime_profile(
                core,
                XrayTunRuntimeProfile::FoloIos as libc::c_int,
                &mut err,
            )
        };
        assert_eq!(status, XrayStatus::Ok);

        let raw = CString::new(tun_config_minimal()).unwrap();
        let status = unsafe { xray_core_load_config_json(core, raw.as_ptr(), &mut err) };
        assert_eq!(status, XrayStatus::Ok);

        let status = unsafe { xray_core_start(core, &mut err) };
        assert_eq!(status, XrayStatus::Ok);

        let pkt = ipv4_icmp_echo_request([10, 0, 0, 2], [10, 0, 0, 1], i as u16, 1, b"endurance");
        let ptrs = [pkt.as_ptr()];
        let lens = [pkt.len()];
        let mut pushed = 0usize;
        let status =
            unsafe { xray_tun_push_packets(core, ptrs.as_ptr(), lens.as_ptr(), 1, &mut pushed, &mut err) };
        assert_eq!(status, XrayStatus::Ok);

        let cancel_status = unsafe { xray_core_cancel_tun_poll(core, &mut err) };
        assert_eq!(cancel_status, XrayStatus::Ok);

        let stop_status = unsafe { xray_core_stop(core, &mut err) };
        assert_eq!(stop_status, XrayStatus::Ok);

        unsafe { xray_core_free(core) };
    }
}
