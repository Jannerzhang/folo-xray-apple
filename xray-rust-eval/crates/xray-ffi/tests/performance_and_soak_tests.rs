// SPDX-License-Identifier: LicenseRef-Folo-Proprietary

use std::ffi::CString;
use std::fs;
use std::time::{Duration, Instant};
use std::{env, sync::Arc, thread};

use xray_ffi::{
    xray_core_free, xray_core_load_config_json, xray_core_new, xray_core_set_tun_runtime_profile,
    xray_core_start, xray_core_stop, xray_tun_poll_packets, xray_tun_push_packets, xray_tun_stats,
    XrayStatus, XrayTunRuntimeProfile, XrayTunStats,
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

fn tun_config_for_gate() -> String {
    env::var("XRAY_FFI_CONFIG_PATH")
        .ok()
        .filter(|path| !path.is_empty())
        .map(|path| fs::read_to_string(path).expect("XRAY_FFI_CONFIG_PATH must be readable"))
        .unwrap_or_else(tun_config_minimal)
}

#[test]
fn test_throughput_burst_and_soak_memory_stability() {
    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());

    let profile_status = unsafe {
        xray_core_set_tun_runtime_profile(core, XrayTunRuntimeProfile::FoloIos as i32, &mut err)
    };
    assert_eq!(profile_status, XrayStatus::Ok);

    let config_c = CString::new(tun_config_minimal()).unwrap();
    let load_status = unsafe { xray_core_load_config_json(core, config_c.as_ptr(), &mut err) };
    assert_eq!(load_status, XrayStatus::Ok);

    let start_status = unsafe { xray_core_start(core, &mut err) };
    assert_eq!(start_status, XrayStatus::Ok);

    // Sustained soak test: 64 concurrent streams pushing bursts over at least 5 seconds
    const CONCURRENCY: usize = 64;
    const BATCH_SIZE: usize = 16;
    let core_addr = core as usize;

    let soak_start = Instant::now();
    let test_duration = Duration::from_secs(5);

    let mut handles = Vec::with_capacity(CONCURRENCY);

    for worker_id in 0..CONCURRENCY {
        handles.push(std::thread::spawn(move || {
            let core_ptr = core_addr as *mut xray_ffi::XrayCoreHandle;
            let mut local_err = std::ptr::null_mut();
            let mut pushed_count_total = 0usize;

            let packets_batch: Vec<Vec<u8>> = (0..BATCH_SIZE)
                .map(|seq| {
                    ipv4_icmp_echo_request(
                        [
                            10,
                            (worker_id >> 8) as u8,
                            (worker_id & 0xff) as u8,
                            (seq + 2) as u8,
                        ],
                        [10, 0, 0, 1],
                        0x1234 + worker_id as u16,
                        seq as u16,
                        b"soak-stress-packet-stream-payload-5s",
                    )
                })
                .collect();
            let ptrs: Vec<*const u8> = packets_batch.iter().map(|p| p.as_ptr()).collect();
            let lengths: Vec<usize> = packets_batch.iter().map(|p| p.len()).collect();

            while soak_start.elapsed() < test_duration {
                let mut accepted = 0usize;
                let push_res = unsafe {
                    xray_tun_push_packets(
                        core_ptr,
                        ptrs.as_ptr(),
                        lengths.as_ptr(),
                        ptrs.len(),
                        &mut accepted,
                        &mut local_err,
                    )
                };
                if push_res == XrayStatus::Ok {
                    pushed_count_total += accepted;
                }
                if !local_err.is_null() {
                    unsafe { xray_ffi::xray_error_free(local_err) };
                    local_err = std::ptr::null_mut();
                }
                std::thread::yield_now();
            }
            pushed_count_total
        }));
    }

    // Simultaneously run draining poller on main thread
    let mut poll_buffer = vec![0u8; 1500 * BATCH_SIZE];
    let mut packet_lengths = vec![0usize; BATCH_SIZE];
    let mut total_polled = 0usize;

    while soak_start.elapsed() < test_duration + Duration::from_millis(500) {
        let mut polled_in_call = 0usize;
        let poll_status = unsafe {
            xray_tun_poll_packets(
                core,
                poll_buffer.as_mut_ptr(),
                poll_buffer.len(),
                packet_lengths.as_mut_ptr(),
                packet_lengths.len(),
                &mut polled_in_call,
                1,
                &mut err,
            )
        };
        assert!(
            matches!(poll_status, XrayStatus::Ok | XrayStatus::NoPacket),
            "poll returned unexpected status: {poll_status:?}"
        );
        total_polled += polled_in_call;
        std::thread::yield_now();
    }

    let mut total_pushed = 0usize;
    for handle in handles {
        total_pushed += handle.join().expect("Worker thread must join successfully");
    }

    let soak_elapsed = soak_start.elapsed();
    assert!(
        soak_elapsed >= test_duration,
        "Soak test must run for at least 5 seconds"
    );
    assert!(
        total_pushed > 0,
        "short smoke test should accept at least one packet, actual pushed: {total_pushed}"
    );
    assert!(
        total_polled > 0,
        "the smoke poller must observe at least one reply"
    );

    // Inspect final runtime statistics
    let mut stats = XrayTunStats {
        struct_size: std::mem::size_of::<XrayTunStats>(),
        ..Default::default()
    };
    let stats_status = unsafe { xray_tun_stats(core, &mut stats, &mut err) };
    assert_eq!(stats_status, XrayStatus::Ok);
    assert!(
        stats.inbound_packets >= total_pushed as u64,
        "Inbound packets counter ({}) must match or exceed pushed packets ({})",
        stats.inbound_packets,
        total_pushed
    );

    // Stop and teardown cleanly without leaking or crashing
    let stop_status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(stop_status, XrayStatus::Ok);
    unsafe { xray_core_free(core) };
}

fn ipv4_udp_datagram(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    sequence: u16,
) -> Vec<u8> {
    let payload = sequence.to_be_bytes();
    let total_len = 20 + 8 + payload.len();
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(8u16 + payload.len() as u16).to_be_bytes());
    packet[28..].copy_from_slice(&payload);
    packet
}

fn ipv4_tcp_syn(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> Vec<u8> {
    let total_len = 40usize;
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    let tcp = &mut packet[20..];
    tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&65_535u16.to_be_bytes());
    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    tcp[16..18].copy_from_slice(&internet_checksum(&pseudo).to_be_bytes());
    packet
}

fn env_duration(name: &str, default_seconds: u64) -> Duration {
    Duration::from_secs(
        env::var(name)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(default_seconds),
    )
}

fn process_usage() -> (u64, u64, u64) {
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return (0, 0, 0);
    }
    let user = u64::try_from(usage.ru_utime.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000)
        .saturating_add(u64::try_from(usage.ru_utime.tv_usec).unwrap_or(0));
    let system = u64::try_from(usage.ru_stime.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000)
        .saturating_add(u64::try_from(usage.ru_stime.tv_usec).unwrap_or(0));
    let max_rss = u64::try_from(usage.ru_maxrss).unwrap_or(0);
    #[cfg(not(target_os = "macos"))]
    let max_rss = max_rss.saturating_mul(1024);
    (user, system, max_rss)
}

fn push_batch_reliably(
    core: *mut xray_ffi::XrayCoreHandle,
    packets: &[Vec<u8>],
    error: &mut *mut xray_ffi::XrayError,
) -> usize {
    let pointers = packets
        .iter()
        .map(|packet| packet.as_ptr())
        .collect::<Vec<_>>();
    let lengths = packets.iter().map(Vec::len).collect::<Vec<_>>();
    let mut offset = 0usize;
    for _ in 0..256 {
        if offset == packets.len() {
            return offset;
        }
        let mut accepted = 0usize;
        let status = unsafe {
            xray_tun_push_packets(
                core,
                pointers.as_ptr().add(offset),
                lengths.as_ptr().add(offset),
                packets.len() - offset,
                &mut accepted,
                error,
            )
        };
        offset = offset.saturating_add(accepted.min(packets.len() - offset));
        if !(*error).is_null() {
            unsafe { xray_ffi::xray_error_free(*error) };
            *error = std::ptr::null_mut();
        }
        if offset == packets.len() {
            return offset;
        }
        assert_eq!(
            status,
            XrayStatus::TunError,
            "batch push must either accept all packets or report a bounded queue error"
        );
        thread::sleep(Duration::from_millis(1));
    }
    panic!(
        "batch push did not drain after bounded retries; accepted {offset}/{}",
        packets.len()
    );
}

#[test]
#[ignore = "release gate: run with a controlled service/device and the 30-minute default"]
fn test_mixed_256_tcp_256_udp_release_gate() {
    const TCP_FLOWS: usize = 256;
    const UDP_FLOWS: usize = 256;
    const WORKERS: usize = 32;
    const BATCH_SIZE: usize = 16;
    const MTU: usize = 1500;

    let mut err = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut err) };
    assert!(!core.is_null());
    if !err.is_null() {
        unsafe { xray_ffi::xray_error_free(err) };
        err = std::ptr::null_mut();
    }

    assert_eq!(
        unsafe {
            xray_core_set_tun_runtime_profile(core, XrayTunRuntimeProfile::FoloIos as i32, &mut err)
        },
        XrayStatus::Ok
    );
    let soak_duration = env_duration("XRAY_FFI_SOAK_SECONDS", 30 * 60);
    if soak_duration >= Duration::from_secs(30 * 60) {
        assert!(
            env::var("XRAY_FFI_CONFIG_PATH")
                .ok()
                .filter(|path| !path.is_empty())
                .is_some_and(|path| std::path::Path::new(&path).is_file()),
            "the 30-minute gate requires XRAY_FFI_CONFIG_PATH for a controlled service configuration"
        );
    }
    let config = CString::new(tun_config_for_gate()).unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, config.as_ptr(), &mut err) },
        XrayStatus::Ok
    );
    assert_eq!(unsafe { xray_core_start(core, &mut err) }, XrayStatus::Ok);

    let core_addr = core as usize;
    let end_at = Instant::now() + soak_duration;
    let (start_user_cpu, start_system_cpu, _) = process_usage();
    let require_zero_drops = env::var("XRAY_FFI_REQUIRE_ZERO_DROPS")
        .ok()
        .is_some_and(|value| value == "1");
    let barrier = Arc::new(std::sync::Barrier::new(WORKERS + 1));
    let mut workers = Vec::with_capacity(WORKERS);
    for worker_id in 0..WORKERS {
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            let core = core_addr as *mut xray_ffi::XrayCoreHandle;
            let first_tcp = worker_id * (TCP_FLOWS / WORKERS);
            let first_udp = worker_id * (UDP_FLOWS / WORKERS);
            let mut packets = Vec::with_capacity(BATCH_SIZE);
            for sequence in 0..BATCH_SIZE {
                let flow = first_tcp + sequence % (TCP_FLOWS / WORKERS);
                packets.push(ipv4_tcp_syn(
                    [10, 1, (flow >> 8) as u8, flow as u8],
                    [198, 18, 0, 1],
                    10_000 + flow as u16,
                    443,
                    sequence as u32,
                ));
                let udp_flow = first_udp + sequence % (UDP_FLOWS / WORKERS);
                packets.push(ipv4_udp_datagram(
                    [10, 2, (udp_flow >> 8) as u8, udp_flow as u8],
                    [198, 18, 0, 1],
                    20_000 + udp_flow as u16,
                    443,
                    sequence as u16,
                ));
            }
            let ptrs = packets
                .iter()
                .map(|packet| packet.as_ptr())
                .collect::<Vec<_>>();
            let lengths = packets.iter().map(Vec::len).collect::<Vec<_>>();
            let mut local_err = std::ptr::null_mut();
            let mut accepted_total = 0usize;
            barrier.wait();
            thread::sleep(Duration::from_millis(100 + worker_id as u64));
            while Instant::now() < end_at {
                accepted_total += push_batch_reliably(core, &packets, &mut local_err);
                assert!(ptrs
                    .iter()
                    .zip(&lengths)
                    .all(|(ptr, len)| !ptr.is_null() && *len <= MTU));
                thread::sleep(Duration::from_millis(1));
            }
            accepted_total
        }));
    }

    barrier.wait();
    let mut poll_buffer = vec![0u8; MTU * 64];
    let mut packet_lengths = vec![0usize; 64];
    let mut total_polled = 0usize;
    let mut peak_inbound_queue = 0u64;
    let mut peak_outbound_queue = 0u64;
    let mut peak_tcp_flows = 0u64;
    let mut peak_udp_flows = 0u64;
    let mut poll_calls = 0usize;
    while Instant::now() < end_at + Duration::from_secs(2) {
        let mut packet_count = 0usize;
        let status = unsafe {
            xray_tun_poll_packets(
                core,
                poll_buffer.as_mut_ptr(),
                poll_buffer.len(),
                packet_lengths.as_mut_ptr(),
                packet_lengths.len(),
                &mut packet_count,
                10,
                &mut err,
            )
        };
        poll_calls += 1;
        assert!(
            matches!(status, XrayStatus::Ok | XrayStatus::NoPacket),
            "poll call {poll_calls} returned {status:?}"
        );
        if !err.is_null() {
            unsafe { xray_ffi::xray_error_free(err) };
            err = std::ptr::null_mut();
        }
        assert!(packet_count <= packet_lengths.len());
        for length in &packet_lengths[..packet_count] {
            assert!((1..=MTU).contains(length));
        }
        total_polled += packet_count;

        let mut stats = XrayTunStats {
            struct_size: std::mem::size_of::<XrayTunStats>(),
            ..Default::default()
        };
        assert_eq!(
            unsafe { xray_tun_stats(core, &mut stats, &mut err) },
            XrayStatus::Ok
        );
        peak_inbound_queue = peak_inbound_queue.max(stats.inbound_queue_max_packets);
        peak_outbound_queue = peak_outbound_queue.max(stats.outbound_queue_max_packets);
        peak_tcp_flows = peak_tcp_flows.max(stats.active_tcp_flows);
        peak_udp_flows = peak_udp_flows.max(stats.active_udp_flows);
        if require_zero_drops {
            assert_eq!(
                stats.dropped_packets, 0,
                "internal packet drops are not allowed in the release gate"
            );
        }
        if !err.is_null() {
            unsafe { xray_ffi::xray_error_free(err) };
            err = std::ptr::null_mut();
        }
        thread::yield_now();
    }

    let accepted_total: usize = workers
        .into_iter()
        .map(|worker| worker.join().expect("stress worker must join"))
        .sum();
    let mut final_stats = XrayTunStats {
        struct_size: std::mem::size_of::<XrayTunStats>(),
        ..Default::default()
    };
    assert_eq!(
        unsafe { xray_tun_stats(core, &mut final_stats, &mut err) },
        XrayStatus::Ok
    );
    if require_zero_drops {
        assert_eq!(final_stats.dropped_packets, 0);
    }
    assert!(final_stats.inbound_packets >= accepted_total as u64);
    assert!(
        total_polled > 0,
        "TUN output must be observed by the poller"
    );
    assert_eq!(
        final_stats.outbound_packets, total_polled as u64,
        "reported TUN replies must match the packets observed by the poller"
    );
    assert!(peak_tcp_flows <= TCP_FLOWS as u64);
    assert!(peak_udp_flows <= UDP_FLOWS as u64);
    assert!(peak_inbound_queue <= 64);
    assert!(peak_outbound_queue <= 256);
    assert!(poll_calls > 0);
    let stop_start = Instant::now();
    assert_eq!(unsafe { xray_core_stop(core, &mut err) }, XrayStatus::Ok);
    let stop_duration = stop_start.elapsed();
    assert!(
        stop_duration < Duration::from_secs(2),
        "core stop exceeded the two-second gate: {stop_duration:?}"
    );
    let (end_user_cpu, end_system_cpu, peak_rss_bytes) = process_usage();
    eprintln!(
        "mixed_gate duration_s={} accepted={} polled={} poll_calls={} drops={} peak_queue={}/{} peak_flows={}/{} zero_drop_required={}",
        soak_duration.as_secs(),
        accepted_total,
        total_polled,
        poll_calls,
        final_stats.dropped_packets,
        peak_inbound_queue,
        peak_outbound_queue,
        peak_tcp_flows,
        peak_udp_flows,
        require_zero_drops
    );
    eprintln!(
        "mixed_gate resources user_cpu_us={} system_cpu_us={} peak_rss_bytes={} stop_ms={}",
        end_user_cpu.saturating_sub(start_user_cpu),
        end_system_cpu.saturating_sub(start_system_cpu),
        peak_rss_bytes,
        stop_duration.as_millis()
    );
    if !err.is_null() {
        unsafe { xray_ffi::xray_error_free(err) };
    }
    unsafe { xray_core_free(core) };
}
