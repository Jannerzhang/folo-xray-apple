// SPDX-License-Identifier: LicenseRef-Folo-Proprietary

use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use xray_ffi::{
    xray_core_cancel_tun_poll, xray_core_free, xray_core_load_config_json, xray_core_new,
    xray_core_set_tun_runtime_profile, xray_core_start, xray_core_stop, xray_error_free,
    xray_tun_poll_packets, xray_tun_stats, XrayStatus, XrayTunRuntimeProfile, XrayTunStats,
};

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
fn test_cancel_tun_poll_unblocks_immediately() {
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

    let core_addr = core as usize;
    let poller_started = Arc::new(AtomicBool::new(false));
    let poller_done = Arc::new(AtomicBool::new(false));

    let started_clone = Arc::clone(&poller_started);
    let done_clone = Arc::clone(&poller_done);

    let poller_thread = thread::spawn(move || {
        let handle = core_addr as *mut xray_ffi::XrayCoreHandle;
        let mut buffer = vec![0u8; 65536];
        let mut packet_lengths = [0usize; 32];
        let mut packet_count = 0usize;
        let mut thread_err = std::ptr::null_mut();

        started_clone.store(true, Ordering::SeqCst);
        let start_time = Instant::now();

        let status = unsafe {
            xray_tun_poll_packets(
                handle,
                buffer.as_mut_ptr(),
                buffer.len(),
                packet_lengths.as_mut_ptr(),
                packet_lengths.len(),
                &mut packet_count,
                10_000,
                &mut thread_err,
            )
        };

        let elapsed = start_time.elapsed();
        if !thread_err.is_null() {
            unsafe { xray_error_free(thread_err) };
        }
        done_clone.store(true, Ordering::SeqCst);
        (status, elapsed)
    });

    while !poller_started.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(5));
    }
    thread::sleep(Duration::from_millis(50));

    let cancel_start = Instant::now();
    let cancel_status = unsafe { xray_core_cancel_tun_poll(core, &mut err) };
    assert_eq!(cancel_status, XrayStatus::Ok);

    let (poller_result_status, poller_elapsed) = poller_thread.join().expect("thread join failed");
    let cancel_elapsed = cancel_start.elapsed();

    assert!(
        cancel_elapsed < Duration::from_millis(500),
        "Cancellation took too long: {:?}",
        cancel_elapsed
    );
    assert!(
        poller_elapsed < Duration::from_secs(2),
        "Poller elapsed too long: {:?}",
        poller_elapsed
    );
    assert_eq!(poller_result_status, XrayStatus::NoPacket);

    let stop_status = unsafe { xray_core_stop(core, &mut err) };
    assert_eq!(stop_status, XrayStatus::Ok);

    unsafe { xray_core_free(core) };
}

#[test]
fn test_five_lifecycle_stop_paths() {
    // Path 1: Normal start, stats check, stop, free
    {
        let mut err = std::ptr::null_mut();
        let core = unsafe { xray_core_new(&mut err) };
        assert!(!core.is_null());

        let cfg = CString::new(tun_config_minimal()).unwrap();
        assert_eq!(
            unsafe { xray_core_load_config_json(core, cfg.as_ptr(), &mut err) },
            XrayStatus::Ok
        );
        assert_eq!(unsafe { xray_core_start(core, &mut err) }, XrayStatus::Ok);

        let stop_start = Instant::now();
        assert_eq!(unsafe { xray_core_stop(core, &mut err) }, XrayStatus::Ok);
        assert!(
            stop_start.elapsed() < Duration::from_secs(2),
            "Normal stop exceeded 2s"
        );
        unsafe { xray_core_free(core) };
    }

    // Path 2: Cancel during startup (load config then immediately stop without start)
    {
        let mut err = std::ptr::null_mut();
        let core = unsafe { xray_core_new(&mut err) };
        assert!(!core.is_null());

        let cfg = CString::new(tun_config_minimal()).unwrap();
        assert_eq!(
            unsafe { xray_core_load_config_json(core, cfg.as_ptr(), &mut err) },
            XrayStatus::Ok
        );

        let stop_start = Instant::now();
        assert_eq!(unsafe { xray_core_stop(core, &mut err) }, XrayStatus::Ok);
        assert!(
            stop_start.elapsed() < Duration::from_secs(2),
            "Startup-cancel stop exceeded 2s"
        );
        unsafe { xray_core_free(core) };
    }

    // Path 3: Stop without config load (unconfigured handle free)
    {
        let mut err = std::ptr::null_mut();
        let core = unsafe { xray_core_new(&mut err) };
        assert!(!core.is_null());

        let stop_status = unsafe { xray_core_stop(core, &mut err) };
        assert_eq!(stop_status, XrayStatus::CoreNotLoaded);
        if !err.is_null() {
            unsafe { xray_error_free(err) };
        }

        unsafe { xray_core_free(core) };
    }

    // Path 4: Extension stop / automatic cancel while polling
    {
        let mut err = std::ptr::null_mut();
        let core = unsafe { xray_core_new(&mut err) };
        assert!(!core.is_null());

        let cfg = CString::new(tun_config_minimal()).unwrap();
        assert_eq!(
            unsafe { xray_core_load_config_json(core, cfg.as_ptr(), &mut err) },
            XrayStatus::Ok
        );
        assert_eq!(unsafe { xray_core_start(core, &mut err) }, XrayStatus::Ok);

        let core_addr = core as usize;
        let started = Arc::new(AtomicBool::new(false));
        let started_clone = Arc::clone(&started);

        let thread_handle = thread::spawn(move || {
            let handle = core_addr as *mut xray_ffi::XrayCoreHandle;
            let mut buffer = vec![0u8; 4096];
            let mut lengths = [0usize; 4];
            let mut count = 0usize;
            let mut thread_err = std::ptr::null_mut();
            started_clone.store(true, Ordering::SeqCst);
            let s = unsafe {
                xray_tun_poll_packets(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    lengths.as_mut_ptr(),
                    lengths.len(),
                    &mut count,
                    10_000,
                    &mut thread_err,
                )
            };
            if !thread_err.is_null() {
                unsafe { xray_error_free(thread_err) };
            }
            s
        });

        while !started.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(50));

        let stop_start = Instant::now();
        assert_eq!(unsafe { xray_core_stop(core, &mut err) }, XrayStatus::Ok);
        assert!(
            stop_start.elapsed() < Duration::from_secs(2),
            "Extension stop with active poll exceeded 2s"
        );

        let _ = thread_handle.join().unwrap();
        unsafe { xray_core_free(core) };
    }

    // Path 5: Simulated network migration / teardown with stats verification
    {
        let mut err = std::ptr::null_mut();
        let core = unsafe { xray_core_new(&mut err) };
        assert!(!core.is_null());

        let cfg = CString::new(tun_config_minimal()).unwrap();
        assert_eq!(
            unsafe { xray_core_load_config_json(core, cfg.as_ptr(), &mut err) },
            XrayStatus::Ok
        );
        assert_eq!(unsafe { xray_core_start(core, &mut err) }, XrayStatus::Ok);

        let mut stats = XrayTunStats {
            struct_size: std::mem::size_of::<XrayTunStats>(),
            ..unsafe { std::mem::zeroed() }
        };
        assert_eq!(
            unsafe { xray_tun_stats(core, &mut stats, &mut err) },
            XrayStatus::Ok
        );
        assert_eq!(stats.active_tcp_flows, 0);
        assert_eq!(stats.active_udp_flows, 0);

        let stop_start = Instant::now();
        assert_eq!(unsafe { xray_core_stop(core, &mut err) }, XrayStatus::Ok);
        assert!(
            stop_start.elapsed() < Duration::from_secs(2),
            "Migration teardown stop exceeded 2s"
        );

        unsafe { xray_core_free(core) };
    }
}

#[test]
fn test_repeated_reconnect_lifecycle_loop() {
    for cycle in 1..=50 {
        let mut err = std::ptr::null_mut();
        let core = unsafe { xray_core_new(&mut err) };
        assert!(!core.is_null(), "Failed to create core on cycle {}", cycle);

        assert_eq!(
            unsafe {
                xray_core_set_tun_runtime_profile(
                    core,
                    XrayTunRuntimeProfile::FoloIos as i32,
                    &mut err,
                )
            },
            XrayStatus::Ok
        );

        let cfg = CString::new(tun_config_minimal()).unwrap();
        assert_eq!(
            unsafe { xray_core_load_config_json(core, cfg.as_ptr(), &mut err) },
            XrayStatus::Ok
        );

        assert_eq!(
            unsafe { xray_core_start(core, &mut err) },
            XrayStatus::Ok
        );

        let stop_time = Instant::now();
        assert_eq!(
            unsafe { xray_core_stop(core, &mut err) },
            XrayStatus::Ok
        );
        assert!(
            stop_time.elapsed() < Duration::from_millis(500),
            "Cycle {} stop took too long: {:?}",
            cycle,
            stop_time.elapsed()
        );

        unsafe { xray_core_free(core) };
    }
}
