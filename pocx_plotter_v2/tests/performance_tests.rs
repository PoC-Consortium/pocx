#![allow(clippy::manual_range_contains)]
#![allow(clippy::identity_op)]
#![allow(clippy::needless_range_loop)]

// Copyright (c) 2025 Proof of Capacity Consortium
// MIT License

use pocx_plotter_v2::PageAlignedByteBuffer;
use std::time::Instant;

#[test]
fn test_buffer_allocation_performance() {
    let sizes = [4096, 65536, 1048576, 4194304];
    let mut allocation_times = Vec::new();

    for &size in &sizes {
        let start = Instant::now();
        let buffer = PageAlignedByteBuffer::new(size).expect("Buffer allocation failed");
        let allocation_time = start.elapsed();

        allocation_times.push((size, allocation_time));

        let data = buffer.get_buffer();
        let guard = data.lock().unwrap();
        assert_eq!(guard.len(), size);

        let ptr = guard.as_ptr() as usize;
        let page_size = page_size::get();
        assert_eq!(ptr % page_size, 0, "Buffer should be page-aligned");

        println!(
            "Buffer {}KB: allocated in {:?}",
            size / 1024,
            allocation_time
        );
    }

    for i in 1..allocation_times.len() {
        let (prev_size, prev_time) = allocation_times[i - 1];
        let (curr_size, curr_time) = allocation_times[i];

        let size_ratio = curr_size as f64 / prev_size as f64;
        let time_ratio = curr_time.as_nanos() as f64 / prev_time.as_nanos() as f64;

        assert!(
            time_ratio < size_ratio * 50.0,
            "Allocation time growth is excessive: {}x size -> {}x time",
            size_ratio,
            time_ratio
        );
    }
}

#[test]
fn test_plotting_components_performance() {
    let mut test_bytes = [0u8; 25];
    test_bytes[0] = 0x55;
    for i in 1..25 {
        test_bytes[i] = ((i * 13) % 256) as u8;
    }

    let start = Instant::now();
    let payload = &test_bytes[1..21];
    let mut payload_array = [0u8; 20];
    payload_array.copy_from_slice(payload);
    let network_id = pocx_address::NetworkId::Base58(test_bytes[0]);
    let encoded = pocx_address::encode_address(&payload_array, network_id).unwrap();
    let (decoded_payload, decoded_network) = pocx_address::decode_address(&encoded).unwrap();
    let id_time = start.elapsed();

    assert_eq!(decoded_payload, payload_array);
    if let pocx_address::NetworkId::Base58(version) = decoded_network {
        assert_eq!(version, test_bytes[0]);
    }
    println!("PoC address validation: {:?}", id_time);

    let start = Instant::now();
    let warps = 1u64;
    let escalate = 1u64;

    let warps_valid = warps <= 1_000_000;
    let escalate_valid = escalate >= 1 && escalate <= 64;

    let mem_calc = if warps_valid && escalate_valid {
        (4096u64)
            .checked_mul(escalate)
            .and_then(|v| v.checked_mul(warps))
    } else {
        None
    };

    let param_time = start.elapsed();
    assert!(mem_calc.is_some());
    println!("Parameter validation: {:?}", param_time);

    let total_component_time = id_time + param_time;
    assert!(
        total_component_time.as_millis() < 100,
        "Core components taking too long: {:?}",
        total_component_time
    );
}

#[test]
fn test_parameter_validation_performance() {
    let test_cases = vec![
        (100_000u64, 8u64, true),
        (1_500_000u64, 8u64, false),
        (500_000u64, 0u64, false),
        (500_000u64, 8u64, true),
    ];

    let mut total_validation_time = std::time::Duration::new(0, 0);

    let test_cases_len = test_cases.len();
    for (warps, escalate, should_be_valid) in test_cases {
        let start = Instant::now();

        let warps_valid = warps <= 1_000_000;
        let escalate_valid = escalate >= 1 && escalate <= 64;

        let overall_valid = warps_valid && escalate_valid;

        let validation_time = start.elapsed();
        total_validation_time += validation_time;

        assert_eq!(overall_valid, should_be_valid);
    }

    println!(
        "Parameter validation performance: {:?} total for {} cases",
        total_validation_time, test_cases_len
    );

    assert!(
        total_validation_time.as_millis() < 10,
        "Parameter validation taking too long: {:?}",
        total_validation_time
    );
}

#[test]
fn test_memory_access_patterns() {
    let buffer_size = 4 * 1024 * 1024;
    let buffer = PageAlignedByteBuffer::new(buffer_size).expect("Buffer allocation failed");
    let data = buffer.get_buffer();
    let mut guard = data.lock().unwrap();

    let start = Instant::now();
    for i in 0..guard.len() {
        guard[i] = (i % 256) as u8;
    }
    let sequential_time = start.elapsed();

    let start = Instant::now();
    let stride = 4096;
    for i in (0..guard.len()).step_by(stride) {
        guard[i] = ((i / stride) % 256) as u8;
    }
    let strided_time = start.elapsed();

    println!(
        "Sequential access ({}MB): {:?}",
        buffer_size / 1024 / 1024,
        sequential_time
    );
    println!(
        "Strided access ({}MB, {}B stride): {:?}",
        buffer_size / 1024 / 1024,
        stride,
        strided_time
    );

    let ratio = strided_time.as_nanos() as f64 / sequential_time.as_nanos() as f64;
    assert!(ratio > 0.0001);
    assert!(ratio < 1000.0);
}

#[test]
fn test_crypto_consistency() {
    let test_ids = [[0x55u8; 25], [0x7Fu8; 25]];

    for test_id in &test_ids {
        let payload = &test_id[1..21];
        let mut payload_array = [0u8; 20];
        payload_array.copy_from_slice(payload);
        let network_id = test_id[0];

        let network_id_enum = pocx_address::NetworkId::Base58(network_id);
        let encoded1 =
            pocx_address::encode_address(&payload_array, network_id_enum.clone()).unwrap();
        let encoded2 =
            pocx_address::encode_address(&payload_array, network_id_enum.clone()).unwrap();
        assert_eq!(encoded1, encoded2);

        let (decoded_payload1, decoded_network1) = pocx_address::decode_address(&encoded1).unwrap();
        let (decoded_payload2, _decoded_network2) =
            pocx_address::decode_address(&encoded2).unwrap();
        assert_eq!(decoded_payload1, decoded_payload2);
        assert_eq!(decoded_payload1, payload_array);
        assert_eq!(decoded_network1, network_id_enum);
    }

    let test_seeds = [[0x00u8; 32], [0xFFu8; 32], [0x55u8; 32]];

    for test_seed in &test_seeds {
        let hex1 = hex::encode(test_seed);
        let hex2 = hex::encode(test_seed);
        assert_eq!(hex1, hex2);
        assert_eq!(hex1.len(), 64);

        let decoded1 = hex::decode(&hex1).unwrap();
        let decoded2 = hex::decode(&hex2).unwrap();
        assert_eq!(decoded1, decoded2);
        assert_eq!(decoded1, test_seed.to_vec());
    }
}

#[test]
#[ignore]
fn test_performance_scaling() {
    let sizes = [1024, 2048, 4096, 8192];
    let mut times = Vec::new();

    for &size in &sizes {
        let start = Instant::now();
        let buffer = PageAlignedByteBuffer::new(size).unwrap();
        let data = buffer.get_buffer();
        let mut guard = data.lock().unwrap();

        for i in 0..size {
            guard[i] = (i % 256) as u8;
        }

        let time = start.elapsed();
        times.push((size, time));
    }

    for i in 1..times.len() {
        let (prev_size, prev_time) = times[i - 1];
        let (curr_size, curr_time) = times[i];

        let size_ratio = curr_size as f64 / prev_size as f64;
        let time_ratio = curr_time.as_nanos() as f64 / prev_time.as_nanos() as f64;

        assert!(
            time_ratio < size_ratio * 5.0,
            "Performance scaling too poor: {}x size led to {}x time",
            size_ratio,
            time_ratio
        );
    }
}

#[cfg(feature = "opencl")]
#[test]
fn test_ring_size_computation_performance() {
    use pocx_plotter_v2::ocl::compute_ring_size;

    let start = Instant::now();
    for worksize in (256..32768).step_by(256) {
        let ring_size = compute_ring_size(worksize);
        assert!(ring_size >= worksize);
        assert!(ring_size >= 8192);
    }
    let elapsed = start.elapsed();
    println!("Ring size computation for 128 worksizes: {:?}", elapsed);
    assert!(elapsed.as_millis() < 10);
}
