// Copyright (c) 2025 Proof of Capacity Consortium
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use indicatif::{ProgressBar, ProgressStyle};
use pocx_plotfile::{AccessType, PoCXPlotFile, NUM_SCOOPS};
use rand::rngs::SmallRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use std::path::Path;

pub fn plotcheck(matches: &clap::ArgMatches) {
    println!("PoCX Verifier {}", env!("CARGO_PKG_VERSION"));
    println!("written by PoCX developers in Rust\n");
    let filename = matches
        .get_one::<String>("file")
        .expect("ERROR: Plot file argument is required")
        .clone();

    // load plotfile
    let plotfile = PoCXPlotFile::open(Path::new(&filename), AccessType::Read, false)
        .unwrap_or_else(|e| {
            eprintln!("ERROR: Cannot open plot file '{}': {}", filename, e);
            std::process::exit(1);
        });

    // display plotfile info
    println!("Filename      : {}", plotfile.meta.filename);
    println!("PoC account   : {}", plotfile.meta.base58);
    println!(
        "Seed          : {}",
        &hex::encode_upper(plotfile.meta.seed_decoded)
    );
    println!("Warps         : {}", plotfile.meta.number_of_warps);
    println!("Compression   : X{}\n", plotfile.meta.compression);

    let mode = matches
        .get_one::<String>("mode")
        .expect("ERROR: Mode argument is required")
        .clone();
    match mode.as_str() {
        "single" => single(matches, plotfile),
        "partial" => partial(plotfile),
        "random" => random(plotfile),
        "complete" => complete(plotfile),
        _ => (),
    }
}

fn single(matches: &clap::ArgMatches, mut plotfile: PoCXPlotFile) {
    println!("Mode          : SINGLE");

    let nonce = matches.get_one::<u64>("nonce").copied().unwrap_or(0);
    let scoop = matches.get_one::<u64>("scoop").copied().unwrap_or(0);
    let base_target = matches
        .get_one::<u64>("base_target")
        .copied()
        .unwrap_or(2u64.pow(42) / 120);

    let generation_signature_hex = matches
        .get_one::<String>("generation_signature")
        .expect("generation_signature is required for single mode");

    let generation_signature = hex::decode(generation_signature_hex).unwrap_or_else(|e| {
        eprintln!("ERROR: Invalid generation signature hex: {}", e);
        std::process::exit(1);
    });

    if generation_signature.len() != 32 {
        eprintln!("ERROR: Generation signature must be exactly 32 bytes (64 hex characters)");
        std::process::exit(1);
    }

    let mut generation_signature_bytes = [0u8; 32];
    generation_signature_bytes.copy_from_slice(&generation_signature);

    if !(0..NUM_SCOOPS).contains(&scoop) {
        eprintln!(
            "ERROR: Invalid scoop value {}. Valid range: 0..{}",
            scoop,
            NUM_SCOOPS - 1
        );
        std::process::exit(1);
    }

    let warp = nonce / NUM_SCOOPS;
    let nonce_in_warp = nonce % NUM_SCOOPS;

    // get hash from plotfile
    let hash = plotfile.read_nonce(scoop, nonce).unwrap_or_else(|e| {
        eprintln!(
            "ERROR: Failed to read nonce {} at scoop {}: {}",
            nonce, scoop, e
        );
        std::process::exit(1);
    });

    // calc hash to verify
    let hash_ref = pocx_hashlib::generate_scoop(
        &plotfile.meta.base58_decoded,
        &plotfile.meta.seed_decoded,
        scoop,
        nonce,
        plotfile.meta.compression as u8,
    )
    .unwrap_or_else(|e| {
        eprintln!("ERROR: Failed to generate reference scoop: {}", e);
        std::process::exit(1);
    });

    let quality = pocx_hashlib::find_best_quality(&hash, 1, &generation_signature_bytes).0;

    println!(
        "\rTarget        : nonce = {}, warp = {}, nonce_in_warp = {}, scoop = {}",
        nonce, warp, nonce_in_warp, scoop
    );
    println!("\rPlotfile data : {}", &hex::encode(hash));
    println!("\rReference data: {}\n", &hex::encode(hash_ref));

    println!(
        "gen_signature : {}",
        hex::encode(generation_signature_bytes)
    );
    println!("quality_raw   : {}", quality);
    println!("base_target   : {}", base_target);
    println!("quality_adj   : {}", quality / base_target);

    if hash != hash_ref {
        eprintln!("\nERROR: Verification FAILED!");
        eprintln!("The plot file data does not match the expected hash.");
        std::process::exit(1);
    }
    println!("\nVerification PASSED!");
}

fn partial(mut plotfile: PoCXPlotFile) {
    println!("Mode          : PARTIAL");
    println!("Press CTRL+C to stop...");

    // each file is checked with the same paths
    let mut rng: SmallRng = SeedableRng::from_seed(plotfile.meta.seed_decoded);

    let mut scoops: Vec<u64> = (0..NUM_SCOOPS).collect();
    let mut nonces_in_warp: Vec<u64> = (0..NUM_SCOOPS).collect();

    scoops.shuffle(&mut rng);
    nonces_in_warp.shuffle(&mut rng);

    let pb = ProgressBar::new(4096);
    pb.set_style(
        ProgressStyle::with_template(
            "Checking: {pos:>4}/{len:4} │{bar:80}│ {percent:>3}% {per_sec:>6} {eta}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("█▓▒░ "),
    );

    for i in 0..NUM_SCOOPS as usize {
        let scoop = scoops[i];
        let nonce_in_warp = nonces_in_warp[i];
        let warp = rng.random_range(0..plotfile.meta.number_of_warps);

        // get hash from plotfile
        let nonce = warp * 4096 + nonce_in_warp;
        let hash = plotfile.read_nonce(scoop, nonce).unwrap_or_else(|e| {
            eprintln!("ERROR: Failed to read plotfile: {}", e);
            std::process::exit(1);
        });

        // calc hash to verify
        let hash_ref = pocx_hashlib::generate_scoop(
            &plotfile.meta.base58_decoded,
            &plotfile.meta.seed_decoded,
            scoop,
            nonce,
            plotfile.meta.compression as u8,
        )
        .unwrap_or_else(|e| {
            eprintln!("ERROR: Failed to generate reference scoop: {}", e);
            std::process::exit(1);
        });

        if hash != hash_ref {
            println!(
                "\rTarget         : warp = {}, nonce_in_warp = {}, scoop = {}",
                warp, scoop, nonce_in_warp
            );
            println!("\rPlotfile data  : {}", &hex::encode(hash));
            println!("\rReference data : {}\n", &hex::encode(hash_ref));
        }

        if hash != hash_ref {
            eprintln!("\nERROR: Verification FAILED!");
            eprintln!("Plot file data does not match expected hash.");
            std::process::exit(1);
        }
        pb.inc(1);
    }
    pb.finish_with_message("All checks passed.");
}

fn random(mut plotfile: PoCXPlotFile) {
    println!("Mode          : RANDOM");
    println!("Press CTRL+C to stop...");
    loop {
        let scoop = rand::rng().random_range(0..4096);
        let warp = rand::rng().random_range(0..plotfile.meta.number_of_warps);
        let nonce_in_warp = rand::rng().random_range(0..NUM_SCOOPS);

        // get hash from plotfile
        let nonce = warp * 4096 + nonce_in_warp;
        let hash = plotfile.read_nonce(scoop, nonce).unwrap_or_else(|e| {
            eprintln!("ERROR: Failed to read plotfile: {}", e);
            std::process::exit(1);
        });

        // calc hash to verify
        let hash_ref = pocx_hashlib::generate_scoop(
            &plotfile.meta.base58_decoded,
            &plotfile.meta.seed_decoded,
            scoop,
            nonce,
            plotfile.meta.compression as u8,
        )
        .unwrap_or_else(|e| {
            eprintln!("ERROR: Failed to generate reference scoop: {}", e);
            std::process::exit(1);
        });

        if hash != hash_ref {
            println!(
                "\rTarget         : warp = {}, nonce_in_warp = {}, scoop = {}",
                warp, scoop, nonce_in_warp
            );
            println!("\rPlotfile data  : {}", &hex::encode(hash));
            println!("\rReference data : {}\n", &hex::encode(hash_ref));
        }

        if hash != hash_ref {
            eprintln!("\nERROR: Verification FAILED!");
            eprintln!("Plot file data does not match expected hash.");
            std::process::exit(1);
        }
    }
}

fn complete(mut plotfile: PoCXPlotFile) {
    println!("Mode          : Complete");
    println!("Press CTRL+C to stop...");
    let pb = ProgressBar::new(plotfile.meta.number_of_warps * NUM_SCOOPS * NUM_SCOOPS);
    pb.set_style(
        ProgressStyle::with_template(
            "Checking: {pos:>8}/{len:8} │{bar:80}│ {percent:>3}% {per_sec:>6} {eta}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("█▓▒░ "),
    );

    for scoop in 0..NUM_SCOOPS {
        for warp in 0..plotfile.meta.number_of_warps {
            for nonce_in_warp in 0..NUM_SCOOPS {
                // get hash from plotfile
                let nonce = warp * NUM_SCOOPS + nonce_in_warp;
                let hash = plotfile.read_nonce(scoop, nonce).unwrap_or_else(|e| {
                    eprintln!("ERROR: Failed to read plotfile: {}", e);
                    std::process::exit(1);
                });

                // calc hash to verify
                let hash_ref = pocx_hashlib::generate_scoop(
                    &plotfile.meta.base58_decoded,
                    &plotfile.meta.seed_decoded,
                    scoop,
                    nonce,
                    plotfile.meta.compression as u8,
                )
                .unwrap_or_else(|e| {
                    eprintln!("ERROR: Failed to generate reference scoop: {}", e);
                    std::process::exit(1);
                });

                if hash != hash_ref {
                    println!(
                        "\rTarget         : warp = {}, nonce_in_warp = {}, scoop = {}",
                        warp, scoop, nonce_in_warp
                    );
                    println!("\rPlotfile data  : {}", &hex::encode(hash));
                    println!("\rReference data : {}\n", &hex::encode(hash_ref));
                }

                if hash != hash_ref {
                    eprintln!("\nERROR: Verification FAILED!");
                    eprintln!("Plot file data does not match expected hash.");
                    std::process::exit(1);
                }
                pb.inc(1);
            }
        }
    }
    pb.finish_with_message("All checks passed.");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use clap::ArgMatches;
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};
    #[allow(unused_imports)]
    use std::collections::HashMap;

    #[test]
    fn test_version_display() {
        // Test that version info is accessible
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());

        // Test version format (should be semantic version)
        let version_parts: Vec<&str> = version.split('.').collect();
        assert!(version_parts.len() >= 2); // At least major.minor
    }

    #[test]
    fn test_scoop_validation() {
        // Test scoop range validation logic
        let valid_scoops = [0, 1, 100, 2000, 4095];
        let invalid_scoops = [4096, 4097, 10000, u64::MAX];

        for scoop in &valid_scoops {
            assert!(
                (0..NUM_SCOOPS).contains(scoop),
                "Scoop {} should be valid (range: 0..{})",
                scoop,
                NUM_SCOOPS - 1
            );
        }

        for scoop in &invalid_scoops {
            assert!(
                !(0..NUM_SCOOPS).contains(scoop),
                "Scoop {} should be invalid (range: 0..{})",
                scoop,
                NUM_SCOOPS - 1
            );
        }
    }

    #[test]
    fn test_nonce_calculations() {
        // Test warp and nonce_in_warp calculations
        let test_cases = [
            (0u64, 0u64, 0u64),       // nonce=0: warp=0, nonce_in_warp=0
            (4095u64, 0u64, 4095u64), // nonce=4095: warp=0, nonce_in_warp=4095
            (4096u64, 1u64, 0u64),    // nonce=4096: warp=1, nonce_in_warp=0
            (8191u64, 1u64, 4095u64), // nonce=8191: warp=1, nonce_in_warp=4095
            (8192u64, 2u64, 0u64),    // nonce=8192: warp=2, nonce_in_warp=0
        ];

        for (nonce, expected_warp, expected_nonce_in_warp) in &test_cases {
            let warp = nonce / NUM_SCOOPS;
            let nonce_in_warp = nonce % NUM_SCOOPS;

            assert_eq!(
                warp, *expected_warp,
                "Warp calculation failed for nonce {}",
                nonce
            );
            assert_eq!(
                nonce_in_warp, *expected_nonce_in_warp,
                "Nonce_in_warp calculation failed for nonce {}",
                nonce
            );

            // Verify reverse calculation
            let reconstructed_nonce = warp * NUM_SCOOPS + nonce_in_warp;
            assert_eq!(
                reconstructed_nonce, *nonce,
                "Reverse nonce calculation failed"
            );
        }
    }

    #[test]
    fn test_base_target_default() {
        // Test default base target calculation
        let default_base_target = 2u64.pow(42) / 120;
        let expected = 4398046511104u64 / 120; // 2^42 = 4398046511104
        assert_eq!(default_base_target, expected);

        // Test that it's a reasonable value (not zero, not too large)
        assert!(default_base_target > 0);
        assert!(default_base_target < u64::MAX / 1000); // Should be much
                                                        // smaller than max
    }

    #[test]
    fn test_quality_calculation() {
        // Test quality calculation doesn't panic with various inputs
        let test_hash = [0u8; 64]; // All zeros hash
        let generation_signature = [0u8; 32];

        let quality = pocx_hashlib::find_best_quality(&test_hash, 1, &generation_signature).0;

        // Quality is u64, so it's always >= 0 by definition
        // Just verify we got a value
        let _ = quality;

        // Test with different hash values
        let max_hash = [0xFFu8; 64];
        let max_quality = pocx_hashlib::find_best_quality(&max_hash, 1, &generation_signature).0;
        // max_quality is u64, so it's always >= 0 by definition
        let _ = max_quality;
    }

    #[test]
    fn test_hex_encoding() {
        // Test hex encoding functionality used in output
        let test_data = [0x12, 0x34, 0xAB, 0xCD];
        let hex_lower = hex::encode(test_data);
        let hex_upper = hex::encode_upper(test_data);

        assert_eq!(hex_lower, "1234abcd");
        assert_eq!(hex_upper, "1234ABCD");

        // Test with zero data
        let zero_data = [0x00, 0x00];
        assert_eq!(hex::encode(zero_data), "0000");

        // Test with max data
        let max_data = [0xFF, 0xFF];
        assert_eq!(hex::encode_upper(max_data), "FFFF");
    }

    #[test]
    fn test_random_number_generation() {
        // Test that random number generation works as expected
        let seed = [0u8; 32];
        let mut rng: SmallRng = SeedableRng::from_seed(seed);

        // Generate some random numbers
        let random1 = rng.random_range(0..100u64);
        let random2 = rng.random_range(0..100u64);

        // Reset with same seed should produce same sequence
        let mut rng2: SmallRng = SeedableRng::from_seed(seed);
        let random1_repeat = rng2.random_range(0..100u64);
        let random2_repeat = rng2.random_range(0..100u64);

        assert_eq!(random1, random1_repeat);
        assert_eq!(random2, random2_repeat);

        // Values should be in range
        assert!(random1 < 100);
        assert!(random2 < 100);
    }

    #[test]
    fn test_vector_shuffling() {
        // Test that vector shuffling works
        let mut original_scoops: Vec<u64> = (0..10).collect();
        let seed = [1u8; 32];
        let mut rng: SmallRng = SeedableRng::from_seed(seed);

        let original_copy = original_scoops.clone();
        original_scoops.shuffle(&mut rng);

        // After shuffling, should contain same elements but potentially different order
        assert_eq!(original_scoops.len(), original_copy.len());

        // All original elements should still be present
        for element in &original_copy {
            assert!(original_scoops.contains(element));
        }
    }

    #[test]
    fn test_progress_bar_creation() {
        // Test progress bar creation doesn't panic
        let pb = ProgressBar::new(100);

        // Test setting style doesn't panic
        let style_result =
            ProgressStyle::with_template("Test: {pos:>4}/{len:4} │{bar:40}│ {percent:>3}%");
        assert!(style_result.is_ok());

        if let Ok(style) = style_result {
            pb.set_style(style.progress_chars("█▓▒░ "));
        }

        // Test progress operations
        pb.inc(1);
        pb.set_position(50);
        pb.finish();
    }

    #[test]
    fn test_mode_string_matching() {
        // Test that mode strings are handled correctly
        let valid_modes = ["single", "partial", "random", "complete"];

        for mode in &valid_modes {
            match mode {
                &"single" | &"partial" | &"random" | &"complete" => {
                    // Valid mode recognized
                }
                _ => {
                    panic!("Mode {} should be recognized", mode);
                }
            }
        }

        // Test invalid mode
        let invalid_mode = "invalid";
        match invalid_mode {
            "single" | "partial" | "random" | "complete" => {
                panic!("Invalid mode should not match");
            }
            _ => {
                // Expected: invalid mode doesn't match
            }
        }
    }
}
