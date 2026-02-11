#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::bool_comparison)]

// Copyright (c) 2025 Proof of Capacity Consortium
//
// Integration tests for pocx_verifier

#[cfg(test)]
mod tests {
    use std::process::Command;

    #[test]
    fn test_concurrent_verification_safety() {
        // Test that multiple verifier instances can run concurrently
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        let success_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        // Run multiple help commands concurrently
        for _ in 0..3 {
            let success_count = Arc::clone(&success_count);
            let handle = thread::spawn(move || {
                let output = Command::new("cargo")
                    .args(&["run", "--bin", "pocx_verifier", "--", "--help"])
                    .current_dir("../")
                    .output()
                    .expect("Failed to execute pocx_verifier");

                if output.status.success() {
                    success_count.fetch_add(1, Ordering::SeqCst);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // All should succeed
        assert_eq!(
            success_count.load(Ordering::SeqCst),
            3,
            "All concurrent runs should succeed"
        );
    }
}
