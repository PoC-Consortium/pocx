// Copyright (c) 2025 Proof of Capacity Consortium
//
// Integration tests for pocx_miner

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Once;

    static INIT: Once = Once::new();

    /// Build the miner binary once and return its path
    fn get_miner_binary() -> PathBuf {
        INIT.call_once(|| {
            // Build the binary once for all tests
            let output = Command::new("cargo")
                .args(["build", "--bin", "pocx_miner"])
                .current_dir("../")
                .output()
                .expect("Failed to build pocx_miner");

            assert!(
                output.status.success(),
                "Failed to build pocx_miner: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        });

        // Return path to the built binary
        PathBuf::from("../target/debug/pocx_miner")
    }

    #[test]
    fn test_miner_invalid_arguments() {
        let binary = get_miner_binary();
        let output = Command::new(&binary)
            .arg("--invalid-flag")
            .output()
            .expect("Failed to execute pocx_miner with invalid args");

        // Should fail with exit code != 0 when invalid arguments provided
        assert!(
            !output.status.success(),
            "Should fail when invalid arguments provided"
        );
    }
}
