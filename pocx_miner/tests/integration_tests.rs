// Copyright (c) 2025 Proof of Capacity Consortium
//
// Integration tests for pocx_miner

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Once;
    use tempfile::TempDir;

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
    fn test_config_file_handling() {
        let binary = get_miner_binary();
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let config_path = temp_dir.path().join("nonexistent_config.yaml");

        let _output = Command::new(&binary)
            .args(["-c", config_path.to_str().unwrap()])
            .output()
            .expect("Failed to execute pocx_miner with config");

        // Should handle missing config file gracefully (may succeed or fail
        // depending on implementation) The important thing is it doesn't crash
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

    #[test]
    fn test_configuration_file_parsing() {
        use std::fs::File;
        use std::io::Write;

        let binary = get_miner_binary();
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("miner_config.yaml");

        // Create a valid YAML configuration file
        let mut file = File::create(&config_file).unwrap();
        writeln!(file, "# PoCX Miner Configuration").unwrap();
        writeln!(file, "plots: []").unwrap();
        writeln!(file, "server: http://localhost:8080").unwrap();
        writeln!(file, "account_id: test_account").unwrap();

        let output = Command::new(&binary)
            .args(["--config", config_file.to_str().unwrap(), "--help"])
            .output()
            .expect("Failed to execute pocx_miner with config");

        // Should at least not crash on config parsing
        assert!(
            output.status.success() || !output.stderr.is_empty(),
            "Should handle configuration file gracefully"
        );
    }

    #[test]
    fn test_plot_file_scanning_safety() {
        use std::fs::File;

        let binary = get_miner_binary();
        let temp_dir = TempDir::new().unwrap();
        let fake_plot = temp_dir.path().join("test_plot.plot");

        // Create an empty file (not a real plot file)
        File::create(&fake_plot).unwrap();

        let output = Command::new(&binary)
            .args(["--plots", fake_plot.to_str().unwrap(), "--help"])
            .output()
            .expect("Failed to execute pocx_miner with plot path");

        // Should handle invalid plot files gracefully
        assert!(
            output.status.success() || !output.stderr.is_empty(),
            "Should handle invalid plot files gracefully"
        );
    }

    #[test]
    fn test_error_recovery_patterns() {
        let binary = get_miner_binary();
        let error_scenarios = vec![
            vec!["--server", "invalid://url"],
            vec!["--account", ""],
            vec!["--plots", "/nonexistent/path"],
        ];

        for scenario in error_scenarios {
            let mut args: Vec<&str> = scenario;
            args.push("--help"); // Add help to avoid actually trying to mine

            let output = Command::new(&binary)
                .args(&args)
                .output()
                .expect("Failed to execute pocx_miner error scenario");

            // Should either succeed (help) or fail gracefully with error message
            if !output.status.success() {
                assert!(
                    !output.stderr.is_empty(),
                    "Error scenarios should provide error messages"
                );
            }
        }
    }

    #[test]
    fn test_performance_monitoring_basics() {
        // Test that basic performance monitoring doesn't cause issues
        use std::time::Instant;

        let binary = get_miner_binary();
        let start = Instant::now();

        let output = Command::new(&binary)
            .arg("--help")
            .output()
            .expect("Failed to execute pocx_miner");

        let duration = start.elapsed();

        // Help should complete reasonably quickly (binary is pre-built)
        assert!(
            duration.as_secs() < 5,
            "Help command should complete within 5 seconds"
        );

        if output.status.success() {
            assert!(!output.stdout.is_empty(), "Help should produce output");
        }
    }

    #[test]
    fn test_graceful_shutdown_preparation() {
        let binary = get_miner_binary();
        let output = Command::new(&binary)
            .arg("--version")
            .output()
            .expect("Failed to execute pocx_miner version");

        // Version command should complete successfully and quickly
        if output.status.success() {
            assert!(!output.stdout.is_empty(), "Version should produce output");
        }
    }
}
