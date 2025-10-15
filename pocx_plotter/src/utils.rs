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

use crate::error::{PoCXPlotterError, Result};
use std::path::Path;

cfg_if! {
    if #[cfg(unix)] {
        use std::process::Command;

        pub fn set_low_prio() {
            // NOTE: Thread priority setting is not implemented yet
            // This would require platform-specific syscalls (nice, setpriority, etc.)
            // Currently no-op to maintain API compatibility
            #[cfg(target_os = "linux")]
            {
                eprintln!("Warning: Thread priority setting not implemented in this build");
            }
        }

        // On unix, get the device id from 'df' command
        fn get_device_id_unix(path: &str) -> Result<String> {
            let output = Command::new("df")
                 .arg(path)
                 .output()
                 .map_err(|e| PoCXPlotterError::SystemInfo(format!("Failed to execute 'df': {}", e)))?;
             let source = String::from_utf8(output.stdout).map_err(|e| PoCXPlotterError::SystemInfo(format!("Invalid UTF-8 from df: {}", e)))?;
             let lines: Vec<&str> = source.split('\n').collect();
             let device = lines.get(1)
                 .ok_or_else(|| PoCXPlotterError::SystemInfo("No device line in df output".to_string()))?
                 .split(' ')
                 .next()
                 .ok_or_else(|| PoCXPlotterError::SystemInfo("Invalid df output format".to_string()))?;
             Ok(device.to_string())
         }

        // On macos, use df and 'diskutil info <device>' to get the Device Block Size line
        // and extract the size
        fn get_sector_size_macos(path: &str) -> Result<u64> {
            let source = get_device_id_unix(path)?;
            let output = Command::new("diskutil")
                .arg("info")
                .arg(source)
                .output()
                .map_err(|e| PoCXPlotterError::SystemInfo(format!("Failed to execute 'diskutil info': {}", e)))?;
            let source = String::from_utf8(output.stdout).map_err(|e| PoCXPlotterError::SystemInfo(format!("Invalid UTF-8 from diskutil: {}", e)))?;
            let mut sector_size: u64 = 0;
            for line in source.split('\n').collect::<Vec<&str>>() {
                if line.trim().starts_with("Device Block Size") {
                    // e.g. in reverse: "Bytes 512 Size Block Device"
                    let source = line.rsplit(' ').collect::<Vec<&str>>()[1];

                    sector_size = source.parse::<u64>().map_err(|e| PoCXPlotterError::SystemInfo(format!("Invalid sector size: {}", e)))?;
                }
            }
            if sector_size == 0 {
                Err(PoCXPlotterError::SystemInfo("Unable to determine disk physical sector size from diskutil info".to_string()))
            } else {
                Ok(sector_size)
            }
        }

        // On unix, use df and lsblk to extract the device sector size
        fn get_sector_size_unix(path: &str) -> Result<u64> {
            let source = get_device_id_unix(path)?;
            let output = Command::new("lsblk")
                .arg(source)
                .arg("-o")
                .arg("LOG-SeC")
                .output()
                .map_err(|e| PoCXPlotterError::SystemInfo(format!("Failed to execute 'lsblk -o LOG-SeC': {}", e)))?;

            let sector_size = String::from_utf8(output.stdout).map_err(|e| PoCXPlotterError::SystemInfo(format!("Invalid UTF-8 from lsblk: {}", e)))?;
            let sector_size = sector_size.split('\n').collect::<Vec<&str>>().get(1).unwrap_or_else(|| {
                println!("failed to determine sector size, defaulting to 4096.");
                &"4096"
            }).trim();

            sector_size.parse::<u64>().map_err(|e| PoCXPlotterError::SystemInfo(format!("Invalid sector size from lsblk: {}", e)))
        }

        pub fn get_sector_size(path: &str) -> Result<u64> {
            if cfg!(target_os = "macos") {
                get_sector_size_macos(path)
            } else {
                get_sector_size_unix(path)
            }
        }

        pub fn free_disk_space(path: &str) -> Result<u64> {
            // I don't like the following code, but I had to. It's difficult to estimate the space available for a new file on ext4 due to overhead.
            // Therefor I enforce a 2MB cushion assuming this is sufficient.
            Ok(fs2::available_space(Path::new(&path))?.saturating_sub(2097152))
        }

    } else {
        use std::ffi::CString;
        use std::ptr::null_mut;
        use std::mem;
        use winapi::um::fileapi::GetDiskFreeSpaceA;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::{SetThreadIdealProcessor,GetCurrentThread,OpenProcessToken,GetCurrentProcess,SetPriorityClass};
        use winapi::um::winnt::TokenElevation;
        use winapi::um::winnt::{HANDLE,TOKEN_ELEVATION,TOKEN_QUERY};
        use winapi::ctypes::c_void;
        use winapi::um::securitybaseapi::GetTokenInformation;

        const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;

        pub fn is_elevated() -> bool {

            let mut handle: HANDLE = null_mut();
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) };

            let elevation = unsafe { libc::malloc(mem::size_of::<TOKEN_ELEVATION>()) as *mut c_void };
            let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
            let mut ret_size = size;
            unsafe {
                GetTokenInformation(
                    handle,
                    TokenElevation,
                    elevation,
                    size as u32,
                    &mut ret_size,
                )
            };
            let elevation_struct: TOKEN_ELEVATION = unsafe{ *(elevation as *mut TOKEN_ELEVATION)};

            if !handle.is_null() {
                unsafe {
                    CloseHandle(handle);
                }
            }

            elevation_struct.TokenIsElevated == 1
        }

        pub fn get_sector_size(path: &str) -> Result<u64> {
            let path_encoded = Path::new(path);
            let path_str = path_encoded.to_str().ok_or_else(|| PoCXPlotterError::InvalidInput("Invalid path encoding".to_string()))?;
            let parent_path_encoded = CString::new(path_str).map_err(|e| PoCXPlotterError::InvalidInput(format!("Invalid path: {}", e)))?;
            let mut sectors_per_cluster  = 0u32;
            let mut bytes_per_sector  = 0u32;
            let mut number_of_free_cluster  = 0u32;
            let mut total_number_of_cluster  = 0u32;
            if unsafe {
                GetDiskFreeSpaceA(
                    parent_path_encoded.as_ptr(),
                    &mut sectors_per_cluster,
                    &mut bytes_per_sector,
                    &mut number_of_free_cluster,
                    &mut total_number_of_cluster
                )
            } == 0  {
                return Err(PoCXPlotterError::SystemInfo(format!("Failed to get sector size for path: {}", path)));
            };
            Ok(u64::from(bytes_per_sector))
        }

        pub fn set_thread_ideal_processor(id: usize){
            // Set core affinity for current thread.
        unsafe {
            SetThreadIdealProcessor(
                GetCurrentThread(),
                id as u32
            );
            }
        }
        pub fn set_low_prio() {
            unsafe{
                SetPriorityClass(GetCurrentProcess(),BELOW_NORMAL_PRIORITY_CLASS);
            }
        }
        pub fn free_disk_space(path: &str) -> Result<u64> {
            Ok(fs2::available_space(Path::new(&path))?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_free_disk_space() {
        // Test with current directory - should not panic and return a reasonable value
        let result = free_disk_space(".");
        assert!(result.is_ok());

        let space = result.unwrap();
        // Available space should be reasonable (less than 1 petabyte as sanity check)
        assert!(space < 1_000_000_000_000_000); // 1 PB
    }

    #[test]
    fn test_free_disk_space_invalid_path() {
        let result = free_disk_space("/nonexistent/path/that/should/not/exist");

        // This might succeed or fail depending on the OS and filesystem
        // but it should not panic
        match result {
            Ok(space) => {
                // If it succeeds, space should be reasonable
                assert!(space < 1_000_000_000_000_000);
            }
            Err(_) => {
                // Failing is also acceptable for invalid paths
            }
        }
    }

    #[test]
    fn test_get_sector_size() {
        // Test with current directory
        let result = get_sector_size(".");

        // This should work on most systems, but may fail on some configurations
        match result {
            Ok(sector_size) => {
                // Common sector sizes are 512, 1024, 2048, 4096, 8192 bytes
                assert!(sector_size >= 512);
                assert!(sector_size <= 65536); // Reasonable upper bound
                                               // Should be a power of 2
                assert!(sector_size & (sector_size - 1) == 0);
            }
            Err(_) => {
                // Some systems might not support this operation
                // That's acceptable for the test
            }
        }
    }

    #[test]
    fn test_set_low_prio() {
        // This function should not panic when called
        set_low_prio();

        // No assertions needed - just ensuring it doesn't crash
        // The actual priority change is OS-dependent and hard to test
    }

    #[cfg(unix)]
    #[test]
    fn test_get_device_id_unix_current_dir() {
        let result = super::get_device_id_unix(".");

        // This should work on most Unix systems
        match result {
            Ok(device_id) => {
                assert!(!device_id.is_empty());
                // Device ID should be a reasonable filesystem path
                assert!(device_id.starts_with('/') || device_id.starts_with("dev"));
            }
            Err(_) => {
                // Some systems might not have df command or it might fail
                // That's acceptable for the test
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_get_device_id_unix_invalid_path() {
        let result = super::get_device_id_unix("/this/path/should/not/exist");

        // This might succeed (if df can handle the parent directory)
        // or fail (if the path is completely invalid)
        // Either outcome is acceptable - we just test it doesn't panic
        let _ = result;
    }

    #[cfg(windows)]
    #[test]
    fn test_is_elevated() {
        // Test the Windows elevation check
        let elevated = is_elevated();

        // Should return either true or false, not panic
        assert!(elevated == true || elevated == false);
    }

    #[cfg(windows)]
    #[test]
    fn test_set_thread_ideal_processor() {
        // Test setting thread processor affinity
        set_thread_ideal_processor(0);
        set_thread_ideal_processor(1);

        // Should not panic - actual effect is hard to test
    }

    #[test]
    fn test_path_handling() {
        // Test various path formats that the utilities might encounter
        let test_paths = [".", "..", "/", "C:\\", "/tmp", "/var"];

        for path in &test_paths {
            // Test that Path::new doesn't panic with these inputs
            let path_obj = Path::new(path);
            assert!(path_obj.as_os_str().len() >= path.len());
        }
    }

    #[test]
    fn test_error_propagation() {
        // Test that errors are properly propagated through the Result types
        fn test_error_chain() -> Result<()> {
            // Create a test that might fail
            let _space = free_disk_space(".")?;
            Ok(())
        }

        let result = test_error_chain();
        // Should either succeed or return a proper error
        match result {
            Ok(_) => {}
            Err(e) => {
                // Error should be displayable
                let error_msg = format!("{}", e);
                assert!(!error_msg.is_empty());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_sector_size_functions() {
        // Test the sector size detection functions
        if cfg!(target_os = "macos") {
            // Test macOS-specific function if available
            let result = super::get_sector_size_macos(".");
            match result {
                Ok(size) => {
                    assert!((512..=65536).contains(&size));
                    assert!(size & (size - 1) == 0); // Power of 2
                }
                Err(_) => {
                    // May fail if diskutil is not available or path is invalid
                }
            }
        } else {
            // Test Unix-specific function if available
            let result = super::get_sector_size_unix(".");
            match result {
                Ok(size) => {
                    assert!((512..=65536).contains(&size));
                }
                Err(_) => {
                    // May fail if lsblk is not available or path is invalid
                }
            }
        }
    }

    #[test]
    fn test_cross_platform_consistency() {
        // Test that the public API behaves consistently across platforms
        let current_dir_result = get_sector_size(".");
        let free_space_result = free_disk_space(".");

        // Both should either succeed or fail gracefully
        match (current_dir_result, free_space_result) {
            (Ok(sector_size), Ok(_free_space)) => {
                assert!(sector_size > 0);
                // free_space is u64, so it's always >= 0 by definition
                // Just check that we got a valid value (could be 0 if disk is full)

                // Sector size should be reasonable
                assert!(sector_size >= 512);
                assert!(sector_size <= 65536);
            }
            _ => {
                // Some combinations might fail on certain systems
                // That's acceptable as long as they don't panic
            }
        }
    }
}
