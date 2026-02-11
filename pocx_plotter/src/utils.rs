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

use crate::error::Result;
use std::path::Path;

// Wrapper around pocx_plotfile::get_sector_size to match plotter's Result type
// pocx_plotfile always returns a valid u64 (with fallbacks), but plotter
// expects Result
pub fn get_sector_size(path: &str) -> Result<u64> {
    Ok(pocx_plotfile::get_sector_size(path))
}

cfg_if! {
    if #[cfg(unix)] {

        pub fn set_low_prio() {
            // NOTE: Thread priority setting is not implemented yet
            // This would require platform-specific syscalls (nice, setpriority, etc.)
            // Currently no-op to maintain API compatibility
            #[cfg(target_os = "linux")]
            {
                eprintln!("Warning: Thread priority setting not implemented in this build");
            }
        }

        pub fn free_disk_space(path: &str) -> Result<u64> {
            // I don't like the following code, but I had to. It's difficult to estimate the space available for a new file on ext4 due to overhead.
            // Therefor I enforce a 2MB cushion assuming this is sufficient.
            Ok(fs2::available_space(Path::new(&path))?.saturating_sub(2097152))
        }

    } else {
        use std::ptr::null_mut;
        use std::mem;
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
                    size,
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
}
