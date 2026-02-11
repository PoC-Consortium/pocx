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

/// Detect and return the SIMD instruction set name for display purposes
pub fn get_simd_name() -> &'static str {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("avx512f") {
            "AVX512"
        } else if is_x86_feature_detected!("avx2") {
            "AVX2"
        } else if is_x86_feature_detected!("avx") {
            "AVX"
        } else if is_x86_feature_detected!("sse2") {
            "SSE2"
        } else {
            "Scalar"
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // NEON is mandatory on all AArch64 processors
        return "NEON";
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        return "Scalar";
    }
}

pub fn new_thread_pool(num_threads: usize, thread_pinning: bool) -> rayon::ThreadPool {
    let core_ids = if thread_pinning {
        core_affinity::get_core_ids().unwrap()
    } else {
        Vec::new()
    };
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .start_handler(move |id| {
            if thread_pinning {
                #[cfg(not(windows))]
                let core_id = core_ids[id % core_ids.len()];
                #[cfg(not(windows))]
                core_affinity::set_for_current(core_id);
                #[cfg(windows)]
                set_thread_ideal_processor(id % core_ids.len());
            }
        })
        .build()
        .unwrap()
}

cfg_if! {
    if #[cfg(unix)] {
        use std::process::Command;

        pub fn get_device_id(path: &str) -> String {
            let output = Command::new("stat")
                .arg(path)
                .args(["-c", "%D"])
                .output()
                .expect("failed to execute 'stat -c %D'");
            String::from_utf8(output.stdout).expect("not utf8").trim_end().to_owned()
        }

    } else {
        use winapi::um::processthreadsapi::SetThreadIdealProcessor;
        use winapi::um::processthreadsapi::GetCurrentThread;
        use std::os::windows::ffi::OsStrExt;
        use std::ffi::OsStr;
        use std::iter::once;

        pub fn get_device_id(path: &str) -> String {
            let path_encoded: Vec<u16> = OsStr::new(path).encode_wide().chain(once(0)).collect();
            let mut volume_encoded: Vec<u16> = OsStr::new(path)
                .encode_wide()
                .chain(once(0))
                .collect();

            if unsafe {
                winapi::um::fileapi::GetVolumePathNameW(
                    path_encoded.as_ptr(),
                    volume_encoded.as_mut_ptr(),
                    path.chars().count() as u32
                )
            } == 0  {
                // Return empty string for invalid paths instead of panicking
                return String::new();
            };
            let res = String::from_utf16_lossy(&volume_encoded);
            let v: Vec<&str> = res.split('\u{00}').collect();
            String::from(v[0])
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
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_thread_pool_creation() {
        // Test creating thread pool with various sizes
        let pool_sizes = [1, 2, 4, 8];

        for &size in &pool_sizes {
            let pool = new_thread_pool(size, false);

            // Test that pool can execute tasks
            let result = std::sync::Arc::new(std::sync::Mutex::new(0));
            let result_clone = result.clone();

            pool.install(|| {
                *result_clone.lock().unwrap() = 42;
            });

            assert_eq!(*result.lock().unwrap(), 42);
        }
    }

    #[test]
    fn test_thread_pool_with_pinning() {
        let pool = new_thread_pool(2, true);

        // Test that pool works even with thread pinning enabled
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();

        pool.install(|| {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });

        // Give thread time to complete
        std::thread::sleep(std::time::Duration::from_millis(10));

        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn test_thread_pool_zero_size() {
        // Test edge case: zero-sized thread pool
        // This should default to at least 1 thread
        let pool = new_thread_pool(0, false);

        let executed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let executed_clone = executed.clone();

        pool.install(|| {
            executed_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(
            executed.load(std::sync::atomic::Ordering::SeqCst),
            "Task should execute even with zero-sized pool request"
        );
    }
}
