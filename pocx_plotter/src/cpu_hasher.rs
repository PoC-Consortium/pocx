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

use crate::plotter::NONCE_SIZE;
use crate::xpu_scheduler::HasherMessage;
use crossbeam_channel::Sender;
use pocx_hashlib::generate_nonces;
use std::slice::from_raw_parts_mut;

pub struct SafePointer {
    ptr: *mut u8,
}

impl SafePointer {
    pub fn new(ptr: *mut u8) -> Self {
        SafePointer { ptr }
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }
}

// SAFETY: SafePointer is a wrapper around a raw pointer that is used for CPU
// hashing. The pointer is guaranteed to be valid for the lifetime of the
// SafePointer instance, and the memory it points to is managed externally
// (typically page-aligned buffers). Send/Sync are safe because the pointer is
// read-only during parallel processing.
unsafe impl Send for SafePointer {}
unsafe impl Sync for SafePointer {}

pub struct CpuTask {
    pub cache: SafePointer,
    pub cache_size: usize,
    pub chunk_offset: usize,
    pub address_payload: [u8; 20], // Network-independent address payload
    pub seed: [u8; 32],
    pub local_startnonce: u64,
    pub local_nonces: u64,
}

#[derive(Debug, Clone)]
pub enum SimdExtension {
    #[cfg_attr(
        not(any(target_arch = "x86", target_arch = "x86_64")),
        allow(dead_code)
    )]
    Avx512f,
    #[cfg_attr(
        not(any(target_arch = "x86", target_arch = "x86_64")),
        allow(dead_code)
    )]
    Avx2,
    #[cfg_attr(
        not(any(target_arch = "x86", target_arch = "x86_64")),
        allow(dead_code)
    )]
    Avx,
    #[cfg_attr(
        not(any(target_arch = "x86", target_arch = "x86_64")),
        allow(dead_code)
    )]
    Sse2,
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    Neon,
    None,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn init_simd() -> SimdExtension {
    if is_x86_feature_detected!("avx512f") {
        SimdExtension::Avx512f
    } else if is_x86_feature_detected!("avx2") {
        SimdExtension::Avx2
    } else if is_x86_feature_detected!("avx") {
        SimdExtension::Avx
    } else if is_x86_feature_detected!("sse2") {
        SimdExtension::Sse2
    } else {
        SimdExtension::None
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn init_simd() -> SimdExtension {
    #[cfg(target_arch = "aarch64")]
    {
        // NEON is mandatory on all AArch64 processors
        SimdExtension::Neon
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        SimdExtension::None
    }
}

pub fn hash_cpu(tx: Sender<HasherMessage>, hasher_task: CpuTask) -> impl FnOnce() + Send {
    move || {
        // SAFETY: The cache pointer is valid and points to properly allocated memory.
        // The cache_size is validated to match the actual allocated size.
        // This creates a mutable slice for nonce generation.
        let nonce_generation_result = unsafe {
            let data = from_raw_parts_mut(
                hasher_task.cache.as_ptr(),
                hasher_task.cache_size * NONCE_SIZE as usize,
            );
            generate_nonces(
                data,
                hasher_task.chunk_offset,
                &hasher_task.address_payload,
                &hasher_task.seed,
                hasher_task.local_startnonce,
                hasher_task.local_nonces,
            )
        };

        // Handle any errors from nonce generation
        if let Err(e) = nonce_generation_result {
            eprintln!("Error generating nonces: {}", e);
            return; // Exit early on error, don't report success
        }

        // report hashing done
        if tx
            .send(HasherMessage::NoncesHashed(hasher_task.local_nonces))
            .is_err()
        {
            // Scheduler thread has likely exited, stop this worker thread gracefully
            return;
        }
        if tx.send(HasherMessage::CpuRequestForWork).is_err() {
            // Scheduler thread has likely exited, stop this worker thread
            // gracefully
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::plotter;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_noncegen() {
        let mut seed = [0u8; 32];
        seed[..].clone_from_slice(
            &hex::decode("AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE")
                .unwrap(),
        );
        let mut address_payload = [0u8; 20];
        address_payload
            .clone_from_slice(&hex::decode("5599BC78BA577A95A11F1A344D4D2AE55F2F857B").unwrap());
        let start_nonce = 1337;
        let exp_result_hash = "5c1859fb691fdf0a6a8d8dc5e2fef462b3ec2f10b0d1cce9f651ed5b2d6ee53e";

        let check_result = |buf: &Vec<u8>| {
            let mut hasher = Sha256::new();
            hasher.update(buf);
            assert_eq!(format!("{:x}", hasher.finalize()), exp_result_hash);
        };

        let mut buf = vec![0; 32 * plotter::NONCE_SIZE as usize];
        let _ = generate_nonces(&mut buf, 0, &address_payload, &seed, start_nonce, 32);
        check_result(&buf);
    }
}
