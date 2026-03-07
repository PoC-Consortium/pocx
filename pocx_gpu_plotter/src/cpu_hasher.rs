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

//! CPU nonce hashing using SIMD-accelerated `generate_nonces` from pocx_hashlib.

const CPU_TASK_SIZE: u64 = 64;

/// Hash `num_nonces` into scatter buffer using rayon thread pool.
///
/// `generate_nonces` scatters into scoop-major layout internally.
/// `cache_offset` in `generate_nonces` is a nonce index (not byte offset).
pub fn hash_nonces_cpu(
    scatter_buf: &mut [u8],
    address_payload: &[u8; 20],
    seed: &[u8; 32],
    start_nonce: u64,
    num_nonces: u64,
    pool: &rayon::ThreadPool,
) {
    let buf_addr = scatter_buf.as_mut_ptr() as usize;
    let buf_len = scatter_buf.len();
    let addr = *address_payload;
    let s = *seed;

    pool.scope(move |scope| {
        let mut offset = 0u64;
        while offset < num_nonces {
            let chunk_size = std::cmp::min(CPU_TASK_SIZE, num_nonces - offset);
            let cache_offset = offset as usize;
            let nonce_start = start_nonce + offset;

            scope.spawn(move |_| {
                // SAFETY: Each task writes to a distinct nonce region [cache_offset..cache_offset+chunk_size]
                // in the scoop-major layout. No two tasks overlap.
                let buf = unsafe { std::slice::from_raw_parts_mut(buf_addr as *mut u8, buf_len) };
                pocx_hashlib::generate_nonces(buf, cache_offset, &addr, &s, nonce_start, chunk_size)
                    .expect("generate_nonces failed");
            });

            offset += chunk_size;
        }
    });
}
