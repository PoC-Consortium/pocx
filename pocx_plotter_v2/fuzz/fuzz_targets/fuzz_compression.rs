// Copyright (c) 2025 Proof of Capacity Consortium
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz target for compression algorithms
/// Tests that compression functions handle arbitrary data without panicking

// Use smaller test constants for fuzzing performance
const FUZZ_DIM: u64 = 4;
const FUZZ_DOUBLE_HASH_SIZE: u64 = 32;
const FUZZ_WARP_SIZE: u64 = FUZZ_DIM * FUZZ_DIM * FUZZ_DOUBLE_HASH_SIZE;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return; // Need minimum data for meaningful test
    }
    
    // Extract parameters from input data
    let warp_offset = (data[0] as u64) % 4;
    let output_len = ((data[1] as u64) % 4) + 1;
    let iterations = ((data[2] as u32) % 3) + 1;
    
    // Test helix compression with various buffer sizes
    let source_size = (2 * FUZZ_DIM * FUZZ_DIM * FUZZ_DOUBLE_HASH_SIZE) as usize;
    let target_size = (4 * FUZZ_DIM * FUZZ_DIM * FUZZ_DOUBLE_HASH_SIZE) as usize;
    
    if data.len() >= source_size {
        let source_buffer = &data[..source_size];
        let mut target_buffer = vec![0u8; target_size];
        
        // Test helix compression - should never panic
        pocx_plotter::compressor::helix_compress(
            source_buffer,
            &mut target_buffer,
            warp_offset,
            output_len
        );
        
        // Verify buffer integrity
        assert_eq!(target_buffer.len(), target_size);
    }
    
    // Test XOR compression
    let src_len = u64::pow(2, iterations);
    let xor_source_size = (src_len * FUZZ_DIM * FUZZ_DIM * FUZZ_DOUBLE_HASH_SIZE) as usize;
    let xor_target_size = (output_len * FUZZ_DIM * FUZZ_DIM * FUZZ_DOUBLE_HASH_SIZE) as usize;
    
    if data.len() >= xor_source_size {
        let source_buffer = &data[..xor_source_size];
        let mut target_buffer = vec![0u8; xor_target_size];
        
        // Test XOR compression - should never panic
        pocx_plotter::compressor::xor_compress(
            source_buffer,
            &mut target_buffer,
            warp_offset,
            output_len,
            iterations
        );
        
        // Verify buffer integrity
        assert_eq!(target_buffer.len(), xor_target_size);
    }
    
    // Test inline compression with smaller buffers
    let inline_size = (2 * FUZZ_DIM * FUZZ_DIM * FUZZ_DOUBLE_HASH_SIZE) as usize;
    if data.len() >= inline_size {
        let mut buffer = Vec::from(&data[..inline_size]);
        
        // Test inline compression - should never panic
        pocx_plotter::compressor::helix_compress_inline(
            &mut buffer,
            warp_offset,
            output_len
        );
        
        // Verify buffer integrity
        assert_eq!(buffer.len(), inline_size);
    }
    
    // Test with edge case parameters
    if data.len() >= 1024 {
        let small_source = &data[..1024];
        let mut small_target = vec![0u8; 1024];
        
        // Should handle small buffers gracefully
        pocx_plotter::compressor::helix_compress(
            small_source,
            &mut small_target,
            0,
            1
        );
    }
});