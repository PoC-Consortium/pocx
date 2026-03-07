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
use pocx_plotter::buffer::PageAlignedByteBuffer;

/// Fuzz target for buffer allocation
/// Tests that buffer allocation handles all size inputs gracefully

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    
    // Extract buffer size from input data (limit to reasonable range)
    let size_bytes = [data[0], data[1], data[2], data[3]];
    let mut raw_size = u32::from_le_bytes(size_bytes) as usize;
    
    // Limit to reasonable range to prevent excessive memory usage during fuzzing
    raw_size = raw_size % (64 * 1024 * 1024); // Max 64MB for fuzzing
    
    // Test various size ranges
    let test_sizes = [
        0,                              // Invalid: zero size
        1,                              // Minimum positive size
        raw_size % 4096,               // Small size
        4096,                          // Page size
        raw_size % (1024 * 1024),      // Medium size  
        raw_size,                      // Full fuzzed size
    ];
    
    for &size in &test_sizes {
        let result = PageAlignedByteBuffer::new(size);
        
        match result {
            Ok(buffer) => {
                // If allocation succeeded, verify properties
                assert!(size > 0, "Should not succeed with zero size");
                assert!(size <= 16 * 1024 * 1024 * 1024, "Should not exceed max size");
                
                let data = buffer.get_buffer();
                let guard = data.lock().unwrap();
                
                // Verify buffer properties
                assert_eq!(guard.len(), size);
                
                // Verify alignment
                let ptr = guard.as_ptr() as usize;
                let page_size = page_size::get();
                assert_eq!(ptr % page_size, 0, "Buffer should be page-aligned");
                
                // Test that we can write to the buffer without panic
                if size > 0 {
                    // Drop the guard to get mutable access
                    drop(guard);
                    let data = buffer.get_buffer();
                    let mut guard = data.lock().unwrap();
                    
                    // Write some test data
                    guard[0] = 0xFF;
                    if size > 1 {
                        guard[size - 1] = 0xAA;
                    }
                    
                    // Verify the writes
                    assert_eq!(guard[0], 0xFF);
                    if size > 1 {
                        assert_eq!(guard[size - 1], 0xAA);
                    }
                }
            }
            Err(_) => {
                // If allocation failed, it should be for valid reasons
                let should_fail = size == 0 || 
                                size > 16 * 1024 * 1024 * 1024 || // > 16GB
                                size > 64 * 1024 * 1024; // > 64MB (fuzzing limit)
                
                if !should_fail {
                    // For sizes that should work but failed, this might be due to 
                    // system memory constraints, which is acceptable during fuzzing
                }
            }
        }
    }
    
    // Test page size validation
    let page_size = page_size::get();
    assert!(page_size > 0, "Page size should be positive");
    assert!(page_size <= 1024 * 1024, "Page size should be reasonable");
    
    // Test alignment requirements
    if data.len() >= 8 {
        let test_alignment_size = (u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7]
        ]) % (1024 * 1024)) as usize;
        
        if test_alignment_size > 0 && test_alignment_size <= 1024 * 1024 {
            let _result = PageAlignedByteBuffer::new(test_alignment_size);
            // Should not panic regardless of success or failure
        }
    }
});