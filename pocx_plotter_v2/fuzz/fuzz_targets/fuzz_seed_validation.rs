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

/// Fuzz target for seed validation
/// Tests that seed validation and hex encoding/decoding never panics

fuzz_target!(|data: &[u8]| {
    // Test hex encoding of arbitrary data
    let hex_encoded = hex::encode(data);
    
    // Should always be valid hex
    assert!(hex_encoded.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(hex_encoded.len(), data.len() * 2);
    
    // Should be able to decode back
    if let Ok(decoded) = hex::decode(&hex_encoded) {
        assert_eq!(decoded, data);
    }
    
    // Test with exactly 32 bytes (seed size)
    if data.len() >= 32 {
        let seed_bytes = &data[..32];
        let seed_hex = hex::encode(seed_bytes);
        
        // Should be exactly 64 hex characters
        assert_eq!(seed_hex.len(), 64);
        assert!(seed_hex.chars().all(|c| c.is_ascii_hexdigit()));
        
        // Should decode back to original
        if let Ok(decoded) = hex::decode(&seed_hex) {
            assert_eq!(decoded, seed_bytes);
        }
    }
    
    // Test arbitrary string input as hex seed
    if let Ok(input_str) = std::str::from_utf8(data) {
        if input_str.len() <= 128 { // Reasonable limit
            // Decoding should never panic, but may fail
            let _decode_result = hex::decode(input_str);
            
            // Character validation should never panic
            let _all_hex = input_str.chars().all(|c| c.is_ascii_hexdigit());
            let _valid_length = input_str.len() == 64;
        }
    }
    
    // Test edge cases
    if data.is_empty() {
        let empty_hex = hex::encode(data);
        assert_eq!(empty_hex, "");
    }
    
    // Test maximum reasonable size
    if data.len() <= 1024 {
        let large_hex = hex::encode(data);
        assert_eq!(large_hex.len(), data.len() * 2);
    }
});