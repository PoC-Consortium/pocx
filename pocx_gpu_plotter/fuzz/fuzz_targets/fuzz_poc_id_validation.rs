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

/// Fuzz target for PoCX address validation
/// Tests that address validation never panics and handles all possible inputs correctly

fuzz_target!(|data: &[u8]| {
    // Test raw bytes to base58 encoding
    if data.len() >= 25 {
        let mut id_bytes = [0u8; 25];
        id_bytes.copy_from_slice(&data[..25]);
        
        // Should never panic
        let payload = &id_bytes[1..21];
        let mut payload_array = [0u8; 20];
        payload_array.copy_from_slice(payload);
        let encoded = pocx_address::encode_with_format(&payload_array, id_bytes[0], pocx_address::AddressFormat::Base58);
        
        // Should be able to decode back
        if let Ok((decoded_payload, decoded_network, _)) = pocx_address::decode_universal(&encoded) {
            assert_eq!(decoded_payload, payload_array);
            assert_eq!(decoded_network, id_bytes[0]);
        }
    }
    
    // Test arbitrary string input as PoC address
    if let Ok(input_str) = std::str::from_utf8(data) {
        // Limit length to prevent excessive memory usage
        if input_str.len() <= 1000 {
            // Test decoding - should never panic
            let _decode_result = pocx_address::decode_universal(input_str);
        }
    }
    
    // Test validation logic on various lengths
    for chunk_size in [1, 24, 25, 26, 32, 100].iter() {
        if data.len() >= *chunk_size {
            let chunk = &data[..*chunk_size];
            if *chunk_size >= 21 {
                let payload = &chunk[1..21];
                let mut payload_array = [0u8; 20];
                payload_array.copy_from_slice(payload);
                let encoded = pocx_address::encode_with_format(&payload_array, chunk[0], pocx_address::AddressFormat::Base58);
            } else {
                // For chunks too small to contain a valid address, just test with dummy data
                let mut payload_array = [0u8; 20];
                payload_array[..chunk.len().min(20)].copy_from_slice(&chunk[..chunk.len().min(20)]);
                let encoded = pocx_address::encode_with_format(&payload_array, 0x55, pocx_address::AddressFormat::Base58);
            }
            
            // Basic validation checks should never panic
            let _is_empty = encoded.is_empty();
            let _length_check = encoded.len() > 100;
            let _contains_invalid = encoded.chars().any(|c| !c.is_ascii());
        }
    }
});