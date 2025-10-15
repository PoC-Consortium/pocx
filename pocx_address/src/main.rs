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

use pocx_address::{crypto, encode_address, NetworkId};

fn main() {
    println!("Address generation for testing purposes.\n");

    // Generate test keypair
    let private_key = crypto::PrivateKey::generate_random();
    let payload = private_key.to_public_key().to_address_payload();

    // Generate mainnet addresses (Base58 and Bech32)
    let base58_addr = encode_address(&payload, NetworkId::Base58(0x55)).unwrap();
    let bech32_addr = encode_address(&payload, NetworkId::Bech32("pocx".to_string())).unwrap();

    println!("Base58: {}", base58_addr);
    println!("Bech32: {}", bech32_addr);
    println!("\n⚠️  Test addresses only - not for production use.");
}
