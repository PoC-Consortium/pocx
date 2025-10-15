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

//! Common types and constants for address handling

use std::fmt;

/// Base58 decoded length (version byte + 20-byte payload + 4-byte checksum)
pub const BASE58_DECODED_LENGTH: usize = 25;

/// Standard PoC payload length (20 bytes)
pub const PAYLOAD_LENGTH: usize = 20;

/// Network identifier that determines the address format
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkId {
    /// Base58 format with version byte
    Base58(u8),
    /// Bech32 format with Human Readable Part
    Bech32(String),
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkId::Base58(version) => write!(f, "Base58(0x{:02X})", version),
            NetworkId::Bech32(hrp) => write!(f, "Bech32({})", hrp),
        }
    }
}

/// Address format types supported by the library
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFormat {
    /// Base58Check encoding
    Base58,
    /// Bech32 encoding with P2WPKH
    Bech32,
}

impl fmt::Display for AddressFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressFormat::Base58 => write!(f, "Base58"),
            AddressFormat::Bech32 => write!(f, "Bech32"),
        }
    }
}

/// Errors that can occur during address operations
#[derive(Debug, Clone)]
pub enum AddressError {
    /// Invalid Base58 encoding
    InvalidBase58(String),
    /// Invalid Bech32 encoding
    InvalidBech32(String),
    /// Invalid address length
    InvalidLength { expected: usize, actual: usize },
    /// Checksum verification failed
    ChecksumError,
    /// Invalid witness version for P2WPKH (must be 0)
    InvalidWitnessVersion(u8),
    /// Invalid HRP (Human Readable Part) in Bech32 address
    InvalidHrp(String),
    /// Unknown address format
    UnknownFormat,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::InvalidBase58(msg) => write!(f, "Invalid Base58: {}", msg),
            AddressError::InvalidBech32(msg) => write!(f, "Invalid Bech32: {}", msg),
            AddressError::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "Invalid address length: expected {} bytes, got {} bytes",
                    expected, actual
                )
            }
            AddressError::ChecksumError => write!(f, "Address checksum verification failed"),
            AddressError::InvalidWitnessVersion(v) => {
                write!(f, "Invalid witness version {} (must be 0 for P2WPKH)", v)
            }
            AddressError::InvalidHrp(hrp) => write!(f, "Invalid HRP: {}", hrp),
            AddressError::UnknownFormat => write!(f, "Unknown address format"),
        }
    }
}

impl std::error::Error for AddressError {}

/// Automatically detect address format by attempting to decode with both
/// formats Returns None if the address is invalid
pub fn detect_address_format(addr: &str) -> Option<AddressFormat> {
    // Try Bech32 first (more specific format)
    if crate::bech32::decode(addr).is_ok() {
        return Some(AddressFormat::Bech32);
    }

    // Try Base58 fallback
    if crate::base58::decode(addr).is_ok() {
        return Some(AddressFormat::Base58);
    }

    None
}
