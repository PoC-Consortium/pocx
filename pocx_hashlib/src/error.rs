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

/// Error types for the pocx_hashlib crate
use std::fmt;

/// Main error type for PoC hash library operations
#[derive(Debug, Clone, PartialEq)]
pub enum PoCXHashError {
    /// Memory allocation failure
    AllocationError(String),
    /// Buffer size validation error
    BufferSizeError(String),
    /// Invalid input parameters
    InvalidInput(String),
    /// Hexadecimal decoding error
    HexDecodeError(String),
    /// Layout creation error for page alignment
    LayoutError(String),
    /// Computed quality does not match claimed quality
    QualityMismatch {
        expected: u64,
        actual: u64,
        proof_index: usize,
    },
}

impl fmt::Display for PoCXHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoCXHashError::AllocationError(msg) => write!(f, "Memory allocation failed: {}", msg),
            PoCXHashError::BufferSizeError(msg) => write!(f, "Buffer size error: {}", msg),
            PoCXHashError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            PoCXHashError::HexDecodeError(msg) => write!(f, "Hex decode error: {}", msg),
            PoCXHashError::LayoutError(msg) => write!(f, "Layout error: {}", msg),
            PoCXHashError::QualityMismatch {
                expected,
                actual,
                proof_index,
            } => write!(
                f,
                "Quality mismatch at proof {}: expected {}, got {}",
                proof_index, expected, actual
            ),
        }
    }
}

impl std::error::Error for PoCXHashError {}

/// Conversion from hex::FromHexError to PoCXHashError
impl From<hex::FromHexError> for PoCXHashError {
    fn from(err: hex::FromHexError) -> Self {
        PoCXHashError::HexDecodeError(err.to_string())
    }
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, PoCXHashError>;
