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

//! Miner control signals
//!
//! Provides global stop mechanism for graceful miner shutdown.

// These are library exports used by external crates (e.g., Tauri backend)
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};

/// Global stop flag
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Request the miner to stop
///
/// This sets a flag that the miner checks periodically. The miner will
/// finish its current scan and then stop gracefully.
pub fn request_stop() {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

/// Check if stop has been requested
pub fn is_stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

/// Clear the stop request
///
/// Called when starting a new mining session.
pub fn clear_stop_request() {
    STOP_REQUESTED.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stop_mechanism() {
        // Start clean
        clear_stop_request();
        assert!(!is_stop_requested());

        // Request stop
        request_stop();
        assert!(is_stop_requested());

        // Clear it
        clear_stop_request();
        assert!(!is_stop_requested());
    }
}
