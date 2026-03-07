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

/// Comprehensive error types for the PoCX Plotter
use std::fmt;

/// Main error type for PoCX Plotter operations
#[derive(Debug)]
pub enum PoCXPlotterError {
    /// I/O errors (file operations, disk access)
    Io(std::io::Error),

    /// OpenCL-specific errors
    #[cfg(feature = "opencl")]
    OpenCl(opencl3::error_codes::ClError),

    /// System information errors
    #[allow(dead_code)]
    SystemInfo(String),

    /// Memory allocation errors
    Memory(String),

    /// Invalid user input
    InvalidInput(String),

    /// Cryptographic errors (invalid seeds, addresses)
    Crypto(String),

    /// Threading/communication errors
    Channel(String),

    /// Hardware detection errors
    Hardware(String),

    /// Configuration errors
    Config(String),

    /// Internal errors (panics, unexpected states)
    #[allow(dead_code)] // Used by library consumers via run_plotter_safe()
    Internal(String),
}

impl fmt::Display for PoCXPlotterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoCXPlotterError::Io(err) => write!(f, "I/O error: {}", err),
            #[cfg(feature = "opencl")]
            PoCXPlotterError::OpenCl(err) => write!(f, "OpenCL error: {}", err),
            PoCXPlotterError::SystemInfo(msg) => write!(f, "System information error: {}", msg),
            PoCXPlotterError::Memory(msg) => write!(f, "Memory error: {}", msg),
            PoCXPlotterError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            PoCXPlotterError::Crypto(msg) => write!(f, "Cryptographic error: {}", msg),
            PoCXPlotterError::Channel(msg) => write!(f, "Communication error: {}", msg),
            PoCXPlotterError::Hardware(msg) => write!(f, "Hardware error: {}", msg),
            PoCXPlotterError::Config(msg) => write!(f, "Configuration error: {}", msg),
            PoCXPlotterError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for PoCXPlotterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PoCXPlotterError::Io(err) => Some(err),
            #[cfg(feature = "opencl")]
            PoCXPlotterError::OpenCl(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PoCXPlotterError {
    fn from(err: std::io::Error) -> Self {
        PoCXPlotterError::Io(err)
    }
}

#[cfg(feature = "opencl")]
impl From<opencl3::error_codes::ClError> for PoCXPlotterError {
    fn from(err: opencl3::error_codes::ClError) -> Self {
        PoCXPlotterError::OpenCl(err)
    }
}

impl From<std::num::ParseIntError> for PoCXPlotterError {
    fn from(err: std::num::ParseIntError) -> Self {
        PoCXPlotterError::InvalidInput(format!("Invalid number format: {}", err))
    }
}

impl From<hex::FromHexError> for PoCXPlotterError {
    fn from(err: hex::FromHexError) -> Self {
        PoCXPlotterError::Crypto(format!("Invalid hex data: {}", err))
    }
}

/// Result type for PoCX Plotter operations
pub type Result<T> = std::result::Result<T, PoCXPlotterError>;

/// Utility macro for converting unwrap() to proper error handling
#[macro_export]
macro_rules! safe_unwrap {
    ($expr:expr, $error_type:expr) => {
        $expr.ok_or_else(|| $error_type)?
    };
}

/// Utility for handling mutex poisoning gracefully
pub fn lock_mutex<T>(mutex: &std::sync::Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| PoCXPlotterError::Channel("Mutex poisoned".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn test_lock_mutex_poisoned() {
        let mutex = std::sync::Arc::new(Mutex::new(42));
        let mutex_clone = mutex.clone();

        // Poison the mutex by panicking while holding the lock
        let _ = std::thread::spawn(move || {
            let _guard = mutex_clone.lock().unwrap();
            panic!("Intentional panic to poison mutex");
        })
        .join();

        // Now the mutex should be poisoned
        let result = lock_mutex(&*mutex);
        assert!(result.is_err());

        match result {
            Err(PoCXPlotterError::Channel(msg)) => {
                assert_eq!(msg, "Mutex poisoned");
            }
            _ => panic!("Expected Channel error for poisoned mutex"),
        }
    }
}
