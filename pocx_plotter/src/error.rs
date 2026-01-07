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
    use std::error::Error;
    use std::sync::Mutex;

    #[test]
    fn test_error_display() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let pocx_error = PoCXPlotterError::Io(io_error);
        assert!(format!("{}", pocx_error).contains("I/O error"));
        assert!(format!("{}", pocx_error).contains("File not found"));

        let system_error = PoCXPlotterError::SystemInfo("CPU detection failed".to_string());
        assert_eq!(
            format!("{}", system_error),
            "System information error: CPU detection failed"
        );

        let memory_error = PoCXPlotterError::Memory("Out of memory".to_string());
        assert_eq!(format!("{}", memory_error), "Memory error: Out of memory");

        let input_error = PoCXPlotterError::InvalidInput("Invalid parameter".to_string());
        assert_eq!(
            format!("{}", input_error),
            "Invalid input: Invalid parameter"
        );

        let crypto_error = PoCXPlotterError::Crypto("Invalid signature".to_string());
        assert_eq!(
            format!("{}", crypto_error),
            "Cryptographic error: Invalid signature"
        );

        let channel_error = PoCXPlotterError::Channel("Send failed".to_string());
        assert_eq!(
            format!("{}", channel_error),
            "Communication error: Send failed"
        );

        let hardware_error = PoCXPlotterError::Hardware("GPU not found".to_string());
        assert_eq!(
            format!("{}", hardware_error),
            "Hardware error: GPU not found"
        );

        let config_error = PoCXPlotterError::Config("Invalid config".to_string());
        assert_eq!(
            format!("{}", config_error),
            "Configuration error: Invalid config"
        );
    }

    #[test]
    fn test_error_debug() {
        let error = PoCXPlotterError::Memory("Test memory error".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Memory"));
        assert!(debug_str.contains("Test memory error"));
    }

    #[test]
    fn test_error_source() {
        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied");
        let pocx_error = PoCXPlotterError::Io(io_error);

        assert!(pocx_error.source().is_some());
        assert!(pocx_error
            .source()
            .unwrap()
            .to_string()
            .contains("Access denied"));

        let memory_error = PoCXPlotterError::Memory("No source".to_string());
        assert!(memory_error.source().is_none());
    }

    #[test]
    fn test_from_io_error() {
        let io_error = std::io::Error::new(std::io::ErrorKind::InvalidData, "Corrupt data");
        let pocx_error: PoCXPlotterError = io_error.into();

        match pocx_error {
            PoCXPlotterError::Io(err) => {
                assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
                assert!(err.to_string().contains("Corrupt data"));
            }
            _ => panic!("Expected Io error variant"),
        }
    }

    #[test]
    fn test_from_parse_int_error() {
        let parse_result = "invalid_number".parse::<u64>();
        assert!(parse_result.is_err());

        let pocx_error: PoCXPlotterError = parse_result.unwrap_err().into();
        match pocx_error {
            PoCXPlotterError::InvalidInput(msg) => {
                assert!(msg.contains("Invalid number format"));
            }
            _ => panic!("Expected InvalidInput error variant"),
        }
    }

    #[test]
    fn test_from_hex_error() {
        let hex_result = hex::decode("invalid_hex_gg");
        assert!(hex_result.is_err());

        let pocx_error: PoCXPlotterError = hex_result.unwrap_err().into();
        match pocx_error {
            PoCXPlotterError::Crypto(msg) => {
                assert!(msg.contains("Invalid hex data"));
            }
            _ => panic!("Expected Crypto error variant"),
        }
    }

    #[test]
    fn test_result_type_usage() {
        fn test_function() -> Result<u32> {
            Ok(42)
        }

        fn test_error_function() -> Result<u32> {
            Err(PoCXPlotterError::InvalidInput("Test error".to_string()))
        }

        assert_eq!(test_function().unwrap(), 42);
        assert!(test_error_function().is_err());

        match test_error_function() {
            Err(PoCXPlotterError::InvalidInput(msg)) => {
                assert_eq!(msg, "Test error");
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn test_lock_mutex_success() {
        let mutex = Mutex::new(42);
        let result = lock_mutex(&mutex);
        assert!(result.is_ok());
        assert_eq!(*result.unwrap(), 42);
    }

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

    #[test]
    fn test_safe_unwrap_macro() {
        fn test_safe_unwrap_usage() -> Result<i32> {
            let some_value = Some(42);
            let result = safe_unwrap!(
                some_value,
                PoCXPlotterError::InvalidInput("Should not happen".to_string())
            );
            Ok(result)
        }

        // Test successful case
        assert_eq!(test_safe_unwrap_usage().unwrap(), 42);

        // Test error case
        fn test_safe_unwrap_error() -> Result<i32> {
            let none_value: Option<i32> = None;
            let _result = safe_unwrap!(
                none_value,
                PoCXPlotterError::InvalidInput("Test error".to_string())
            );
            Ok(0)
        }

        let error_result = test_safe_unwrap_error();
        assert!(error_result.is_err());
    }

    #[test]
    fn test_error_variants_completeness() {
        // Test that all error variants can be constructed and formatted
        let errors = vec![
            PoCXPlotterError::Io(std::io::Error::other("test")),
            PoCXPlotterError::SystemInfo("test".to_string()),
            PoCXPlotterError::Memory("test".to_string()),
            PoCXPlotterError::InvalidInput("test".to_string()),
            PoCXPlotterError::Crypto("test".to_string()),
            PoCXPlotterError::Channel("test".to_string()),
            PoCXPlotterError::Hardware("test".to_string()),
            PoCXPlotterError::Config("test".to_string()),
            PoCXPlotterError::Internal("test".to_string()),
        ];

        for error in errors {
            // All errors should be displayable
            let display_str = format!("{}", error);
            assert!(!display_str.is_empty());

            // All errors should be debuggable
            let debug_str = format!("{:?}", error);
            assert!(!debug_str.is_empty());
        }
    }

    #[test]
    fn test_error_chaining() {
        // Test error conversion chains
        let original_io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File missing");
        let pocx_error: PoCXPlotterError = original_io_error.into();

        // Should preserve the original error as source
        assert!(pocx_error.source().is_some());
        assert!(pocx_error
            .source()
            .unwrap()
            .to_string()
            .contains("File missing"));

        // The display should include both error information
        let display = format!("{}", pocx_error);
        assert!(display.contains("I/O error"));
        assert!(display.contains("File missing"));
    }
}
