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

use serde_json::json;
use thiserror::Error;

use crate::protocol::types::JsonRpcError;

pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

pub const INVALID_SUBMISSION: i32 = -32001;
pub const WRONG_HEIGHT: i32 = -32002;
pub const STALE_SUBMISSION: i32 = -32003;
pub const AUTH_REQUIRED: i32 = -32004;
pub const AUTH_INVALID: i32 = -32005;
pub const RATE_LIMITED: i32 = -32006;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Method not found: {0}")]
    MethodNotFound(String),

    #[error("Invalid params: {0}")]
    InvalidParams(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Invalid submission: {0}")]
    InvalidSubmission(String),

    #[error("Wrong height - expected: {expected}, submitted: {submitted}")]
    WrongHeight { expected: u64, submitted: u64 },

    #[error("Stale submission")]
    StaleSubmission,

    #[error("Authentication required")]
    AuthRequired,

    #[error("Invalid authentication")]
    AuthInvalid,

    #[error("Rate limited")]
    RateLimited,

    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Other error: {0}")]
    Other(String),
}

impl ProtocolError {
    pub fn to_json_rpc_error(&self) -> JsonRpcError {
        match self {
            Self::ParseError(msg) => JsonRpcError {
                code: PARSE_ERROR,
                message: "Parse error".to_string(),
                data: Some(json!({ "details": msg })),
            },
            Self::InvalidRequest(msg) => JsonRpcError {
                code: INVALID_REQUEST,
                message: "Invalid request".to_string(),
                data: Some(json!({ "details": msg })),
            },
            Self::MethodNotFound(method) => JsonRpcError {
                code: METHOD_NOT_FOUND,
                message: "Method not found".to_string(),
                data: Some(json!({ "method": method })),
            },
            Self::InvalidParams(msg) => JsonRpcError {
                code: INVALID_PARAMS,
                message: "Invalid params".to_string(),
                data: Some(json!({ "details": msg })),
            },
            Self::InternalError(msg) => JsonRpcError {
                code: INTERNAL_ERROR,
                message: "Internal error".to_string(),
                data: Some(json!({ "details": msg })),
            },
            Self::InvalidSubmission(reason) => JsonRpcError {
                code: INVALID_SUBMISSION,
                message: "Invalid submission".to_string(),
                data: Some(json!({ "reason": reason })),
            },
            Self::WrongHeight {
                expected,
                submitted,
            } => JsonRpcError {
                code: WRONG_HEIGHT,
                message: "Wrong height".to_string(),
                data: Some(json!({
                    "reason": "wrong_height",
                    "expected": expected,
                    "submitted": submitted
                })),
            },
            Self::StaleSubmission => JsonRpcError {
                code: STALE_SUBMISSION,
                message: "Stale submission".to_string(),
                data: Some(json!({ "reason": "stale" })),
            },
            Self::AuthRequired => JsonRpcError {
                code: AUTH_REQUIRED,
                message: "Authentication required".to_string(),
                data: None,
            },
            Self::AuthInvalid => JsonRpcError {
                code: AUTH_INVALID,
                message: "Invalid authentication".to_string(),
                data: None,
            },
            Self::RateLimited => JsonRpcError {
                code: RATE_LIMITED,
                message: "Rate limited".to_string(),
                data: None,
            },
            Self::NetworkError(err) => JsonRpcError {
                code: INTERNAL_ERROR,
                message: "Network error".to_string(),
                data: Some(json!({ "details": err.to_string() })),
            },
            Self::JsonError(err) => JsonRpcError {
                code: PARSE_ERROR,
                message: "JSON error".to_string(),
                data: Some(json!({ "details": err.to_string() })),
            },
            Self::Other(msg) => JsonRpcError {
                code: INTERNAL_ERROR,
                message: "Error".to_string(),
                data: Some(json!({ "details": msg })),
            },
        }
    }
}

pub fn parse_error(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: PARSE_ERROR,
        message: "Parse error".to_string(),
        data: Some(json!({ "details": msg.into() })),
    }
}

pub fn invalid_request(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: INVALID_REQUEST,
        message: "Invalid request".to_string(),
        data: Some(json!({ "details": msg.into() })),
    }
}

pub fn method_not_found(method: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: METHOD_NOT_FOUND,
        message: "Method not found".to_string(),
        data: Some(json!({ "method": method.into() })),
    }
}

pub fn invalid_params(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: INVALID_PARAMS,
        message: "Invalid params".to_string(),
        data: Some(json!({ "details": msg.into() })),
    }
}

pub fn internal_error(msg: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: INTERNAL_ERROR,
        message: "Internal error".to_string(),
        data: Some(json!({ "details": msg.into() })),
    }
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(PARSE_ERROR, -32700);
        assert_eq!(INVALID_REQUEST, -32600);
        assert_eq!(METHOD_NOT_FOUND, -32601);
        assert_eq!(INVALID_PARAMS, -32602);
        assert_eq!(INTERNAL_ERROR, -32603);

        assert_eq!(INVALID_SUBMISSION, -32001);
        assert_eq!(WRONG_HEIGHT, -32002);
        assert_eq!(STALE_SUBMISSION, -32003);
        assert_eq!(AUTH_REQUIRED, -32004);
        assert_eq!(AUTH_INVALID, -32005);
        assert_eq!(RATE_LIMITED, -32006);
    }

    #[test]
    fn test_wrong_height_error() {
        let err = ProtocolError::WrongHeight {
            expected: 100,
            submitted: 99,
        };

        let json_err = err.to_json_rpc_error();
        assert_eq!(json_err.code, WRONG_HEIGHT);
        assert_eq!(json_err.message, "Wrong height");

        let data = json_err.data.unwrap();
        assert_eq!(data["reason"], "wrong_height");
        assert_eq!(data["expected"], 100);
        assert_eq!(data["submitted"], 99);
    }

    #[test]
    fn test_helper_functions() {
        let err = parse_error("test message");
        assert_eq!(err.code, PARSE_ERROR);
        assert_eq!(err.message, "Parse error");

        let err = method_not_found("unknown_method");
        assert_eq!(err.code, METHOD_NOT_FOUND);
        assert_eq!(err.message, "Method not found");
        assert_eq!(err.data.unwrap()["method"], "unknown_method");
    }
}
