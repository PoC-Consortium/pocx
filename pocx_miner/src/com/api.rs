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

use serde::de;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NonceSubmission {
    pub block_height: u64,
    pub generation_signature: String,
    pub account_id: String, // Changed from base58 to account_id (hex payload)
    pub seed: String,
    pub nonce: u64,
    pub quality: u64, // Changed from quality_adjusted to quality
    pub compression: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitNonceResponse {
    pub quality_adjusted: u64,
    #[serde(default = "default_poc_time")]
    pub poc_time: u64,
}

fn default_poc_time() -> u64 {
    u64::MAX
}

#[derive(Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct MiningInfo {
    pub generation_signature: String,

    #[serde(deserialize_with = "from_str_or_int")]
    pub base_target: u64,

    #[serde(deserialize_with = "from_str_or_int")]
    pub height: u64,

    pub block_hash: String,

    #[serde(deserialize_with = "from_str_or_int_optional")]
    pub target_quality: Option<u64>, // Pool-provided quality limit

    #[serde(
        default = "default_minimum_compression_level",
        deserialize_with = "from_str_or_int_u32"
    )]
    pub minimum_compression_level: u32,

    #[serde(
        default = "default_target_compression_level",
        deserialize_with = "from_str_or_int_u32"
    )]
    pub target_compression_level: u32,
}

fn default_minimum_compression_level() -> u32 {
    1
}

fn default_target_compression_level() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug)]
pub enum FetchError {
    Http(reqwest::Error),
    Pool(PoolError),
}

impl From<reqwest::Error> for FetchError {
    fn from(err: reqwest::Error) -> FetchError {
        FetchError::Http(err)
    }
}

impl From<PoolError> for FetchError {
    fn from(err: PoolError) -> FetchError {
        FetchError::Pool(err)
    }
}

impl fmt::Display for NonceSubmission {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        write!(
            f,
            "height={}, gensig=...{}, account=...{}, seed=...{}, nonce={}, X={}, \
        quality={}",
            self.block_height,
            self.generation_signature
                .chars()
                .skip(56)
                .take(8)
                .collect::<String>(),
            if self.account_id.len() > 8 {
                self.account_id
                    .chars()
                    .skip(self.account_id.len() - 8)
                    .collect::<String>()
            } else {
                self.account_id.clone()
            },
            self.seed.chars().skip(56).take(8).collect::<String>(),
            self.nonce,
            self.compression,
            self.quality
        )
    }
}

// we know it's hard for some to serialise properly...
fn from_str_or_int<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct StringOrIntVisitor;

    impl<'de> de::Visitor<'de> for StringOrIntVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or int")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse::<u64>().map_err(de::Error::custom)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(v)
        }
    }

    deserializer.deserialize_any(StringOrIntVisitor)
}

fn from_str_or_int_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct StringOrIntU32Visitor;

    impl<'de> de::Visitor<'de> for StringOrIntU32Visitor {
        type Value = u32;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or int")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse::<u32>().map_err(de::Error::custom)
        }

        fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E> {
            Ok(v)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(v as u32)
        }
    }

    deserializer.deserialize_any(StringOrIntU32Visitor)
}

fn from_str_or_int_optional<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct OptionalStringOrIntVisitor;

    impl<'de> de::Visitor<'de> for OptionalStringOrIntVisitor {
        type Value = Option<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string, int, or null")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            from_str_or_int(deserializer).map(Some)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse::<u64>().map(Some).map_err(de::Error::custom)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v))
        }
    }

    deserializer.deserialize_option(OptionalStringOrIntVisitor)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionParameters {
    pub block_count: u64,
    pub quality_raw: u64,
    pub nonce_submission: NonceSubmission,
}

/// Useful for deciding which submission parameters are the newest and best.
/// We always cache the currently best submission parameters and on fail
/// resend them with an exponential backoff. In the meantime if we get better
/// parameters the old ones need to be replaced.
impl Ord for SubmissionParameters {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.block_count.cmp(&other.block_count) {
            std::cmp::Ordering::Equal => other.quality_raw.cmp(&self.quality_raw),
            other => other,
        }
    }
}

impl PartialOrd for SubmissionParameters {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
