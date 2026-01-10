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

use crate::callback::{with_callback, AcceptedDeadline};
use crate::com::api::{FetchError, MiningInfo, NonceSubmission, SubmissionParameters};
use crate::com::protocol_client::ProtocolClient;
use crate::future::prio_retry::PrioRetry;
use crate::miner::SubmissionMode;
use futures::channel::mpsc;
use futures::StreamExt;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

#[derive(Clone)]
pub struct RequestHandler {
    client: ProtocolClient,
    tx_submit_data: mpsc::UnboundedSender<SubmissionParameters>,
    // Per-account submission channels, used by demultiplexer for routing
    #[allow(dead_code)]
    account_senders: std::sync::Arc<
        std::sync::Mutex<HashMap<String, mpsc::UnboundedSender<SubmissionParameters>>>,
    >,
}

impl RequestHandler {
    pub fn new(
        url: Url,
        timeout: u64,
        auth_token: Option<String>,
        submission_mode: SubmissionMode,
    ) -> RequestHandler {
        let client = ProtocolClient::new(url, timeout, auth_token)
            .expect("Failed to create protocol client");

        let (tx_submit_data, rx_submit_nonce_data) = mpsc::unbounded();

        let account_senders = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Route based on submission mode
        if submission_mode == SubmissionMode::Wallet {
            // Wallet mode: single global queue (PrioRetry keeps best quality globally)
            RequestHandler::start_wallet_handler(client.clone(), rx_submit_nonce_data);
        } else {
            // Pool mode: per-account queues
            RequestHandler::start_demultiplexer(
                client.clone(),
                rx_submit_nonce_data,
                account_senders.clone(),
            );
        }

        RequestHandler {
            client,
            tx_submit_data,
            account_senders,
        }
    }

    /// Demultiplexer that routes submissions to per-account handlers
    fn start_demultiplexer(
        client: ProtocolClient,
        mut rx: mpsc::UnboundedReceiver<SubmissionParameters>,
        account_senders: std::sync::Arc<
            std::sync::Mutex<HashMap<String, mpsc::UnboundedSender<SubmissionParameters>>>,
        >,
    ) {
        tokio::task::spawn(async move {
            while let Some(submission) = rx.next().await {
                let account_id = submission.nonce_submission.account_id.clone();

                // Get or create sender for this account
                let tx = {
                    let mut senders = account_senders.lock().unwrap();
                    if let Some(tx) = senders.get(&account_id) {
                        tx.clone()
                    } else {
                        // Create new channel and handler for this account
                        let (tx, rx_account) = mpsc::unbounded();
                        senders.insert(account_id.clone(), tx.clone());

                        // Spawn handler for this account
                        RequestHandler::handle_account_submissions(
                            client.clone(),
                            rx_account,
                            account_id.clone(),
                            tx.clone(), // Requeue sender for retries
                        );

                        tx
                    }
                };

                // Route submission to account-specific handler
                if let Err(e) = tx.unbounded_send(submission) {
                    log::error!(
                        "Failed to route submission for account {}: {}",
                        account_id,
                        e
                    );
                }
            }
        });
    }

    /// Per-account submission handler with PrioRetry
    fn handle_account_submissions(
        client: ProtocolClient,
        rx: mpsc::UnboundedReceiver<SubmissionParameters>,
        account_id: String,
        requeue_tx: mpsc::UnboundedSender<SubmissionParameters>,
    ) {
        let stream = PrioRetry::new(rx, Duration::from_secs(3));

        tokio::task::spawn(async move {
            let mut stream = Box::pin(stream);
            while let Some(submission_params) = stream.next().await {
                match client
                    .submit_nonce(&submission_params.nonce_submission)
                    .await
                {
                    Ok(res) => {
                        if submission_params.nonce_submission.quality != res.quality_adjusted {
                            log_quality_mismatch(
                                &submission_params.nonce_submission,
                                res.quality_adjusted,
                            );
                        } else {
                            log_submission_accepted(
                                &submission_params.nonce_submission,
                                res.poc_time,
                            );
                            // Callback for deadline accepted
                            let accepted = AcceptedDeadline {
                                chain: submission_params.chain.clone(),
                                account: submission_params.nonce_submission.account_id.clone(),
                                height: submission_params.nonce_submission.block_height,
                                nonce: submission_params.nonce_submission.nonce,
                                quality_raw: submission_params.quality_raw,
                                compression: submission_params.nonce_submission.compression,
                                poc_time: res.poc_time,
                            };
                            with_callback(|cb| cb.on_deadline_accepted(&accepted));
                        }
                    }
                    Err(FetchError::Pool(e)) => {
                        // If pool sends empty message or "limit exceeded", they are
                        // experiencing too much load - retry later
                        if e.message.is_empty() || e.message == "limit exceeded" {
                            log_server_busy(&submission_params.nonce_submission);
                            // Callback for retry
                            let accepted = AcceptedDeadline {
                                chain: submission_params.chain.clone(),
                                account: submission_params.nonce_submission.account_id.clone(),
                                height: submission_params.nonce_submission.block_height,
                                nonce: submission_params.nonce_submission.nonce,
                                quality_raw: submission_params.quality_raw,
                                compression: submission_params.nonce_submission.compression,
                                poc_time: u64::MAX,
                            };
                            with_callback(|cb| cb.on_deadline_retry(&accepted, "server busy"));
                            // Requeue for retry with exponential backoff via PrioRetry
                            if let Err(send_err) = requeue_tx.unbounded_send(submission_params) {
                                log::error!(
                                    "Failed to requeue submission for account {}: {}",
                                    account_id,
                                    send_err
                                );
                            }
                        } else {
                            log_submission_not_accepted(
                                &submission_params.nonce_submission,
                                e.code,
                                &e.message,
                            );
                            // Callback for rejection
                            let accepted = AcceptedDeadline {
                                chain: submission_params.chain.clone(),
                                account: submission_params.nonce_submission.account_id.clone(),
                                height: submission_params.nonce_submission.block_height,
                                nonce: submission_params.nonce_submission.nonce,
                                quality_raw: submission_params.quality_raw,
                                compression: submission_params.nonce_submission.compression,
                                poc_time: u64::MAX,
                            };
                            with_callback(|cb| {
                                cb.on_deadline_rejected(&accepted, e.code, &e.message)
                            });
                        }
                    }
                    Err(FetchError::Http(x)) => {
                        log_submission_failed(&submission_params.nonce_submission, &x.to_string());
                        // Callback for retry
                        let accepted = AcceptedDeadline {
                            chain: submission_params.chain.clone(),
                            account: submission_params.nonce_submission.account_id.clone(),
                            height: submission_params.nonce_submission.block_height,
                            nonce: submission_params.nonce_submission.nonce,
                            quality_raw: submission_params.quality_raw,
                            compression: submission_params.nonce_submission.compression,
                            poc_time: u64::MAX,
                        };
                        with_callback(|cb| cb.on_deadline_retry(&accepted, &x.to_string()));
                        // Requeue for retry with exponential backoff via PrioRetry
                        if let Err(send_err) = requeue_tx.unbounded_send(submission_params) {
                            log::error!(
                                "Failed to requeue submission for account {}: {}",
                                account_id,
                                send_err
                            );
                        }
                    }
                }
            }
        });
    }

    /// Wallet mode: single global queue handler (global best quality via PrioRetry's Ord)
    fn start_wallet_handler(
        client: ProtocolClient,
        rx: mpsc::UnboundedReceiver<SubmissionParameters>,
    ) {
        let stream = PrioRetry::new(rx, Duration::from_secs(3));

        tokio::task::spawn(async move {
            let mut stream = Box::pin(stream);
            while let Some(submission_params) = stream.next().await {
                match client
                    .submit_nonce(&submission_params.nonce_submission)
                    .await
                {
                    Ok(res) => {
                        if submission_params.nonce_submission.quality != res.quality_adjusted {
                            log_quality_mismatch(
                                &submission_params.nonce_submission,
                                res.quality_adjusted,
                            );
                        } else {
                            log_submission_accepted(
                                &submission_params.nonce_submission,
                                res.poc_time,
                            );
                            // Callback for deadline accepted
                            let accepted = AcceptedDeadline {
                                chain: submission_params.chain.clone(),
                                account: submission_params.nonce_submission.account_id.clone(),
                                height: submission_params.nonce_submission.block_height,
                                nonce: submission_params.nonce_submission.nonce,
                                quality_raw: submission_params.quality_raw,
                                compression: submission_params.nonce_submission.compression,
                                poc_time: res.poc_time,
                            };
                            with_callback(|cb| cb.on_deadline_accepted(&accepted));
                        }
                    }
                    Err(FetchError::Pool(e)) => {
                        if e.message.is_empty() || e.message == "limit exceeded" {
                            log_server_busy(&submission_params.nonce_submission);
                            // Callback for retry (even though we don't requeue in wallet mode)
                            let accepted = AcceptedDeadline {
                                chain: submission_params.chain.clone(),
                                account: submission_params.nonce_submission.account_id.clone(),
                                height: submission_params.nonce_submission.block_height,
                                nonce: submission_params.nonce_submission.nonce,
                                quality_raw: submission_params.quality_raw,
                                compression: submission_params.nonce_submission.compression,
                                poc_time: u64::MAX,
                            };
                            with_callback(|cb| cb.on_deadline_retry(&accepted, "server busy"));
                            // In wallet mode, we don't requeue - PrioRetry keeps best quality
                            // and newer better items replace this one naturally
                        } else {
                            log_submission_not_accepted(
                                &submission_params.nonce_submission,
                                e.code,
                                &e.message,
                            );
                            // Callback for rejection
                            let accepted = AcceptedDeadline {
                                chain: submission_params.chain.clone(),
                                account: submission_params.nonce_submission.account_id.clone(),
                                height: submission_params.nonce_submission.block_height,
                                nonce: submission_params.nonce_submission.nonce,
                                quality_raw: submission_params.quality_raw,
                                compression: submission_params.nonce_submission.compression,
                                poc_time: u64::MAX,
                            };
                            with_callback(|cb| {
                                cb.on_deadline_rejected(&accepted, e.code, &e.message)
                            });
                        }
                    }
                    Err(FetchError::Http(x)) => {
                        log_submission_failed(&submission_params.nonce_submission, &x.to_string());
                        // Callback for retry
                        let accepted = AcceptedDeadline {
                            chain: submission_params.chain.clone(),
                            account: submission_params.nonce_submission.account_id.clone(),
                            height: submission_params.nonce_submission.block_height,
                            nonce: submission_params.nonce_submission.nonce,
                            quality_raw: submission_params.quality_raw,
                            compression: submission_params.nonce_submission.compression,
                            poc_time: u64::MAX,
                        };
                        with_callback(|cb| cb.on_deadline_retry(&accepted, &x.to_string()));
                        // In wallet mode, we don't requeue - if mining continues,
                        // a better quality will naturally replace this one
                    }
                }
            }
        });
    }

    pub async fn get_mining_info(&self) -> Result<MiningInfo, FetchError> {
        self.client.get_mining_info().await
    }

    pub fn submit_nonce(&self, submission_parameters: SubmissionParameters) {
        self.tx_submit_data
            .unbounded_send(submission_parameters)
            .unwrap();
    }
}

fn log_quality_mismatch(nonce_submission: &NonceSubmission, quality_feedback: u64) {
    error!(
        "quality mismatch: {}, \
         quality_server={}",
        nonce_submission, quality_feedback
    );
}

fn log_submission_failed(nonce_submission: &NonceSubmission, err: &str) {
    warn!(
        "{: <80}",
        format!(
            "submission failed, retrying: {}, \
             description={}",
            nonce_submission, err
        )
    );
}

fn log_submission_not_accepted(nonce_submission: &NonceSubmission, err_code: i32, msg: &str) {
    error!(
        "submission not accepted: {}\n\tcode: {}\n\tmessage: {}",
        nonce_submission, err_code, msg,
    );
}

fn log_submission_accepted(nonce_submission: &NonceSubmission, poc_time: u64) {
    if poc_time == u64::MAX {
        // No poc_time provided (default value)
        info!("accepted: {}", nonce_submission);
    } else if poc_time < 86400 {
        info!("accepted: {}, time={}", nonce_submission, poc_time);
    } else {
        info!("accepted: {}, time=∞", nonce_submission);
    }
}

fn log_server_busy(nonce_submission: &NonceSubmission) {
    info!("server busy, retrying: {}", nonce_submission,);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::com::api::NonceSubmission;
    use url::Url;

    #[tokio::test]
    async fn test_request_handler_creation() {
        let url = Url::parse("http://localhost:8080").unwrap();
        let timeout = 5000;

        let handler = RequestHandler::new(url, timeout, None, SubmissionMode::Pool);

        // Verify handler was created (struct exists)
        let _ = &handler.client;
        let _ = &handler.tx_submit_data;
    }

    #[tokio::test]
    async fn test_request_handler_with_auth() {
        let url = Url::parse("http://localhost:8080").unwrap();
        let timeout = 5000;
        let auth_token = Some("user:password".to_string());

        let handler = RequestHandler::new(url, timeout, auth_token, SubmissionMode::Pool);

        // Verify handler was created with auth
        let _ = &handler.client;
        let _ = &handler.tx_submit_data;
    }

    #[tokio::test]
    async fn test_request_handler_wallet_mode() {
        let url = Url::parse("http://localhost:8080").unwrap();
        let timeout = 5000;

        let handler = RequestHandler::new(url, timeout, None, SubmissionMode::Wallet);

        // Verify handler was created in wallet mode
        let _ = &handler.client;
        let _ = &handler.tx_submit_data;
    }

    #[tokio::test]
    async fn test_nonce_submission_parameters() {
        let handler = RequestHandler::new(
            Url::parse("http://localhost:8080").unwrap(),
            5000,
            None,
            SubmissionMode::Pool,
        );

        // Create test submission parameters
        let nonce_submission = NonceSubmission {
            block_height: 100,
            generation_signature: "test_signature".to_string(),
            account_id: "POCX-test-address".to_string(),
            seed: "test_seed".to_string(),
            nonce: 67890,
            quality: 300,
            compression: 4,
        };

        let submission_params = SubmissionParameters {
            chain: "Test Chain".to_string(),
            nonce_submission,
            block_count: 100,
            quality_raw: 500,
        };

        // Test that submit_nonce doesn't panic
        handler.submit_nonce(submission_params);
    }

    #[test]
    fn test_log_quality_mismatch() {
        let nonce_submission = NonceSubmission {
            block_height: 100,
            generation_signature: "test_signature".to_string(),
            account_id: "POCX-test-address".to_string(),
            seed: "test_seed".to_string(),
            nonce: 67890,
            quality: 300,
            compression: 4,
        };

        // Test that logging function doesn't panic
        log_quality_mismatch(&nonce_submission, 350);
        log_quality_mismatch(&nonce_submission, 0);
        log_quality_mismatch(&nonce_submission, u64::MAX);
    }

    #[test]
    fn test_log_submission_failed() {
        let nonce_submission = NonceSubmission {
            block_height: 100,
            generation_signature: "test_signature".to_string(),
            account_id: "POCX-test-address".to_string(),
            seed: "test_seed".to_string(),
            nonce: 67890,
            quality: 300,
            compression: 4,
        };

        // Test logging with various error messages
        log_submission_failed(&nonce_submission, "Network timeout");
        log_submission_failed(&nonce_submission, "Connection refused");
        log_submission_failed(&nonce_submission, "");
        log_submission_failed(&nonce_submission, "Very long error message that should be handled properly without causing issues in the logging system");
    }

    #[test]
    fn test_log_submission_not_accepted() {
        let nonce_submission = NonceSubmission {
            block_height: 100,
            generation_signature: "test_signature".to_string(),
            account_id: "POCX-test-address".to_string(),
            seed: "test_seed".to_string(),
            nonce: 67890,
            quality: 300,
            compression: 4,
        };

        // Test logging with various error codes and messages
        log_submission_not_accepted(&nonce_submission, 400, "Bad request");
        log_submission_not_accepted(&nonce_submission, 500, "Internal server error");
        log_submission_not_accepted(&nonce_submission, -1, "Invalid error code");
        log_submission_not_accepted(&nonce_submission, 0, "");
    }

    #[test]
    fn test_log_submission_accepted() {
        let nonce_submission = NonceSubmission {
            block_height: 100,
            generation_signature: "test_signature".to_string(),
            account_id: "POCX-test-address".to_string(),
            seed: "test_seed".to_string(),
            nonce: 67890,
            quality: 300,
            compression: 4,
        };

        // Test that accepted logging works
        log_submission_accepted(&nonce_submission, 0); // No time display
        log_submission_accepted(&nonce_submission, 240); // Normal time
        log_submission_accepted(&nonce_submission, 86400); // Infinity symbol
    }

    #[test]
    fn test_log_server_busy() {
        let nonce_submission = NonceSubmission {
            block_height: 100,
            generation_signature: "test_signature".to_string(),
            account_id: "POCX-test-address".to_string(),
            seed: "test_seed".to_string(),
            nonce: 67890,
            quality: 300,
            compression: 4,
        };

        // Test that server busy logging works
        log_server_busy(&nonce_submission);
    }

    #[tokio::test]
    async fn test_url_validation() {
        // Test various URL formats
        let valid_urls = [
            "http://localhost:8080",
            "https://pool.example.com",
            "http://192.168.1.1:8080",
            "https://pool.example.com:443/path",
        ];

        for url_str in &valid_urls {
            let url = Url::parse(url_str);
            assert!(url.is_ok(), "Should parse valid URL: {}", url_str);

            if let Ok(parsed_url) = url {
                let handler = RequestHandler::new(parsed_url, 5000, None, SubmissionMode::Pool);
                let _ = &handler.client;
            }
        }
    }

    #[tokio::test]
    async fn test_timeout_values() {
        let url = Url::parse("http://localhost:8080").unwrap();
        let timeout_values = [1000, 5000, 10000, 30000, 60000];

        for &timeout in &timeout_values {
            let handler = RequestHandler::new(url.clone(), timeout, None, SubmissionMode::Pool);

            // Verify handler creation with different timeout values
            let _ = &handler.client;
            let _ = &handler.tx_submit_data;
        }
    }
}
