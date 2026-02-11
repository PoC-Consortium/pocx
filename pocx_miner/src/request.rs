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
use tokio_util::sync::CancellationToken;
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
    /// Create a new RequestHandler with HTTP/HTTPS URL endpoint.
    pub fn new(
        url: Url,
        timeout: u64,
        auth_token: Option<String>,
        submission_mode: SubmissionMode,
        token: CancellationToken,
    ) -> RequestHandler {
        let client = ProtocolClient::new(url, timeout, auth_token)
            .expect("Failed to create protocol client");

        let (tx_submit_data, rx_submit_nonce_data) = mpsc::unbounded();

        let account_senders = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Route based on submission mode
        if submission_mode == SubmissionMode::Wallet {
            // Wallet mode: single global queue (PrioRetry keeps best quality globally)
            RequestHandler::start_wallet_handler(client.clone(), rx_submit_nonce_data, token);
        } else {
            // Pool mode: per-account queues
            RequestHandler::start_demultiplexer(
                client.clone(),
                rx_submit_nonce_data,
                account_senders.clone(),
                token,
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
        token: CancellationToken,
    ) {
        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    biased;

                    _ = token.cancelled() => {
                        log::info!("[SHUTDOWN] Demultiplexer task stopping");
                        break;
                    }

                    submission = rx.next() => {
                        match submission {
                            Some(submission) => {
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
                                            token.clone(),
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
                            None => break, // Channel closed
                        }
                    }
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
        token: CancellationToken,
    ) {
        let stream = PrioRetry::new(rx, Duration::from_secs(3));

        tokio::task::spawn(async move {
            let mut stream = Box::pin(stream);
            loop {
                tokio::select! {
                    biased;

                    _ = token.cancelled() => {
                        log::info!("[SHUTDOWN] Account handler for {} stopping", account_id);
                        break;
                    }

                    submission_params = stream.next() => {
                        match submission_params {
                            Some(submission_params) => {
                                match client
                                    .submit_nonce(&submission_params.nonce_submission)
                                    .await
                                {
                                    Ok(res) => {
                                        if res.raw_quality != submission_params.nonce_submission.raw_quality {
                                            warn!(
                                                "raw quality mismatch: submitted={}, server={}",
                                                submission_params.nonce_submission.raw_quality,
                                                res.raw_quality,
                                            );
                                        }
                                        log_submission_accepted(
                                            &submission_params.nonce_submission,
                                            res.poc_time,
                                        );
                                        let accepted = AcceptedDeadline {
                                            chain: submission_params.chain.clone(),
                                            account: submission_params.nonce_submission.account_id.clone(),
                                            height: submission_params.nonce_submission.block_height,
                                            nonce: submission_params.nonce_submission.nonce,
                                            quality_raw: submission_params.nonce_submission.raw_quality,
                                            compression: submission_params.nonce_submission.compression,
                                            poc_time: res.poc_time,
                                        };
                                        with_callback(|cb| cb.on_deadline_accepted(&accepted));
                                    }
                                    Err(FetchError::Pool(e)) => {
                                        // If pool sends empty message or "limit exceeded", they are
                                        // experiencing too much load - retry later
                                        if e.message.is_empty() || e.message == "limit exceeded" {
                                            log_server_busy(&submission_params.nonce_submission);
                                            let accepted = AcceptedDeadline {
                                                chain: submission_params.chain.clone(),
                                                account: submission_params.nonce_submission.account_id.clone(),
                                                height: submission_params.nonce_submission.block_height,
                                                nonce: submission_params.nonce_submission.nonce,
                                                quality_raw: submission_params.nonce_submission.raw_quality,
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
                                            let accepted = AcceptedDeadline {
                                                chain: submission_params.chain.clone(),
                                                account: submission_params.nonce_submission.account_id.clone(),
                                                height: submission_params.nonce_submission.block_height,
                                                nonce: submission_params.nonce_submission.nonce,
                                                quality_raw: submission_params.nonce_submission.raw_quality,
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
                                        let accepted = AcceptedDeadline {
                                            chain: submission_params.chain.clone(),
                                            account: submission_params.nonce_submission.account_id.clone(),
                                            height: submission_params.nonce_submission.block_height,
                                            nonce: submission_params.nonce_submission.nonce,
                                            quality_raw: submission_params.nonce_submission.raw_quality,
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
                            None => break, // Channel closed
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
        token: CancellationToken,
    ) {
        let stream = PrioRetry::new(rx, Duration::from_secs(3));

        tokio::task::spawn(async move {
            let mut stream = Box::pin(stream);
            loop {
                tokio::select! {
                    biased;

                    _ = token.cancelled() => {
                        log::info!("[SHUTDOWN] Wallet handler task stopping");
                        break;
                    }

                    submission_params = stream.next() => {
                        match submission_params {
                            Some(submission_params) => {
                                match client
                                    .submit_nonce(&submission_params.nonce_submission)
                                    .await
                                {
                                    Ok(res) => {
                                        if res.raw_quality != submission_params.nonce_submission.raw_quality {
                                            warn!(
                                                "raw quality mismatch: submitted={}, server={}",
                                                submission_params.nonce_submission.raw_quality,
                                                res.raw_quality,
                                            );
                                        }
                                        log_submission_accepted(
                                            &submission_params.nonce_submission,
                                            res.poc_time,
                                        );
                                        let accepted = AcceptedDeadline {
                                            chain: submission_params.chain.clone(),
                                            account: submission_params.nonce_submission.account_id.clone(),
                                            height: submission_params.nonce_submission.block_height,
                                            nonce: submission_params.nonce_submission.nonce,
                                            quality_raw: submission_params.nonce_submission.raw_quality,
                                            compression: submission_params.nonce_submission.compression,
                                            poc_time: res.poc_time,
                                        };
                                        with_callback(|cb| cb.on_deadline_accepted(&accepted));
                                    }
                                    Err(FetchError::Pool(e)) => {
                                        if e.message.is_empty() || e.message == "limit exceeded" {
                                            log_server_busy(&submission_params.nonce_submission);
                                            let accepted = AcceptedDeadline {
                                                chain: submission_params.chain.clone(),
                                                account: submission_params.nonce_submission.account_id.clone(),
                                                height: submission_params.nonce_submission.block_height,
                                                nonce: submission_params.nonce_submission.nonce,
                                                quality_raw: submission_params.nonce_submission.raw_quality,
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
                                            let accepted = AcceptedDeadline {
                                                chain: submission_params.chain.clone(),
                                                account: submission_params.nonce_submission.account_id.clone(),
                                                height: submission_params.nonce_submission.block_height,
                                                nonce: submission_params.nonce_submission.nonce,
                                                quality_raw: submission_params.nonce_submission.raw_quality,
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
                                        let accepted = AcceptedDeadline {
                                            chain: submission_params.chain.clone(),
                                            account: submission_params.nonce_submission.account_id.clone(),
                                            height: submission_params.nonce_submission.block_height,
                                            nonce: submission_params.nonce_submission.nonce,
                                            quality_raw: submission_params.nonce_submission.raw_quality,
                                            compression: submission_params.nonce_submission.compression,
                                            poc_time: u64::MAX,
                                        };
                                        with_callback(|cb| cb.on_deadline_retry(&accepted, &x.to_string()));
                                        // In wallet mode, we don't requeue - if mining continues,
                                        // a better quality will naturally replace this one
                                    }
                                }
                            }
                            None => break, // Channel closed
                        }
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
