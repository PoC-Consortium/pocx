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

use crate::buffer::PageAlignedByteBuffer;
use crate::com::api::SubmissionParameters;
use crate::com::api::{FetchError, MiningInfo};
use crate::config::{Benchmark, Cfg};
use crate::hasher::calc_qualities;
use crate::hasher::HashingTask;
use crate::plots::{CompressionConfig, PoCXArray};
use crate::plots::{ResumeInfo, ScanMessage};
use crate::request::RequestHandler;
use crate::utils::new_thread_pool;
#[cfg(windows)]
use crate::utils::set_thread_ideal_processor;

use bytesize::ByteSize;
use serde::{Deserialize, Serialize};

mod url_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use url::Url;

    pub fn serialize<S>(url: &Url, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        url.as_str().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Url, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Url::parse(&s).map_err(serde::de::Error::custom)
    }
}

use crate::future::interval::Interval;
use crossbeam_channel::bounded;
use crossbeam_channel::{Receiver, Sender};
use futures::channel::mpsc;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use pocx_plotfile::{NUM_SCOOPS, SCOOP_SIZE};
use priority_queue::PriorityQueue;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::task;
use url::Url;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SubmissionMode {
    #[default]
    Pool, // Per-account tracking and submission (pool mining)
    Wallet, // Global best tracking and submission (solo mining)
}

fn default_submission_mode() -> SubmissionMode {
    SubmissionMode::Pool
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChainAccount {
    pub account: String,
    #[serde(default)]
    pub target_quality: Option<u64>, // Account-specific quality limit
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Chain {
    pub name: String,
    #[serde(with = "url_serde")]
    pub base_url: Url,
    pub api_path: String,
    #[serde(default = "default_block_time")]
    pub block_time_seconds: u64,
    #[serde(default)]
    pub auth_token: Option<String>, // Bearer token for JSON-RPC authentication
    #[serde(default)]
    pub target_quality: Option<u64>, // Chain-level quality limit
    #[serde(default)]
    pub headers: HashMap<String, String>, // Chain-level headers
    #[serde(default)]
    pub accounts: Vec<ChainAccount>, // Per-account overrides
    #[serde(default = "default_submission_mode")]
    pub submission_mode: SubmissionMode, // Pool vs Wallet submission strategy
}

fn default_block_time() -> u64 {
    120 // Default to 2 minutes
}

/// Calculate genesis base target for a given block time
pub fn genesis_base_target(block_time: u64) -> u64 {
    2u64.pow(42) / block_time
}

/// Calculate estimated network capacity from base target and block time
pub fn calculate_network_capacity(base_target: u64, block_time: u64) -> String {
    let genesis_base_target = genesis_base_target(block_time);
    let capacity_ratio = genesis_base_target as f64 / base_target as f64;
    let capacity_bytes = capacity_ratio * (1u64 << 40) as f64;
    ByteSize::b(capacity_bytes as u64).to_string()
}

pub struct Miner {
    miner_state: Arc<Mutex<MinerState>>,
    channels: Channels,
    get_mining_info_interval: u64,
    chains: Vec<Chain>,
    chain_states: Vec<Arc<Mutex<ChainState>>>,
    plots: Arc<PoCXArray>,
    request_handler: Vec<RequestHandler>,
    reader_thread_pool: Arc<rayon::ThreadPool>,
    rx_scheduler: Option<UnboundedReceiver<SchedulerMessage>>,
    known_account_payloads: Vec<String>, // Hex payloads from plot files
    cfg: Cfg,                            // Store config for target quality access
    rx_nonce_data: Option<UnboundedReceiver<(usize, SubmissionParameters)>>,
    benchmark: Option<Benchmark>,
    hdd_wakeup_after: i64,      // HDD wakeup interval in seconds
    max_compression_steps: u32, // Maximum compression steps based on buffer size
}

pub struct DecodedMiningInfo {
    generation_signature_bytes: [u8; 32],
    scoop: u64,
}

#[derive(Clone)]
pub struct Channels {
    pub tx_empty_buffer: Sender<PageAlignedByteBuffer>,
    pub rx_empty_buffer: Receiver<PageAlignedByteBuffer>,
    pub tx_scheduler: UnboundedSender<SchedulerMessage>,
    pub tx_nonce_data: UnboundedSender<(usize, SubmissionParameters)>,
}

#[derive(Clone, Debug, Default)]
pub struct ChainState {
    generation_signature: String,
    block_hash: String,
    outage: bool,
    account_id_to_best_quality: HashMap<String, u64>,
    account_id_to_target_quality: HashMap<String, u64>,
    block: u64,
    submission_mode: SubmissionMode,
}

impl ChainState {
    fn update_mining_info(
        &mut self,
        mining_info: &MiningInfo,
        _chain_name: &str,
        chain_target_quality: Option<u64>,
        chain_accounts: &[ChainAccount], // Chain account configurations
        known_account_payloads: &[String], // Hex payloads from plot files
        submission_mode: SubmissionMode,
    ) {
        self.generation_signature = mining_info.generation_signature.clone();
        self.block_hash = mining_info.block_hash.clone();
        self.submission_mode = submission_mode;

        // Reset best qualities for new block
        for best_quality in self.account_id_to_best_quality.values_mut() {
            *best_quality = u64::MAX;
        }

        for account_payload in known_account_payloads {
            let account_target = chain_accounts
                .iter()
                .find(|acc| acc.account == *account_payload)
                .and_then(|acc| acc.target_quality)
                .unwrap_or(u64::MAX);

            let chain_target = chain_target_quality.unwrap_or(u64::MAX);
            let pool_target = mining_info.target_quality.unwrap_or(u64::MAX);
            let effective_target = account_target.min(chain_target).min(pool_target);

            self.account_id_to_target_quality
                .insert(account_payload.clone(), effective_target);
        }

        self.block += 1;
    }
}

// All variants relate to blockchain block processing, naming is intentional
#[allow(clippy::enum_variant_names)]
pub enum SchedulerMessage {
    ScheduleNewBlock {
        chain_id: usize,
        mining_info: MiningInfo,
        initial: bool,
    },
    RescheduleBlock {
        chain_id: usize,
        mining_info: MiningInfo,
        resume_info: ResumeInfo,
    },
    ProcessBlock,
}

#[derive(Default)]
pub struct MinerState {
    start_time: Option<Instant>,
    scanning: bool,
    chain_id: usize,
    block: u64,
    prio: usize,
    name: String,
    generation_signature: String,
    pub interrupt: bool,
    pub pause: bool,
    next_wakeup_at: Option<std::time::Instant>, // When next HDD wakeup should occur
}

impl DecodedMiningInfo {
    fn new(mining_info: &MiningInfo) -> Self {
        // do the math
        let generation_signature_bytes =
            pocx_hashlib::decode_generation_signature(&mining_info.generation_signature)
                .expect("Failed to decode generation signature");

        let scoop = pocx_hashlib::calculate_scoop(mining_info.height, &generation_signature_bytes);
        Self {
            generation_signature_bytes,
            scoop,
        }
    }
}

impl MinerState {
    fn new() -> Self {
        Default::default()
    }

    fn update_state(
        &mut self,
        chain_id: usize,
        block: u64,
        prio: usize,
        name: String,
        generation_signature: String,
    ) {
        self.start_time = Some(Instant::now());
        self.scanning = true;
        self.chain_id = chain_id;
        self.block = block;
        self.prio = prio;
        self.name = name;
        self.interrupt = false;
        self.pause = false;
        self.generation_signature = generation_signature;
    }
}

// Validate compression capabilities at startup
fn validate_compression_setup(cfg: &Cfg) -> Result<u32, String> {
    if !cfg.enable_on_the_fly_compression {
        return Ok(0); // No compression, no validation needed
    }

    // Check if power of 2
    if cfg.hdd_read_cache_in_warps & (cfg.hdd_read_cache_in_warps - 1) != 0 {
        return Err(format!(
            "hdd_read_cache_in_warps ({}) must be power of 2 for compression (2, 4, 8, 16, 32, ...)",
            cfg.hdd_read_cache_in_warps
        ));
    }

    let max_compression_steps = (cfg.hdd_read_cache_in_warps as f64).log2().floor() as u32;

    info!(
        "On-the-fly compression enabled. Buffer size: {} warps, max compression steps: {}",
        cfg.hdd_read_cache_in_warps, max_compression_steps
    );

    Ok(max_compression_steps)
}

impl Miner {
    pub fn new(cfg: Cfg) -> Miner {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let cpu_name = {
            let cpuid = raw_cpuid::CpuId::new();
            cpuid
                .get_processor_brand_string()
                .map(|pbs| pbs.as_str().trim().to_string())
                .unwrap_or_else(|| "Unknown CPU".to_string())
        };

        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        let cpu_name = "ARM/Other CPU".to_string();

        let cpu_threads = if cfg.cpu_threads == 0 {
            num_cpus::get()
        } else {
            cfg.cpu_threads
        };

        info!(
            "CPU: {} [using {} of {} cores + {}]",
            cpu_name,
            cpu_threads,
            num_cpus::get(),
            crate::utils::get_simd_name()
        );

        let thread_pinning = cfg.cpu_thread_pinning;
        let core_ids = if thread_pinning {
            core_affinity::get_core_ids().unwrap()
        } else {
            Vec::new()
        };
        rayon::ThreadPoolBuilder::new()
            .num_threads(cpu_threads)
            .start_handler(move |id| {
                if thread_pinning {
                    #[cfg(not(windows))]
                    let core_id = core_ids[id % core_ids.len()];
                    #[cfg(not(windows))]
                    core_affinity::set_for_current(core_id);
                    #[cfg(windows)]
                    set_thread_ideal_processor(id % core_ids.len());
                }
            })
            .build_global()
            .unwrap();

        let mut chain_states = Vec::new();
        let mut request_handler = Vec::new();
        info!("Chain Configuration:");
        for (i, chain) in cfg.chains.iter().enumerate() {
            info!(
                "Priority {} : ({}) {}",
                i + 1,
                chain.name,
                chain
                    .base_url
                    .join(&chain.api_path)
                    .expect("error parsing server url")
            );
            chain_states.push(Arc::new(Mutex::new(ChainState::default())));

            let chain_specific_headers = cfg.chains[i].headers.clone();

            request_handler.push(RequestHandler::new(
                cfg.chains[i].base_url.clone(),
                cfg.chains[i].api_path.clone(),
                cfg.timeout,
                chain_specific_headers,
                cfg.chains[i].accounts.clone(),
                cfg.chains[i].auth_token.clone(),
                cfg.chains[i].submission_mode.clone(),
            ));
        }

        let dummy_io = matches!(cfg.benchmark, Some(Benchmark::Cpu));
        if dummy_io {
            info!("BENCHMARK MODE: CPU");
        }
        let plots = PoCXArray::new(&cfg.plot_dirs, cfg.hdd_use_direct_io, dummy_io);

        let mut known_account_payloads = std::collections::HashSet::new();
        for disk in plots.disks.values() {
            let disk = disk.lock().unwrap();
            let plots_in_disk = disk.plots.lock().unwrap();
            for plot in plots_in_disk.iter() {
                let plot = plot.lock().unwrap();
                known_account_payloads.insert(hex::encode(plot.meta.base58_decoded));
            }
        }
        let known_account_payloads: Vec<String> = known_account_payloads.into_iter().collect();

        let max_compression_steps = validate_compression_setup(&cfg).unwrap_or_else(|e| {
            error!("Configuration error: {}", e);
            std::process::exit(1);
        });

        let reader_thread_pool =
            Arc::new(new_thread_pool(plots.disks.len(), cfg.cpu_thread_pinning));

        let num_write_buffers = plots.disks.len() * 2;
        let (tx_empty_buffer, rx_empty_buffer) = bounded(num_write_buffers);
        for _ in 0..num_write_buffers {
            tx_empty_buffer
                .try_send(PageAlignedByteBuffer::new(
                    (cfg.hdd_read_cache_in_warps * NUM_SCOOPS * SCOOP_SIZE) as usize,
                ))
                .unwrap();
        }

        let (tx_scheduler, rx_scheduler) = mpsc::unbounded();
        let (tx_nonce_data, rx_nonce_data) = mpsc::unbounded();

        let channels = Channels {
            tx_empty_buffer,
            rx_empty_buffer,
            tx_scheduler,
            tx_nonce_data,
        };

        Miner {
            miner_state: Arc::new(Mutex::new(MinerState::new())),
            channels,
            get_mining_info_interval: cfg.get_mining_info_interval,
            chains: cfg.chains.clone(),
            chain_states,
            plots: Arc::new(plots),
            request_handler,
            reader_thread_pool,
            rx_scheduler: Some(rx_scheduler),
            known_account_payloads,
            benchmark: cfg.benchmark.clone(),
            hdd_wakeup_after: cfg.hdd_wakeup_after,
            max_compression_steps,
            cfg,
            rx_nonce_data: Some(rx_nonce_data),
        }
    }

    fn get_inital_mining_infos(&self) {
        let (tx_done, rx_done) = bounded(self.chains.len());
        for (i, chain) in self.chains.iter().enumerate() {
            let request_handler = self.request_handler.clone();
            let chain_state = self.chain_states[i].clone();
            let chain = chain.clone();
            let tx_scheduler = self.channels.tx_scheduler.clone();
            let tx_done = tx_done.clone();

            // Capture values needed for update_mining_info
            let chain_name = chain.name.clone();
            let chain_target_quality = chain.target_quality;
            let chain_accounts = chain.accounts.clone();
            let submission_mode = chain.submission_mode.clone();
            let known_accounts = self.known_account_payloads.clone();
            task::spawn(async move {
                let mining_info = request_handler[i]
                    .get_mining_info(chain.base_url.clone(), &chain.api_path)
                    .await;
                let mut state = chain_state.lock().unwrap();
                match mining_info {
                    Ok(mining_info) => {
                        if mining_info.block_hash != state.block_hash {
                            state.update_mining_info(
                                &mining_info,
                                &chain_name,
                                chain_target_quality,
                                &chain_accounts,
                                &known_accounts,
                                submission_mode,
                            );
                            // schedule block
                            tx_scheduler
                                .unbounded_send(SchedulerMessage::ScheduleNewBlock {
                                    chain_id: i,
                                    mining_info,
                                    initial: true,
                                })
                                .expect("failed to schedule block");
                        }
                    }
                    _ => {
                        state.outage = true;
                        log::error!(
                            "{: <80}",
                            format!(
                                "[{}], error getting mining info, please check server config",
                                chain.name
                            )
                        );
                    }
                }
                tx_done.send(true).unwrap();
            });
        }

        // await initial mining infos
        for _ in 0..self.chains.len() {
            rx_done.recv().unwrap();
        }

        // trigger mining
        self.channels
            .tx_scheduler
            .clone()
            .unbounded_send(SchedulerMessage::ProcessBlock)
            .expect("failed to communicate with scheduler task");
    }

    fn create_mining_info_tasks(&self) {
        for (i, chain) in self.chains.iter().enumerate() {
            let request_handler = self.request_handler.clone();
            let chain_state = self.chain_states[i].clone();
            let chain = chain.clone();
            let tx_scheduler = self.channels.tx_scheduler.clone();
            let get_mining_info_interval = self.get_mining_info_interval;

            // Capture values needed for update_mining_info
            let chain_name = chain.name.clone();
            let chain_target_quality = chain.target_quality;
            let chain_accounts = chain.accounts.clone();
            let submission_mode = chain.submission_mode.clone();
            let known_accounts = self.known_account_payloads.clone();
            task::spawn(async move {
                let mut interval_stream =
                    Interval::new_interval(Duration::from_millis(get_mining_info_interval));
                while (StreamExt::next(&mut interval_stream).await).is_some() {
                    let mining_info = request_handler[i]
                        .get_mining_info(chain.base_url.clone(), &chain.api_path)
                        .await;
                    let mut state = chain_state.lock().unwrap();
                    match mining_info {
                        Ok(mining_info) => {
                            if state.outage {
                                log::error!(
                                    "{: <80}",
                                    format!("[{}]: outage resolved.", chain.name)
                                );
                                state.outage = false;
                            }
                            if mining_info.block_hash != state.block_hash {
                                state.update_mining_info(
                                    &mining_info,
                                    &chain_name,
                                    chain_target_quality,
                                    &chain_accounts,
                                    &known_accounts,
                                    submission_mode.clone(),
                                );
                                // schedule block
                                tx_scheduler
                                    .unbounded_send(SchedulerMessage::ScheduleNewBlock {
                                        chain_id: i,
                                        mining_info,
                                        initial: false,
                                    })
                                    .expect("failed to schedule block");
                            }
                        }
                        Err(err) => {
                            match err {
                                FetchError::Pool(e) => {
                                    log::error!("{}:{}", e.code, e.message);
                                }
                                FetchError::Http(e) => {
                                    log::error!("{:?}", e);
                                }
                            }
                            if !state.outage {
                                log::error!(
                                    "{: <80}",
                                    format!(
                                        "[{}], error getting mining info => connection outage...",
                                        chain.name
                                    )
                                );
                            }
                            state.outage = true;
                        }
                    }
                }
            });
        }
    }

    fn create_scheduler_task(&mut self) {
        let pq = Arc::new(Mutex::new(PriorityQueue::new()));
        // chain_info and mining_info store
        let mut mining_infos = Vec::new();
        let mut resume_states: Vec<Option<ResumeInfo>> = Vec::new();
        for _ in 0..self.chains.len() {
            mining_infos.push(MiningInfo::default());
            resume_states.push(None);
        }
        // move executor out of self and schedule a thread consuming self
        let scheduler_rx = self.rx_scheduler.take().unwrap();
        let chains = self.chains.clone();
        let miner_state = self.miner_state.clone();
        let chain_states = self.chain_states.clone();
        let tx_scheduler = self.channels.tx_scheduler.clone();
        let plots = self.plots.clone();
        let channels = self.channels.clone();
        let reader_thread_pool = self.reader_thread_pool.clone();
        let benchmark = self.benchmark.clone();
        let cfg = self.cfg.clone();
        let max_compression_steps = self.max_compression_steps;
        task::spawn(async move {
            let mut mining_infos = mining_infos;
            let mut resume_states = resume_states;
            let mut scheduler_rx = scheduler_rx;
            while let Some(message) = StreamExt::next(&mut scheduler_rx).await {
                match message {
                    SchedulerMessage::ScheduleNewBlock {
                        chain_id,
                        mining_info,
                        initial,
                    } => {
                        let pq = pq.clone();
                        let mut pq = pq.lock().unwrap();
                        if pq.push(chain_id, chains.len() - chain_id).is_some() {
                            let resume_info = resume_states[chain_id].take();
                            let progress_precentage = if let Some(i) = resume_info {
                                i.warps_scanned as f64 / i.total_warps as f64 * 100.0
                            } else {
                                0.0
                            };
                            warn!(
                                "{: <80}",
                                format!(
                                    "unfinished : [{}:{}:{:.2}%], gensig=...{}, base_target={}",
                                    chains[chain_id].name,
                                    mining_infos[chain_id].height,
                                    progress_precentage,
                                    &mining_infos[chain_id].generation_signature[mining_infos
                                        [chain_id]
                                        .generation_signature
                                        .len()
                                        .saturating_sub(8)..],
                                    mining_infos[chain_id].base_target,
                                )
                            );
                        }
                        mining_infos[chain_id] = mining_info;
                        resume_states[chain_id] = None;

                        // *** CANCEL WAKEUP - NEW WORK ARRIVED ***
                        {
                            let mut mut_state = miner_state.lock().unwrap();
                            mut_state.next_wakeup_at = None;
                        }
                        let network_capacity = calculate_network_capacity(
                            mining_infos[chain_id].base_target,
                            chains[chain_id].block_time_seconds,
                        );
                        info!(
                            "{: <80}",
                            format!(
                                "new block  : [{}:{}], gensig=...{}, base_target={}, network_capacity={}, {}",
                                chains[chain_id].name,
                                mining_infos[chain_id].height,
                                &mining_infos[chain_id].generation_signature[mining_infos[chain_id].generation_signature.len().saturating_sub(8)..],
                                mining_infos[chain_id].base_target,
                                network_capacity,
                                if mining_infos[chain_id].minimum_compression_level == mining_infos[chain_id].target_compression_level {
                                    format!("POCX{}", mining_infos[chain_id].minimum_compression_level)
                                } else {
                                    format!("POCX{}-POCX{}", mining_infos[chain_id].minimum_compression_level, mining_infos[chain_id].target_compression_level)
                                },
                            )
                        );
                        // trigger mining
                        if !initial {
                            tx_scheduler
                                .clone()
                                .unbounded_send(SchedulerMessage::ProcessBlock)
                                .expect("failed to communicate with scheduler task");
                        }
                    }
                    SchedulerMessage::RescheduleBlock {
                        chain_id,
                        mining_info,
                        resume_info,
                    } => {
                        let pq = pq.clone();
                        let mut pq = pq.lock().unwrap();
                        // only reschedule if no new block in the meantime
                        if pq.get_priority(&chain_id).is_none() {
                            pq.push(chain_id, chains.len() - chain_id);
                            mining_infos[chain_id] = mining_info;
                            resume_states[chain_id] = Some(resume_info);

                            // *** CANCEL WAKEUP - WORK RESCHEDULED ***
                            {
                                let mut mut_state = miner_state.lock().unwrap();
                                mut_state.next_wakeup_at = None;
                            }
                            info!(
                                "{: <80}",
                                format!(
                                    "rescheduled: [{}:{}], gensig={}, base_target={}",
                                    chains[chain_id].name,
                                    mining_infos[chain_id].height,
                                    mining_infos[chain_id].generation_signature,
                                    mining_infos[chain_id].base_target,
                                )
                            );
                        } else {
                            // rare case: while pausing chain a new block arrived
                            warn!(
                                "{: <80}",
                                format!(
                                    "unfinished : [{}:{}:{:.2}%], gensig=...{}, base_target={}",
                                    chains[chain_id].name,
                                    mining_info.height,
                                    resume_info.warps_scanned as f64
                                        / resume_info.total_warps as f64
                                        * 100.0,
                                    &mining_info.generation_signature[mining_info
                                        .generation_signature
                                        .len()
                                        .saturating_sub(8)..],
                                    mining_info.base_target,
                                )
                            );
                        }
                        // trigger mining
                        tx_scheduler
                            .clone()
                            .unbounded_send(SchedulerMessage::ProcessBlock)
                            .expect("failed to communicate with scheduler task");
                    }
                    SchedulerMessage::ProcessBlock => {
                        let pq = pq.clone();
                        let mut pq = pq.lock().unwrap();

                        if pq.is_empty() {
                            info!("queue      : [] waiting for new block...");
                        } else {
                            let mut queue: String = "queue      : ".to_owned();
                            for (item, _) in pq.clone().into_sorted_iter() {
                                let percentage_processed =
                                    if let Some(i) = resume_states[item].as_ref() {
                                        i.warps_scanned as f64 / i.total_warps as f64 * 100.0
                                    } else {
                                        0.0
                                    };
                                queue.push_str(&format!(
                                    "[{}:{}]:{:.2}%>",
                                    chains[item].name,
                                    mining_infos[item].height,
                                    percentage_processed,
                                ));
                            }
                            info!("{}", queue);
                        }

                        // trigger mining
                        let mut mut_state = miner_state.lock().unwrap();
                        if !mut_state.scanning {
                            // get item with highest prio
                            if let Some((chain_id, prio)) = pq.pop() {
                                // *** WORK IS STARTING - CANCEL WAKEUP ***
                                mut_state.next_wakeup_at = None;

                                let mining_info = mining_infos[chain_id].clone();
                                let decoded_mining_info = DecodedMiningInfo::new(&mining_info);
                                let chain_state = chain_states[chain_id].lock().unwrap();
                                let block = chain_state.block;
                                mut_state.update_state(
                                    chain_id,
                                    block,
                                    prio,
                                    chains[chain_id].name.clone(),
                                    mining_info.generation_signature.clone(),
                                );
                                drop(mut_state);

                                info!(
                                    "{: <80}",
                                    format!(
                                        "{}   : [{}:{}], gensig={}, base_target={}, scoop={:04}",
                                        if resume_states[chain_id].is_some() {
                                            "resuming"
                                        } else {
                                            "scanning"
                                        },
                                        chains[chain_id].name,
                                        mining_info.height,
                                        mining_info.generation_signature,
                                        mining_info.base_target,
                                        decoded_mining_info.scoop,
                                    )
                                );
                                // thread spawn
                                let mining_round_plots = plots.clone();
                                let mining_round_channels = channels.clone();
                                let mining_round_miner_state = miner_state.clone();
                                let mining_round_reader_threadpool = reader_thread_pool.clone();
                                let resume_info = resume_states[chain_id].take();
                                let benchmark_clone = benchmark.clone();

                                // Build compression configuration
                                let compression_config = if cfg.enable_on_the_fly_compression {
                                    Some(CompressionConfig {
                                        min_compression_level: mining_info
                                            .minimum_compression_level,
                                        target_compression_level: mining_info
                                            .target_compression_level,
                                        max_compression_steps,
                                    })
                                } else {
                                    None
                                };

                                thread::spawn(move || {
                                    Self::mining_round_impl(
                                        mining_round_plots,
                                        mining_round_channels,
                                        mining_round_miner_state,
                                        mining_round_reader_threadpool,
                                        mining_info,
                                        decoded_mining_info,
                                        resume_info,
                                        chain_id,
                                        block,
                                        matches!(benchmark_clone, Some(Benchmark::Io)),
                                        compression_config,
                                        cfg.line_progress,
                                    )
                                });
                            }
                        } else {
                            // check prioritization
                            if let Some((_, prio)) = pq.peek() {
                                if *prio == mut_state.prio {
                                    info!(
                                        "{: <80}",
                                        format!(
                                            "interrupt  : [{}]: new block waiting...",
                                            mut_state.name
                                        )
                                    );
                                    mut_state.interrupt = true;
                                } else if *prio > mut_state.prio
                                    && !mut_state.interrupt
                                    && !mut_state.pause
                                {
                                    info!("{: <80}", format!("pausing    : [{}]", mut_state.name));
                                    mut_state.interrupt = true;
                                    mut_state.pause = true;
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    fn create_hdd_wakeup_task(&self, hdd_wakeup_after: i64) {
        if hdd_wakeup_after <= 0 {
            return; // Wakeup disabled
        }

        let plots = self.plots.clone();
        let miner_state = self.miner_state.clone();

        task::spawn(async move {
            let wakeup_check_interval = Duration::from_secs(1); // Check every second
            let mut interval_stream = Interval::new_interval(wakeup_check_interval);

            while (StreamExt::next(&mut interval_stream).await).is_some() {
                let mut mut_state = miner_state.lock().unwrap();
                let now = Instant::now();

                // Initialize wakeup timer on first run or when not scanning
                if mut_state.next_wakeup_at.is_none() && !mut_state.scanning {
                    mut_state.next_wakeup_at =
                        Some(now + Duration::from_secs(hdd_wakeup_after as u64));
                }

                // Check if it's time to wake up
                if let Some(wakeup_time) = mut_state.next_wakeup_at {
                    if now >= wakeup_time && !mut_state.scanning {
                        // Schedule next wakeup
                        mut_state.next_wakeup_at =
                            Some(now + Duration::from_secs(hdd_wakeup_after as u64));
                        drop(mut_state); // Release lock before I/O

                        plots.wakeup_drives();
                    }
                }
            }
        });
    }

    fn create_nonce_submission_tasks(&mut self) {
        let request_handler = self.request_handler.clone();
        let chain_states = self.chain_states.clone();
        let nonce_rx = self.rx_nonce_data.take().unwrap();
        task::spawn(async move {
            let mut nonce_rx = nonce_rx;
            while let Some((chain_id, submission_parameter)) = StreamExt::next(&mut nonce_rx).await
            {
                // check if nonce submission is for current block of the respective chain
                let mut chain_state = chain_states[chain_id].lock().unwrap();

                if chain_state.generation_signature.to_lowercase()
                    == submission_parameter.nonce_submission.generation_signature
                {
                    // Determine best quality based on submission mode
                    let best_quality = if chain_state.submission_mode == SubmissionMode::Wallet {
                        // Wallet mode: global best across all accounts
                        chain_state
                            .account_id_to_best_quality
                            .values()
                            .min()
                            .copied()
                            .unwrap_or(u64::MAX)
                    } else {
                        // Pool mode: per-account best
                        *chain_state
                            .account_id_to_best_quality
                            .get(&submission_parameter.nonce_submission.account_id)
                            .unwrap_or(&u64::MAX)
                    };

                    let target_quality = *chain_state
                        .account_id_to_target_quality
                        .get(&submission_parameter.nonce_submission.account_id)
                        .unwrap_or(&u64::MAX);

                    // Check: 1) Better than our best, 2) Better than target quality
                    if submission_parameter.nonce_submission.quality < best_quality
                        && submission_parameter.nonce_submission.quality < target_quality
                    {
                        chain_state.account_id_to_best_quality.insert(
                            submission_parameter.nonce_submission.account_id.clone(),
                            submission_parameter.nonce_submission.quality,
                        );
                        request_handler[chain_id].submit_nonce(submission_parameter);
                    } else if submission_parameter.nonce_submission.quality >= target_quality {
                        debug!(
                            "Filtered nonce - quality {} exceeds target {}",
                            submission_parameter.nonce_submission.quality, target_quality
                        );
                    }
                }
            }
        });
    }

    pub async fn run(mut self) {
        info!("Starting mining...");

        // get initial mining infos
        self.get_inital_mining_infos();

        // create some async tasks...

        // create a task for each chain to receive mining info updates
        self.create_mining_info_tasks();

        // create a task to send nonce data
        self.create_nonce_submission_tasks();

        // create a scheduler task
        self.create_scheduler_task();

        // create HDD wakeup task
        self.create_hdd_wakeup_task(self.hdd_wakeup_after);

        // Keep the main thread alive by waiting indefinitely
        // The spawned tasks will run in the background
        futures::future::pending::<()>().await;
    }

    // TODO: Refactor to reduce parameter count - keeping for later cleanup phase
    #[allow(clippy::too_many_arguments)]
    fn mining_round_impl(
        plots: Arc<PoCXArray>,
        channels: Channels,
        miner_state: Arc<Mutex<MinerState>>,
        reader_threadpool: Arc<rayon::ThreadPool>,
        mining_info: MiningInfo,
        decoded_mining_info: DecodedMiningInfo,
        resume_info: Option<ResumeInfo>,
        chain_id: usize,
        block_count: u64,
        io_bench: bool,
        compression_config: Option<CompressionConfig>,
        line_progress: bool,
    ) {
        let (tx_readstate, rx_readstate) = crossbeam_channel::unbounded();
        let start_time = Instant::now();

        // load resume info or reset
        let resume_from = if let Some(i) = resume_info {
            plots.set_resume_info(&i);
            i.warps_scanned
        } else {
            plots.reset();
            0u64
        };

        // start scans
        for disk in plots.disks.values() {
            let disk = disk.lock().unwrap();
            reader_threadpool.spawn(disk.read_disk(
                miner_state.clone(),
                channels.clone(),
                tx_readstate.clone(),
                decoded_mining_info.scoop,
                compression_config.clone(),
            ));
        }

        // Emit progress protocol or create progress bar
        if line_progress {
            // Machine-parsable progress protocol for GUI
            println!("#TOTAL:{}", plots.size_in_warps - resume_from);
        }

        let pb = ProgressBar::new((plots.size_in_warps - resume_from) * NUM_SCOOPS * SCOOP_SIZE);
        if !line_progress {
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                    .unwrap(),
            );
            pb.set_message("Scanning");
        }

        // collect scan results
        let mut finished_count = 0;
        let mut interrupted_count = 0;
        let mut warps_processed = 0;
        for msg in &rx_readstate {
            match msg {
                ScanMessage::ScanFinished => {
                    finished_count += 1;
                }
                ScanMessage::ScanInterrupted => {
                    interrupted_count += 1;
                }
                ScanMessage::WarpsProcessed(i) => {
                    if line_progress {
                        // Machine-parsable progress protocol for GUI
                        println!("#SCAN_PROGRESS:{}", i);
                    } else {
                        pb.inc(i * NUM_SCOOPS * SCOOP_SIZE);
                    }
                    warps_processed += i;
                }
                ScanMessage::Data(read_reply) => {
                    if io_bench {
                        channels.tx_empty_buffer.send(read_reply.buffer).unwrap();
                    } else {
                        // Spawn quality calc task on global threadpool
                        let task = calc_qualities(HashingTask {
                            buffer: read_reply.buffer,
                            chain_id,
                            block_count,
                            generation_signature_bytes: decoded_mining_info
                                .generation_signature_bytes,
                            account_id: read_reply.account_id,
                            seed: read_reply.seed,
                            block_height: mining_info.height,
                            base_target: mining_info.base_target,
                            start_warp: read_reply.warp_offset,
                            number_of_warps: read_reply.number_of_warps,
                            compression_level: read_reply.compression_level,
                            tx_buffer: channels.tx_empty_buffer.clone(),
                            tx_nonce_data: channels.tx_nonce_data.clone(),
                        });
                        rayon::spawn(task);
                    }
                }
            }
            if (interrupted_count + finished_count) == plots.disks.len() {
                break;
            }
        }

        let mut mut_state = miner_state.lock().unwrap();
        // check for interrupt
        if mut_state.interrupt {
            // check if pause
            if mut_state.pause {
                if interrupted_count == 0 {
                    // no need to pause and reschedule if just finished
                    info!(
                        "{: <80}",
                        format!(
                            "finished   : [{}:{}]: done after {:.2}s.",
                            mut_state.name,
                            mining_info.height,
                            start_time.elapsed().as_secs_f64()
                        )
                    );
                } else {
                    // take snapshot
                    let resume_info = plots.get_resume_info();
                    let percentage_processed =
                        resume_info.warps_scanned as f64 / resume_info.total_warps as f64 * 100.0;
                    // else reschedule
                    info!(
                        "{: <80}",
                        format!(
                            "{}: [{}:{}] after {}s at {:.2}%.",
                            "paused     ",
                            mut_state.name,
                            mining_info.height,
                            start_time.elapsed().as_secs_f64(),
                            percentage_processed
                        )
                    );

                    channels
                        .tx_scheduler
                        .clone()
                        .unbounded_send(SchedulerMessage::RescheduleBlock {
                            chain_id: mut_state.chain_id,
                            mining_info: mining_info.clone(),
                            // TODO: Include best qualities in ResumeInfo (minor optimization)
                            resume_info,
                        })
                        .expect("failed to schedule block");
                }
            } else {
                warn!(
                    "{: <80}",
                    format!(
                        "unfinished : [{}:{}:{:.2}%], gensig=...{}, base_target={}",
                        mut_state.name,
                        mining_info.height,
                        warps_processed as f64 / plots.size_in_warps as f64 * 100.0,
                        &mining_info.generation_signature
                            [mining_info.generation_signature.len().saturating_sub(8)..],
                        mining_info.base_target,
                    )
                );
            }

            mut_state.scanning = false;
            channels
                .tx_scheduler
                .unbounded_send(SchedulerMessage::ProcessBlock)
                .expect("failed to communicate with scheduler task");
            return;
        }

        mut_state.scanning = false;
        info!(
            "{: <80}",
            format!(
                "finished   : [{}:{}]: done after {:.2}s.",
                mut_state.name,
                mining_info.height,
                start_time.elapsed().as_secs_f64()
            )
        );
        channels
            .tx_scheduler
            .unbounded_send(SchedulerMessage::ProcessBlock)
            .expect("failed to communicate with scheduler task");
    }
}
