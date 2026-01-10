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
use crate::compression::{compress_warps_inline, determine_compression_action, CompressionAction};
use crate::miner::{Channels, MinerState};
use crate::utils::get_device_id;

use crossbeam_channel::Sender;
use pocx_plotfile::{AccessType, PoCXPlotFile};
use rand::distr::Alphanumeric;
use rand::Rng;
use std::collections::HashMap;
use std::fs::read_dir;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// Compression configuration passed to read_disk
#[derive(Clone)]
pub struct CompressionConfig {
    pub min_compression_level: u32,
    pub target_compression_level: u32,
    pub max_compression_steps: u32,
}

// Type aliases for complex types
/// Thread-safe disk container
pub type SafeDisk = Arc<Mutex<PoCXDisk>>;
/// Thread-safe plot file
pub type SafePlotFile = Mutex<PoCXPlotFile>;
/// Map of disk ID to disk container
pub type DiskMap = HashMap<String, SafeDisk>;

/// Collection of plot files organized by disk for efficient mining
pub struct PoCXArray {
    /// Map of disk IDs to their associated plot files
    pub disks: DiskMap,
    /// Total capacity in warps across all disks
    pub size_in_warps: u64,
}

/// Container for plot files on a single disk
pub struct PoCXDisk {
    /// Vector of plot files on this disk
    pub plots: Arc<Mutex<Vec<SafePlotFile>>>,
    /// Total capacity in warps for this disk
    pub size_in_warps: u64,
}

/// Information about mining scan progress for resume functionality
pub struct ResumeInfo {
    /// Progress per disk and plot file
    pub scan_progress: Vec<Vec<u64>>,
    /// Total warps scanned so far
    pub warps_scanned: u64,
    /// Total warps to scan
    pub total_warps: u64,
}

/// Messages sent during plot scanning operations
pub enum ScanMessage {
    /// Scanning completed successfully
    ScanFinished,
    /// Scanning was interrupted
    ScanInterrupted,
    /// Number of warps processed in this batch
    WarpsProcessed(u64),
    /// Data read from plot files
    Data(ReadReply),
}

/// Response containing data read from plot files
pub struct ReadReply {
    /// Buffer containing the read plot data
    pub buffer: PageAlignedByteBuffer,
    /// Starting warp offset for this data
    pub warp_offset: u64,
    /// Number of warps in this data
    pub number_of_warps: u64,
    /// Hex encoded account ID (payload)
    pub account_id: String,
    /// Seed value for this plot
    pub seed: String,
    /// Compression level from plotfile metadata
    pub compression_level: u8,
}

impl PoCXArray {
    pub fn new(plot_dirs: &[PathBuf], use_direct_io: bool, dummy: bool) -> PoCXArray {
        let mut size_in_warps: u64 = 0;
        info!("Loading plots...");

        let mut disks = HashMap::new();

        for plot_dir in plot_dirs {
            let mut num_plots = 0;
            let mut local_capacity: u64 = 0;

            let dummy_disk_id = if dummy {
                rand::rng()
                    .sample_iter(&Alphanumeric)
                    .take(10)
                    .map(char::from)
                    .collect()
            } else {
                "".to_owned()
            };

            for file in read_dir(plot_dir).unwrap() {
                let file = &file.unwrap().path();

                if let Ok(plotfile) = PoCXPlotFile::open(
                    file,
                    if dummy {
                        AccessType::Dummy
                    } else {
                        AccessType::Read
                    },
                    use_direct_io,
                ) {
                    let disk_id = if dummy {
                        dummy_disk_id.clone()
                    } else {
                        get_device_id(file.to_str().unwrap())
                    };

                    let disk = disks
                        .entry(disk_id)
                        .or_insert_with(|| Arc::new(Mutex::new(PoCXDisk::new())));

                    local_capacity += plotfile.meta.number_of_warps;
                    let mut disk = disk.lock().unwrap();
                    disk.add(plotfile);
                    num_plots += 1;
                }
            }

            info!(
                "path={}, files={}, size={:.4} TiB",
                plot_dir.to_str().unwrap(),
                num_plots,
                local_capacity as f64 / 1024.0
            );

            size_in_warps += local_capacity;
            if num_plots == 0 {
                warn!("no plots in {}", plot_dir.to_str().unwrap());
            }
        }

        // sort plots by filetime
        for disk in disks.values_mut() {
            let mut disk = disk.lock().unwrap();
            disk.sort();
        }

        info!(
            "..done. total drives={}, total capacity={:.4} TiB",
            disks.values().len(),
            size_in_warps as f64 / 1024.0
        );

        PoCXArray {
            disks,
            size_in_warps,
        }
    }
    pub fn reset(&self) {
        for disk in self.disks.values() {
            let disk = disk.lock().unwrap();
            disk.reset();
        }
    }

    pub fn get_resume_info(&self) -> ResumeInfo {
        let mut scan_progress = Vec::new();
        let mut warps_scanned = 0;
        let total_warps = self.size_in_warps;
        for disk in self.disks.values() {
            let disk = disk.lock().unwrap();
            let (disk_scan_progress, disk_warps_scanned) = disk.get_resume_info();
            scan_progress.push(disk_scan_progress);
            warps_scanned += disk_warps_scanned;
        }

        ResumeInfo {
            scan_progress,
            warps_scanned,
            total_warps,
        }
    }

    pub fn set_resume_info(&self, ri: &ResumeInfo) {
        for (i, disk) in self.disks.values().enumerate() {
            let disk = disk.lock().unwrap();
            disk.set_resume_info(&ri.scan_progress[i]);
        }
    }

    /// Wakes up all drives by calling wakeup on each disk
    pub fn wakeup_drives(&self) {
        // Single info message when wakeup is triggered
        info!("HDD wakeup!");

        // Wake each disk, only log failures
        for disk in self.disks.values() {
            let disk = disk.lock().unwrap();
            if let Err(error) = disk.wakeup() {
                warn!("HDD wakeup failed: {}", error);
            }
            // Success: no message (silent)
        }
    }
}

impl PoCXDisk {
    pub fn new() -> PoCXDisk {
        PoCXDisk {
            plots: Arc::new(Mutex::new(Vec::new())),
            size_in_warps: 0,
        }
    }
    pub fn add(&mut self, plotfile: PoCXPlotFile) {
        self.size_in_warps += plotfile.meta.number_of_warps;
        let mut plots = self.plots.lock().unwrap();
        plots.push(Mutex::new(plotfile));
    }

    pub fn sort(&mut self) {
        // reverse sort by filetime
        let mut plots = self.plots.lock().unwrap();
        plots.sort_by(|a, b| {
            let a = a.lock().unwrap();
            let b = b.lock().unwrap();
            b.meta.filetime.cmp(&a.meta.filetime)
        });
    }

    fn reset(&self) {
        let plots = self.plots.lock().unwrap();
        for plot in &*plots {
            let mut plot = plot.lock().unwrap();
            plot.read_progress = 0;
        }
    }

    fn get_resume_info(&self) -> (Vec<u64>, u64) {
        let mut disk_scan_progress = Vec::new();
        let mut disk_warps_scanned = 0;
        let plots = self.plots.lock().unwrap();
        for plot in &*plots {
            let plot = plot.lock().unwrap();
            disk_scan_progress.push(plot.read_progress);
            disk_warps_scanned += plot.read_progress;
        }
        (disk_scan_progress, disk_warps_scanned)
    }

    pub fn set_resume_info(&self, ri: &[u64]) {
        let plots = self.plots.lock().unwrap();
        for (i, plot) in (*plots).iter().enumerate() {
            let mut plot = plot.lock().unwrap();
            plot.read_progress = ri[i];
        }
    }

    pub fn read_disk(
        &self,
        state: Arc<Mutex<MinerState>>,
        channels: Channels,
        tx_readstate: Sender<ScanMessage>,
        scoop: u64,
        compression_config: Option<CompressionConfig>,
    ) -> impl FnOnce() {
        let plots = self.plots.clone();
        move || {
            let plots = plots.lock().unwrap();

            for plot in &*plots {
                let mut plot = plot.lock().unwrap();

                // NEW: Check compression requirements early - before any reads
                let compression_action = if let Some(ref config) = compression_config {
                    determine_compression_action(
                        plot.meta.compression,
                        config.min_compression_level,
                        config.target_compression_level,
                        config.max_compression_steps,
                    )
                } else {
                    CompressionAction::MineNormal
                };

                if let CompressionAction::Skip(reason) = compression_action {
                    info!(
                        "Skipping plot {} - {}",
                        plot.meta.filename_and_path.display(),
                        reason
                    );
                    continue;
                }

                while plot.read_progress < plot.meta.number_of_warps {
                    // Get buffer and fill it completely first
                    // Channel may be closed during shutdown - handle gracefully
                    let mut buffer = match channels.rx_empty_buffer.recv() {
                        Ok(buf) => buf,
                        Err(_) => {
                            // Channel closed - miner is shutting down
                            log::debug!("Reader: buffer channel closed (shutdown in progress)");
                            return;
                        }
                    };
                    let bs = buffer.get_buffer_mut();
                    let buffer_start_offset = plot.read_progress;
                    let mut total_warps_in_buffer = 0;

                    // Fill buffer completely before any compression
                    while total_warps_in_buffer == 0
                        || (plot.read_progress < plot.meta.number_of_warps
                            && (total_warps_in_buffer
                                * pocx_plotfile::NUM_SCOOPS
                                * pocx_plotfile::SCOOP_SIZE)
                                < bs.capacity() as u64)
                    {
                        match plot.read(bs, scoop) {
                            Ok(warps_red) => {
                                if warps_red == 0 {
                                    break; // No more data to read
                                }
                                total_warps_in_buffer += warps_red;

                                // Ignore send error during shutdown
                                let _ = tx_readstate.send(ScanMessage::WarpsProcessed(warps_red));

                                // Check interrupt
                                let state = state.lock().unwrap();
                                if state.interrupt {
                                    let _ = tx_readstate.send(ScanMessage::ScanInterrupted);
                                    let _ = channels.tx_empty_buffer.send(buffer);
                                    return;
                                }
                            }
                            Err(e) => {
                                error!(
                                    "reader: error reading chunk from {}: {} -> skip rest of plot",
                                    plot.meta.filename_and_path.display(),
                                    e
                                );
                                plot.read_progress = plot.meta.number_of_warps;
                                break;
                            }
                        }
                    }

                    if total_warps_in_buffer == 0 {
                        // No data was read, return buffer and exit
                        let _ = channels.tx_empty_buffer.send(buffer);
                        break;
                    }

                    // Now compress the full buffer if needed
                    let (final_warps, final_compression) = match compression_action {
                        CompressionAction::CompressOnFly { steps } => {
                            // Handle odd warp count - drop last warp if odd
                            let compressible_warps = if total_warps_in_buffer % 2 == 1 {
                                total_warps_in_buffer - 1
                            } else {
                                total_warps_in_buffer
                            };

                            if compressible_warps == 0 {
                                // Single warp, cannot compress - skip this buffer (normal for last
                                // warp of odd-sized files)
                                (0, plot.meta.compression)
                            } else {
                                // Perform inline SIMD compression on full buffer
                                if let Some(ref _config) = compression_config {
                                    let compressed_warps = compress_warps_inline(
                                        bs,                 // Same buffer, modify in-place
                                        compressible_warps, // Even number of warps
                                        steps,              // Compression steps
                                    );

                                    (compressed_warps, plot.meta.compression + steps as u8)
                                } else {
                                    (compressible_warps, plot.meta.compression)
                                }
                            }
                        }
                        _ => {
                            (total_warps_in_buffer, plot.meta.compression) // Normal path unchanged
                        }
                    };

                    if final_warps > 0 {
                        // Calculate compressed warp offset
                        // After compression, warp indices are divided by 2^steps
                        let compressed_warp_offset = match compression_action {
                            CompressionAction::CompressOnFly { steps } => {
                                buffer_start_offset >> steps
                            }
                            _ => buffer_start_offset,
                        };

                        // Send buffer to hasher - ignore error during shutdown
                        let _ = tx_readstate.send(ScanMessage::Data(ReadReply {
                            buffer,
                            warp_offset: compressed_warp_offset, // Adjusted for compression
                            number_of_warps: final_warps,        // Reduced after compression
                            account_id: hex::encode(plot.meta.base58_decoded),
                            seed: plot.meta.seed.clone(),
                            compression_level: final_compression, // Updated compression level
                        }));
                    } else {
                        // Return empty buffer to pool - ignore error during shutdown
                        let _ = channels.tx_empty_buffer.send(buffer);
                    }
                }
            }

            // Ignore error during shutdown
            let _ = tx_readstate.send(ScanMessage::ScanFinished);
        }
    }

    /// Wakes up the first plot on this disk to prevent drive sleep
    pub fn wakeup(&self) -> Result<(), String> {
        let plots = self.plots.lock().unwrap();
        if let Some(first_plot) = plots.first() {
            let mut plot = first_plot.lock().unwrap();
            plot.wakeup()
                .map_err(|e| format!("{}: {}", plot.meta.filename_and_path.display(), e))
        } else {
            Ok(()) // No plots on this disk
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_pocx_disk_new() {
        let disk = PoCXDisk::new();
        let plots = disk.plots.lock().unwrap();
        assert!(plots.is_empty());
    }

    #[test]
    fn test_pocx_array_new_with_empty_dirs() {
        let array = PoCXArray::new(&[], false, true);
        assert!(array.disks.is_empty());
        assert_eq!(array.size_in_warps, 0);
    }

    #[test]
    #[should_panic]
    fn test_pocx_array_new_with_nonexistent_dir() {
        let non_existent_path = PathBuf::from("/this/path/does/not/exist");
        // This should panic because the current implementation uses unwrap() on
        // read_dir
        let _array = PoCXArray::new(&[non_existent_path], false, true);
    }

    #[test]
    fn test_resume_info_structure() {
        let ri = ResumeInfo {
            scan_progress: Vec::new(),
            warps_scanned: 0,
            total_warps: 100,
        };
        assert!(ri.scan_progress.is_empty());
        assert_eq!(ri.warps_scanned, 0);
        assert_eq!(ri.total_warps, 100);
    }

    #[test]
    fn test_resume_info_with_progress() {
        let mut ri = ResumeInfo {
            scan_progress: vec![vec![10, 20], vec![30, 40]],
            warps_scanned: 50,
            total_warps: 100,
        };

        assert_eq!(ri.scan_progress.len(), 2);
        assert_eq!(ri.scan_progress[0], vec![10, 20]);
        assert_eq!(ri.scan_progress[1], vec![30, 40]);
        assert_eq!(ri.warps_scanned, 50);

        // Test modification
        ri.warps_scanned += 25;
        assert_eq!(ri.warps_scanned, 75);
    }

    #[test]
    fn test_pocx_array_reset() {
        let array = PoCXArray::new(&[], false, true);
        // Reset should not panic
        array.reset();
    }

    #[test]
    fn test_pocx_array_get_resume_info() {
        let array = PoCXArray::new(&[], false, true);
        let resume_info = array.get_resume_info();
        assert!(resume_info.scan_progress.is_empty());
        assert_eq!(resume_info.warps_scanned, 0);
        assert_eq!(resume_info.total_warps, 0);
    }

    #[test]
    fn test_pocx_array_set_resume_info() {
        let array = PoCXArray::new(&[], false, true);
        let resume_info = ResumeInfo {
            scan_progress: vec![vec![50]],
            warps_scanned: 25,
            total_warps: 100,
        };

        // Should not panic
        array.set_resume_info(&resume_info);
    }
}
