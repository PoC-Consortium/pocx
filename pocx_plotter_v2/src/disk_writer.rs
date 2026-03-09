#![allow(clippy::needless_range_loop)]

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
use crate::get_plotter_callback;
use crate::plotter::{PlotterTask, WARP_SIZE};
use crossbeam_channel::{Receiver, Sender};
use pocx_plotfile::PoCXPlotFile;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Total warps lost to write errors across all writer threads.
/// Reported at the end so the user knows how many warps need re-computation.
pub static WARPS_DROPPED: AtomicU64 = AtomicU64::new(0);

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_millis(500);

#[derive(Debug)]
pub enum WriterTask {
    EndTask,
    ProcessTask {
        buffer: PageAlignedByteBuffer,
        seed: [u8; 32],
        warp_offset: u64,
        warps_to_write: u64,
        number_of_warps: u64,
    },
}

pub fn create_writer_thread(
    task: Arc<PlotterTask>,
    pb: Option<Arc<indicatif::ProgressBar>>,
    rx_buffers_to_writer: Receiver<WriterTask>,
    tx_empty_buffers: Sender<PageAlignedByteBuffer>,
    path_ptr: usize,
    io_permit: Option<(Receiver<()>, Sender<()>)>,
) -> impl FnOnce() {
    move || {
        for write_task in rx_buffers_to_writer {
            match write_task {
                WriterTask::EndTask => {
                    if let Some(pb) = pb {
                        pb.force_draw();
                        pb.finish_with_message("Writer done.");
                    }
                    break;
                }
                WriterTask::ProcessTask {
                    buffer,
                    seed,
                    warp_offset,
                    warps_to_write,
                    number_of_warps,
                } => {
                    let arc_buf = buffer.get_buffer();
                    let delta = warps_to_write * WARP_SIZE;
                    let mut write_ok = false;

                    // Helper to print messages coordinated with progress bars
                    let log = |msg: &str| {
                        if let Some(pb) = &pb {
                            pb.suspend(|| eprintln!("{}", msg));
                        } else {
                            eprintln!("{}", msg);
                        }
                    };

                    // Acquire I/O permit BEFORE locking the buffer so that
                    // writers waiting for a permit don't hold buffer locks,
                    // which would starve the GPU of write buffers.
                    let _has_permit = io_permit.as_ref().and_then(|(rx, _)| rx.recv().ok());

                    let mut bs_opt = match arc_buf.lock() {
                        Ok(bs) => Some(bs),
                        Err(_) => {
                            log("ERROR: Buffer mutex poisoned in disk writer");
                            if let Some((_, tx)) = &io_permit {
                                let _ = tx.send(());
                            }
                            if tx_empty_buffers.send(buffer).is_err() {
                                break;
                            }
                            continue;
                        }
                    };

                    if !task.benchmark {
                        // Try the write, with limited fast retries for transient I/O errors.
                        // On failure the buffer lock is released during the retry delay
                        // so the GPU pipeline isn't starved of write buffers.
                        for attempt in 0..=MAX_RETRIES {
                            let bs = bs_opt.as_ref().unwrap();
                            let file = PoCXPlotFile::new(
                                &task.output_paths[path_ptr],
                                &task.address_payload,
                                &seed,
                                number_of_warps,
                                task.compress,
                                task.direct_io,
                                warp_offset == 0,
                            );

                            match file {
                                Ok(mut f) => {
                                    match f.write_optimised_buffer_into_plotfile(
                                        bs,
                                        warp_offset,
                                        warps_to_write,
                                        &pb,
                                    ) {
                                        Ok(_) => {
                                            write_ok = true;
                                            break;
                                        }
                                        Err(e) => {
                                            let msg = format!("{}", e);
                                            // ResumeGap means the scheduler advanced past a
                                            // previous failed write — retrying won't help.
                                            if msg.contains("Resume gap") {
                                                log(&format!(
                                                    "SKIP: {} (warp data will be recovered on next run)",
                                                    msg
                                                ));
                                                break;
                                            }
                                            log(&format!(
                                                "ERROR: Write failed in {} (attempt {}): {}",
                                                &task.output_paths[path_ptr],
                                                attempt + 1,
                                                e
                                            ));
                                        }
                                    }
                                }
                                Err(e) => {
                                    log(&format!(
                                        "ERROR: Failed to open plot file in {} (attempt {}): {}",
                                        &task.output_paths[path_ptr],
                                        attempt + 1,
                                        e
                                    ));
                                }
                            }

                            if attempt < MAX_RETRIES {
                                // Release buffer lock during retry delay so other
                                // threads can reclaim it if the pool is starved.
                                bs_opt.take();
                                std::thread::sleep(RETRY_DELAY);
                                bs_opt = match arc_buf.lock() {
                                    Ok(guard) => Some(guard),
                                    Err(_) => {
                                        log("ERROR: Buffer mutex poisoned during retry");
                                        break;
                                    }
                                };
                            }
                        }
                        if !write_ok {
                            WARPS_DROPPED.fetch_add(warps_to_write, Ordering::Relaxed);
                        }
                    } else if let Some(pbr) = &pb {
                        pbr.inc(delta);
                    }

                    // Release I/O permit before returning the buffer
                    if let Some((_, tx)) = &io_permit {
                        let _ = tx.send(());
                    }

                    if write_ok {
                        if task.line_progress {
                            println!("#WRITE_DELTA:{}", warps_to_write);
                        }

                        // Notify callback of writing progress
                        if let Some(cb) = get_plotter_callback() {
                            cb.on_writing_progress(warps_to_write);
                        }
                    }

                    drop(bs_opt);
                    drop(arc_buf);
                    if tx_empty_buffers.send(buffer).is_err() {
                        // Channel closed — scheduler finished, no more buffers needed
                        break;
                    }
                }
            }
        }
    }
}
