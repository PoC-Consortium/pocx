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
use std::sync::Arc;

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
                    let mut_bs = &buffer.get_buffer();
                    let bs = match mut_bs.lock() {
                        Ok(bs) => bs,
                        Err(_) => {
                            eprintln!("ERROR: Buffer mutex poisoned in disk writer");
                            continue;
                        }
                    };

                    let delta = warps_to_write * WARP_SIZE;

                    if !task.benchmark {
                        let mut optimized_plot_file = PoCXPlotFile::new(
                            &task.output_paths[path_ptr],
                            &task.address_payload,
                            &seed,
                            number_of_warps,
                            task.compress,
                            task.direct_io,
                            warp_offset == 0,
                        )
                        .expect("can't open output file");
                        optimized_plot_file
                            .write_optimised_buffer_into_plotfile(
                                &bs,
                                warp_offset,
                                warps_to_write,
                                &pb,
                            )
                            .expect("error writing to file");
                    } else if let Some(pbr) = &pb {
                        pbr.inc(delta);
                    }

                    if task.line_progress {
                        println!("#WRITE_DELTA:{}", warps_to_write);
                    }

                    // Notify callback of writing progress
                    if let Some(cb) = get_plotter_callback() {
                        cb.on_writing_progress(warps_to_write);
                    }

                    if let Err(e) = tx_empty_buffers.send(buffer) {
                        eprintln!("ERROR: Failed to send empty buffer back to pool: {}", e);
                        break;
                    }
                }
            }
        }
    }
}
