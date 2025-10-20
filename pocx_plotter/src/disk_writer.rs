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

                    if let Err(e) = tx_empty_buffers.send(buffer) {
                        eprintln!("ERROR: Failed to send empty buffer back to pool: {}", e);
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::PageAlignedByteBuffer;
    use crossbeam_channel::unbounded;

    #[test]
    fn test_writer_task_variants() {
        // Test EndTask variant
        let end_task = WriterTask::EndTask;
        match end_task {
            WriterTask::EndTask => {} // Should match
            _ => panic!("EndTask variant not matching correctly"),
        }

        // Test ProcessTask variant
        let buffer = PageAlignedByteBuffer::new(4096).unwrap();
        let seed = [42u8; 32];
        let process_task = WriterTask::ProcessTask {
            buffer,
            seed,
            warp_offset: 0,
            warps_to_write: 1,
            number_of_warps: 10,
        };

        match process_task {
            WriterTask::ProcessTask {
                buffer: _,
                seed: task_seed,
                warp_offset,
                warps_to_write,
                number_of_warps,
            } => {
                assert_eq!(task_seed, [42u8; 32]);
                assert_eq!(warp_offset, 0);
                assert_eq!(warps_to_write, 1);
                assert_eq!(number_of_warps, 10);
            }
            _ => panic!("ProcessTask variant not matching correctly"),
        }
    }

    #[test]
    fn test_writer_task_memory_layout() {
        // Test that WriterTask has a reasonable size
        let size = std::mem::size_of::<WriterTask>();

        // Should be reasonable size (not too large)
        // Buffer is already allocated, so we're mainly measuring the enum overhead
        assert!(size > 0);
        assert!(size < 1024); // Reasonable upper bound
    }

    #[test]
    fn test_channel_communication() {
        let (tx, rx) = unbounded::<WriterTask>();

        // Test sending EndTask
        tx.send(WriterTask::EndTask).unwrap();
        let received = rx.recv().unwrap();
        match received {
            WriterTask::EndTask => {}
            _ => panic!("EndTask not transmitted correctly"),
        }

        // Test sending ProcessTask
        let buffer = PageAlignedByteBuffer::new(1024).unwrap();
        let seed = [100u8; 32];
        tx.send(WriterTask::ProcessTask {
            buffer,
            seed,
            warp_offset: 5,
            warps_to_write: 3,
            number_of_warps: 20,
        })
        .unwrap();

        let received = rx.recv().unwrap();
        match received {
            WriterTask::ProcessTask {
                buffer: _,
                seed: recv_seed,
                warp_offset,
                warps_to_write,
                number_of_warps,
            } => {
                assert_eq!(recv_seed, [100u8; 32]);
                assert_eq!(warp_offset, 5);
                assert_eq!(warps_to_write, 3);
                assert_eq!(number_of_warps, 20);
            }
            _ => panic!("ProcessTask not transmitted correctly"),
        }
    }

    #[test]
    fn test_writer_task_with_different_buffer_sizes() {
        let buffer_sizes = [512, 1024, 2048, 4096, 8192];

        for &size in &buffer_sizes {
            let buffer = PageAlignedByteBuffer::new(size).unwrap();
            let seed = [255u8; 32];

            let task = WriterTask::ProcessTask {
                buffer,
                seed,
                warp_offset: 0,
                warps_to_write: 1,
                number_of_warps: 1,
            };

            // Ensure task can be created with various buffer sizes
            match task {
                WriterTask::ProcessTask { .. } => {}
                _ => panic!("Failed to create ProcessTask with buffer size {}", size),
            }
        }
    }

    #[test]
    fn test_seed_variations() {
        // Test with different seed patterns
        let seeds = [
            [0u8; 32],    // All zeros
            [255u8; 32],  // All ones
            [0x55u8; 32], // Pattern
            {
                let mut seed = [0u8; 32];
                for i in 0..32 {
                    seed[i] = (i * 7) as u8; // Sequence
                }
                seed
            },
        ];

        for seed in &seeds {
            let buffer = PageAlignedByteBuffer::new(1024).unwrap();
            let task = WriterTask::ProcessTask {
                buffer,
                seed: *seed,
                warp_offset: 0,
                warps_to_write: 1,
                number_of_warps: 1,
            };

            match task {
                WriterTask::ProcessTask {
                    seed: task_seed, ..
                } => {
                    assert_eq!(task_seed, *seed);
                }
                _ => panic!("Failed to create task with seed pattern"),
            }
        }
    }

    #[test]
    fn test_warp_parameters() {
        let seed = [42u8; 32];

        // Test various warp parameter combinations
        let test_cases = [
            (0, 1, 10),     // Start at beginning
            (5, 3, 20),     // Middle offset
            (100, 50, 200), // Large numbers
            (0, 0, 1),      // Zero warps to write (edge case)
        ];

        for &(offset, to_write, total) in &test_cases {
            let buffer = PageAlignedByteBuffer::new(1024).unwrap();
            let task = WriterTask::ProcessTask {
                buffer,
                seed,
                warp_offset: offset,
                warps_to_write: to_write,
                number_of_warps: total,
            };

            match task {
                WriterTask::ProcessTask {
                    warp_offset,
                    warps_to_write,
                    number_of_warps,
                    ..
                } => {
                    assert_eq!(warp_offset, offset);
                    assert_eq!(warps_to_write, to_write);
                    assert_eq!(number_of_warps, total);
                }
                _ => panic!(
                    "Failed to create task with warp params ({}, {}, {})",
                    offset, to_write, total
                ),
            }
        }
    }

    #[test]
    fn test_buffer_ownership() {
        let buffer1 = PageAlignedByteBuffer::new(2048).unwrap();
        let buffer2 = PageAlignedByteBuffer::new(2048).unwrap();

        // Verify that buffers can be moved into tasks
        let seed = [77u8; 32];

        let task1 = WriterTask::ProcessTask {
            buffer: buffer1,
            seed,
            warp_offset: 0,
            warps_to_write: 1,
            number_of_warps: 1,
        };

        let task2 = WriterTask::ProcessTask {
            buffer: buffer2,
            seed,
            warp_offset: 0,
            warps_to_write: 1,
            number_of_warps: 1,
        };

        // Both tasks should be valid
        match (&task1, &task2) {
            (WriterTask::ProcessTask { .. }, WriterTask::ProcessTask { .. }) => {}
            _ => panic!("Buffer ownership transfer failed"),
        }
    }

    #[test]
    fn test_channel_error_handling() {
        let (tx, rx) = unbounded::<WriterTask>();

        // Drop receiver to cause send errors
        drop(rx);

        let buffer = PageAlignedByteBuffer::new(1024).unwrap();
        let seed = [1u8; 32];
        let task = WriterTask::ProcessTask {
            buffer,
            seed,
            warp_offset: 0,
            warps_to_write: 1,
            number_of_warps: 1,
        };

        // Send should fail gracefully
        let result = tx.send(task);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_end_tasks() {
        let (tx, rx) = unbounded::<WriterTask>();

        // Send multiple end tasks
        tx.send(WriterTask::EndTask).unwrap();
        tx.send(WriterTask::EndTask).unwrap();

        // Both should be receivable
        let task1 = rx.recv().unwrap();
        let task2 = rx.recv().unwrap();

        match (task1, task2) {
            (WriterTask::EndTask, WriterTask::EndTask) => {}
            _ => panic!("Multiple EndTasks not handled correctly"),
        }
    }

    #[test]
    fn test_debug_representation() {
        let buffer = PageAlignedByteBuffer::new(512).unwrap();
        let seed = [200u8; 32];
        let task = WriterTask::ProcessTask {
            buffer,
            seed,
            warp_offset: 10,
            warps_to_write: 5,
            number_of_warps: 100,
        };

        // Should be able to format for debugging (though the actual output depends on
        // buffer implementation)
        let debug_str = format!("{:?}", &task);
        // At minimum, debug string should not be empty
        assert!(!debug_str.is_empty());
    }
}
