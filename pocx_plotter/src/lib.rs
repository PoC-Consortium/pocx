#![allow(clippy::needless_range_loop)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::const_is_empty)]
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

//! PoCX Plotter Library
//!
//! Professional cryptocurrency plotting library for PoCX blockchain
//! Provides high-performance CPU and GPU plotting capabilities

#[macro_use]
extern crate cfg_if;

pub mod buffer;
pub mod compressor;
pub mod cpu_hasher;
pub mod disk_writer;
pub mod error;
#[cfg(feature = "opencl")]
pub mod gpu_hasher;
#[cfg(feature = "opencl")]
pub mod ocl;
pub mod perf_monitor;
pub mod plotter;
pub mod utils;
pub mod xpu_scheduler;

// Re-export main types for convenience
pub use buffer::PageAlignedByteBuffer;
pub use error::{PoCXPlotterError, Result};
pub use plotter::{Plotter, PlotterTask};
