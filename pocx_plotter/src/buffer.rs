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

use crate::error::{PoCXPlotterError, Result};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::fmt;
use std::sync::{Arc, Mutex};

pub struct PageAlignedByteBuffer {
    data: Option<Arc<Mutex<Vec<u8>>>>,
    pointer: *mut u8,
    layout: Layout,
}

impl PageAlignedByteBuffer {
    pub fn new(buffer_size: usize) -> Result<Self> {
        // Security: Validate buffer size to prevent excessive memory allocation
        if buffer_size == 0 {
            return Err(PoCXPlotterError::Memory(
                "Buffer size cannot be zero".to_string(),
            ));
        }

        let page_size = page_size::get();

        // Security: Validate page size is reasonable
        if page_size == 0 || page_size > 1024 * 1024 {
            // Max 1MB page size
            return Err(PoCXPlotterError::Memory(format!(
                "Invalid page size: {}",
                page_size
            )));
        }

        let layout = Layout::from_size_align(buffer_size, page_size).map_err(|e| {
            PoCXPlotterError::Memory(format!(
                "Failed to create layout for page-aligned buffer: {}",
                e
            ))
        })?;

        // SAFETY: Layout is valid and properly aligned, created from page_size::get()
        let pointer = unsafe { alloc_zeroed(layout) };
        if pointer.is_null() {
            return Err(PoCXPlotterError::Memory(format!(
                "Failed to allocate page-aligned buffer of {} bytes: out of memory",
                buffer_size
            )));
        }

        let data: Vec<u8>;
        // SAFETY: pointer is valid (checked for null above), buffer_size is the exact
        // size allocated, and we take ownership of the allocated memory
        unsafe {
            data = Vec::from_raw_parts(pointer, buffer_size, buffer_size);
        }
        Ok(PageAlignedByteBuffer {
            data: Some(Arc::new(Mutex::new(data))),
            pointer,
            layout,
        })
    }

    pub fn get_buffer(&self) -> Arc<Mutex<Vec<u8>>> {
        self.data
            .as_ref()
            .expect("Buffer data should always be available until Drop")
            .clone()
    }
}

impl fmt::Debug for PageAlignedByteBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageAlignedByteBuffer")
            .field("layout", &self.layout)
            .field("pointer", &format!("{:p}", self.pointer))
            .field("data_available", &self.data.is_some())
            .finish()
    }
}

impl Drop for PageAlignedByteBuffer {
    fn drop(&mut self) {
        // Forget the Vec to prevent double-free since we manually deallocate below
        if let Some(data) = self.data.take() {
            std::mem::forget(data);
        }
        // SAFETY: pointer and layout are the same ones used in alloc_zeroed,
        // and we're in Drop so this is the final cleanup
        unsafe {
            dealloc(self.pointer, self.layout);
        }
    }
}

// SAFETY: PageAlignedByteBuffer manages its own memory allocation and the
// Arc<Mutex<Vec<u8>>> provides thread-safe access to the underlying data. The
// raw pointer is only used for allocation/deallocation and the Vec provides
// safe access.
unsafe impl Send for PageAlignedByteBuffer {}

#[cfg(test)]
mod buffer_tests {
    use super::PageAlignedByteBuffer;

    #[test]
    fn buffer_creation_destruction_test() {
        {
            let _test =
                PageAlignedByteBuffer::new(1024 * 1024).expect("Test buffer allocation failed");
        }
        // Test completed successfully
    }
}
