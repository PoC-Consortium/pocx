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

use crate::error::{PoCXHashError, Result};
use std::alloc::{alloc_zeroed, dealloc, Layout};

#[derive(Debug)]
pub struct PageAlignedByteBuffer {
    data: Option<Vec<u8>>,
    pointer: *mut u8,
    layout: Layout,
}

impl PageAlignedByteBuffer {
    /// Creates a new page-aligned buffer with the specified size.
    ///
    /// # Arguments
    ///
    /// * `buffer_size` - The size of the buffer to allocate in bytes
    ///
    /// # Returns
    ///
    /// Returns `Ok(PageAlignedByteBuffer)` on success, or `Err(PoCXHashError)`
    /// if:
    /// - The layout cannot be created (invalid size/alignment combination)
    /// - Memory allocation fails (out of memory)
    ///
    /// # Safety
    ///
    /// This function uses unsafe code for memory allocation but maintains
    /// safety by:
    /// - Validating allocation success before creating Vec from raw parts
    /// - Ensuring proper cleanup in Drop implementation
    /// - Using page-aligned layout for optimal performance
    pub fn new(buffer_size: usize) -> Result<Self> {
        let page_size = page_size::get();
        let layout = Layout::from_size_align(buffer_size, page_size).map_err(|e| {
            PoCXHashError::LayoutError(format!(
                "Cannot create page-aligned layout for size {}: {}",
                buffer_size, e
            ))
        })?;

        let pointer = unsafe { alloc_zeroed(layout) };
        if pointer.is_null() {
            return Err(PoCXHashError::AllocationError(format!(
                "Failed to allocate {} bytes of page-aligned memory",
                buffer_size
            )));
        }

        // SAFETY: We've verified that pointer is not null and layout is valid
        // Vec::from_raw_parts is safe here because:
        // - pointer was allocated with the correct size and alignment
        // - buffer_size matches the allocated size
        // - we take ownership of the memory and will properly deallocate in Drop
        let data = unsafe { Vec::from_raw_parts(pointer, buffer_size, buffer_size) };

        Ok(PageAlignedByteBuffer {
            data: Some(data),
            pointer,
            layout,
        })
    }

    /// Returns a mutable reference to the internal buffer, with safe
    /// unwrapping.
    ///
    /// # Returns
    ///
    /// Returns `&mut Vec<u8>`. This is safe because the buffer is guaranteed to
    /// exist until Drop is called.
    ///
    /// # Panics
    ///
    /// Panics only if the buffer has been consumed, which should never happen
    /// in normal usage.
    pub fn get_buffer_mut_unchecked(&mut self) -> &mut Vec<u8> {
        self.data
            .as_mut()
            .expect("Buffer should always be available until Drop")
    }
}

impl Drop for PageAlignedByteBuffer {
    fn drop(&mut self) {
        // Take ownership of the Vec and forget it to prevent double-free
        // since we're manually deallocating the memory
        if let Some(data) = self.data.take() {
            std::mem::forget(data);
        }

        // SAFETY:
        // - pointer and layout were created together in new()
        // - we have exclusive ownership through &mut self
        // - this is only called once due to Drop semantics
        unsafe {
            dealloc(self.pointer, self.layout);
        }
    }
}

unsafe impl Send for PageAlignedByteBuffer {}
unsafe impl Sync for PageAlignedByteBuffer {}

#[cfg(test)]
mod buffer_tests {
    use super::PageAlignedByteBuffer;

    #[test]
    fn buffer_creation_destruction_test() {
        {
            let test = PageAlignedByteBuffer::new(1024 * 1024)
                .expect("Should be able to allocate 1MB page-aligned buffer");
            drop(test);
        }
        // Test passed - buffer was created and destroyed successfully
    }

    #[test]
    fn buffer_allocation_error_test() {
        // Test with an impossibly large size to trigger allocation failure
        // This may not fail on systems with overcommit, but tests the error path
        let result = PageAlignedByteBuffer::new(usize::MAX);
        assert!(result.is_err());
        assert!(
            matches!(
                result,
                Err(crate::error::PoCXHashError::AllocationError(_))
                    | Err(crate::error::PoCXHashError::LayoutError(_))
            ),
            "Expected allocation or layout error, got: {:?}",
            result
        );
    }

    #[test]
    fn buffer_access_test() {
        let mut buffer =
            PageAlignedByteBuffer::new(4096).expect("Should be able to allocate 4KB buffer");

        // Test buffer access
        let vec_ref = buffer.get_buffer_mut_unchecked();
        vec_ref[0] = 42;
        assert_eq!(vec_ref[0], 42);

        vec_ref[1] = 24;
        assert_eq!(vec_ref[1], 24);
    }
}
