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

//! This is almost the exact code of the tokio Interval implementation with a
//! simple difference:
//!
//! In PoCX miner we request the `MiningInfo` in a certain interval. If the
//! pool or wallet is not available in a certain time frame the request will
//! take longer than `Interval`. As soon as the pool or wallet is available a
//! bunch of requests are going to be fired at once.
//!
//! Here we delay once an item has been processed, e.g.:
//! 1. We have a interval of 3s.
//! 2. We fire our request at time = 0s.
//! 3. We timeout after time = 10s
//! 4. We fire our next request at time t = 13s

use futures::{Future, Stream};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::time::{sleep_until, Instant as TokioInstant, Sleep};

/// A stream representing notifications at fixed interval
pub struct Interval {
    /// Future that completes the next time the `Interval` yields a value.
    delay: Pin<Box<Sleep>>,

    /// The duration between values yielded by `Interval`.
    duration: Duration,

    /// The next time we should fire
    next_time: TokioInstant,
}

impl Interval {
    /// Create a new `Interval` that starts at `at` and yields every `duration`
    /// interval after that.
    ///
    /// Note that when it starts, it produces item too.
    ///
    /// The `duration` argument must be a non-zero duration.
    ///
    /// # Panics
    ///
    /// This function panics if `duration` is zero.
    pub fn new(_at: Instant, duration: Duration) -> Interval {
        assert!(
            duration > Duration::new(0, 0),
            "`duration` must be non-zero."
        );

        let tokio_at = TokioInstant::now() + duration;
        Interval {
            delay: Box::pin(sleep_until(tokio_at)),
            duration,
            next_time: tokio_at,
        }
    }

    /// Creates new `Interval` that yields with interval of `duration`.
    ///
    /// The function is shortcut for `Interval::new(Instant::now() + duration,
    /// duration)`.
    ///
    /// The `duration` argument must be a non-zero duration.
    ///
    /// # Panics
    ///
    /// This function panics if `duration` is zero.
    pub fn new_interval(duration: Duration) -> Interval {
        Interval::new(Instant::now(), duration)
    }
}

impl Stream for Interval {
    type Item = Instant;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Wait for the delay to be done
        match self.delay.as_mut().poll(cx) {
            Poll::Ready(()) => {
                // Always schedule next fire from current time to prevent catch-up bursts
                // When requests take longer than interval duration (e.g., timeouts),
                // this ensures we wait the full interval before the next attempt
                let duration = self.duration;
                let now = TokioInstant::now();
                self.next_time = now + duration;
                self.delay = Box::pin(sleep_until(self.next_time));

                // Return the current instant
                Poll::Ready(Some(Instant::now()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
