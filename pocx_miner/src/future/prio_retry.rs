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

//! Prio retry consumes a stream and yields elements with exponential backoffs.
//!
//! An element that is enqueued will be yielded instantly if it is a new
//! element. Otherwise it will be delayed according to the number of times that
//! it has been enqueued consecutively.
//! New items will replace old items and start with a delay of 0.

use futures::stream::Fuse;
use futures::{Future, Stream, StreamExt};
use std::cmp::Ordering;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::{sleep_until, Instant as TokioInstant, Sleep};

struct DelayedItem<Item> {
    attempt: u32,
    delay: Option<Pin<Box<Sleep>>>,
    value: Item,
}

impl<Item> DelayedItem<Item> {
    fn new(i: Item) -> Self {
        Self {
            attempt: 0,
            delay: None,
            value: i,
        }
    }

    fn exp_backoff(&mut self, delay: Duration) {
        let backoff = 2u32.pow(self.attempt) * delay;
        let sleep_until_time = TokioInstant::now() + backoff;
        self.delay = Some(Box::pin(sleep_until(sleep_until_time)));
        self.attempt += 1;
    }

    fn pause(&mut self) {
        self.delay = None;
    }
}

pub struct PrioRetry<S>
where
    S: Stream + Unpin,
    S::Item: Ord + Clone + Eq + Unpin,
{
    delay_duration: Duration,
    delayed_item: Option<DelayedItem<S::Item>>,
    stream: Fuse<S>,
}

impl<S> PrioRetry<S>
where
    S: Stream + Unpin,
    S::Item: Ord + Clone + Eq + Unpin,
{
    pub fn new(stream: S, delay_duration: Duration) -> Self {
        Self {
            delay_duration,
            delayed_item: None,
            stream: stream.fuse(),
        }
    }
}

impl<S> Stream for PrioRetry<S>
where
    S: Stream + Unpin,
    S::Item: Ord + Clone + Eq + Unpin,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match Pin::new(&mut this.stream).poll_next(cx) {
                Poll::Pending => {
                    break;
                }
                Poll::Ready(Some(new_item)) => {
                    // check if we currently have a delay item
                    if let Some(ref mut delayed_item) = this.delayed_item {
                        match delayed_item.value.cmp(&new_item) {
                            Ordering::Less => {
                                // we have new item, this one will be yielded instantly
                                this.delayed_item = Some(DelayedItem::new(new_item.clone()));
                                return Poll::Ready(Some(new_item));
                            }
                            Ordering::Equal => {
                                // if the current item was requeued, then we will yield it with a
                                // backoff
                                delayed_item.exp_backoff(this.delay_duration);
                            }
                            Ordering::Greater => (),
                        }
                    } else {
                        // we have new item, this one will be yielded instantly
                        this.delayed_item = Some(DelayedItem::new(new_item.clone()));
                        return Poll::Ready(Some(new_item));
                    }
                }
                Poll::Ready(None) => {
                    return Poll::Ready(None);
                }
            }
        }

        if let Some(ref mut delayed_item) = this.delayed_item {
            if let Some(ref mut delay) = delayed_item.delay {
                match delay.as_mut().poll(cx) {
                    Poll::Pending => {}
                    Poll::Ready(()) => {
                        // we yield a clone, since we need the old copy to check if an item was
                        // requeued
                        delayed_item.pause();
                        return Poll::Ready(Some(delayed_item.value.clone()));
                    }
                }
            }
        };

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::interval;

    #[tokio::test]
    async fn test_prio_retry() {
        let mut items = vec![0, 1, 2, 3, 3, 3, 0, 1, 2, 2, 6, 5, 7].into_iter();
        let len = items.len();
        let items =
            tokio_stream::wrappers::IntervalStream::new(interval(Duration::from_millis(200)))
                .take(len)
                .map(move |_| items.next().unwrap());
        let exp: Vec<i64> = vec![0, 1, 2, 3, 3, 3, 6, 7];
        let stream = PrioRetry::new(items, Duration::from_millis(100));
        let items: Vec<_> = stream.collect().await;
        assert_eq!(items, exp, "can't get expected items from prio retry");
    }
}
