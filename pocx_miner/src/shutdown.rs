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

//! Graceful shutdown coordination for the miner.
//!
//! This module provides:
//! - `ShutdownCoordinator`: Manages cancellation tokens for signaling shutdown
//! - `TaskRegistry`: Tracks spawned async tasks and OS threads for cleanup

use std::sync::Mutex;
use std::thread::JoinHandle;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Coordinates graceful shutdown across all miner components.
///
/// Uses `CancellationToken` from tokio-util for efficient, hierarchical
/// cancellation signaling. Child tokens can be created for sub-components
/// that need independent cancellation control.
#[derive(Clone)]
#[allow(dead_code)]
pub struct ShutdownCoordinator {
    /// Main cancellation token - when cancelled, all tasks should stop
    token: CancellationToken,
}

#[allow(dead_code)]
impl ShutdownCoordinator {
    /// Create a new shutdown coordinator.
    pub fn new() -> Self {
        Self {
            token: CancellationToken::new(),
        }
    }

    /// Get a clone of the cancellation token for use in async tasks.
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Create a child token that will be cancelled when the parent is cancelled.
    /// Useful for mining rounds that need their own cancellation scope.
    pub fn child_token(&self) -> CancellationToken {
        self.token.child_token()
    }

    /// Signal all tasks to shut down.
    pub fn initiate_shutdown(&self) {
        log::info!("[SHUTDOWN] Signaling all tasks to stop");
        self.token.cancel();
    }

    /// Check if shutdown has been initiated.
    pub fn is_shutting_down(&self) -> bool {
        self.token.is_cancelled()
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks spawned async tasks and OS threads for cleanup during shutdown.
///
/// Uses `JoinSet` for async tasks (allows awaiting all completions) and
/// stores `JoinHandle`s for OS threads.
#[allow(dead_code)]
pub struct TaskRegistry {
    /// Async tasks spawned via tokio
    async_tasks: Mutex<JoinSet<()>>,
    /// OS thread handles for blocking operations (e.g., mining rounds)
    thread_handles: Mutex<Vec<JoinHandle<()>>>,
}

#[allow(dead_code)]
impl TaskRegistry {
    /// Create a new task registry.
    pub fn new() -> Self {
        Self {
            async_tasks: Mutex::new(JoinSet::new()),
            thread_handles: Mutex::new(Vec::new()),
        }
    }

    /// Spawn an async task and track it for cleanup.
    ///
    /// The task will be awaited during shutdown to ensure clean termination.
    pub fn spawn<F>(&self, future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        if let Ok(mut tasks) = self.async_tasks.lock() {
            tasks.spawn(future);
        }
    }

    /// Register an OS thread handle for cleanup.
    ///
    /// The thread will be joined during shutdown.
    pub fn register_thread(&self, handle: JoinHandle<()>) {
        if let Ok(mut handles) = self.thread_handles.lock() {
            handles.push(handle);
        }
    }

    /// Wait for all async tasks to complete.
    ///
    /// Called during shutdown to ensure all tasks have terminated.
    pub async fn wait_async_tasks(&self) {
        // Take ownership of the JoinSet to drain it
        let mut tasks = {
            let mut guard = self.async_tasks.lock().unwrap();
            std::mem::take(&mut *guard)
        };

        log::info!(
            "[SHUTDOWN] Waiting for {} async tasks to complete",
            tasks.len()
        );

        while tasks.join_next().await.is_some() {}

        log::info!("[SHUTDOWN] All async tasks completed");
    }

    /// Wait for all OS threads to complete.
    ///
    /// Called during shutdown after async tasks to ensure threads have terminated.
    pub fn wait_threads(&self) {
        let handles = {
            let mut guard = self.thread_handles.lock().unwrap();
            std::mem::take(&mut *guard)
        };

        log::info!(
            "[SHUTDOWN] Waiting for {} threads to complete",
            handles.len()
        );

        for handle in handles {
            if let Err(e) = handle.join() {
                log::warn!("[SHUTDOWN] Thread panicked during shutdown: {:?}", e);
            }
        }

        log::info!("[SHUTDOWN] All threads completed");
    }

    /// Get the count of tracked async tasks.
    pub fn async_task_count(&self) -> usize {
        self.async_tasks
            .lock()
            .map(|tasks| tasks.len())
            .unwrap_or(0)
    }

    /// Get the count of tracked threads.
    pub fn thread_count(&self) -> usize {
        self.thread_handles
            .lock()
            .map(|handles| handles.len())
            .unwrap_or(0)
    }
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_shutdown_coordinator_creation() {
        let coordinator = ShutdownCoordinator::new();
        assert!(!coordinator.is_shutting_down());
    }

    #[test]
    fn test_shutdown_initiation() {
        let coordinator = ShutdownCoordinator::new();
        coordinator.initiate_shutdown();
        assert!(coordinator.is_shutting_down());
    }

    #[test]
    fn test_child_token_cancellation() {
        let coordinator = ShutdownCoordinator::new();
        let child = coordinator.child_token();

        assert!(!child.is_cancelled());
        coordinator.initiate_shutdown();
        assert!(child.is_cancelled());
    }

    #[tokio::test]
    async fn test_task_registry_spawn() {
        let registry = TaskRegistry::new();
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        registry.spawn(async move {
            completed_clone.store(true, Ordering::SeqCst);
        });

        // Give the task time to run
        tokio::time::sleep(Duration::from_millis(50)).await;
        registry.wait_async_tasks().await;

        assert!(completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_task_cancellation_with_select() {
        let coordinator = ShutdownCoordinator::new();
        let registry = TaskRegistry::new();
        let token = coordinator.token();

        let was_cancelled = Arc::new(AtomicBool::new(false));
        let was_cancelled_clone = was_cancelled.clone();

        registry.spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => {
                        was_cancelled_clone.store(true, Ordering::SeqCst);
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {
                        // Would keep looping
                    }
                }
            }
        });

        // Give task time to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Signal shutdown
        coordinator.initiate_shutdown();

        // Wait with timeout
        let _ = tokio::time::timeout(Duration::from_secs(1), registry.wait_async_tasks()).await;

        assert!(was_cancelled.load(Ordering::SeqCst));
    }

    #[test]
    fn test_thread_registration() {
        let registry = TaskRegistry::new();
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        let handle = std::thread::spawn(move || {
            completed_clone.store(true, Ordering::SeqCst);
        });

        registry.register_thread(handle);
        registry.wait_threads();

        assert!(completed.load(Ordering::SeqCst));
    }
}
