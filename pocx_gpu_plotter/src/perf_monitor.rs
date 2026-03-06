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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
/// Performance monitoring and optimization utilities for PoCX Plotter
/// Provides runtime performance analysis without impacting production
/// performance
use std::time::{Duration, Instant};

/// Performance metrics collector
#[derive(Debug, Clone)]
pub struct PerfMetrics {
    pub operation: String,
    pub duration: Duration,
    pub throughput_bytes: Option<u64>,
    pub timestamp: Instant,
}

impl PerfMetrics {
    pub fn new(operation: String, duration: Duration) -> Self {
        Self {
            operation,
            duration,
            throughput_bytes: None,
            timestamp: Instant::now(),
        }
    }

    pub fn with_throughput(mut self, bytes: u64) -> Self {
        self.throughput_bytes = Some(bytes);
        self
    }

    pub fn throughput_mbps(&self) -> Option<f64> {
        self.throughput_bytes.map(|bytes| {
            let seconds = self.duration.as_secs_f64();
            if seconds > 0.0 {
                (bytes as f64) / (1024.0 * 1024.0) / seconds
            } else {
                0.0
            }
        })
    }
}

/// Global performance monitor (thread-safe)
pub struct PerfMonitor {
    metrics: Arc<Mutex<Vec<PerfMetrics>>>,
    enabled: bool,
}

impl PerfMonitor {
    pub fn new(enabled: bool) -> Self {
        Self {
            metrics: Arc::new(Mutex::new(Vec::new())),
            enabled,
        }
    }

    pub fn record(&self, metric: PerfMetrics) {
        if self.enabled {
            if let Ok(mut metrics) = self.metrics.lock() {
                metrics.push(metric);
            }
        }
    }

    pub fn get_summary(&self) -> PerfSummary {
        if let Ok(metrics) = self.metrics.lock() {
            PerfSummary::from_metrics(&metrics)
        } else {
            PerfSummary::default()
        }
    }

    pub fn clear(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.clear();
        }
    }
}

/// Performance summary and analysis
#[derive(Debug, Default)]
pub struct PerfSummary {
    pub operation_stats: HashMap<String, OperationStats>,
    pub total_operations: usize,
    pub total_duration: Duration,
}

#[derive(Debug)]
pub struct OperationStats {
    pub count: usize,
    pub total_duration: Duration,
    pub avg_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    pub avg_throughput_mbps: Option<f64>,
}

impl PerfSummary {
    pub fn from_metrics(metrics: &[PerfMetrics]) -> Self {
        let mut operation_stats = HashMap::new();
        let mut total_duration = Duration::from_secs(0);

        for metric in metrics {
            total_duration += metric.duration;

            let stats = operation_stats
                .entry(metric.operation.clone())
                .or_insert_with(|| OperationStats {
                    count: 0,
                    total_duration: Duration::from_secs(0),
                    avg_duration: Duration::from_secs(0),
                    min_duration: metric.duration,
                    max_duration: metric.duration,
                    avg_throughput_mbps: None,
                });

            stats.count += 1;
            stats.total_duration += metric.duration;
            stats.min_duration = stats.min_duration.min(metric.duration);
            stats.max_duration = stats.max_duration.max(metric.duration);
        }

        // Calculate averages
        for stats in operation_stats.values_mut() {
            if stats.count > 0 {
                stats.avg_duration = stats.total_duration / stats.count as u32;
            }
        }

        // Calculate average throughput for operations that have it
        for operation in operation_stats.keys().cloned().collect::<Vec<_>>() {
            let throughputs: Vec<f64> = metrics
                .iter()
                .filter(|m| m.operation == operation && m.throughput_mbps().is_some())
                .filter_map(|m| m.throughput_mbps())
                .collect();

            if !throughputs.is_empty() {
                let avg_throughput = throughputs.iter().sum::<f64>() / throughputs.len() as f64;
                if let Some(stats) = operation_stats.get_mut(&operation) {
                    stats.avg_throughput_mbps = Some(avg_throughput);
                }
            }
        }

        Self {
            operation_stats,
            total_operations: metrics.len(),
            total_duration,
        }
    }

    pub fn print_report(&self) {
        println!("\n=== Performance Report ===");
        println!("Total operations: {}", self.total_operations);
        println!("Total duration: {:?}", self.total_duration);
        println!();

        // Sort operations by total duration (most expensive first)
        let mut sorted_ops: Vec<_> = self.operation_stats.iter().collect();
        sorted_ops.sort_by(|a, b| b.1.total_duration.cmp(&a.1.total_duration));

        for (operation, stats) in sorted_ops {
            println!("Operation: {}", operation);
            println!("  Count: {}", stats.count);
            println!("  Total duration: {:?}", stats.total_duration);
            println!("  Average duration: {:?}", stats.avg_duration);
            println!("  Min duration: {:?}", stats.min_duration);
            println!("  Max duration: {:?}", stats.max_duration);
            if let Some(throughput) = stats.avg_throughput_mbps {
                println!("  Average throughput: {:.2} MB/s", throughput);
            }
            println!();
        }
    }

    /// Identify performance bottlenecks
    pub fn identify_bottlenecks(&self) -> Vec<String> {
        let mut bottlenecks = Vec::new();

        // Find operations that take more than 10% of total time
        let threshold = self.total_duration.as_millis() / 10;

        for (operation, stats) in &self.operation_stats {
            if stats.total_duration.as_millis() > threshold {
                bottlenecks.push(format!(
                    "{}: {:.1}% of total time ({:?})",
                    operation,
                    (stats.total_duration.as_millis() as f64
                        / self.total_duration.as_millis() as f64)
                        * 100.0,
                    stats.total_duration
                ));
            }
        }

        // Find operations with high variance (max >> avg)
        for (operation, stats) in &self.operation_stats {
            if stats.count > 1 {
                let variance_ratio =
                    stats.max_duration.as_millis() as f64 / stats.avg_duration.as_millis() as f64;
                if variance_ratio > 3.0 {
                    bottlenecks.push(format!(
                        "{}: high variance (max/avg = {:.1}x)",
                        operation, variance_ratio
                    ));
                }
            }
        }

        bottlenecks
    }
}

/// RAII performance timer
pub struct PerfTimer {
    operation: String,
    start: Instant,
    monitor: Arc<PerfMonitor>,
    bytes: Option<u64>,
}

impl PerfTimer {
    pub fn new(operation: String, monitor: Arc<PerfMonitor>) -> Self {
        Self {
            operation,
            start: Instant::now(),
            monitor,
            bytes: None,
        }
    }

    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes = Some(bytes);
        self
    }

    pub fn finish(self) {
        // Drop will handle the recording
    }
}

impl Drop for PerfTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        let mut metric = PerfMetrics::new(self.operation.clone(), duration);

        if let Some(bytes) = self.bytes {
            metric = metric.with_throughput(bytes);
        }

        self.monitor.record(metric);
    }
}

/// Performance analysis utilities
pub struct PerfAnalyzer;

impl PerfAnalyzer {
    /// Analyze memory bandwidth
    pub fn analyze_memory_bandwidth() -> f64 {
        let size = 16 * 1024 * 1024; // 16MB
        let mut data = vec![0u8; size];

        let start = Instant::now();
        for (i, item) in data.iter_mut().enumerate() {
            *item = (i % 256) as u8;
        }
        let duration = start.elapsed();

        // Calculate bandwidth in MB/s
        let seconds = duration.as_secs_f64();
        if seconds > 0.0 {
            (size as f64) / (1024.0 * 1024.0) / seconds
        } else {
            0.0
        }
    }

    /// Analyze CPU performance with simple computation
    pub fn analyze_cpu_performance() -> f64 {
        let iterations = 1_000_000;
        let start = Instant::now();

        let mut sum = 0u64;
        for i in 0..iterations {
            sum = sum
                .wrapping_add(i as u64)
                .wrapping_mul(1103515245)
                .wrapping_add(12345);
        }

        let duration = start.elapsed();
        let ops_per_sec = iterations as f64 / duration.as_secs_f64();

        // Prevent compiler optimization
        std::hint::black_box(sum);

        ops_per_sec
    }

    /// Benchmark buffer allocation performance
    pub fn benchmark_buffer_allocation(size: usize) -> Duration {
        use crate::buffer::PageAlignedByteBuffer;

        let start = Instant::now();
        let _buffer = PageAlignedByteBuffer::new(size);
        start.elapsed()
    }

    /// System performance baseline
    pub fn system_baseline() -> SystemBaseline {
        SystemBaseline {
            memory_bandwidth_mbps: Self::analyze_memory_bandwidth(),
            cpu_ops_per_sec: Self::analyze_cpu_performance(),
            buffer_alloc_4mb: Self::benchmark_buffer_allocation(4 * 1024 * 1024),
        }
    }
}

#[derive(Debug)]
pub struct SystemBaseline {
    pub memory_bandwidth_mbps: f64,
    pub cpu_ops_per_sec: f64,
    pub buffer_alloc_4mb: Duration,
}

impl SystemBaseline {
    pub fn print_report(&self) {
        println!("\n=== System Performance Baseline ===");
        println!("Memory bandwidth: {:.2} MB/s", self.memory_bandwidth_mbps);
        println!("CPU performance: {:.0} ops/sec", self.cpu_ops_per_sec);
        println!("Buffer allocation (4MB): {:?}", self.buffer_alloc_4mb);

        // Provide context
        if self.memory_bandwidth_mbps < 1000.0 {
            println!("⚠️  Memory bandwidth seems low for modern systems");
        }

        if self.cpu_ops_per_sec < 10_000_000.0 {
            println!("⚠️  CPU performance seems low");
        }

        if self.buffer_alloc_4mb.as_millis() > 10 {
            println!("⚠️  Buffer allocation seems slow");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_perf_monitor() {
        let monitor = Arc::new(PerfMonitor::new(true));

        // Record some test metrics
        monitor.record(PerfMetrics::new(
            "test_op".to_string(),
            Duration::from_millis(100),
        ));
        monitor.record(PerfMetrics::new(
            "test_op".to_string(),
            Duration::from_millis(150),
        ));
        monitor.record(PerfMetrics::new(
            "other_op".to_string(),
            Duration::from_millis(50),
        ));

        let summary = monitor.get_summary();
        assert_eq!(summary.total_operations, 3);
        assert_eq!(summary.operation_stats.len(), 2);

        let test_op_stats = &summary.operation_stats["test_op"];
        assert_eq!(test_op_stats.count, 2);
        assert_eq!(test_op_stats.avg_duration, Duration::from_millis(125));
    }

    #[test]
    fn test_perf_timer() {
        let monitor = Arc::new(PerfMonitor::new(true));

        {
            let _timer = PerfTimer::new("timer_test".to_string(), monitor.clone());
            std::thread::sleep(Duration::from_millis(10));
        } // Timer drops here and records metrics

        let summary = monitor.get_summary();
        assert_eq!(summary.total_operations, 1);
        assert!(summary.operation_stats["timer_test"].avg_duration >= Duration::from_millis(10));
    }

    #[test]
    fn test_performance_analysis() {
        let baseline = PerfAnalyzer::system_baseline();

        // Basic sanity checks
        assert!(baseline.memory_bandwidth_mbps > 0.0);
        assert!(baseline.cpu_ops_per_sec > 0.0);
        assert!(baseline.buffer_alloc_4mb > Duration::from_nanos(0));

        println!("System baseline: {:?}", baseline);
    }
}
