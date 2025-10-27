//! Prometheus metrics collection and exposure.
//!
//! This module provides comprehensive metrics for monitoring the RPC server's
//! performance, health, and usage patterns. Metrics are exposed in Prometheus
//! format on the `/metrics` endpoint.
//!
//! # Metrics Categories
//!
//! - **Request Metrics**: Total requests, duration, status codes
//! - **Method Metrics**: Per-RPC-method call counts and latencies
//! - **Rate Limiting**: Rate limit hits and rejections
//! - **Authentication**: Auth success/failure counts
//! - **Errors**: Error counts by type and method
//! - **Cache**: Cache hit/miss ratios (when caching is enabled)
//! - **System**: Active connections, uptime

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec, register_int_counter_vec,
    register_int_gauge, CounterVec, Encoder, Gauge, HistogramVec, IntCounterVec, IntGauge,
    TextEncoder,
};
use std::time::Instant;

lazy_static! {
    /// Total number of HTTP requests received, labeled by endpoint and status code.
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "http_requests_total",
        "Total number of HTTP requests received",
        &["endpoint", "method", "status"]
    )
    .unwrap();

    /// Duration of HTTP requests in seconds.
    pub static ref HTTP_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["endpoint", "method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap();

    /// Total number of RPC method calls, labeled by method name and status.
    pub static ref RPC_CALLS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "rpc_calls_total",
        "Total number of RPC method calls",
        &["method", "status"]
    )
    .unwrap();

    /// Duration of RPC method calls in seconds.
    pub static ref RPC_CALL_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "rpc_call_duration_seconds",
        "RPC method call duration in seconds",
        &["method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
    )
    .unwrap();

    /// Number of currently active HTTP connections.
    pub static ref ACTIVE_CONNECTIONS: IntGauge = register_int_gauge!(
        "active_connections",
        "Number of currently active HTTP connections"
    )
    .unwrap();

    /// Total number of rate limit hits.
    pub static ref RATE_LIMIT_HITS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "rate_limit_hits_total",
        "Total number of rate limit hits",
        &["ip", "limit_type"]
    )
    .unwrap();

    /// Total number of authentication attempts.
    pub static ref AUTH_ATTEMPTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "auth_attempts_total",
        "Total number of authentication attempts",
        &["status"]
    )
    .unwrap();

    /// Total number of method allowlist rejections.
    pub static ref METHOD_REJECTIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "method_rejections_total",
        "Total number of method allowlist rejections",
        &["method"]
    )
    .unwrap();

    /// Total number of errors by type.
    pub static ref ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "errors_total",
        "Total number of errors by type",
        &["error_type", "method"]
    )
    .unwrap();

    /// Total number of upstream RPC errors.
    pub static ref UPSTREAM_ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "upstream_errors_total",
        "Total number of upstream RPC errors",
        &["error_code"]
    )
    .unwrap();

    /// Cache hit/miss counters.
    pub static ref CACHE_OPERATIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "cache_operations_total",
        "Total number of cache operations",
        &["operation", "method"]
    )
    .unwrap();

    /// Current cache size (number of entries).
    pub static ref CACHE_SIZE: IntGauge = register_int_gauge!(
        "cache_size",
        "Current number of entries in the cache"
    )
    .unwrap();

    /// Server uptime in seconds.
    pub static ref UPTIME_SECONDS: Gauge = register_gauge!(
        "uptime_seconds",
        "Server uptime in seconds"
    )
    .unwrap();

    /// Total bytes sent in responses.
    pub static ref RESPONSE_SIZE_BYTES: CounterVec = register_counter_vec!(
        "response_size_bytes_total",
        "Total bytes sent in responses",
        &["endpoint"]
    )
    .unwrap();

    /// Total bytes received in requests.
    pub static ref REQUEST_SIZE_BYTES: CounterVec = register_counter_vec!(
        "request_size_bytes_total",
        "Total bytes received in requests",
        &["endpoint"]
    )
    .unwrap();
}

/// Server start time for uptime calculation.
static SERVER_START: once_cell::sync::Lazy<Instant> = once_cell::sync::Lazy::new(Instant::now);

/// Initialize metrics system.
///
/// This should be called once at server startup.
pub fn init() {
    // Ensure all metrics are registered by accessing them
    let _ = &*HTTP_REQUESTS_TOTAL;
    let _ = &*HTTP_REQUEST_DURATION_SECONDS;
    let _ = &*RPC_CALLS_TOTAL;
    let _ = &*RPC_CALL_DURATION_SECONDS;
    let _ = &*ACTIVE_CONNECTIONS;
    let _ = &*RATE_LIMIT_HITS_TOTAL;
    let _ = &*AUTH_ATTEMPTS_TOTAL;
    let _ = &*METHOD_REJECTIONS_TOTAL;
    let _ = &*ERRORS_TOTAL;
    let _ = &*UPSTREAM_ERRORS_TOTAL;
    let _ = &*CACHE_OPERATIONS_TOTAL;
    let _ = &*CACHE_SIZE;
    let _ = &*UPTIME_SECONDS;
    let _ = &*RESPONSE_SIZE_BYTES;
    let _ = &*REQUEST_SIZE_BYTES;

    // Initialize server start time
    let _ = &*SERVER_START;

    tracing::info!("Metrics system initialized");
}

/// Update uptime metric.
pub fn update_uptime() {
    let uptime = SERVER_START.elapsed().as_secs_f64();
    UPTIME_SECONDS.set(uptime);
}

/// Gather and encode all metrics in Prometheus text format.
///
/// # Returns
///
/// Encoded metrics as a UTF-8 string, or an error if encoding fails.
pub fn gather() -> Result<String, anyhow::Error> {
    // Update uptime before gathering
    update_uptime();

    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}

/// Helper for timing operations.
#[allow(dead_code)] // Utility for future timing instrumentation
pub struct Timer {
    start: Instant,
}

#[allow(dead_code)]
impl Timer {
    /// Start a new timer.
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Observe the elapsed time in the given histogram.
    pub fn observe_duration(self, histogram: &HistogramVec, labels: &[&str]) {
        let duration = self.start.elapsed().as_secs_f64();
        histogram.with_label_values(labels).observe(duration);
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        init();
        // Should not panic
    }

    #[test]
    fn test_gather_metrics() {
        init();
        let result = gather();
        assert!(result.is_ok());
        let metrics = result.unwrap();
        assert!(metrics.contains("http_requests_total"));
        assert!(metrics.contains("uptime_seconds"));
    }

    #[test]
    fn test_timer() {
        use std::thread;
        use std::time::Duration;

        let timer = Timer::new();
        thread::sleep(Duration::from_millis(10));
        timer.observe_duration(&HTTP_REQUEST_DURATION_SECONDS, &["/test", "GET"]);

        // Verify the metric was recorded
        let result = gather().unwrap();
        assert!(result.contains("http_request_duration_seconds"));
    }

    #[test]
    fn test_counter_increment() {
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["/test", "GET", "200"])
            .inc();

        let result = gather().unwrap();
        assert!(result.contains("http_requests_total"));
    }

    #[test]
    fn test_uptime_updates() {
        use std::thread;
        use std::time::Duration;

        update_uptime();
        let first_uptime = UPTIME_SECONDS.get();

        thread::sleep(Duration::from_millis(100));
        update_uptime();
        let second_uptime = UPTIME_SECONDS.get();

        assert!(second_uptime > first_uptime);
    }

    #[test]
    fn test_rpc_call_metrics() {
        RPC_CALLS_TOTAL
            .with_label_values(&["getinfo", "success"])
            .inc();

        let timer = Timer::new();
        timer.observe_duration(&RPC_CALL_DURATION_SECONDS, &["getinfo"]);

        let result = gather().unwrap();
        assert!(result.contains("rpc_calls_total"));
        assert!(result.contains("rpc_call_duration_seconds"));
    }

    #[test]
    fn test_active_connections() {
        ACTIVE_CONNECTIONS.inc();
        assert_eq!(ACTIVE_CONNECTIONS.get(), 1);

        ACTIVE_CONNECTIONS.dec();
        assert_eq!(ACTIVE_CONNECTIONS.get(), 0);
    }

    #[test]
    fn test_error_metrics() {
        ERRORS_TOTAL
            .with_label_values(&["timeout", "getblock"])
            .inc();

        UPSTREAM_ERRORS_TOTAL.with_label_values(&["-32603"]).inc();

        let result = gather().unwrap();
        assert!(result.contains("errors_total"));
        assert!(result.contains("upstream_errors_total"));
    }
}
