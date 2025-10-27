//! Audit logging for security and compliance.
//!
//! This module provides structured audit logging for security-sensitive operations
//! including authentication, authorization, and RPC method calls.

use crate::config_types::AuditConfig;
use serde::Serialize;
use std::net::IpAddr;
use tracing::{info, warn};

/// Maximum length for sanitized strings in audit logs.
const MAX_AUDIT_STRING_LENGTH: usize = 256;

/// Sanitizes user-controlled input for safe logging.
///
/// This function prevents log injection attacks by:
/// - Removing control characters (newlines, carriage returns, tabs, etc.)
/// - Limiting string length to prevent log flooding
/// - Preserving only printable ASCII and common UTF-8 characters
///
/// # Arguments
///
/// * `input` - The string to sanitize
///
/// # Returns
///
/// A sanitized string safe for logging
fn sanitize_for_log(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .filter(|c| {
            // Keep printable ASCII and common UTF-8, but exclude control characters
            !c.is_control() || *c == ' '
        })
        .take(MAX_AUDIT_STRING_LENGTH)
        .collect();

    // Add truncation marker if string was truncated
    if input.len() > MAX_AUDIT_STRING_LENGTH {
        format!("{}...[truncated]", cleaned)
    } else {
        cleaned
    }
}

/// Audit logger for security events.
#[derive(Debug, Clone)]
pub struct AuditLogger {
    config: AuditConfig,
}

impl AuditLogger {
    /// Create a new audit logger with the given configuration.
    pub fn new(config: AuditConfig) -> Self {
        Self { config }
    }

    /// Log an RPC request.
    #[allow(dead_code)] // Infrastructure for comprehensive audit logging
    pub fn log_request(&self, event: &RequestEvent) {
        if !self.config.enabled || !self.config.log_requests {
            return;
        }

        let method = sanitize_for_log(&event.method);

        info!(
            target: "audit",
            event_type = "rpc_request",
            request_id = %event.request_id,
            client_ip = %event.client_ip,
            method = %method,
            param_count = event.param_count,
            "RPC request"
        );
    }

    /// Log an RPC response.
    #[allow(dead_code)] // Infrastructure for comprehensive audit logging
    pub fn log_response(&self, event: &ResponseEvent) {
        if !self.config.enabled || !self.config.log_responses {
            return;
        }

        let method = sanitize_for_log(&event.method);

        info!(
            target: "audit",
            event_type = "rpc_response",
            request_id = %event.request_id,
            method = %method,
            success = event.success,
            duration_ms = event.duration_ms,
            response_size = event.response_size,
            "RPC response"
        );
    }

    /// Log an authentication attempt.
    pub fn log_auth(&self, event: &AuthEvent) {
        if !self.config.enabled || !self.config.log_auth {
            return;
        }

        if event.success {
            info!(
                target: "audit",
                event_type = "authentication",
                request_id = %event.request_id,
                client_ip = %event.client_ip,
                success = true,
                key_name = ?event.key_name,
                "Authentication successful"
            );
        } else {
            let reason = event
                .failure_reason
                .as_ref()
                .map(|r| sanitize_for_log(r))
                .unwrap_or_else(|| "unknown".to_string());

            warn!(
                target: "audit",
                event_type = "authentication",
                request_id = %event.request_id,
                client_ip = %event.client_ip,
                success = false,
                reason = %reason,
                "Authentication failed"
            );
        }
    }

    /// Log a rate limit event.
    pub fn log_rate_limit(&self, event: &RateLimitEvent) {
        if !self.config.enabled || !self.config.log_rate_limits {
            return;
        }

        let limit_type = sanitize_for_log(&event.limit_type);

        warn!(
            target: "audit",
            event_type = "rate_limit",
            request_id = %event.request_id,
            client_ip = %event.client_ip,
            limit_type = %limit_type,
            "Rate limit exceeded"
        );
    }

    /// Log an error event.
    #[allow(dead_code)] // Infrastructure for comprehensive audit logging
    pub fn log_error(&self, event: &ErrorEvent) {
        if !self.config.enabled || !self.config.log_errors {
            return;
        }

        let error_type = sanitize_for_log(&event.error_type);
        let method = event.method.as_ref().map(|m| sanitize_for_log(m));
        let message = sanitize_for_log(&event.message);

        warn!(
            target: "audit",
            event_type = "error",
            request_id = %event.request_id,
            client_ip = %event.client_ip,
            error_type = %error_type,
            error_code = ?event.error_code,
            method = ?method,
            message = %message,
            "RPC error"
        );
    }

    /// Log a method rejection (allowlist).
    #[allow(dead_code)] // Infrastructure for comprehensive audit logging
    pub fn log_method_rejection(&self, event: &MethodRejectionEvent) {
        if !self.config.enabled {
            return;
        }

        let method = sanitize_for_log(&event.method);
        let reason = sanitize_for_log(&event.reason);

        warn!(
            target: "audit",
            event_type = "method_rejection",
            request_id = %event.request_id,
            client_ip = %event.client_ip,
            method = %method,
            reason = %reason,
            "Method not allowed"
        );
    }
}

/// RPC request event.
#[allow(dead_code)] // Infrastructure for comprehensive audit logging
#[derive(Debug, Clone, Serialize)]
pub struct RequestEvent {
    pub request_id: String,
    pub client_ip: IpAddr,
    pub method: String,
    pub param_count: usize,
}

/// RPC response event.
#[allow(dead_code)] // Infrastructure for comprehensive audit logging
#[derive(Debug, Clone, Serialize)]
pub struct ResponseEvent {
    pub request_id: String,
    pub method: String,
    pub success: bool,
    pub duration_ms: u64,
    pub response_size: usize,
}

/// Authentication event.
#[derive(Debug, Clone, Serialize)]
pub struct AuthEvent {
    pub request_id: String,
    pub client_ip: IpAddr,
    pub success: bool,
    pub key_name: Option<String>,
    pub failure_reason: Option<String>,
}

/// Rate limit event.
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitEvent {
    pub request_id: String,
    pub client_ip: IpAddr,
    pub limit_type: String,
}

/// Error event.
#[allow(dead_code)] // Infrastructure for comprehensive audit logging
#[derive(Debug, Clone, Serialize)]
pub struct ErrorEvent {
    pub request_id: String,
    pub client_ip: IpAddr,
    pub error_type: String,
    pub error_code: Option<i64>,
    pub method: Option<String>,
    pub message: String,
}

/// Method rejection event.
#[allow(dead_code)] // Infrastructure for comprehensive audit logging
#[derive(Debug, Clone, Serialize)]
pub struct MethodRejectionEvent {
    pub request_id: String,
    pub client_ip: IpAddr,
    pub method: String,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_sanitize_for_log_basic() {
        assert_eq!(sanitize_for_log("hello"), "hello");
        assert_eq!(sanitize_for_log("hello world"), "hello world");
    }

    #[test]
    fn test_sanitize_for_log_newlines() {
        assert_eq!(sanitize_for_log("hello\nworld"), "helloworld");
        assert_eq!(sanitize_for_log("hello\r\nworld"), "helloworld");
        assert_eq!(sanitize_for_log("line1\nline2\nline3"), "line1line2line3");
    }

    #[test]
    fn test_sanitize_for_log_control_chars() {
        assert_eq!(sanitize_for_log("hello\tworld"), "helloworld");
        assert_eq!(sanitize_for_log("hello\x00world"), "helloworld");
        assert_eq!(sanitize_for_log("test\x1b[31mRED\x1b[0m"), "test[31mRED[0m");
    }

    #[test]
    fn test_sanitize_for_log_preserves_space() {
        assert_eq!(sanitize_for_log("hello world"), "hello world");
        assert_eq!(sanitize_for_log("  spaces  "), "  spaces  ");
    }

    #[test]
    fn test_sanitize_for_log_truncation() {
        let long_string = "a".repeat(300);
        let sanitized = sanitize_for_log(&long_string);

        // Should have marker
        assert!(sanitized.ends_with("...[truncated]"));

        // Should have exactly MAX_AUDIT_STRING_LENGTH characters before the marker
        let without_marker = sanitized.strip_suffix("...[truncated]").unwrap();
        assert_eq!(without_marker.len(), MAX_AUDIT_STRING_LENGTH);
        assert_eq!(without_marker.matches('a').count(), MAX_AUDIT_STRING_LENGTH);
    }

    #[test]
    fn test_sanitize_for_log_log_injection_attempt() {
        // Simulate log injection attempt
        let injection = "normal_method\n[2024-01-01] FAKE LOG ENTRY";
        let sanitized = sanitize_for_log(injection);

        assert!(!sanitized.contains('\n'));
        assert_eq!(sanitized, "normal_method[2024-01-01] FAKE LOG ENTRY");
    }

    #[test]
    fn test_sanitize_for_log_utf8() {
        assert_eq!(sanitize_for_log("hello 世界"), "hello 世界");
        assert_eq!(sanitize_for_log("café"), "café");
    }

    #[test]
    fn test_sanitize_for_log_empty() {
        assert_eq!(sanitize_for_log(""), "");
    }

    fn make_test_logger() -> AuditLogger {
        AuditLogger::new(AuditConfig {
            enabled: true,
            log_requests: true,
            log_responses: true,
            log_errors: true,
            log_auth: true,
            log_rate_limits: true,
        })
    }

    #[test]
    fn test_audit_logger_creation() {
        let logger = make_test_logger();
        assert!(logger.config.enabled);
    }

    #[test]
    fn test_log_request() {
        let logger = make_test_logger();
        let event = RequestEvent {
            request_id: "test-123".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            method: "getinfo".to_string(),
            param_count: 0,
        };
        logger.log_request(&event);
        // Should not panic
    }

    #[test]
    fn test_log_response() {
        let logger = make_test_logger();
        let event = ResponseEvent {
            request_id: "test-123".to_string(),
            method: "getinfo".to_string(),
            success: true,
            duration_ms: 100,
            response_size: 1024,
        };
        logger.log_response(&event);
        // Should not panic
    }

    #[test]
    fn test_log_auth_success() {
        let logger = make_test_logger();
        let event = AuthEvent {
            request_id: "test-123".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            success: true,
            key_name: Some("admin-key".to_string()),
            failure_reason: None,
        };
        logger.log_auth(&event);
        // Should not panic
    }

    #[test]
    fn test_log_auth_failure() {
        let logger = make_test_logger();
        let event = AuthEvent {
            request_id: "test-123".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            success: false,
            key_name: None,
            failure_reason: Some("invalid_key".to_string()),
        };
        logger.log_auth(&event);
        // Should not panic
    }

    #[test]
    fn test_log_rate_limit() {
        let logger = make_test_logger();
        let event = RateLimitEvent {
            request_id: "test-123".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            limit_type: "ip_global".to_string(),
        };
        logger.log_rate_limit(&event);
        // Should not panic
    }

    #[test]
    fn test_log_error() {
        let logger = make_test_logger();
        let event = ErrorEvent {
            request_id: "test-123".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            error_type: "timeout".to_string(),
            error_code: Some(-32603),
            method: Some("getblock".to_string()),
            message: "Request timeout".to_string(),
        };
        logger.log_error(&event);
        // Should not panic
    }

    #[test]
    fn test_log_method_rejection() {
        let logger = make_test_logger();
        let event = MethodRejectionEvent {
            request_id: "test-123".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            method: "sendmoney".to_string(),
            reason: "not_in_allowlist".to_string(),
        };
        logger.log_method_rejection(&event);
        // Should not panic
    }

    #[test]
    fn test_disabled_logger() {
        let logger = AuditLogger::new(AuditConfig {
            enabled: false,
            ..Default::default()
        });

        let event = RequestEvent {
            request_id: "test-123".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            method: "getinfo".to_string(),
            param_count: 0,
        };

        logger.log_request(&event);
        // Should not log anything, but also not panic
    }
}
