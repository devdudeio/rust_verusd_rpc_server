//! Audit logging for security and compliance.
//!
//! This module provides structured audit logging for security-sensitive operations
//! including authentication, authorization, and RPC method calls.

use crate::config_types::AuditConfig;
use serde::Serialize;
use std::net::IpAddr;
use tracing::{info, warn};

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

        info!(
            target: "audit",
            event_type = "rpc_request",
            request_id = %event.request_id,
            client_ip = %event.client_ip,
            method = %event.method,
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

        info!(
            target: "audit",
            event_type = "rpc_response",
            request_id = %event.request_id,
            method = %event.method,
            success = event.success,
            duration_ms = event.duration_ms,
            response_size = event.response_size,
            "RPC response"
        );
    }

    /// Log an authentication attempt.
    #[allow(dead_code)] // Infrastructure for comprehensive audit logging
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
            warn!(
                target: "audit",
                event_type = "authentication",
                request_id = %event.request_id,
                client_ip = %event.client_ip,
                success = false,
                reason = %event.failure_reason.as_ref().unwrap_or(&"unknown".to_string()),
                "Authentication failed"
            );
        }
    }

    /// Log a rate limit event.
    #[allow(dead_code)] // Infrastructure for comprehensive audit logging
    pub fn log_rate_limit(&self, event: &RateLimitEvent) {
        if !self.config.enabled || !self.config.log_rate_limits {
            return;
        }

        warn!(
            target: "audit",
            event_type = "rate_limit",
            request_id = %event.request_id,
            client_ip = %event.client_ip,
            limit_type = %event.limit_type,
            "Rate limit exceeded"
        );
    }

    /// Log an error event.
    #[allow(dead_code)] // Infrastructure for comprehensive audit logging
    pub fn log_error(&self, event: &ErrorEvent) {
        if !self.config.enabled || !self.config.log_errors {
            return;
        }

        warn!(
            target: "audit",
            event_type = "error",
            request_id = %event.request_id,
            client_ip = %event.client_ip,
            error_type = %event.error_type,
            error_code = ?event.error_code,
            method = ?event.method,
            message = %event.message,
            "RPC error"
        );
    }

    /// Log a method rejection (allowlist).
    #[allow(dead_code)] // Infrastructure for comprehensive audit logging
    pub fn log_method_rejection(&self, event: &MethodRejectionEvent) {
        if !self.config.enabled {
            return;
        }

        warn!(
            target: "audit",
            event_type = "method_rejection",
            request_id = %event.request_id,
            client_ip = %event.client_ip,
            method = %event.method,
            reason = %event.reason,
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
#[allow(dead_code)] // Infrastructure for comprehensive audit logging
#[derive(Debug, Clone, Serialize)]
pub struct AuthEvent {
    pub request_id: String,
    pub client_ip: IpAddr,
    pub success: bool,
    pub key_name: Option<String>,
    pub failure_reason: Option<String>,
}

/// Rate limit event.
#[allow(dead_code)] // Infrastructure for comprehensive audit logging
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
