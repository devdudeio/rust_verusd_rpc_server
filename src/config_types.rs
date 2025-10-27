//! Configuration type definitions for the RPC server.
//!
//! This module defines all configuration structures used by the server,
//! including metrics, authentication, rate limiting, caching, and audit logging.

use ipnetwork::IpNetwork;
use serde::Deserialize;
use std::collections::HashMap;

/// Metrics configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Whether metrics collection is enabled.
    pub enabled: bool,

    /// Endpoint path for metrics (default: "/metrics").
    pub endpoint: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "/metrics".to_string(),
        }
    }
}

/// Method-specific rate limit configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MethodRateLimitConfig {
    /// Default rate limit for all methods (requests per minute).
    #[allow(dead_code)] // Used in infrastructure, will be used for displaying limits
    #[serde(default = "default_rate_limit")]
    pub default: u32,

    /// Per-method rate limits (method_name -> requests_per_minute).
    #[serde(default)]
    pub methods: HashMap<String, u32>,
}

fn default_rate_limit() -> u32 {
    60
}

impl Default for MethodRateLimitConfig {
    fn default() -> Self {
        Self {
            default: default_rate_limit(),
            methods: HashMap::new(),
        }
    }
}

/// IP access control configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct IpAccessConfig {
    /// IP networks to allow (allowlist mode if not empty).
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// IP networks to block (always checked).
    #[serde(default)]
    pub blocklist: Vec<String>,
}

impl IpAccessConfig {
    /// Parse allowlist into IpNetwork objects.
    pub fn parse_allowlist(&self) -> Result<Vec<IpNetwork>, anyhow::Error> {
        self.allowlist
            .iter()
            .map(|s| s.parse::<IpNetwork>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Invalid IP network in allowlist: {}", e))
    }

    /// Parse blocklist into IpNetwork objects.
    pub fn parse_blocklist(&self) -> Result<Vec<IpNetwork>, anyhow::Error> {
        self.blocklist
            .iter()
            .map(|s| s.parse::<IpNetwork>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Invalid IP network in blocklist: {}", e))
    }
}

/// Audit logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Whether audit logging is enabled.
    pub enabled: bool,

    /// Log all requests (can be verbose).
    pub log_requests: bool,

    /// Log response bodies (can be very large).
    pub log_responses: bool,

    /// Log errors (recommended).
    pub log_errors: bool,

    /// Log authentication attempts.
    pub log_auth: bool,

    /// Log rate limit hits.
    pub log_rate_limits: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_requests: true,
            log_responses: false,
            log_errors: true,
            log_auth: true,
            log_rate_limits: true,
        }
    }
}

/// Response caching configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Whether caching is enabled.
    pub enabled: bool,

    /// Default TTL in seconds for cached responses.
    pub ttl_seconds: u64,

    /// Maximum number of cached entries.
    pub max_entries: usize,

    /// Methods to cache (empty means cache none by default).
    pub methods: Vec<String>,

    /// Per-method TTL overrides (method_name -> ttl_seconds).
    #[serde(default)]
    pub method_ttl: HashMap<String, u64>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_seconds: 10,
            max_entries: 1000,
            methods: vec![],
            method_ttl: HashMap::new(),
        }
    }
}

/// Upstream RPC connection configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UpstreamConfig {
    /// Maximum number of concurrent connections.
    pub max_connections: usize,

    /// Connection timeout in milliseconds.
    pub connection_timeout_ms: u64,

    /// Keep-alive timeout in milliseconds.
    pub keep_alive_timeout_ms: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            connection_timeout_ms: 5000,
            keep_alive_timeout_ms: 90000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_config_default() {
        let config = MetricsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.endpoint, "/metrics");
    }

    #[test]
    fn test_ip_access_config_parse() {
        let config = IpAccessConfig {
            allowlist: vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()],
            blocklist: vec!["1.2.3.4/32".to_string()],
        };

        let allowlist = config.parse_allowlist().unwrap();
        assert_eq!(allowlist.len(), 2);

        let blocklist = config.parse_blocklist().unwrap();
        assert_eq!(blocklist.len(), 1);
    }

    #[test]
    fn test_ip_access_config_invalid() {
        let config = IpAccessConfig {
            allowlist: vec!["invalid".to_string()],
            blocklist: vec![],
        };

        assert!(config.parse_allowlist().is_err());
    }

    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();
        assert!(!config.enabled);
        assert!(config.log_requests);
        assert!(!config.log_responses);
        assert!(config.log_errors);
    }

    #[test]
    fn test_cache_config_default() {
        let config = CacheConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.ttl_seconds, 10);
        assert_eq!(config.max_entries, 1000);
    }

    #[test]
    fn test_method_rate_limit_config() {
        let config = MethodRateLimitConfig {
            default: 60,
            methods: [("getblock".to_string(), 10)].iter().cloned().collect(),
        };

        assert_eq!(config.default, 60);
        assert_eq!(config.methods.get("getblock"), Some(&10));
    }

    #[test]
    fn test_upstream_config_default() {
        let config = UpstreamConfig::default();
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.connection_timeout_ms, 5000);
        assert_eq!(config.keep_alive_timeout_ms, 90000);
    }
}
