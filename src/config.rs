//! Configuration management for the Verus RPC server.
//!
//! This module handles loading and validation of all server configuration,
//! including security settings, rate limits, caching, and more.

use crate::allowlist_config::MethodsConfig;
use crate::config_types::{
    AuditConfig, CacheConfig, IpAccessConfig, MethodRateLimitConfig, MetricsConfig, UpstreamConfig,
};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

/// Default timeout for RPC requests in seconds.
const DEFAULT_REQUEST_TIMEOUT: u64 = 30;

/// Default maximum requests per IP address per minute.
const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 60;

/// Default burst capacity for rate limiting.
const DEFAULT_RATE_LIMIT_BURST: u32 = 10;

/// Complete server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfiguration {
    /// RPC endpoint URL.
    pub rpc_url: String,
    /// RPC username.
    pub rpc_user: String,
    /// RPC password.
    pub rpc_password: String,
    /// Server bind address.
    pub server_addr: String,
    /// Server port.
    pub server_port: u16,
    /// Request timeout.
    pub request_timeout: Duration,
    /// Global rate limit per minute.
    pub rate_limit_per_minute: u32,
    /// Global rate limit burst.
    pub rate_limit_burst: u32,
    /// Simple API keys (legacy mode).
    pub api_keys: Option<HashSet<String>>,
    /// CORS allowed origins.
    pub cors_origins: Vec<String>,
    /// Methods configuration.
    pub methods: MethodsConfig,
    /// Metrics configuration.
    pub metrics: MetricsConfig,
    /// Method-specific rate limits.
    pub method_rate_limits: MethodRateLimitConfig,
    /// IP access control.
    pub ip_access: IpAccessConfig,
    /// Audit logging configuration.
    pub audit: AuditConfig,
    /// Response caching configuration.
    pub cache: CacheConfig,
    /// Upstream RPC connection configuration.
    #[allow(dead_code)] // Infrastructure for future connection pool management
    pub upstream: UpstreamConfig,
}

/// Raw configuration from TOML/environment that can be deserialized.
#[derive(Debug, Deserialize)]
struct RawConfig {
    rpc_url: String,
    rpc_user: String,
    rpc_password: String,
    server_addr: String,
    server_port: u16,
    #[serde(default)]
    request_timeout: Option<u64>,
    #[serde(default)]
    rate_limit_per_minute: Option<u32>,
    #[serde(default)]
    rate_limit_burst: Option<u32>,
    #[serde(default)]
    api_keys: Option<String>,
    #[serde(default)]
    cors_allowed_origins: Option<String>,
    #[serde(default)]
    methods: MethodsConfig,
    #[serde(default)]
    metrics: MetricsConfig,
    #[serde(default)]
    method_rate_limits: MethodRateLimitConfig,
    #[serde(default)]
    ip_access: IpAccessConfig,
    #[serde(default)]
    audit: AuditConfig,
    #[serde(default)]
    cache: CacheConfig,
    #[serde(default)]
    upstream: UpstreamConfig,
}

impl ServerConfiguration {
    /// Load configuration from file and environment variables.
    pub fn load() -> Result<Self> {
        // Load configuration from file and environment variables
        let settings = config::Config::builder()
            .add_source(config::File::with_name("Conf"))
            .add_source(config::Environment::with_prefix("VERUS_RPC").separator("_"))
            .build()
            .context("Failed to load configuration")?;

        // Deserialize into raw config
        let raw: RawConfig = settings
            .try_deserialize()
            .context("Failed to deserialize configuration")?;

        // Validate basic settings
        Self::validate_basic(&raw)?;

        // Parse API keys
        let api_keys = raw
            .api_keys
            .map(|keys_str| {
                keys_str
                    .split(',')
                    .map(|k| k.trim().to_string())
                    .filter(|k| !k.is_empty())
                    .collect::<HashSet<String>>()
            })
            .filter(|keys: &HashSet<String>| !keys.is_empty());

        // Parse CORS origins
        let cors_origins = raw
            .cors_allowed_origins
            .map(|origins_str| {
                origins_str
                    .split(',')
                    .map(|o| o.trim().to_string())
                    .filter(|o| !o.is_empty())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_else(|| vec!["*".to_string()]);

        Ok(Self {
            rpc_url: raw.rpc_url,
            rpc_user: raw.rpc_user,
            rpc_password: raw.rpc_password,
            server_addr: raw.server_addr,
            server_port: raw.server_port,
            request_timeout: Duration::from_secs(
                raw.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
            ),
            rate_limit_per_minute: raw
                .rate_limit_per_minute
                .unwrap_or(DEFAULT_RATE_LIMIT_PER_MINUTE),
            rate_limit_burst: raw.rate_limit_burst.unwrap_or(DEFAULT_RATE_LIMIT_BURST),
            api_keys,
            cors_origins,
            methods: raw.methods,
            metrics: raw.metrics,
            method_rate_limits: raw.method_rate_limits,
            ip_access: raw.ip_access,
            audit: raw.audit,
            cache: raw.cache,
            upstream: raw.upstream,
        })
    }

    /// Validate basic configuration settings.
    fn validate_basic(raw: &RawConfig) -> Result<()> {
        // Validate RPC URL format
        if raw.rpc_url.is_empty() {
            anyhow::bail!("rpc_url cannot be empty");
        }
        if !raw.rpc_url.starts_with("http://") && !raw.rpc_url.starts_with("https://") {
            anyhow::bail!("rpc_url must start with http:// or https://");
        }

        // Validate credentials are not empty
        if raw.rpc_user.is_empty() {
            anyhow::bail!("rpc_user cannot be empty");
        }
        if raw.rpc_password.is_empty() {
            anyhow::bail!("rpc_password cannot be empty");
        }

        // Validate server address is not empty
        if raw.server_addr.is_empty() {
            anyhow::bail!("server_addr cannot be empty");
        }

        // Validate server address format
        raw.server_addr
            .parse::<std::net::IpAddr>()
            .context("Invalid server_addr: must be a valid IP address")?;

        // Validate server port
        if raw.server_port == 0 {
            anyhow::bail!("server_port cannot be 0");
        }

        // Warn about privileged ports (< 1024) which require root on Unix systems
        #[cfg(unix)]
        if raw.server_port < 1024 {
            use std::os::unix::fs::MetadataExt;
            // Check if running as root (UID 0)
            let is_root = std::fs::metadata("/proc/self")
                .map(|m| m.uid() == 0)
                .unwrap_or(false);

            if !is_root {
                tracing::warn!(
                    "Port {} is a privileged port (<1024) and may require root privileges to bind. \
                    Consider using a port >=1024 or running with appropriate permissions.",
                    raw.server_port
                );
            }
        }

        // Validate IP access control CIDR notation
        Self::validate_ip_access(&raw.ip_access)?;

        Ok(())
    }

    /// Validate IP access control configuration.
    fn validate_ip_access(ip_access: &IpAccessConfig) -> Result<()> {
        use ipnetwork::IpNetwork;

        // Validate allowlist CIDR notation
        for cidr in &ip_access.allowlist {
            cidr.parse::<IpNetwork>()
                .with_context(|| format!("Invalid CIDR notation in allowlist: '{}'", cidr))?;
        }

        // Validate blocklist CIDR notation
        for cidr in &ip_access.blocklist {
            cidr.parse::<IpNetwork>()
                .with_context(|| format!("Invalid CIDR notation in blocklist: '{}'", cidr))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        assert_eq!(DEFAULT_REQUEST_TIMEOUT, 30);
        assert_eq!(DEFAULT_RATE_LIMIT_PER_MINUTE, 60);
        assert_eq!(DEFAULT_RATE_LIMIT_BURST, 10);
    }
}
