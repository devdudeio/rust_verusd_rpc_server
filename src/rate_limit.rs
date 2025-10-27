//! Advanced rate limiting with per-method and per-key limits.
//!
//! This module provides a sophisticated rate limiting system that supports:
//! - Per-IP global rate limits
//! - Per-method rate limits
//! - Per-API-key rate limits
//! - Hierarchical limit checking

use crate::config_types::MethodRateLimitConfig;
use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::InMemoryState;
use governor::{Quota, RateLimiter};
use std::net::IpAddr;
use std::num::NonZeroU32;

/// Composite key for rate limiting (IP + method or IP + API key).
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
enum RateLimitKey {
    /// Global per-IP limit.
    Ip(IpAddr),
    /// Per-IP, per-method limit.
    IpMethod(IpAddr, String),
    /// Per-API-key limit.
    ApiKey(String),
}

/// Advanced rate limiter with multiple limit types.
pub struct AdvancedRateLimiter {
    /// Global per-IP rate limiter.
    global_limiter: RateLimiter<IpAddr, DashMap<IpAddr, InMemoryState>, DefaultClock>,
    /// Per-method rate limiters.
    method_limiters:
        DashMap<String, RateLimiter<IpAddr, DashMap<IpAddr, InMemoryState>, DefaultClock>>,
    /// Method-specific rate limits configuration.
    method_limits: MethodRateLimitConfig,
    /// Global burst capacity.
    global_burst: u32,
}

impl AdvancedRateLimiter {
    /// Create a new advanced rate limiter.
    ///
    /// # Arguments
    ///
    /// * `global_limit` - Global requests per minute per IP
    /// * `global_burst` - Global burst capacity
    /// * `method_limits` - Per-method rate limit configuration
    pub fn new(
        global_limit: u32,
        global_burst: u32,
        method_limits: MethodRateLimitConfig,
    ) -> Result<Self, anyhow::Error> {
        let global_quota = Quota::per_minute(
            NonZeroU32::new(global_limit)
                .ok_or_else(|| anyhow::anyhow!("Global limit must be > 0"))?,
        )
        .allow_burst(
            NonZeroU32::new(global_burst)
                .ok_or_else(|| anyhow::anyhow!("Global burst must be > 0"))?,
        );

        let global_limiter = RateLimiter::dashmap(global_quota);

        Ok(Self {
            global_limiter,
            method_limiters: DashMap::new(),
            method_limits,
            global_burst,
        })
    }

    /// Check if a request should be allowed based on all applicable rate limits.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if request is allowed
    /// - `Err(String)` with the limit type that was exceeded
    pub fn check(&self, ip: IpAddr, method: Option<&str>) -> Result<(), String> {
        // Always check global limit first
        self.global_limiter
            .check_key(&ip)
            .map_err(|_| "global".to_string())?;

        // Check method-specific limit if applicable
        if let Some(method_name) = method {
            if let Some(method_limit) = self.method_limits.methods.get(method_name) {
                self.check_method_limit(ip, method_name, *method_limit)?;
            }
        }

        Ok(())
    }

    /// Check method-specific rate limit.
    fn check_method_limit(&self, ip: IpAddr, method: &str, limit: u32) -> Result<(), String> {
        // Get or create method-specific limiter
        if !self.method_limiters.contains_key(method) {
            // Use the method's limit as the burst capacity to prevent
            // burst capacity from exceeding the rate limit
            let burst = limit.max(1);
            let quota =
                Quota::per_minute(NonZeroU32::new(limit).unwrap_or(NonZeroU32::new(1).unwrap()))
                    .allow_burst(NonZeroU32::new(burst).unwrap_or(NonZeroU32::new(1).unwrap()));

            self.method_limiters
                .insert(method.to_string(), RateLimiter::dashmap(quota));
        }

        // Check the method-specific limit
        if let Some(limiter) = self.method_limiters.get(method) {
            limiter
                .check_key(&ip)
                .map_err(|_| format!("method_{}", method))?;
        }

        Ok(())
    }

    /// Get the configured limit for a method (for informational purposes).
    pub fn get_method_limit(&self, method: &str) -> u32 {
        self.method_limits
            .methods
            .get(method)
            .copied()
            .unwrap_or(self.method_limits.default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    #[test]
    fn test_global_rate_limit() {
        let method_limits = MethodRateLimitConfig {
            default: 60,
            methods: HashMap::new(),
        };

        let limiter = AdvancedRateLimiter::new(10, 5, method_limits).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should allow burst requests
        for _ in 0..5 {
            assert!(limiter.check(ip, None).is_ok());
        }

        // Should hit rate limit after burst
        assert!(limiter.check(ip, None).is_err());
    }

    #[test]
    fn test_method_specific_limit() {
        let mut methods = HashMap::new();
        methods.insert("getblock".to_string(), 2);

        let method_limits = MethodRateLimitConfig {
            default: 60,
            methods,
        };

        // Use higher global burst to not interfere with method-specific testing
        let limiter = AdvancedRateLimiter::new(100, 10, method_limits).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Method has limit=2, so burst=2. Should allow 2 requests.
        assert!(limiter.check(ip, Some("getblock")).is_ok());
        assert!(limiter.check(ip, Some("getblock")).is_ok());

        // 3rd request should hit method-specific limit
        let result = limiter.check(ip, Some("getblock"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("method_getblock"));
    }

    #[test]
    fn test_different_methods_independent() {
        let mut methods = HashMap::new();
        methods.insert("method1".to_string(), 2);
        methods.insert("method2".to_string(), 3);

        let method_limits = MethodRateLimitConfig {
            default: 60,
            methods,
        };

        // Use higher global burst to not interfere with method-specific testing
        let limiter = AdvancedRateLimiter::new(100, 10, method_limits).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // method1 has limit=2, so burst=2. Should allow 2 requests then fail.
        assert!(limiter.check(ip, Some("method1")).is_ok());
        assert!(limiter.check(ip, Some("method1")).is_ok());
        assert!(limiter.check(ip, Some("method1")).is_err());

        // method2 has limit=3, so burst=3. Should allow 3 requests independently.
        assert!(limiter.check(ip, Some("method2")).is_ok());
        assert!(limiter.check(ip, Some("method2")).is_ok());
        assert!(limiter.check(ip, Some("method2")).is_ok());
        // 4th request should fail
        assert!(limiter.check(ip, Some("method2")).is_err());
    }

    #[test]
    fn test_different_ips_independent() {
        let method_limits = MethodRateLimitConfig {
            default: 60,
            methods: HashMap::new(),
        };

        let limiter = AdvancedRateLimiter::new(2, 2, method_limits).unwrap();
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        // Exhaust IP1 limit
        assert!(limiter.check(ip1, None).is_ok());
        assert!(limiter.check(ip1, None).is_ok());
        assert!(limiter.check(ip1, None).is_err());

        // IP2 should still work
        assert!(limiter.check(ip2, None).is_ok());
        assert!(limiter.check(ip2, None).is_ok());
    }

    #[test]
    fn test_get_method_limit() {
        let mut methods = HashMap::new();
        methods.insert("getblock".to_string(), 10);

        let method_limits = MethodRateLimitConfig {
            default: 60,
            methods,
        };

        let limiter = AdvancedRateLimiter::new(100, 10, method_limits).unwrap();

        assert_eq!(limiter.get_method_limit("getblock"), 10);
        assert_eq!(limiter.get_method_limit("getinfo"), 60); // default
    }

    #[test]
    fn test_invalid_limits() {
        let method_limits = MethodRateLimitConfig {
            default: 60,
            methods: HashMap::new(),
        };

        assert!(AdvancedRateLimiter::new(0, 10, method_limits.clone()).is_err());
        assert!(AdvancedRateLimiter::new(10, 0, method_limits).is_err());
    }

    #[test]
    fn test_global_limit_checked_first() {
        let mut methods = HashMap::new();
        methods.insert("test".to_string(), 1000); // Very high method limit

        let method_limits = MethodRateLimitConfig {
            default: 60,
            methods,
        };

        let limiter = AdvancedRateLimiter::new(2, 2, method_limits).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Global limit should be hit first despite high method limit
        assert!(limiter.check(ip, Some("test")).is_ok());
        assert!(limiter.check(ip, Some("test")).is_ok());

        let result = limiter.check(ip, Some("test"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "global");
    }
}
