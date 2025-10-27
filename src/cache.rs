//! Response caching system with TTL and LRU eviction.
//!
//! This module implements a thread-safe cache for RPC responses to reduce load
//! on the upstream Verus daemon and improve response times for frequently
//! requested data.
//!
//! # Features
//!
//! - LRU eviction policy
//! - Per-entry TTL with configurable defaults
//! - Thread-safe with minimal lock contention
//! - Metrics integration for cache hits/misses
//! - Configurable per-method caching

use crate::config_types::CacheConfig;
use crate::metrics;
use lru::LruCache;
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

/// Cache entry with TTL.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Cached response value.
    value: Value,
    /// When this entry expires.
    expires_at: Instant,
}

impl CacheEntry {
    /// Check if this entry has expired.
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Thread-safe response cache with LRU eviction and TTL.
pub struct ResponseCache {
    /// LRU cache storage.
    cache: Mutex<LruCache<String, CacheEntry>>,
    /// Default TTL for cache entries.
    default_ttl: Duration,
    /// Per-method TTL overrides.
    method_ttl: HashMap<String, Duration>,
    /// Methods that should be cached.
    cacheable_methods: HashMap<String, bool>,
}

impl ResponseCache {
    /// Create a new response cache from configuration.
    pub fn new(config: &CacheConfig) -> Self {
        let capacity = NonZeroUsize::new(config.max_entries).unwrap_or_else(|| {
            NonZeroUsize::new(1).expect("1 is non-zero, this should never fail")
        });

        let cacheable_methods: HashMap<String, bool> =
            config.methods.iter().map(|m| (m.clone(), true)).collect();

        let method_ttl: HashMap<String, Duration> = config
            .method_ttl
            .iter()
            .map(|(k, v)| (k.clone(), Duration::from_secs(*v)))
            .collect();

        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            default_ttl: Duration::from_secs(config.ttl_seconds),
            method_ttl,
            cacheable_methods,
        }
    }

    /// Check if a method should be cached.
    pub fn is_cacheable(&self, method: &str) -> bool {
        self.cacheable_methods.get(method).copied().unwrap_or(false)
    }

    /// Get the TTL for a specific method.
    fn get_ttl(&self, method: &str) -> Duration {
        self.method_ttl
            .get(method)
            .copied()
            .unwrap_or(self.default_ttl)
    }

    /// Generate cache key from method and parameters.
    fn make_key(method: &str, params: &[Box<serde_json::value::RawValue>]) -> String {
        let params_str = params.iter().map(|p| p.get()).collect::<Vec<_>>().join(",");
        format!("{}:{}", method, params_str)
    }

    /// Get a cached response if it exists and hasn't expired.
    pub fn get(&self, method: &str, params: &[Box<serde_json::value::RawValue>]) -> Option<Value> {
        if !self.is_cacheable(method) {
            return None;
        }

        let key = Self::make_key(method, params);
        let mut cache = self.cache.lock();

        if let Some(entry) = cache.get(&key) {
            if entry.is_expired() {
                cache.pop(&key);
                metrics::CACHE_OPERATIONS_TOTAL
                    .with_label_values(&["expired", method])
                    .inc();
                None
            } else {
                metrics::CACHE_OPERATIONS_TOTAL
                    .with_label_values(&["hit", method])
                    .inc();
                Some(entry.value.clone())
            }
        } else {
            metrics::CACHE_OPERATIONS_TOTAL
                .with_label_values(&["miss", method])
                .inc();
            None
        }
    }

    /// Store a response in the cache.
    pub fn put(&self, method: &str, params: &[Box<serde_json::value::RawValue>], value: Value) {
        if !self.is_cacheable(method) {
            return;
        }

        let key = Self::make_key(method, params);
        let ttl = self.get_ttl(method);
        let entry = CacheEntry {
            value,
            expires_at: Instant::now() + ttl,
        };

        let mut cache = self.cache.lock();
        cache.put(key, entry);

        // Update cache size metric
        metrics::CACHE_SIZE.set(cache.len() as i64);
    }

    /// Clear all cached entries.
    #[allow(dead_code)] // Utility method for future cache management endpoints
    pub fn clear(&self) {
        let mut cache = self.cache.lock();
        cache.clear();
        metrics::CACHE_SIZE.set(0);
    }

    /// Get current cache statistics.
    #[allow(dead_code)] // Utility method for future monitoring endpoints
    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.lock();
        CacheStats {
            size: cache.len(),
            capacity: cache.cap().get(),
        }
    }
}

/// Cache statistics.
#[allow(dead_code)] // Used by stats() method for future monitoring
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Current number of entries in cache.
    pub size: usize,
    /// Maximum cache capacity.
    pub capacity: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, value::RawValue};

    fn make_test_cache() -> ResponseCache {
        let config = CacheConfig {
            enabled: true,
            ttl_seconds: 10,
            max_entries: 100,
            methods: vec!["getinfo".to_string(), "getblockcount".to_string()],
            method_ttl: [("getblock".to_string(), 5)].iter().cloned().collect(),
        };
        ResponseCache::new(&config)
    }

    #[test]
    fn test_cache_basic_operations() {
        let cache = make_test_cache();
        let params = vec![];
        let value = json!({"result": "test"});

        // Miss on first access
        assert!(cache.get("getinfo", &params).is_none());

        // Store value
        cache.put("getinfo", &params, value.clone());

        // Hit on second access
        let cached = cache.get("getinfo", &params);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), value);
    }

    #[test]
    fn test_cache_non_cacheable_method() {
        let cache = make_test_cache();
        let params = vec![];
        let value = json!({"result": "test"});

        // Non-cacheable method
        cache.put("sendrawtransaction", &params, value.clone());
        assert!(cache.get("sendrawtransaction", &params).is_none());
    }

    #[test]
    fn test_cache_with_params() {
        let config = CacheConfig {
            enabled: true,
            ttl_seconds: 10,
            max_entries: 100,
            methods: vec!["getblock".to_string()],
            method_ttl: HashMap::new(),
        };
        let cache = ResponseCache::new(&config);

        let params1 = vec![RawValue::from_string("\"hash1\"".to_string()).unwrap()];
        let params2 = vec![RawValue::from_string("\"hash2\"".to_string()).unwrap()];
        let value1 = json!({"block": 1});
        let value2 = json!({"block": 2});

        cache.put("getblock", &params1, value1.clone());
        cache.put("getblock", &params2, value2.clone());

        // Different params should have different cache entries
        assert_eq!(cache.get("getblock", &params1).unwrap(), value1);
        assert_eq!(cache.get("getblock", &params2).unwrap(), value2);
    }

    #[test]
    fn test_cache_expiration() {
        use std::thread;

        let config = CacheConfig {
            enabled: true,
            ttl_seconds: 0, // Expire immediately for testing
            max_entries: 100,
            methods: vec!["getinfo".to_string()],
            method_ttl: HashMap::new(),
        };
        let cache = ResponseCache::new(&config);

        let params = vec![];
        let value = json!({"result": "test"});

        cache.put("getinfo", &params, value);
        thread::sleep(Duration::from_millis(10));

        // Should be expired
        assert!(cache.get("getinfo", &params).is_none());
    }

    #[test]
    fn test_cache_lru_eviction() {
        let config = CacheConfig {
            enabled: true,
            ttl_seconds: 10,
            max_entries: 2, // Small cache for testing eviction
            methods: vec!["getinfo".to_string()],
            method_ttl: HashMap::new(),
        };
        let cache = ResponseCache::new(&config);

        let params1: Vec<Box<RawValue>> = vec![RawValue::from_string("\"1\"".to_string()).unwrap()];
        let params2: Vec<Box<RawValue>> = vec![RawValue::from_string("\"2\"".to_string()).unwrap()];
        let params3: Vec<Box<RawValue>> = vec![RawValue::from_string("\"3\"".to_string()).unwrap()];

        cache.put("getinfo", &params1, json!(1));
        cache.put("getinfo", &params2, json!(2));
        cache.put("getinfo", &params3, json!(3)); // Should evict params1

        // First entry should be evicted
        assert!(cache.get("getinfo", &params1).is_none());
        // Other entries should still be there
        assert!(cache.get("getinfo", &params2).is_some());
        assert!(cache.get("getinfo", &params3).is_some());
    }

    #[test]
    fn test_cache_clear() {
        let cache = make_test_cache();
        let params = vec![];

        cache.put("getinfo", &params, json!({"result": "test"}));
        assert!(cache.get("getinfo", &params).is_some());

        cache.clear();
        assert!(cache.get("getinfo", &params).is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache = make_test_cache();
        let params = vec![];

        let stats = cache.stats();
        assert_eq!(stats.size, 0);
        assert_eq!(stats.capacity, 100);

        cache.put("getinfo", &params, json!({"result": "test"}));

        let stats = cache.stats();
        assert_eq!(stats.size, 1);
    }

    #[test]
    fn test_per_method_ttl() {
        let cache = make_test_cache();

        // getinfo has default TTL (10s)
        assert_eq!(cache.get_ttl("getinfo"), Duration::from_secs(10));

        // getblock has custom TTL (5s)
        assert_eq!(cache.get_ttl("getblock"), Duration::from_secs(5));
    }
}
