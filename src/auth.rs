//! Authentication and authorization system.
//!
//! This module handles API key authentication with support for per-key
//! method allowlists and rate limits.

use crate::allowlist::Allowlist;
use crate::allowlist_config::MethodsConfig;
use crate::config_types::ApiKeyConfig;
use std::collections::HashMap;

/// API key with associated permissions and limits.
#[derive(Debug, Clone)]
pub struct ApiKey {
    /// The key value (for constant-time comparison).
    pub key: String,
    /// Optional name for logging/debugging.
    pub name: Option<String>,
    /// Method allowlist for this key.
    pub allowlist: Allowlist,
    /// Optional custom rate limit (requests per minute).
    pub rate_limit_per_minute: Option<u32>,
}

/// Authentication manager with per-key permissions.
#[derive(Debug, Clone)]
pub struct AuthManager {
    /// Map of API key -> ApiKey struct.
    keys: HashMap<String, ApiKey>,
    /// Whether authentication is enabled (keys is non-empty).
    enabled: bool,
}

impl AuthManager {
    /// Create a new authentication manager from API key configurations.
    pub fn new(key_configs: Vec<ApiKeyConfig>, default_methods: &MethodsConfig) -> Self {
        let keys: HashMap<String, ApiKey> = key_configs
            .into_iter()
            .map(|config| {
                // Use per-key methods config if specified, otherwise use default
                let methods_config = if let Some(preset) = config.methods_preset {
                    MethodsConfig {
                        preset,
                        allow_groups: config.allow_groups.clone(),
                        allow_extra: config.allow_extra.clone(),
                        deny: config.deny.clone(),
                    }
                } else {
                    default_methods.clone()
                };

                let api_key = ApiKey {
                    key: config.key.clone(),
                    name: config.name,
                    allowlist: Allowlist::from_config(&methods_config),
                    rate_limit_per_minute: config.rate_limit_per_minute,
                };

                (config.key, api_key)
            })
            .collect();

        let enabled = !keys.is_empty();

        Self { keys, enabled }
    }

    /// Create a simple auth manager from a list of key strings (legacy mode).
    pub fn from_simple_keys(keys: Vec<String>, default_allowlist: Allowlist) -> Self {
        let key_map: HashMap<String, ApiKey> = keys
            .into_iter()
            .map(|key| {
                let api_key = ApiKey {
                    key: key.clone(),
                    name: None,
                    allowlist: default_allowlist.clone(),
                    rate_limit_per_minute: None,
                };
                (key, api_key)
            })
            .collect();

        let enabled = !key_map.is_empty();

        Self {
            keys: key_map,
            enabled,
        }
    }

    /// Check if authentication is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Validate an API key using constant-time comparison.
    ///
    /// # Returns
    ///
    /// - `Some(ApiKey)` if the key is valid
    /// - `None` if the key is invalid or auth is disabled
    pub fn validate_key(&self, provided_key: &str) -> Option<&ApiKey> {
        if !self.enabled {
            return None;
        }

        // Constant-time comparison to prevent timing attacks
        for (key_str, api_key) in &self.keys {
            if provided_key.len() != key_str.len() {
                continue;
            }

            let provided_bytes = provided_key.as_bytes();
            let valid_bytes = key_str.as_bytes();

            let mut result = 0u8;
            for i in 0..provided_bytes.len() {
                result |= provided_bytes[i] ^ valid_bytes[i];
            }

            if result == 0 {
                return Some(api_key);
            }
        }

        None
    }

    /// Get the number of configured API keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist_config::Preset;

    #[test]
    fn test_auth_manager_creation() {
        let default_methods = MethodsConfig {
            preset: Preset::Safe,
            ..Default::default()
        };

        let configs = vec![ApiKeyConfig {
            key: "test-key-1".to_string(),
            name: Some("Test Key".to_string()),
            methods_preset: Some(Preset::Minimal),
            allow_groups: vec![],
            allow_extra: vec![],
            deny: vec![],
            rate_limit_per_minute: Some(100),
        }];

        let manager = AuthManager::new(configs, &default_methods);

        assert!(manager.is_enabled());
        assert_eq!(manager.key_count(), 1);
    }

    #[test]
    fn test_validate_key_success() {
        let default_methods = MethodsConfig {
            preset: Preset::Safe,
            ..Default::default()
        };

        let configs = vec![ApiKeyConfig {
            key: "valid-key".to_string(),
            name: Some("Valid".to_string()),
            methods_preset: None,
            allow_groups: vec![],
            allow_extra: vec![],
            deny: vec![],
            rate_limit_per_minute: None,
        }];

        let manager = AuthManager::new(configs, &default_methods);

        let result = manager.validate_key("valid-key");
        assert!(result.is_some());

        let api_key = result.unwrap();
        assert_eq!(api_key.key, "valid-key");
        assert_eq!(api_key.name, Some("Valid".to_string()));
    }

    #[test]
    fn test_validate_key_failure() {
        let default_methods = MethodsConfig {
            preset: Preset::Safe,
            ..Default::default()
        };

        let configs = vec![ApiKeyConfig {
            key: "valid-key".to_string(),
            name: None,
            methods_preset: None,
            allow_groups: vec![],
            allow_extra: vec![],
            deny: vec![],
            rate_limit_per_minute: None,
        }];

        let manager = AuthManager::new(configs, &default_methods);

        assert!(manager.validate_key("invalid-key").is_none());
        assert!(manager.validate_key("").is_none());
    }

    #[test]
    fn test_constant_time_comparison() {
        let default_methods = MethodsConfig {
            preset: Preset::Safe,
            ..Default::default()
        };

        let configs = vec![
            ApiKeyConfig {
                key: "key1".to_string(),
                name: None,
                methods_preset: None,
                allow_groups: vec![],
                allow_extra: vec![],
                deny: vec![],
                rate_limit_per_minute: None,
            },
            ApiKeyConfig {
                key: "key2".to_string(),
                name: None,
                methods_preset: None,
                allow_groups: vec![],
                allow_extra: vec![],
                deny: vec![],
                rate_limit_per_minute: None,
            },
        ];

        let manager = AuthManager::new(configs, &default_methods);

        // Should validate correctly
        assert!(manager.validate_key("key1").is_some());
        assert!(manager.validate_key("key2").is_some());

        // Should reject similar but incorrect keys
        assert!(manager.validate_key("key3").is_none());
        assert!(manager.validate_key("key").is_none());
    }

    #[test]
    fn test_per_key_allowlist() {
        let default_methods = MethodsConfig {
            preset: Preset::Safe,
            ..Default::default()
        };

        let configs = vec![
            ApiKeyConfig {
                key: "admin-key".to_string(),
                name: Some("Admin".to_string()),
                methods_preset: Some(Preset::Full),
                allow_groups: vec![],
                allow_extra: vec![],
                deny: vec![],
                rate_limit_per_minute: None,
            },
            ApiKeyConfig {
                key: "readonly-key".to_string(),
                name: Some("Read Only".to_string()),
                methods_preset: Some(Preset::Minimal),
                allow_groups: vec![],
                allow_extra: vec![],
                deny: vec![],
                rate_limit_per_minute: None,
            },
        ];

        let manager = AuthManager::new(configs, &default_methods);

        let admin = manager.validate_key("admin-key").unwrap();
        let readonly = manager.validate_key("readonly-key").unwrap();

        // Admin key should have more methods allowed
        assert!(admin.allowlist.len() > readonly.allowlist.len());
    }

    #[test]
    fn test_per_key_rate_limit() {
        let default_methods = MethodsConfig {
            preset: Preset::Safe,
            ..Default::default()
        };

        let configs = vec![ApiKeyConfig {
            key: "limited-key".to_string(),
            name: None,
            methods_preset: None,
            allow_groups: vec![],
            allow_extra: vec![],
            deny: vec![],
            rate_limit_per_minute: Some(10),
        }];

        let manager = AuthManager::new(configs, &default_methods);

        let api_key = manager.validate_key("limited-key").unwrap();
        assert_eq!(api_key.rate_limit_per_minute, Some(10));
    }

    #[test]
    fn test_simple_keys_mode() {
        let default_allowlist = Allowlist::from_config(&MethodsConfig {
            preset: Preset::Safe,
            ..Default::default()
        });

        let keys = vec!["key1".to_string(), "key2".to_string()];
        let manager = AuthManager::from_simple_keys(keys, default_allowlist);

        assert!(manager.is_enabled());
        assert_eq!(manager.key_count(), 2);
        assert!(manager.validate_key("key1").is_some());
        assert!(manager.validate_key("key2").is_some());
        assert!(manager.validate_key("key3").is_none());
    }

    #[test]
    fn test_disabled_auth() {
        let default_methods = MethodsConfig {
            preset: Preset::Safe,
            ..Default::default()
        };

        let manager = AuthManager::new(vec![], &default_methods);

        assert!(!manager.is_enabled());
        assert_eq!(manager.key_count(), 0);
        assert!(manager.validate_key("any-key").is_none());
    }
}
