//! Configuration structures for method allowlisting.
//!
//! This module defines the configuration options for controlling which RPC methods
//! are allowed to be called through the proxy server.

use serde::Deserialize;
use std::collections::HashSet;

/// Preset mode for method allowlisting.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    /// Only basic info methods (getinfo, getblockcount, etc.)
    Minimal,
    /// All read-only methods, no spending/wallet operations (default)
    #[default]
    Safe,
    /// All methods in the allowlist including identity operations
    Full,
    /// Define your own using allow_groups, allow_extra, and deny
    Custom,
}

/// Method group names for allowlisting.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum MethodGroup {
    /// Basic info (getinfo, getblockcount, getdifficulty, etc.)
    Readonly,
    /// Block/transaction queries (getblock, getrawtransaction, etc.)
    Blockchain,
    /// Mempool operations (getrawmempool, getmempoolinfo, etc.)
    Mempool,
    /// Address queries (getaddressbalance, getaddressutxos, etc.)
    Address,
    /// Currency operations (getcurrency, getcurrencystate, etc.)
    Currency,
    /// Identity operations (getidentity, registeridentity, etc.)
    Identity,
    /// Signature verification (verifymessage, verifyhash, etc.)
    Verification,
    /// Raw transaction operations (createrawtransaction, sendrawtransaction, etc.)
    Rawtx,
    /// Utility methods (help, estimatefee, createmultisig, etc.)
    Utility,
    /// Advanced operations (signdata, submitimports, etc.)
    Advanced,
}

/// Configuration for method allowlisting.
#[derive(Debug, Clone, Deserialize)]
pub struct MethodsConfig {
    /// Preset mode (minimal, safe, full, or custom)
    #[serde(default)]
    pub preset: Preset,

    /// Method groups to allow (only used when preset = custom)
    #[serde(default)]
    pub allow_groups: Vec<MethodGroup>,

    /// Specific methods to allow (only used when preset = custom)
    #[serde(default)]
    pub allow_extra: Vec<String>,

    /// Specific methods to deny (takes precedence, only used when preset = custom)
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Default for MethodsConfig {
    fn default() -> Self {
        Self {
            preset: Preset::Safe,
            allow_groups: Vec::new(),
            allow_extra: Vec::new(),
            deny: Vec::new(),
        }
    }
}

impl MethodsConfig {
    /// Returns the set of allowed method names based on this configuration.
    pub fn allowed_methods(&self) -> HashSet<String> {
        match self.preset {
            Preset::Minimal => Self::minimal_methods(),
            Preset::Safe => Self::safe_methods(),
            Preset::Full => Self::full_methods(),
            Preset::Custom => self.custom_methods(),
        }
    }

    /// Returns methods for the "minimal" preset.
    fn minimal_methods() -> HashSet<String> {
        vec![
            "getinfo",
            "getblockcount",
            "getbestblockhash",
            "getdifficulty",
            "getblockchaininfo",
            "getnetworkinfo",
            "getmininginfo",
            "gettxoutsetinfo",
            "coinsupply",
            "help",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    /// Returns methods for the "safe" preset.
    fn safe_methods() -> HashSet<String> {
        let mut methods = Self::group_methods(&MethodGroup::Readonly);
        methods.extend(Self::group_methods(&MethodGroup::Blockchain));
        methods.extend(Self::group_methods(&MethodGroup::Mempool));
        methods.extend(Self::group_methods(&MethodGroup::Address));
        methods.extend(Self::group_methods(&MethodGroup::Currency));
        methods.extend(Self::group_methods(&MethodGroup::Verification));
        methods.extend(Self::group_methods(&MethodGroup::Utility));
        methods
    }

    /// Returns all methods in the allowlist (full preset).
    fn full_methods() -> HashSet<String> {
        let mut methods = Self::safe_methods();
        methods.extend(Self::group_methods(&MethodGroup::Identity));
        methods.extend(Self::group_methods(&MethodGroup::Rawtx));
        methods.extend(Self::group_methods(&MethodGroup::Advanced));
        methods
    }

    /// Returns methods for custom configuration.
    fn custom_methods(&self) -> HashSet<String> {
        let mut methods = HashSet::new();

        // Add all methods from specified groups
        for group in &self.allow_groups {
            methods.extend(Self::group_methods(group));
        }

        // Add extra methods
        for method in &self.allow_extra {
            methods.insert(method.clone());
        }

        // Remove denied methods
        for method in &self.deny {
            methods.remove(method);
        }

        methods
    }

    /// Returns methods belonging to a specific group.
    fn group_methods(group: &MethodGroup) -> HashSet<String> {
        let methods: Vec<&str> = match group {
            MethodGroup::Readonly => vec![
                "getinfo",
                "getblockcount",
                "getbestblockhash",
                "getdifficulty",
                "getchaintips",
                "getblockchaininfo",
                "getnetworkinfo",
                "getmininginfo",
                "getmempoolinfo",
                "gettxoutsetinfo",
                "coinsupply",
            ],
            MethodGroup::Blockchain => vec![
                "getblock",
                "getblockhash",
                "getblockheader",
                "getblocksubsidy",
                "getblockhashes",
                "getbestproofroot",
                "getrawtransaction",
                "gettxout",
                "getspentinfo",
                "getblocktemplate",
            ],
            MethodGroup::Mempool => vec!["getrawmempool", "getmempoolinfo", "getaddressmempool"],
            MethodGroup::Address => vec![
                "getaddressbalance",
                "getaddressdeltas",
                "getaddresstxids",
                "getaddressutxos",
                "getaddressmempool",
            ],
            MethodGroup::Currency => vec![
                "getcurrency",
                "getcurrencystate",
                "getcurrencyconverters",
                "getcurrencytrust",
                "getinitialcurrencystate",
                "listcurrencies",
                "getlaunchinfo",
                "estimateconversion",
                "getoffers",
                "getpendingtransfers",
                "getreservedeposits",
                "getexports",
                "getlastimportfrom",
            ],
            MethodGroup::Identity => vec![
                "getidentity",
                "getidentitycontent",
                "getidentitytrust",
                "getidentitieswithaddress",
                "getidentitieswithrevocation",
                "getidentitieswithrecovery",
                "registeridentity",
                "updateidentity",
                "revokeidentity",
                "recoveridentity",
                "setidentitytimelock",
            ],
            MethodGroup::Verification => {
                vec!["verifymessage", "verifyhash", "verifysignature", "hashdata"]
            }
            MethodGroup::Rawtx => vec![
                "createrawtransaction",
                "decoderawtransaction",
                "decodescript",
                "sendrawtransaction",
                "fundrawtransaction",
            ],
            MethodGroup::Utility => vec![
                "help",
                "estimatefee",
                "estimatepriority",
                "createmultisig",
                "convertpassphrase",
                "getvdxfid",
                "getsaplingtree",
            ],
            MethodGroup::Advanced => vec![
                "signdata",
                "sendcurrency",
                "submitacceptednotarization",
                "submitimports",
                "getnotarizationdata",
            ],
        };

        methods.into_iter().map(String::from).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MethodsConfig::default();
        assert_eq!(config.preset, Preset::Safe);
    }

    #[test]
    fn test_minimal_preset() {
        let config = MethodsConfig {
            preset: Preset::Minimal,
            ..Default::default()
        };
        let methods = config.allowed_methods();
        assert!(methods.contains("getinfo"));
        assert!(methods.contains("getblockcount"));
        assert!(!methods.contains("getrawtransaction")); // Not in minimal
    }

    #[test]
    fn test_safe_preset() {
        let config = MethodsConfig {
            preset: Preset::Safe,
            ..Default::default()
        };
        let methods = config.allowed_methods();
        assert!(methods.contains("getinfo"));
        assert!(methods.contains("getblock"));
        assert!(methods.contains("getcurrency"));
        assert!(!methods.contains("registeridentity")); // Identity not in safe
        assert!(!methods.contains("sendcurrency")); // Advanced not in safe
    }

    #[test]
    fn test_full_preset() {
        let config = MethodsConfig {
            preset: Preset::Full,
            ..Default::default()
        };
        let methods = config.allowed_methods();
        assert!(methods.contains("getinfo"));
        assert!(methods.contains("registeridentity")); // Identity in full
        assert!(methods.contains("sendcurrency")); // Advanced in full
    }

    #[test]
    fn test_custom_with_groups() {
        let config = MethodsConfig {
            preset: Preset::Custom,
            allow_groups: vec![MethodGroup::Readonly, MethodGroup::Blockchain],
            allow_extra: vec!["custommethod".to_string()],
            deny: vec!["getblock".to_string()],
        };
        let methods = config.allowed_methods();
        assert!(methods.contains("getinfo")); // In readonly
        assert!(!methods.contains("getblock")); // Denied
        assert!(methods.contains("custommethod")); // Added extra
        assert!(!methods.contains("getcurrency")); // Not in allowed groups
    }
}
