//! RPC method allowlist and parameter validation.
//!
//! This module implements a security layer that validates JSON-RPC method calls
//! before they are forwarded to the Verus daemon. It provides:
//!
//! * **Method Allowlisting**: Only approved RPC methods can be called (configurable)
//! * **Parameter Type Validation**: Ensures parameters match expected types
//! * **Special Validation Rules**: Custom validation logic for specific methods
//! * **Security Constraints**: Enforces limits on string length, array size, and numeric ranges
//!
//! # Configuration
//!
//! The allowlist can be configured via `Conf.toml` using presets or custom group/method lists.
//! See [`crate::allowlist_config::MethodsConfig`] for configuration options.

use crate::allowlist_config::MethodsConfig;
use once_cell::sync::Lazy;
use serde_json::value::RawValue;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Special validation rules for RPC methods that need custom logic beyond type checking.
///
/// These rules provide additional security constraints and validation for specific
/// methods that have special requirements.
#[derive(Debug, Clone)]
enum SpecialRule {
    /// Requires that a boolean parameter at the given index must be `true`.
    RequireParamTrue(usize),

    /// Requires that an object parameter does not contain a specific key.
    ObjectMustNotContainKey(&'static str),

    /// Requires an exact number of parameters.
    ExactParamCount(usize),

    /// Limits the maximum length of a string parameter.
    StringMaxLength(usize, usize),

    /// Limits the maximum size of an array parameter.
    ArrayMaxSize(usize, usize),

    /// Requires a numeric parameter to be within an inclusive range.
    NumberRange(usize, i64, i64),
}

/// Method specification defining allowed parameters and validation rules.
#[derive(Debug, Clone)]
struct MethodSpec {
    /// Expected parameter types in order.
    param_types: &'static [&'static str],

    /// Additional validation rules applied after type checking.
    special_rules: Vec<SpecialRule>,
}

impl MethodSpec {
    const fn new(param_types: &'static [&'static str]) -> Self {
        Self {
            param_types,
            special_rules: Vec::new(),
        }
    }

    fn with_special_rules(mut self, rules: Vec<SpecialRule>) -> Self {
        self.special_rules = rules;
        self
    }
}

/// Static map of ALL possible RPC method specifications.
///
/// This contains parameter validation rules for all methods that could ever be allowed.
/// The actual allowed methods are filtered based on configuration.
static ALL_METHOD_SPECS: Lazy<HashMap<&'static str, MethodSpec>> = Lazy::new(|| {
    let mut m = HashMap::new();

    // Special cases with custom validation
    m.insert(
        "fundrawtransaction",
        MethodSpec::new(&["str", "arr", "str", "float"])
            .with_special_rules(vec![SpecialRule::ExactParamCount(4)]),
    );

    m.insert(
        "signdata",
        MethodSpec::new(&["obj"]).with_special_rules(vec![
            SpecialRule::ObjectMustNotContainKey("address"),
            SpecialRule::ExactParamCount(1),
        ]),
    );

    // Identity methods that require param[1] to be true
    m.insert(
        "recoveridentity",
        MethodSpec::new(&["obj", "bool", "bool", "float", "str"])
            .with_special_rules(vec![SpecialRule::RequireParamTrue(1)]),
    );
    m.insert(
        "registeridentity",
        MethodSpec::new(&["obj", "bool", "float", "str"])
            .with_special_rules(vec![SpecialRule::RequireParamTrue(1)]),
    );
    m.insert(
        "revokeidentity",
        MethodSpec::new(&["str", "bool", "bool", "float", "str"])
            .with_special_rules(vec![SpecialRule::RequireParamTrue(1)]),
    );
    m.insert(
        "updateidentity",
        MethodSpec::new(&["obj", "bool", "bool", "float", "str"])
            .with_special_rules(vec![SpecialRule::RequireParamTrue(1)]),
    );
    m.insert(
        "setidentitytimelock",
        MethodSpec::new(&["str", "obj", "bool", "float", "str"])
            .with_special_rules(vec![SpecialRule::RequireParamTrue(2)]),
    );
    m.insert(
        "sendcurrency",
        MethodSpec::new(&["str", "arr", "int", "float", "bool"])
            .with_special_rules(vec![SpecialRule::RequireParamTrue(4)]),
    );

    // Standard methods with enhanced validation
    m.insert("coinsupply", MethodSpec::new(&[]));
    m.insert(
        "convertpassphrase",
        MethodSpec::new(&["str"]).with_special_rules(vec![SpecialRule::StringMaxLength(0, 10000)]),
    );
    m.insert(
        "createmultisig",
        MethodSpec::new(&["int", "arr"]).with_special_rules(vec![
            SpecialRule::NumberRange(0, 1, 16),
            SpecialRule::ArrayMaxSize(1, 16),
        ]),
    );
    m.insert(
        "createrawtransaction",
        MethodSpec::new(&["arr", "obj", "int", "int"])
            .with_special_rules(vec![SpecialRule::ArrayMaxSize(0, 1000)]),
    );
    m.insert("decoderawtransaction", MethodSpec::new(&["str", "bool"]));
    m.insert("decodescript", MethodSpec::new(&["str", "bool"]));
    m.insert("estimateconversion", MethodSpec::new(&["obj"]));
    m.insert("estimatefee", MethodSpec::new(&["int"]));
    m.insert("estimatepriority", MethodSpec::new(&["int"]));
    m.insert("getaddressmempool", MethodSpec::new(&["obj"]));
    m.insert("getaddressutxos", MethodSpec::new(&["obj"]));
    m.insert("getaddressbalance", MethodSpec::new(&["obj"]));
    m.insert("getaddressdeltas", MethodSpec::new(&["obj"]));
    m.insert("getaddresstxids", MethodSpec::new(&["obj"]));
    m.insert("getbestblockhash", MethodSpec::new(&[]));
    m.insert("getbestproofroot", MethodSpec::new(&["obj"]));
    m.insert("getblock", MethodSpec::new(&["str", "bool"]));
    m.insert("getblockchaininfo", MethodSpec::new(&[]));
    m.insert("getblockcount", MethodSpec::new(&[]));
    m.insert("getblockhashes", MethodSpec::new(&["int", "int"]));
    m.insert("getblockhash", MethodSpec::new(&["int"]));
    m.insert("getblockheader", MethodSpec::new(&["str"]));
    m.insert("getblocksubsidy", MethodSpec::new(&["int"]));
    m.insert("getblocktemplate", MethodSpec::new(&["obj"]));
    m.insert("getchaintips", MethodSpec::new(&[]));
    m.insert("getcurrency", MethodSpec::new(&["str"]));
    m.insert(
        "getcurrencyconverters",
        MethodSpec::new(&["str", "str", "str"]),
    );
    m.insert("getcurrencystate", MethodSpec::new(&["str", "str", "str"]));
    m.insert("getcurrencytrust", MethodSpec::new(&["arr"]));
    m.insert("getdifficulty", MethodSpec::new(&[]));
    m.insert("getexports", MethodSpec::new(&["str", "int", "int"]));
    m.insert("getinfo", MethodSpec::new(&[]));
    m.insert("getinitialcurrencystate", MethodSpec::new(&["str"]));
    m.insert("getidentitieswithaddress", MethodSpec::new(&["obj"]));
    m.insert("getidentitieswithrevocation", MethodSpec::new(&["obj"]));
    m.insert("getidentitieswithrecovery", MethodSpec::new(&["obj"]));
    m.insert(
        "getidentity",
        MethodSpec::new(&["str", "int", "bool", "int"]),
    );
    m.insert("getidentitytrust", MethodSpec::new(&["arr"]));
    m.insert(
        "getidentitycontent",
        MethodSpec::new(&["str", "int", "int", "bool", "int", "str", "bool"]),
    );
    m.insert("getlastimportfrom", MethodSpec::new(&["str"]));
    m.insert("getlaunchinfo", MethodSpec::new(&["str"]));
    m.insert("getmempoolinfo", MethodSpec::new(&[]));
    m.insert("getmininginfo", MethodSpec::new(&[]));
    m.insert("getnetworkinfo", MethodSpec::new(&[]));
    m.insert("getnotarizationdata", MethodSpec::new(&["str"]));
    m.insert("getoffers", MethodSpec::new(&["str", "bool", "bool"]));
    m.insert("getpendingtransfers", MethodSpec::new(&["str"]));
    m.insert("getrawmempool", MethodSpec::new(&[]));
    m.insert("getrawtransaction", MethodSpec::new(&["str", "int"]));
    m.insert("getreservedeposits", MethodSpec::new(&["str"]));
    m.insert("getsaplingtree", MethodSpec::new(&["int"]));
    m.insert("getspentinfo", MethodSpec::new(&["obj"]));
    m.insert("gettxout", MethodSpec::new(&["str", "int", "bool"]));
    m.insert("gettxoutsetinfo", MethodSpec::new(&[]));
    m.insert("getvdxfid", MethodSpec::new(&["str", "obj"]));
    m.insert("hashdata", MethodSpec::new(&["str", "str", "str"]));
    m.insert("help", MethodSpec::new(&[]));
    m.insert("listcurrencies", MethodSpec::new(&["obj", "int", "int"]));
    m.insert("sendrawtransaction", MethodSpec::new(&["str"]));
    m.insert(
        "submitacceptednotarization",
        MethodSpec::new(&["obj", "obj"]),
    );
    m.insert("submitimports", MethodSpec::new(&["obj"]));
    m.insert(
        "verifymessage",
        MethodSpec::new(&["str", "str", "str", "bool"]),
    );
    m.insert(
        "verifyhash",
        MethodSpec::new(&["str", "str", "str", "bool"]),
    );
    m.insert("verifysignature", MethodSpec::new(&["obj"]));

    m
});

/// Allowlist validator that checks methods against configuration and validates parameters.
#[derive(Debug, Clone)]
pub struct Allowlist {
    /// Set of allowed method names based on configuration
    allowed_methods: HashSet<String>,
}

impl Allowlist {
    /// Creates a new allowlist from configuration.
    pub fn from_config(config: &MethodsConfig) -> Self {
        Self {
            allowed_methods: config.allowed_methods(),
        }
    }

    /// Checks if an RPC method is allowed and validates its parameters.
    ///
    /// This checks:
    /// 1. Whether the method is in the configured allowlist
    /// 2. Whether all special validation rules pass
    /// 3. Whether parameter types match the expected types
    pub fn is_method_allowed(&self, method: &str, params: &[Box<RawValue>]) -> bool {
        // First check if method is in configured allowlist
        if !self.allowed_methods.contains(method) {
            return false;
        }

        // Then validate parameters using the method spec
        match ALL_METHOD_SPECS.get(method) {
            Some(spec) => {
                // Check special rules
                if !Self::apply_special_rules(params, &spec.special_rules) {
                    return false;
                }
                // Check parameter types
                Self::check_params(params, spec.param_types)
            }
            None => {
                // Method is in allowed list but has no spec - allow it
                // This handles any custom methods added via allow_extra
                true
            }
        }
    }

    /// Validates that parameter types match the expected types for a method.
    fn check_params(params: &[Box<RawValue>], expected_types: &[&str]) -> bool {
        if params.len() > expected_types.len() {
            return false;
        }
        for (param, &expected_type) in params.iter().zip(expected_types) {
            let value: Value = match serde_json::from_str(&param.to_string()) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let type_matches = match expected_type {
                "obj" => matches!(value, Value::Object(_)),
                "arr" => matches!(value, Value::Array(_)),
                "int" => matches!(value, Value::Number(n) if n.is_i64()),
                "float" => matches!(value, Value::Number(_)),
                "str" => matches!(value, Value::String(_)),
                "bool" => matches!(value, Value::Bool(_)),
                _ => false,
            };
            if !type_matches {
                return false;
            }
        }
        true
    }

    /// Applies special validation rules to method parameters.
    fn apply_special_rules(params: &[Box<RawValue>], rules: &[SpecialRule]) -> bool {
        for rule in rules {
            match rule {
                SpecialRule::RequireParamTrue(index) => {
                    let is_true = params
                        .get(*index)
                        .and_then(|p| serde_json::from_str::<Value>(&p.to_string()).ok())
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !is_true {
                        return false;
                    }
                }
                SpecialRule::ObjectMustNotContainKey(key) => {
                    if params.is_empty() {
                        return false;
                    }
                    let contains_key = serde_json::from_str::<Value>(&params[0].to_string())
                        .ok()
                        .and_then(|v| v.as_object().map(|obj| obj.contains_key(*key)))
                        .unwrap_or(false);
                    if contains_key {
                        return false;
                    }
                }
                SpecialRule::ExactParamCount(count) => {
                    if params.len() != *count {
                        return false;
                    }
                }
                SpecialRule::StringMaxLength(index, max_len) => {
                    let str_len = params
                        .get(*index)
                        .and_then(|p| serde_json::from_str::<Value>(&p.to_string()).ok())
                        .and_then(|v| v.as_str().map(|s| s.len()))
                        .unwrap_or(0);
                    if str_len > *max_len {
                        return false;
                    }
                }
                SpecialRule::ArrayMaxSize(index, max_size) => {
                    let arr_len = params
                        .get(*index)
                        .and_then(|p| serde_json::from_str::<Value>(&p.to_string()).ok())
                        .and_then(|v| v.as_array().map(|a| a.len()))
                        .unwrap_or(0);
                    if arr_len > *max_size {
                        return false;
                    }
                }
                SpecialRule::NumberRange(index, min, max) => {
                    let num_in_range = params
                        .get(*index)
                        .and_then(|p| serde_json::from_str::<Value>(&p.to_string()).ok())
                        .and_then(|v| v.as_i64())
                        .map(|n| n >= *min && n <= *max)
                        .unwrap_or(false);
                    if !num_in_range {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Returns the number of methods currently allowed.
    pub fn len(&self) -> usize {
        self.allowed_methods.len()
    }

    /// Returns whether the allowlist is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.allowed_methods.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist_config::Preset;

    #[test]
    fn test_safe_preset_allows_basic_methods() {
        let config = MethodsConfig {
            preset: Preset::Safe,
            ..Default::default()
        };
        let allowlist = Allowlist::from_config(&config);

        let params = vec![];
        assert!(allowlist.is_method_allowed("getinfo", &params));
        assert!(allowlist.is_method_allowed("getblock", &params));
    }

    #[test]
    fn test_safe_preset_blocks_identity_methods() {
        let config = MethodsConfig {
            preset: Preset::Safe,
            ..Default::default()
        };
        let allowlist = Allowlist::from_config(&config);

        let params = vec![];
        assert!(!allowlist.is_method_allowed("registeridentity", &params));
    }

    #[test]
    fn test_full_preset_allows_identity_methods() {
        let config = MethodsConfig {
            preset: Preset::Full,
            ..Default::default()
        };
        let allowlist = Allowlist::from_config(&config);

        let bool_param = RawValue::from_string("true".to_string()).unwrap();
        let obj_param = RawValue::from_string("{}".to_string()).unwrap();
        let params = vec![obj_param, bool_param];
        assert!(allowlist.is_method_allowed("registeridentity", &params));
    }

    #[test]
    fn test_signdata_without_address() {
        let config = MethodsConfig {
            preset: Preset::Full,
            ..Default::default()
        };
        let allowlist = Allowlist::from_config(&config);

        let obj_param = RawValue::from_string("{\"message\":\"test\"}".to_string()).unwrap();
        let params = vec![obj_param];
        assert!(allowlist.is_method_allowed("signdata", &params));
    }

    #[test]
    fn test_signdata_with_address_rejected() {
        let config = MethodsConfig {
            preset: Preset::Full,
            ..Default::default()
        };
        let allowlist = Allowlist::from_config(&config);

        let obj_param =
            RawValue::from_string("{\"address\":\"test\",\"message\":\"test\"}".to_string())
                .unwrap();
        let params = vec![obj_param];
        assert!(!allowlist.is_method_allowed("signdata", &params));
    }
}
