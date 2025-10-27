//! RPC method allowlist and parameter validation.
//!
//! This module implements a security layer that validates JSON-RPC method calls
//! before they are forwarded to the Verus daemon. It provides:
//!
//! * **Method Allowlisting**: Only explicitly allowed methods can be called
//! * **Parameter Type Validation**: Ensures parameters match expected types
//! * **Special Validation Rules**: Custom validation logic for specific methods
//! * **Security Constraints**: Enforces limits on string length, array size, and numeric ranges
//!
//! The allowlist prevents unauthorized access to dangerous RPC methods and protects
//! against various attack vectors including:
//! - Wallet manipulation (methods requiring private keys)
//! - Resource exhaustion (oversized inputs)
//! - Parameter injection attacks
//!
//! # Example
//!
//! ```
//! use serde_json::value::RawValue;
//! # use rust_verusd_rpc_server::allowlist::is_method_allowed;
//!
//! // Check if a method with parameters is allowed
//! let params = vec![];
//! assert!(is_method_allowed("getinfo", &params));
//!
//! // Disallowed method returns false
//! assert!(!is_method_allowed("sendtoaddress", &params));
//! ```

use once_cell::sync::Lazy;
use serde_json::value::RawValue;
use serde_json::Value;
use std::collections::HashMap;

/// Special validation rules for RPC methods that need custom logic beyond type checking.
///
/// These rules provide additional security constraints and validation for specific
/// methods that have special requirements.
#[derive(Debug, Clone)]
enum SpecialRule {
    /// Requires that a boolean parameter at the given index must be `true`.
    ///
    /// Used for methods that require explicit confirmation via a flag (e.g., identity operations).
    ///
    /// # Arguments
    /// * Index of the parameter to check (0-based)
    RequireParamTrue(usize),

    /// Requires that an object parameter does not contain a specific key.
    ///
    /// Used to prevent passing dangerous parameters (e.g., `address` in `signdata`
    /// which would require wallet access).
    ///
    /// # Arguments
    /// * The key name that must not be present
    ObjectMustNotContainKey(&'static str),

    /// Requires an exact number of parameters.
    ///
    /// Used when a method must have a specific parameter count for security or
    /// correctness reasons.
    ///
    /// # Arguments
    /// * The required parameter count
    ExactParamCount(usize),

    /// Limits the maximum length of a string parameter.
    ///
    /// Prevents resource exhaustion attacks via oversized string inputs.
    ///
    /// # Arguments
    /// * Index of the string parameter (0-based)
    /// * Maximum allowed length in characters
    StringMaxLength(usize, usize),

    /// Limits the maximum size of an array parameter.
    ///
    /// Prevents resource exhaustion attacks via oversized array inputs.
    ///
    /// # Arguments
    /// * Index of the array parameter (0-based)
    /// * Maximum allowed element count
    ArrayMaxSize(usize, usize),

    /// Requires a numeric parameter to be within an inclusive range.
    ///
    /// Prevents invalid or dangerous numeric inputs.
    ///
    /// # Arguments
    /// * Index of the numeric parameter (0-based)
    /// * Minimum allowed value (inclusive)
    /// * Maximum allowed value (inclusive)
    NumberRange(usize, i64, i64),
}

/// Method specification defining allowed parameters and validation rules.
///
/// Each RPC method in the allowlist has a `MethodSpec` that defines:
/// * The expected parameter types (as string codes)
/// * Any special validation rules that apply
#[derive(Debug, Clone)]
struct MethodSpec {
    /// Expected parameter types in order.
    ///
    /// Type codes: `"str"`, `"int"`, `"float"`, `"bool"`, `"obj"`, `"arr"`.
    /// Parameters are optional from right to left (partial parameter lists are allowed).
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

/// Static map of allowed RPC methods and their parameter specifications
static ALLOWED_METHODS: Lazy<HashMap<&'static str, MethodSpec>> = Lazy::new(|| {
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

/// Validates that parameter types match the expected types for a method.
///
/// This function performs type checking on the provided parameters, ensuring each
/// parameter matches its expected type code. Parameters are checked left-to-right,
/// and it's valid to provide fewer parameters than expected (trailing parameters
/// are optional).
///
/// # Arguments
///
/// * `params` - The actual parameters from the JSON-RPC request
/// * `expected_types` - The expected parameter type codes
///
/// # Returns
///
/// * `true` - All provided parameters match their expected types
/// * `false` - Parameter count exceeds expected, or a type mismatch was found
///
/// # Type Codes
///
/// * `"obj"` - JSON object
/// * `"arr"` - JSON array
/// * `"int"` - JSON number that is an integer
/// * `"float"` - Any JSON number
/// * `"str"` - JSON string
/// * `"bool"` - JSON boolean
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
///
/// This function runs through each special rule defined for a method, validating
/// that all constraints are met. Rules are applied in order, and validation stops
/// at the first failure.
///
/// # Arguments
///
/// * `params` - The parameters from the JSON-RPC request
/// * `rules` - The special validation rules to apply
///
/// # Returns
///
/// * `true` - All rules passed validation
/// * `false` - At least one rule failed
///
/// # Rules Applied
///
/// See [`SpecialRule`] for the types of validation that can be performed:
/// * `RequireParamTrue` - Boolean must be true
/// * `ObjectMustNotContainKey` - Object must not have a specific key
/// * `ExactParamCount` - Must have exact parameter count
/// * `StringMaxLength` - String length limit
/// * `ArrayMaxSize` - Array size limit
/// * `NumberRange` - Numeric range constraint
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

/// Checks if an RPC method is allowed and validates its parameters.
///
/// This is the main entry point for allowlist validation. It checks:
/// 1. Whether the method is in the allowlist
/// 2. Whether all special validation rules pass
/// 3. Whether parameter types match the expected types
///
/// Only methods explicitly listed in [`ALLOWED_METHODS`] can pass validation.
/// Methods requiring wallet access or other dangerous operations are excluded.
///
/// # Arguments
///
/// * `method` - The RPC method name to check
/// * `params` - The parameters for the method call
///
/// # Returns
///
/// * `true` - Method is allowed and parameters are valid
/// * `false` - Method is not in allowlist or parameters are invalid
///
/// # Examples
///
/// ```
/// use serde_json::value::RawValue;
/// # use rust_verusd_rpc_server::allowlist::is_method_allowed;
///
/// // Allowed read-only method
/// let params = vec![];
/// assert!(is_method_allowed("getinfo", &params));
///
/// // Method not in allowlist
/// assert!(!is_method_allowed("dumpprivkey", &params));
///
/// // Method with invalid parameters
/// let params = vec![
///     RawValue::from_string("\"not_a_number\"".to_string()).unwrap()
/// ];
/// assert!(!is_method_allowed("getblockhash", &params)); // expects int, got string
/// ```
///
/// # Security
///
/// Methods that can:
/// * Access or export private keys
/// * Send funds or create transactions (without explicit confirmation)
/// * Modify wallet state
/// * Perform administrative actions
///
/// ...are **NOT** included in the allowlist and will always return `false`.
pub fn is_method_allowed(method: &str, params: &[Box<RawValue>]) -> bool {
    match ALLOWED_METHODS.get(method) {
        Some(spec) => {
            // First check special rules
            if !apply_special_rules(params, &spec.special_rules) {
                return false;
            }
            // Then check parameter types
            check_params(params, spec.param_types)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_not_in_allowlist() {
        let params = vec![];
        assert!(!is_method_allowed("notarealmethod", &params));
    }

    #[test]
    fn test_getinfo_no_params() {
        let params = vec![];
        assert!(is_method_allowed("getinfo", &params));
    }

    #[test]
    fn test_getblock_with_params() {
        let hash_param = RawValue::from_string("\"000000\"".to_string()).unwrap();
        let verbose_param = RawValue::from_string("true".to_string()).unwrap();
        let params = vec![hash_param, verbose_param];
        assert!(is_method_allowed("getblock", &params));
    }

    #[test]
    fn test_signdata_without_address() {
        let obj_param = RawValue::from_string("{\"message\":\"test\"}".to_string()).unwrap();
        let params = vec![obj_param];
        assert!(is_method_allowed("signdata", &params));
    }

    #[test]
    fn test_signdata_with_address_rejected() {
        let obj_param =
            RawValue::from_string("{\"address\":\"test\",\"message\":\"test\"}".to_string())
                .unwrap();
        let params = vec![obj_param];
        assert!(!is_method_allowed("signdata", &params));
    }

    #[test]
    fn test_createmultisig_valid_range() {
        let num_param = RawValue::from_string("2".to_string()).unwrap();
        let arr_param = RawValue::from_string("[\"key1\",\"key2\",\"key3\"]".to_string()).unwrap();
        let params = vec![num_param, arr_param];
        assert!(is_method_allowed("createmultisig", &params));
    }

    #[test]
    fn test_createmultisig_invalid_range() {
        let num_param = RawValue::from_string("20".to_string()).unwrap();
        let arr_param = RawValue::from_string("[]".to_string()).unwrap();
        let params = vec![num_param, arr_param];
        assert!(!is_method_allowed("createmultisig", &params));
    }

    #[test]
    fn test_createmultisig_array_too_large() {
        let num_param = RawValue::from_string("2".to_string()).unwrap();
        let large_arr = (0..20)
            .map(|i| format!("\"key{}\"", i))
            .collect::<Vec<_>>()
            .join(",");
        let arr_param = RawValue::from_string(format!("[{}]", large_arr)).unwrap();
        let params = vec![num_param, arr_param];
        assert!(!is_method_allowed("createmultisig", &params));
    }
}
