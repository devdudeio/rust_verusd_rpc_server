use serde_json::Value;
use serde_json::value::RawValue;
use std::collections::HashMap;
use once_cell::sync::Lazy;

/// Type definitions for RPC method parameters
#[derive(Debug, Clone)]
enum ParamType {
    Str,
    Int,
    Float,
    Bool,
    Obj,
    Arr,
}

/// Special validation rules for methods that need custom logic
#[derive(Debug, Clone)]
enum SpecialRule {
    /// Check that parameter at index is true before validating types
    RequireParamTrue(usize),
    /// Check that object param doesn't contain specific key
    ObjectMustNotContainKey(&'static str),
    /// Require exact parameter count
    ExactParamCount(usize),
    /// Check string parameter max length
    StringMaxLength(usize, usize), // (param_index, max_length)
    /// Check array parameter max size
    ArrayMaxSize(usize, usize), // (param_index, max_size)
    /// Check number is in range (inclusive)
    NumberRange(usize, i64, i64), // (param_index, min, max)
}

/// Method specification defining allowed parameters and validation rules
#[derive(Debug, Clone)]
struct MethodSpec {
    param_types: &'static [&'static str],
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
    m.insert("fundrawtransaction", MethodSpec::new(&["str", "arr", "str", "float"])
        .with_special_rules(vec![SpecialRule::ExactParamCount(4)]));

    m.insert("signdata", MethodSpec::new(&["obj"])
        .with_special_rules(vec![
            SpecialRule::ObjectMustNotContainKey("address"),
            SpecialRule::ExactParamCount(1)
        ]));

    // Identity methods that require param[1] to be true
    m.insert("recoveridentity", MethodSpec::new(&["obj", "bool", "bool", "float", "str"])
        .with_special_rules(vec![SpecialRule::RequireParamTrue(1)]));
    m.insert("registeridentity", MethodSpec::new(&["obj", "bool", "float", "str"])
        .with_special_rules(vec![SpecialRule::RequireParamTrue(1)]));
    m.insert("revokeidentity", MethodSpec::new(&["str", "bool", "bool", "float", "str"])
        .with_special_rules(vec![SpecialRule::RequireParamTrue(1)]));
    m.insert("updateidentity", MethodSpec::new(&["obj", "bool", "bool", "float", "str"])
        .with_special_rules(vec![SpecialRule::RequireParamTrue(1)]));
    m.insert("setidentitytimelock", MethodSpec::new(&["str", "obj", "bool", "float", "str"])
        .with_special_rules(vec![SpecialRule::RequireParamTrue(2)]));
    m.insert("sendcurrency", MethodSpec::new(&["str", "arr", "int", "float", "bool"])
        .with_special_rules(vec![SpecialRule::RequireParamTrue(4)]));

    // Standard methods with enhanced validation
    m.insert("coinsupply", MethodSpec::new(&[]));
    m.insert("convertpassphrase", MethodSpec::new(&["str"])
        .with_special_rules(vec![SpecialRule::StringMaxLength(0, 10000)]));
    m.insert("createmultisig", MethodSpec::new(&["int", "arr"])
        .with_special_rules(vec![
            SpecialRule::NumberRange(0, 1, 16),
            SpecialRule::ArrayMaxSize(1, 16)
        ]));
    m.insert("createrawtransaction", MethodSpec::new(&["arr", "obj", "int", "int"])
        .with_special_rules(vec![SpecialRule::ArrayMaxSize(0, 1000)]));
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
    m.insert("getcurrencyconverters", MethodSpec::new(&["str", "str", "str"]));
    m.insert("getcurrencystate", MethodSpec::new(&["str", "str", "str"]));
    m.insert("getcurrencytrust", MethodSpec::new(&["arr"]));
    m.insert("getdifficulty", MethodSpec::new(&[]));
    m.insert("getexports", MethodSpec::new(&["str", "int", "int"]));
    m.insert("getinfo", MethodSpec::new(&[]));
    m.insert("getinitialcurrencystate", MethodSpec::new(&["str"]));
    m.insert("getidentitieswithaddress", MethodSpec::new(&["obj"]));
    m.insert("getidentitieswithrevocation", MethodSpec::new(&["obj"]));
    m.insert("getidentitieswithrecovery", MethodSpec::new(&["obj"]));
    m.insert("getidentity", MethodSpec::new(&["str", "int", "bool", "int"]));
    m.insert("getidentitytrust", MethodSpec::new(&["arr"]));
    m.insert("getidentitycontent", MethodSpec::new(&["str", "int", "int", "bool", "int", "str", "bool"]));
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
    m.insert("submitacceptednotarization", MethodSpec::new(&["obj", "obj"]));
    m.insert("submitimports", MethodSpec::new(&["obj"]));
    m.insert("verifymessage", MethodSpec::new(&["str", "str", "str", "bool"]));
    m.insert("verifyhash", MethodSpec::new(&["str", "str", "str", "bool"]));
    m.insert("verifysignature", MethodSpec::new(&["obj"]));

    m
});

/// Check if parameter types match expected types
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

/// Apply special validation rules for a method
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

/// Check if a method is allowed and if its parameters are valid
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
        let obj_param = RawValue::from_string("{\"address\":\"test\",\"message\":\"test\"}".to_string()).unwrap();
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
        let large_arr = (0..20).map(|i| format!("\"key{}\"", i)).collect::<Vec<_>>().join(",");
        let arr_param = RawValue::from_string(format!("[{}]", large_arr)).unwrap();
        let params = vec![num_param, arr_param];
        assert!(!is_method_allowed("createmultisig", &params));
    }
}
