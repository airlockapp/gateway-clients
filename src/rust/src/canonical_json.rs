//! RFC 8785 JSON Canonicalization Scheme (JCS).

use serde_json::Value;

use crate::crypto::sha256_hex;

/// Canonicalize a JSON string per RFC 8785 (JCS).
pub fn canonicalize(json_str: &str) -> Result<String, String> {
    let parsed: Value = serde_json::from_str(json_str).map_err(|e| format!("parse json: {e}"))?;
    Ok(canonical_value(&parsed))
}

/// Compute the SHA-256 hex hash of the canonical JSON form.
pub fn hash_canonical(json_str: &str) -> Result<String, String> {
    let canonical = canonicalize(json_str)?;
    Ok(sha256_hex(&canonical))
}

fn canonical_value(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(f) = n.as_f64() {
                if f == (f as i64) as f64 && f.abs() <= 1e15 {
                    (f as i64).to_string()
                } else {
                    format!("{:E}", f)
                }
            } else {
                n.to_string()
            }
        }
        Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonical_value).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    let key_json = serde_json::to_string(*k).unwrap_or_default();
                    format!("{}:{}", key_json, canonical_value(&obj[*k]))
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}
