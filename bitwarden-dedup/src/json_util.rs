// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Tiny `serde_json::Value` helpers shared across modules. Keeping them in
//! one place avoids each module redefining its own `get_str` variant.

use serde_json::Value;

/// Read a top-level string field from an item, defaulting to `""`.
pub(crate) fn get_str<'a>(item: &'a Value, key: &str) -> &'a str {
    item.get(key).and_then(Value::as_str).unwrap_or("")
}
