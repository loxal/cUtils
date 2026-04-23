// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Tiny ISO 8601 helper. Std-only — no `chrono` / `time` dependency.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock time formatted as `YYYY-MM-DDThh:mm:ssZ`.
///
/// Used to stamp `deletedDate` on dedup losers (so Bitwarden shows them in
/// the Trash folder after import) and `creationDate`/`revisionDate` on
/// synthetic items imported from Apple Passwords CSV.
pub(crate) fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso8601_from_epoch_secs(secs)
}

/// Format seconds-since-epoch as `YYYY-MM-DDThh:mm:ssZ`.
pub(crate) fn iso8601_from_epoch_secs(total_secs: u64) -> String {
    let secs = total_secs % 60;
    let total_mins = total_secs / 60;
    let mins = total_mins % 60;
    let total_hours = total_mins / 60;
    let hours = total_hours % 24;
    let days = (total_hours / 24) as i64;
    let (y, m, d) = days_since_epoch_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{mins:02}:{secs:02}Z")
}

/// Days since 1970-01-01 → (year, month [1-12], day [1-31]) using
/// Howard Hinnant's civil-date algorithm.
fn days_since_epoch_to_ymd(days: i64) -> (i32, u8, u8) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero_is_unix_origin() {
        assert_eq!(iso8601_from_epoch_secs(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn recent_date_roundtrips() {
        // 2026-04-23T00:00:00Z = 1_776_902_400 seconds since UNIX epoch.
        assert_eq!(
            iso8601_from_epoch_secs(1_776_902_400),
            "2026-04-23T00:00:00Z"
        );
    }

    #[test]
    fn leap_day_handled() {
        assert_eq!(
            iso8601_from_epoch_secs(1_709_164_800),
            "2024-02-29T00:00:00Z"
        );
    }
}
