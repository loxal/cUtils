// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Produce a fully-redacted replica of a Bitwarden vault export, for
//! LOCAL reviewer sharing only.
//!
//! The output of this binary is NOT a committable repository artifact.
//! The committed `examples/example_export.json` fixture is produced by a
//! different path — `tests/fixture.rs::build_curated_fixture()` — which
//! constructs synthetic data from scratch with no source vault input.
//! This binary's output matches the `*.redacted.json`, `*.dedup.json`,
//! and `vault/` gitignore patterns and must not be placed under
//! `examples/`.
//!
//! Every field that could leak a secret, personally identifiable
//! information, vault-origin identifier, or real timestamp is replaced
//! with a synthetic placeholder. Schema shape (item count, type
//! distribution, URI counts per item, URI schemes, match modes, and
//! custom field counts + types) is preserved so the redacted file is a
//! realistic test fixture for the dedup tool.
//!
//! Duplicate equivalence classes are preserved as well: items that form
//! a strict duplicate group in the source (same `dedup_key`) share a
//! synthetic group id and therefore synthesize to the same name,
//! username, password, and TOTP placeholder. Running `bitwarden-dedup`
//! against the redacted file yields the same group/removed counts as
//! the source, because synthetic creation/revision dates are emitted
//! with rank-based ordering that preserves each group's tiebreak
//! winner.
//!
//! REDACTION RULES
//! ---------------
//! Always scrubbed (replaced with a synthetic placeholder):
//!   - credentials: `login.password`, `login.totp`, `login.fido2Credentials`
//!   - PII: `login.username`, `login.uris[].uri`
//!   - free text: `notes`, `fields[].name`, `fields[].value`
//!   - history: `passwordHistory`
//!   - non-login payloads: `card.*`, `identity.*`
//!   - folder labels: `folders[].name`
//!   - vault-origin identifiers: `id`, `folderId` (both mapped to
//!     zero-prefixed synthetic UUIDs)
//!   - vault-origin timestamps: `creationDate`, `revisionDate`,
//!     `deletedDate` (synthesized from a rank inside each duplicate
//!     group so the dedup tiebreak still picks the same winner)
//!
//! Always set to `null` (never copied through):
//!   - `organizationId`
//!   - `collectionIds`
//!
//! Preserved verbatim (non-sensitive schema structure):
//!   - `type`, `reprompt`, `favorite`
//!   - number of URIs per item, URI match modes, custom field count + types

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use bitwarden_dedup::{dedup_key, skip_from_dedup};
use clap::Parser;
use serde_json::{Map, Value, json};

#[derive(Parser, Debug)]
#[command(
    name = "bitwarden-redact",
    about = "Produce a committable redacted replica of a Bitwarden vault export"
)]
struct Cli {
    /// Path to the real Bitwarden export JSON file.
    #[arg(short, long)]
    input: PathBuf,

    /// Output path for the redacted replica.
    #[arg(short, long)]
    output: PathBuf,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let text = fs::read_to_string(&cli.input)
        .map_err(|e| format!("reading {}: {e}", cli.input.display()))?;
    let data: Value = serde_json::from_str(&text)
        .map_err(|e| format!("parsing {}: {e}", cli.input.display()))?;

    let items = data
        .get("items")
        .and_then(Value::as_array)
        .ok_or("missing 'items' array in export")?;

    // Assign stable group ids that preserve the dedup equivalence classes.
    // Items that are skipped from dedup get their own unique group so they
    // synthesize to distinct names/usernames/passwords.
    let mut groups: HashMap<String, usize> = HashMap::new();
    let mut group_ids: Vec<usize> = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let key = if skip_from_dedup(item) {
            format!("__unique__{idx}")
        } else {
            dedup_key(item)
        };
        let next = groups.len();
        let gid = *groups.entry(key).or_insert(next);
        group_ids.push(gid);
    }
    let total_groups = groups.len();

    // Rank each item within its group by the original (revisionDate,
    // creationDate) tuple so the synthetic dates we emit preserve the
    // tiebreak winner. Rank 0 is the newest real item and gets the
    // newest synthetic date.
    let rank_in_group = compute_ranks(items, &group_ids);

    // Build a map from real folder uuids to synthetic ones so we can
    // replace `item.folderId` references and still have them point at a
    // valid synthetic folder id.
    let folder_id_map = build_folder_id_map(&data);

    let new_items: Vec<Value> = items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            scrub_item(
                item,
                group_ids[idx],
                idx,
                rank_in_group[idx],
                &folder_id_map,
            )
        })
        .collect();

    let folders = data.get("folders").and_then(Value::as_array);
    let new_folders: Vec<Value> = folders
        .map(|arr| {
            arr.iter()
                .enumerate()
                .map(|(fi, f)| {
                    let new_id = f
                        .get("id")
                        .and_then(Value::as_str)
                        .and_then(|old| folder_id_map.get(old).cloned())
                        .unwrap_or_else(|| synth_folder_id(fi));
                    json!({
                        "id": new_id,
                        "name": format!("Folder {:02}", fi + 1),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let output = json!({
        "encrypted": false,
        "folders": new_folders,
        "items": new_items,
    });

    if let Some(parent) = cli.output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&cli.output, serde_json::to_string_pretty(&output)?)?;

    println!("Input:   {}", cli.input.display());
    println!("Output:  {}", cli.output.display());
    println!("Items:   {}", items.len());
    println!("Groups:  {total_groups} synthetic dedup groups");
    println!("Folders: {}", new_folders.len());
    Ok(())
}

/// Build a map from every real folder uuid to a synthetic one.
fn build_folder_id_map(data: &Value) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(folders) = data.get("folders").and_then(Value::as_array) {
        for (fi, f) in folders.iter().enumerate() {
            if let Some(old) = f.get("id").and_then(Value::as_str) {
                map.insert(old.to_string(), synth_folder_id(fi));
            }
        }
    }
    map
}

/// Rank each item within its duplicate group by the original
/// `(revisionDate, creationDate)` tuple, descending. Rank 0 is the
/// newest real item — the one `dedup_items` would keep.
fn compute_ranks(items: &[Value], group_ids: &[usize]) -> Vec<usize> {
    let mut by_group: HashMap<usize, Vec<usize>> = HashMap::new();
    for (idx, &gid) in group_ids.iter().enumerate() {
        by_group.entry(gid).or_default().push(idx);
    }

    let mut ranks = vec![0usize; items.len()];
    for indices in by_group.into_values() {
        let mut ordered = indices;
        ordered.sort_by(|&a, &b| {
            let a_rev = items[a].get("revisionDate").and_then(Value::as_str).unwrap_or("");
            let b_rev = items[b].get("revisionDate").and_then(Value::as_str).unwrap_or("");
            let a_cre = items[a].get("creationDate").and_then(Value::as_str).unwrap_or("");
            let b_cre = items[b].get("creationDate").and_then(Value::as_str).unwrap_or("");
            (b_rev, b_cre).cmp(&(a_rev, a_cre))
        });
        for (rank, idx) in ordered.into_iter().enumerate() {
            ranks[idx] = rank;
        }
    }
    ranks
}

/// Deterministic synthetic UUID. All committed/emitted UUIDs share this
/// zero-prefix shape so leak-guard tests can allowlist them with a single
/// pattern.
fn synth_item_id(idx: usize) -> String {
    format!("00000000-0000-0000-0000-{idx:012x}")
}

fn synth_folder_id(fi: usize) -> String {
    format!("00000000-0000-0000-0001-{fi:012x}")
}

/// Synthetic date that encodes the item's rank within its duplicate group.
/// Rank 0 (newest real item) gets the highest lexical date, so the dedup
/// tiebreak picks the same winner on the redacted file as on the source.
/// Groups up to 86,400 items are supported before rank saturates.
fn synth_date(base_year: u32, rank: usize) -> String {
    let total = (23 * 3600 + 59 * 60 + 59_usize).saturating_sub(rank);
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    format!("{base_year}-12-31T{h:02}:{m:02}:{s:02}Z")
}

fn synth_revision_date(rank: usize) -> String {
    synth_date(2026, rank)
}

fn synth_creation_date(rank: usize) -> String {
    synth_date(2025, rank)
}

fn synth_deleted_date(rank: usize) -> String {
    synth_date(2024, rank)
}

/// Produce a synthetic URI that preserves the original's "shape" category.
///
/// Five cases:
/// - `https://…`        → https placeholder
/// - `http://…`         → http placeholder (legacy/insecure category)
/// - `androidapp://…`   → androidapp placeholder (native Android package)
/// - `<other>://…`      → https placeholder (unknown scheme, close enough)
/// - bare identifier    → synthetic bare identifier (e.g. `com.example.iosapp`)
///                        Preserved as a non-URL opaque string so the fixture
///                        still exercises the dedup library's explicit "opaque
///                        URI" case path.
/// - empty / missing    → https placeholder
fn scrub_uri(orig_uri: Option<&str>, gid: usize, idx: usize) -> String {
    match orig_uri {
        None => format!("https://service{gid:04}.example.test/{idx}"),
        Some("") => format!("https://service{gid:04}.example.test/{idx}"),
        Some(s) => match s.split_once("://") {
            Some(("androidapp", _)) => format!("androidapp://com.example.service{gid:04}"),
            Some(("http", _)) => format!("http://service{gid:04}.example.test/{idx}"),
            Some(_) => format!("https://service{gid:04}.example.test/{idx}"),
            None => format!("com.example.opaque.service{gid:04}.{idx}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::scrub_uri;
    use serde_json::json;

    #[test]
    fn preserves_https_scheme() {
        let out = scrub_uri(Some("https://github.com/login"), 42, 0);
        assert!(out.starts_with("https://"));
    }

    #[test]
    fn preserves_http_scheme() {
        let out = scrub_uri(Some("http://legacy.example.com"), 42, 0);
        assert!(out.starts_with("http://"));
    }

    #[test]
    fn preserves_androidapp_scheme() {
        let out = scrub_uri(Some("androidapp://com.github.android"), 42, 0);
        assert!(out.starts_with("androidapp://"));
    }

    #[test]
    fn preserves_bare_identifier_as_non_url() {
        // `com.example.iosapp` style identifiers (no scheme) must NOT be
        // silently upgraded to `https://…` — that would erase the fixture's
        // coverage of the dedup library's opaque-URI code path.
        let out = scrub_uri(Some("com.example.iosapp"), 42, 0);
        assert!(!out.contains("://"), "bare identifier became a URL: {out}");
    }

    #[test]
    fn preserves_unknown_custom_scheme_as_https_placeholder() {
        let out = scrub_uri(Some("custom-scheme://foo"), 42, 0);
        assert!(out.starts_with("https://"));
    }

    #[test]
    fn empty_string_falls_back_to_https() {
        let out = scrub_uri(Some(""), 42, 0);
        assert!(out.starts_with("https://"));
    }

    #[test]
    fn missing_uri_falls_back_to_https() {
        let out = scrub_uri(None, 42, 0);
        assert!(out.starts_with("https://"));
    }

    #[test]
    fn same_gid_produces_same_bare_identifier() {
        // Determinism: redacting the same bare identifier twice for the
        // same group id must be stable.
        let a = scrub_uri(Some("com.example.app"), 7, 0);
        let b = scrub_uri(Some("com.example.other"), 7, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn synth_item_id_shape_is_zero_prefixed_uuid() {
        let id = super::synth_item_id(42);
        assert_eq!(id.len(), 36);
        assert!(id.starts_with("00000000-0000-0000-0000-"));
        assert_eq!(id.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn synth_dates_preserve_rank_ordering() {
        // Lower rank (newer real item) must produce a LEXICALLY LARGER
        // date string — that's what drives the dedup tiebreak.
        let r0 = super::synth_revision_date(0);
        let r1 = super::synth_revision_date(1);
        let r2 = super::synth_revision_date(2);
        assert!(r0 > r1);
        assert!(r1 > r2);
    }

    #[test]
    fn synth_dates_creation_before_revision() {
        let cre = super::synth_creation_date(5);
        let rev = super::synth_revision_date(5);
        assert!(cre < rev, "creation must predate revision: {cre} !< {rev}");
    }

    #[test]
    fn synth_dates_match_iso_8601_shape() {
        let d = super::synth_revision_date(0);
        assert_eq!(d.len(), 20);
        assert!(d.ends_with('Z'));
        assert_eq!(d.chars().filter(|&c| c == '-').count(), 2);
        assert_eq!(d.chars().filter(|&c| c == ':').count(), 2);
    }

    #[test]
    fn compute_ranks_assigns_zero_to_newest_in_group() {
        let items = vec![
            json!({"revisionDate": "2024-01-01T00:00:00Z", "creationDate": "2023-01-01T00:00:00Z"}),
            json!({"revisionDate": "2026-01-01T00:00:00Z", "creationDate": "2025-01-01T00:00:00Z"}),
            json!({"revisionDate": "2025-01-01T00:00:00Z", "creationDate": "2024-01-01T00:00:00Z"}),
        ];
        let group_ids = vec![0, 0, 0];
        let ranks = super::compute_ranks(&items, &group_ids);
        // Item 1 (2026) is newest → rank 0
        assert_eq!(ranks[1], 0);
        // Item 2 (2025) → rank 1
        assert_eq!(ranks[2], 1);
        // Item 0 (2024) → rank 2
        assert_eq!(ranks[0], 2);
    }

    #[test]
    fn build_folder_id_map_maps_real_uuids_to_synthetic() {
        let data = json!({
            "folders": [
                {"id": "deadbeef-1111-2222-3333-444444444444", "name": "Private"},
                {"id": "cafebabe-5555-6666-7777-888888888888", "name": "Work"},
            ]
        });
        let map = super::build_folder_id_map(&data);
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get("deadbeef-1111-2222-3333-444444444444"),
            Some(&"00000000-0000-0000-0001-000000000000".to_string())
        );
        assert_eq!(
            map.get("cafebabe-5555-6666-7777-888888888888"),
            Some(&"00000000-0000-0000-0001-000000000001".to_string())
        );
    }
}

fn scrub_item(
    item: &Value,
    gid: usize,
    idx: usize,
    rank: usize,
    folder_id_map: &HashMap<String, String>,
) -> Value {
    let mut obj = Map::new();

    // Preserve only the fields that describe WHAT an item is, not WHICH
    // real-world item it is. Everything that could leak vault-origin
    // metadata gets synthesized.
    obj.insert("id".into(), json!(synth_item_id(idx)));
    obj.insert("organizationId".into(), Value::Null);
    obj.insert("collectionIds".into(), Value::Null);
    obj.insert(
        "folderId".into(),
        item.get("folderId")
            .and_then(Value::as_str)
            .and_then(|id| folder_id_map.get(id).cloned())
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    obj.insert(
        "type".into(),
        item.get("type").cloned().unwrap_or(Value::Null),
    );
    obj.insert(
        "reprompt".into(),
        item.get("reprompt").cloned().unwrap_or(json!(0)),
    );
    obj.insert(
        "favorite".into(),
        item.get("favorite").cloned().unwrap_or(json!(false)),
    );
    obj.insert("creationDate".into(), json!(synth_creation_date(rank)));
    obj.insert("revisionDate".into(), json!(synth_revision_date(rank)));
    obj.insert(
        "deletedDate".into(),
        if item
            .get("deletedDate")
            .is_some_and(|v| !v.is_null())
        {
            json!(synth_deleted_date(rank))
        } else {
            Value::Null
        },
    );

    obj.insert("name".into(), json!(format!("Example Service {gid:04}")));
    obj.insert("notes".into(), Value::Null);

    // Custom fields: preserve count, type, and linkedId; scrub name + value.
    let fields_val = match item.get("fields").and_then(Value::as_array) {
        Some(arr) if !arr.is_empty() => {
            let scrubbed: Vec<Value> = arr
                .iter()
                .enumerate()
                .map(|(fi, f)| {
                    json!({
                        "name": format!("field_{fi}"),
                        "value": "REDACTED",
                        "type": f.get("type").cloned().unwrap_or(json!(0)),
                        "linkedId": f.get("linkedId").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect();
            Value::Array(scrubbed)
        }
        _ => Value::Null,
    };
    obj.insert("fields".into(), fields_val);

    obj.insert("passwordHistory".into(), Value::Null);

    let typ = item.get("type").and_then(Value::as_u64).unwrap_or(0);
    match typ {
        1 => {
            // Login
            let lg = item.get("login").and_then(Value::as_object);
            let username = lg
                .and_then(|m| m.get("username"))
                .and_then(Value::as_str)
                .map(|_| json!(format!("user{gid:04}@example.test")))
                .unwrap_or(Value::Null);
            let password = lg
                .and_then(|m| m.get("password"))
                .and_then(Value::as_str)
                .map(|_| json!(format!("redacted-password-{gid:04}")))
                .unwrap_or(Value::Null);
            let totp = lg
                .and_then(|m| m.get("totp"))
                .and_then(Value::as_str)
                .map(|_| json!(format!("redacted-totp-seed-{gid:04}")))
                .unwrap_or(Value::Null);

            let uris_val = match lg.and_then(|m| m.get("uris")).and_then(Value::as_array) {
                Some(arr) if !arr.is_empty() => {
                    let scrubbed: Vec<Value> = arr
                        .iter()
                        .enumerate()
                        .map(|(i, u)| {
                            let orig = u.get("uri").and_then(Value::as_str);
                            json!({
                                "uri": scrub_uri(orig, gid, i),
                                "match": u.get("match").cloned().unwrap_or(Value::Null),
                            })
                        })
                        .collect();
                    Value::Array(scrubbed)
                }
                _ => Value::Null,
            };

            obj.insert(
                "login".into(),
                json!({
                    "username": username,
                    "password": password,
                    "totp": totp,
                    "uris": uris_val,
                    "fido2Credentials": [],
                }),
            );
        }
        2 => {
            obj.insert("secureNote".into(), json!({"type": 0}));
        }
        3 => {
            obj.insert(
                "card".into(),
                json!({
                    "cardholderName": "REDACTED",
                    "brand": Value::Null,
                    "number": Value::Null,
                    "expMonth": Value::Null,
                    "expYear": Value::Null,
                    "code": Value::Null,
                }),
            );
        }
        4 => {
            obj.insert(
                "identity".into(),
                json!({
                    "title": Value::Null,
                    "firstName": "REDACTED",
                    "middleName": Value::Null,
                    "lastName": "REDACTED",
                    "address1": Value::Null,
                    "address2": Value::Null,
                    "address3": Value::Null,
                    "city": Value::Null,
                    "state": Value::Null,
                    "postalCode": Value::Null,
                    "country": Value::Null,
                    "company": Value::Null,
                    "email": Value::Null,
                    "phone": Value::Null,
                    "ssn": Value::Null,
                    "username": Value::Null,
                    "passportNumber": Value::Null,
                    "licenseNumber": Value::Null,
                }),
            );
        }
        _ => {}
    }

    Value::Object(obj)
}
