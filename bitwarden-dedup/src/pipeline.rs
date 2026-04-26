// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! **"Which item survives, and what's the audit trail?"** — pipeline
//! orchestration.
//!
//! The dedup pipeline runs in five passes (the empty-password login
//! pass is opt-in via [`DedupConfig::collapse_empty_passwords`]):
//!
//! 1. **Strict login dedup** — group items by [`crate::key::dedup_key`];
//!    skip items that fail [`crate::key::skip_from_dedup`]. For each
//!    group of size > 1, pick a survivor (longer `passwordHistory` →
//!    newer `revisionDate` → newer `creationDate`), compute the merged
//!    survivor patch via [`crate::merge::build_survivor_patch`], apply
//!    it, and mark the losers with `deletedDate = now`. Losers stay
//!    in the output array so they surface in Bitwarden's **Trash**
//!    folder after import — no item is ever removed.
//! 2. **Empty-password login dedup** (opt-in) — same shape as Pass 1
//!    but keyed by [`crate::key::empty_password_dedup_key`] over items
//!    the strict pass skipped because their `login.password` was empty.
//!    Refuses to group items whose only signal is the display name.
//! 3. **Secure-note dedup** — group `type: 2` items by
//!    [`crate::key::secure_note_key`] (name + org + canonicalized
//!    body), collapse literal duplicates only.
//! 4. **SSH-key dedup** — group `type: 5` items by
//!    [`crate::key::ssh_key_key`] (full canonicalized key material +
//!    org); any byte-level mismatch keeps items separate.
//! 5. **Card dedup** — group `type: 3` items by
//!    [`crate::key::card_key`] (full canonicalized `card` object +
//!    org). Strict equality: any byte mismatch on number, expiry,
//!    CVV, brand, or cardholder name keeps items distinct.
//! 6. **Identity dedup** — group `type: 4` items by
//!    [`crate::key::identity_key`] (full canonicalized `identity`
//!    object + org). Strict equality on every populated field.
//! 7. **Folder dedup** — collapse same-name folders in the top-level
//!    `folders` array and remap every item's `folderId` to the
//!    surviving folder. Runs in [`dedup_export`] before items are
//!    handed to the four item-level passes above so divergent-folder
//!    notes only fire for genuinely different folders.
//!
//! **Survivor selection** is deterministic: longer `passwordHistory` wins
//! (captures more rotation history), then newer `revisionDate`, then newer
//! `creationDate`. That ordering is what keeps the merge safe — older
//! items with richer history aren't discarded in favour of a freshly-updated
//! stub.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;
use serde_json::{Value, json};

use crate::json_util::get_str;
use crate::key::{
    card_key, dedup_key, empty_password_dedup_key, identity_key, is_dedupable_card,
    is_dedupable_empty_password_login, is_dedupable_identity, is_dedupable_secure_note,
    is_dedupable_ssh_key, secure_note_key, skip_from_dedup, ssh_key_key, uri_host_set,
};
use crate::merge::{
    MetadataPatch, SecureNotePatch, SurvivorPatch, apply_metadata_patch, apply_secure_note_patch,
    apply_survivor_patch, build_metadata_patch, build_secure_note_patch, build_survivor_patch,
    secure_note_source_label,
};
use crate::time_util::iso8601_now;

/// Configuration knobs for a dedup run. Defaults match the documented
/// merge semantics; callers only set fields they want to diverge from.
#[derive(Debug, Clone, Default)]
pub struct DedupConfig {
    /// When `true`, items that differ only in `login.totp` stay as
    /// separate living items instead of collapsing with the
    /// newest-by-`revisionDate` pick.
    ///
    /// `revisionDate` is an item-level timestamp (touched by edits to
    /// notes, favorite flag, etc.), so it is an imperfect proxy for
    /// "which TOTP is currently valid on the backend". The default
    /// behavior (`false`) collapses the group and keeps the newest
    /// secret — the non-chosen TOTPs still reach the output inside
    /// their items' Trash entries, so they are recoverable. Set this
    /// to `true` if you would rather keep the duplicates than risk
    /// having the wrong live secret on the living survivor.
    pub split_divergent_totps: bool,

    /// When `true`, run a second login-dedup pass over credential-less
    /// stubs (empty `login.password`) that the strict pass deliberately
    /// skips. Items only group when name + organization + username +
    /// URI host set + fido2 signature all match AND the group has at
    /// least one identifying signal beyond its name (non-empty
    /// username, non-empty URI host set, or a fido2 credential).
    ///
    /// Off by default because empty-password stubs can occasionally
    /// represent distinct real-world accounts the user has not yet
    /// filled in. Losers route to the trash sidecar like every other
    /// dedup loser, so any false positive is recoverable.
    pub collapse_empty_passwords: bool,
}

/// Which signal qualified an empty-password item for grouping in
/// [`DedupConfig::collapse_empty_passwords`]. Listed in least-to-most
/// corroborated order so a reviewer sorting by `signal_kind` sees the
/// riskier groups first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// Group has matching username and nothing else (no URI hosts, no
    /// fido2). Weakest signal class — the one most likely to produce a
    /// false positive on an unusual vault.
    UsernameOnly,
    /// Group has matching URI host set (with or without username).
    /// Stronger than `UsernameOnly` — host text is concrete identity.
    Host,
    /// Group has matching fido2 credential set (with or without
    /// username/host). Strongest signal — identical credential
    /// material.
    Fido2,
}

impl SignalKind {
    fn as_str(self) -> &'static str {
        match self {
            SignalKind::UsernameOnly => "username_only",
            SignalKind::Host => "host",
            SignalKind::Fido2 => "fido2",
        }
    }

    /// Pick the signal kind for a group based on the survivor's
    /// fields. Priority: `Fido2 > Host > UsernameOnly`.
    fn classify(item: &Value) -> Self {
        let has_fido = item
            .get("login")
            .and_then(|l| l.get("fido2Credentials"))
            .and_then(Value::as_array)
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        if has_fido {
            return SignalKind::Fido2;
        }
        if !uri_host_set(item).is_empty() {
            return SignalKind::Host;
        }
        SignalKind::UsernameOnly
    }
}

/// Summary of a [`dedup_items`] run.
///
/// Field meanings:
/// - `total`    — input item count
/// - `skipped`  — items the **strict login pass** (Pass 1) declined to
///                group: non-logins, reprompt-gated, empty password,
///                already tagged `[duplicate]`, already-deleted items
///                in the input. **Note**: when
///                `collapse_empty_passwords` is set, some items
///                counted here may still be grouped by the
///                empty-password pass (Pass 2) — `skipped` is
///                strict-pass-local, not "skipped by every pass".
///                Audit JSON publishes this as `strict_pass_skipped`.
/// - `groups`   — total dedup groups across **all** passes (sum of
///                `strict_login_groups` + `empty_password_groups` +
///                `secure_note_groups` + `ssh_key_groups`). Read the
///                per-pass counters for a breakdown.
/// - `trashed`  — number of items freshly moved to Trash by this run
///                (dedup losers — they stay in the output array with
///                `deletedDate = now` so Bitwarden shows them in the Trash
///                folder after import; no item is ever removed)
/// - `merged`   — total URIs merged from dropped items into kept items
/// - `totp_conflict_groups` — groups that contained more than one distinct
///                non-empty TOTP (the sensitive case reviewers should
///                spot-check; every per-entry audit record carries a
///                `totp_conflict` flag for the same groups)
/// - `output`   — total items in the output array (always equals `total`,
///                because dedup no longer removes anything — it only trashes)
/// - `living`   — items in the output whose `deletedDate` is null, i.e.
///                items the user will see in the main Bitwarden view
/// - `audit_entries` — one JSON record per trashed item, suitable for
///                     writing alongside the deduplicated output
#[derive(Debug, Clone)]
pub struct DedupStats {
    pub total: usize,
    pub skipped: usize,
    /// Total dedup groups across all passes. Kept as the back-compat
    /// sum of the four per-pass counters below.
    pub groups: usize,
    /// Strict login pass (non-empty password, [`crate::key::dedup_key`]).
    pub strict_login_groups: usize,
    /// Empty-password login pass — non-zero only when
    /// [`DedupConfig::collapse_empty_passwords`] is set.
    pub empty_password_groups: usize,
    /// Items routed to trash by the empty-password pass specifically.
    pub empty_password_trashed: usize,
    /// Per-signal-kind breakdown of `empty_password_groups`. Sums to
    /// `empty_password_groups`. Empty when the pass did not run.
    pub empty_password_groups_by_signal: BTreeMap<SignalKind, usize>,
    pub secure_note_groups: usize,
    pub ssh_key_groups: usize,
    /// Card (`type: 3`) duplicate groups collapsed by the strict-
    /// equality card pass. Cards collapse only when every field of
    /// the `card` block (number, expiry, CVV, brand, cardholder
    /// name) is byte-identical and the names normalize to the same
    /// value within the same organization.
    pub card_groups: usize,
    /// Identity (`type: 4`) duplicate groups collapsed by the
    /// strict-equality identity pass. Identities collapse only when
    /// every field of the `identity` block (name, address, email,
    /// phone, government IDs) is byte-identical and the item names
    /// match within the same organization.
    pub identity_groups: usize,
    pub trashed: usize,
    pub merged: usize,
    pub totp_conflict_groups: usize,
    /// How many duplicate folders were collapsed from the top-level
    /// `folders` array. Two folders with the same normalized name
    /// (e.g. two copies of `main` after an additive import) are merged
    /// to one, and every item's `folderId` is remapped so references
    /// stay valid. Only populated by [`dedup_export`] /
    /// [`dedup_export_with_config`] — the plain [`dedup_items`]
    /// entry points don't have the top-level `folders` array.
    pub folders_deduplicated: usize,
    pub output: usize,
    pub living: usize,
    pub audit_entries: Vec<Value>,
}

impl DedupStats {
    /// Backwards-compatible alias for [`Self::trashed`].  Earlier versions
    /// called this field `removed`, meaning "items dropped from the array";
    /// the semantics now are "items moved to Trash", but the count is the
    /// same so callers relying on the old name keep working.
    pub fn removed(&self) -> usize {
        self.trashed
    }
}

/// Run the full dedup pipeline on a `Vec<Value>` of Bitwarden items in place.
///
/// The input vector is mutated:
/// - items that are removed drop out of the vec
/// - the surviving item in each duplicate group absorbs data from the dropped
///   items: URIs, notes, custom fields, passwordHistory, favorite flag,
///   collection memberships, and the longest name in the group. Drops whose
///   `folderId` differs from the survivor's are recorded as a note line so
///   the placement hint survives import.
///
/// **Survivor selection** (within a duplicate group):
/// 1. Longer `passwordHistory` array wins (captures more rotation records)
/// 2. Then newer `revisionDate`
/// 3. Then newer `creationDate`
///
/// The returned [`DedupStats`] describes what happened and includes
/// per-removal audit records.
///
/// For top-level exports that carry a `folders: [{id, name}, …]` array,
/// prefer [`dedup_export`] — it resolves folder UUIDs to names in the
/// disambiguation note. This entry point passes an empty lookup, so
/// divergent folders fall back to bare UUIDs in the merged notes.
pub fn dedup_items(items: &mut Vec<Value>) -> DedupStats {
    dedup_items_with_folders(items, &HashMap::new(), &DedupConfig::default())
}

/// Same as [`dedup_items`] but with an explicit [`DedupConfig`].
pub fn dedup_items_with_config(items: &mut Vec<Value>, config: &DedupConfig) -> DedupStats {
    dedup_items_with_folders(items, &HashMap::new(), config)
}

/// Run the full dedup pipeline on a complete Bitwarden export JSON value.
///
/// Accepts the parsed top-level object (the structure `{folders, items, …}`
/// that `bw export --format json` writes). Extracts the `folders` lookup,
/// dedups `items` in place, and returns the same [`DedupStats`] as
/// [`dedup_items`].
///
/// **Fail-fast**: returns `Err(...)` when the top-level value is not an
/// object, when `items` is missing, or when `items` is present but not
/// an array. Returning zeroed stats on malformed input would silently
/// mask "wrong file pointed at the tool" — that is not safe for a
/// transform that feeds straight into purge-and-reimport.
pub fn dedup_export(export: &mut Value) -> Result<DedupStats, String> {
    dedup_export_with_config(export, &DedupConfig::default())
}

/// Same as [`dedup_export`] but with an explicit [`DedupConfig`].
pub fn dedup_export_with_config(
    export: &mut Value,
    config: &DedupConfig,
) -> Result<DedupStats, String> {
    if !export.is_object() {
        return Err("Bitwarden export is not a top-level JSON object".into());
    }
    // Fold duplicate folders (same normalized name) into one survivor
    // per name, rewriting every item's `folderId` to the survivor's
    // id. Bitwarden's additive import can leave duplicate "main"
    // folders etc. in an export; this cleans them up before item
    // dedup so the folder-disambiguation notes on merged items stay
    // meaningful (they only fire for *genuinely* different folders).
    let folders_deduplicated = dedup_folders_in_export(export)?;

    let folders = extract_folder_names(export);
    let items_value = export
        .as_object_mut()
        .expect("is_object checked above")
        .get_mut("items")
        .ok_or_else(|| "Bitwarden export is missing the `items` array".to_string())?;
    let arr = items_value.as_array_mut().ok_or_else(|| {
        "Bitwarden export `items` field exists but is not an array. Refusing to proceed."
            .to_string()
    })?;
    let mut items = std::mem::take(arr);
    let mut stats = dedup_items_with_folders(&mut items, &folders, config);
    stats.folders_deduplicated = folders_deduplicated;
    *arr = items;
    Ok(stats)
}

/// Collapse duplicate entries in the top-level `folders` array and
/// remap every item's `folderId` to the surviving folder's id.
///
/// - Folders group by [`crate::key::normalize_note_name`] (case-fold +
///   trim + invisible-char scrub). The login-style `(email)` stripping
///   is intentionally NOT applied — folder names can legitimately
///   carry email content.
/// - Survivor per group: the folder that appears first in input order.
///   Folders in Bitwarden exports don't have revisionDate, so there
///   is no more-principled tiebreak.
///
/// Returns the number of duplicate folders collapsed (always
/// `input_folders - output_folders`).
fn dedup_folders_in_export(export: &mut Value) -> Result<usize, String> {
    let Some(obj) = export.as_object_mut() else {
        return Err("export is not a top-level JSON object".into());
    };
    let Some(folders_value) = obj.get_mut("folders") else {
        return Ok(0);
    };
    let Some(folders) = folders_value.as_array_mut() else {
        // Some exports carry `folders: null`. Treat as "no folders".
        return Ok(0);
    };

    // Map duplicate-folder-id → survivor-id, so items can be remapped.
    let mut id_remap: HashMap<String, String> = HashMap::new();
    let mut seen: HashMap<String, String> = HashMap::new(); // normalized name → survivor id
    let mut keep: Vec<Value> = Vec::with_capacity(folders.len());

    for f in std::mem::take(folders) {
        let id = f
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default();
        let name_raw = f.get("name").and_then(Value::as_str).unwrap_or("");
        let key = crate::key::normalize_note_name(name_raw);
        match seen.get(&key) {
            Some(survivor_id) => {
                if !id.is_empty() {
                    id_remap.insert(id, survivor_id.clone());
                }
            }
            None => {
                if !id.is_empty() {
                    seen.insert(key, id.clone());
                }
                keep.push(f);
            }
        }
    }
    let collapsed = id_remap.len();
    *folders = keep;

    // Remap folderId references on every item (living and trashed).
    if collapsed > 0
        && let Some(items) = obj.get_mut("items").and_then(Value::as_array_mut)
    {
        for item in items {
            let Some(item_obj) = item.as_object_mut() else {
                continue;
            };
            let Some(folder_id_val) = item_obj.get("folderId") else {
                continue;
            };
            let Some(folder_id_str) = folder_id_val.as_str() else {
                continue;
            };
            if let Some(survivor) = id_remap.get(folder_id_str) {
                item_obj.insert("folderId".to_string(), Value::String(survivor.clone()));
            }
        }
    }

    Ok(collapsed)
}

fn extract_folder_names(export: &Value) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(folders) = export.get("folders").and_then(Value::as_array) else {
        return out;
    };
    for entry in folders {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        out.insert(id.to_string(), name);
    }
    out
}

/// Core of the pipeline. Exposed `pub(crate)` so inline tests here can drive
/// it with an explicit folders map; the public API is [`dedup_items`] /
/// [`dedup_export`] / [`dedup_items_with_config`] / [`dedup_export_with_config`].
pub(crate) fn dedup_items_with_folders(
    items: &mut Vec<Value>,
    folders: &HashMap<String, String>,
    config: &DedupConfig,
) -> DedupStats {
    let total = items.len();

    // Pass 1: group by dedup key. When `split_divergent_totps` is set,
    // append the item's TOTP to the group key so items with different
    // TOTPs never share a group — they stay as separate living items.
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    let mut skipped = 0usize;
    for (idx, item) in items.iter().enumerate() {
        if skip_from_dedup(item) {
            skipped += 1;
            continue;
        }
        let base_key = dedup_key(item);
        let key = if config.split_divergent_totps {
            let totp = item
                .get("login")
                .and_then(|l| l.get("totp"))
                .and_then(Value::as_str)
                .unwrap_or("");
            format!("{base_key}\0totp={totp}")
        } else {
            base_key
        };
        groups.entry(key).or_default().push(idx);
    }

    let mut dupe_groups: Vec<Vec<usize>> = groups.into_values().filter(|v| v.len() > 1).collect();
    dupe_groups.sort_by_key(|g| *g.first().unwrap_or(&0));

    // Pass 2: plan removals and build the merged-survivor value for each group.
    let mut to_drop: HashSet<usize> = HashSet::new();
    let mut audit_entries: Vec<Value> = Vec::new();
    let mut survivor_patches: Vec<(usize, SurvivorPatch)> = Vec::new();
    let mut total_merged = 0usize;
    let mut totp_conflict_groups = 0usize;

    for group in &dupe_groups {
        let mut ordered = group.clone();
        // Sort to pick survivor: longer passwordHistory > newer revisionDate
        // > newer creationDate. Using DESC ordering, so the winner sits at
        // index 0.
        ordered.sort_by(|a, b| {
            let a_hist = password_history_len(&items[*a]);
            let b_hist = password_history_len(&items[*b]);
            let a_rev = get_str(&items[*a], "revisionDate");
            let b_rev = get_str(&items[*b], "revisionDate");
            let a_cre = get_str(&items[*a], "creationDate");
            let b_cre = get_str(&items[*b], "creationDate");
            (b_hist, b_rev, b_cre).cmp(&(a_hist, a_rev, a_cre))
        });
        let keep_idx = ordered[0];
        let drop_idxs = &ordered[1..];

        let keep = &items[keep_idx];
        let drops: Vec<&Value> = drop_idxs.iter().map(|i| &items[*i]).collect();

        let patch = build_survivor_patch(keep, &drops, folders);
        let merged_here = patch.uri_additions.len();
        total_merged += merged_here;
        if patch.totp.conflict {
            totp_conflict_groups += 1;
        }

        let keep_id = keep.get("id").cloned().unwrap_or(Value::Null);
        let keep_rev = keep.get("revisionDate").cloned().unwrap_or(Value::Null);
        let keep_folder = keep.get("folderId").cloned().unwrap_or(Value::Null);
        let keep_name_for_audit = Value::String(patch.longest_name.clone());
        let totp_conflict = patch.totp.conflict;
        let totp_kept_from_id = patch
            .totp
            .chosen_from_id
            .as_ref()
            .map(|s| Value::String(s.clone()))
            .unwrap_or(Value::Null);
        let fields_merged_count = patch.field_additions.len();
        let collections_merged_count = patch.collection_additions.len();
        let folder_note_added = patch.folder_note_line.is_some();
        let notes_merged_flag = patch.notes_merged;

        for &di in drop_idxs {
            to_drop.insert(di);
            let dropped = &items[di];
            audit_entries.push(json!({
                "removed_id": dropped.get("id").cloned().unwrap_or(Value::Null),
                "removed_name": dropped.get("name").cloned().unwrap_or(Value::Null),
                "removed_username": dropped
                    .get("login").and_then(|l| l.get("username"))
                    .cloned().unwrap_or(Value::Null),
                "removed_revisionDate": dropped.get("revisionDate").cloned().unwrap_or(Value::Null),
                "removed_creationDate": dropped.get("creationDate").cloned().unwrap_or(Value::Null),
                "removed_folderId": dropped.get("folderId").cloned().unwrap_or(Value::Null),
                "removed_totp_present": dropped
                    .get("login").and_then(|l| l.get("totp"))
                    .and_then(Value::as_str)
                    .map(|s| !s.is_empty()).unwrap_or(false),
                "kept_id": keep_id.clone(),
                "kept_name": keep_name_for_audit.clone(),
                "kept_revisionDate": keep_rev.clone(),
                "kept_folderId": keep_folder.clone(),
                "uris_merged_into_kept": merged_here,
                // Merge-sensitivity flags — let reviewers grep risky cases.
                "totp_conflict": totp_conflict,
                "totp_kept_from_id": totp_kept_from_id.clone(),
                "notes_merged": notes_merged_flag,
                "fields_merged": fields_merged_count,
                "collections_merged": collections_merged_count,
                "folder_note_added": folder_note_added,
            }));
        }

        survivor_patches.push((keep_idx, patch));
    }

    // Pass 3: apply merged fields to the surviving items.
    for (keep_idx, patch) in survivor_patches {
        apply_survivor_patch(&mut items[keep_idx], patch);
    }

    // Pass 4: mark login dedup losers with `deletedDate = now`. They stay
    // in the array so Bitwarden surfaces them in the Trash folder after
    // import. Nothing is ever removed — the user can manually recover
    // any false positive.
    let now = iso8601_now();
    for (i, item) in items.iter_mut().enumerate() {
        if to_drop.contains(&i)
            && let Some(obj) = item.as_object_mut()
        {
            obj.insert("deletedDate".to_string(), Value::String(now.clone()));
        }
    }

    // Pass 4.5: empty-password login dedup (opt-in). Runs AFTER the
    // strict pass has already marked its losers with `deletedDate`,
    // and `is_dedupable_empty_password_login` filters those out — so
    // a strict-pass loser is never re-considered, and this pass only
    // touches items the strict pass left alone (skipped because of
    // empty pw).
    let epw_outcome = if config.collapse_empty_passwords {
        dedup_empty_password_logins(items, folders, &now, config)
    } else {
        EmptyPasswordOutcome::default()
    };

    // Pass 5: secure-note dedup.
    let (note_groups, note_trashed, note_audit_entries) = dedup_secure_notes(items, folders, &now);

    // Pass 6: SSH key dedup.
    let (ssh_groups, ssh_trashed, ssh_audit_entries) = dedup_ssh_keys(items, folders, &now);

    // Pass 7: Card dedup (strict equality on every populated card field).
    let (card_groups, card_trashed, card_audit_entries) = dedup_cards(items, folders, &now);

    // Pass 8: Identity dedup (strict equality on every populated identity field).
    let (identity_groups, identity_trashed, identity_audit_entries) =
        dedup_identities(items, folders, &now);

    // Combined counts cover every pass.
    let strict_login_groups = dupe_groups.len();
    let trashed = to_drop.len()
        + epw_outcome.trashed
        + note_trashed
        + ssh_trashed
        + card_trashed
        + identity_trashed;
    let groups_total = strict_login_groups
        + epw_outcome.groups
        + note_groups
        + ssh_groups
        + card_groups
        + identity_groups;
    let mut combined_audit = audit_entries;
    combined_audit.extend(epw_outcome.audit_entries);
    combined_audit.extend(note_audit_entries);
    combined_audit.extend(ssh_audit_entries);
    combined_audit.extend(card_audit_entries);
    combined_audit.extend(identity_audit_entries);
    total_merged += epw_outcome.uris_merged;
    totp_conflict_groups += epw_outcome.totp_conflict_groups;

    let output = items.len();
    let living = items
        .iter()
        .filter(|v| v.get("deletedDate").map(Value::is_null).unwrap_or(true))
        .count();

    DedupStats {
        total,
        skipped,
        groups: groups_total,
        strict_login_groups,
        empty_password_groups: epw_outcome.groups,
        empty_password_trashed: epw_outcome.trashed,
        empty_password_groups_by_signal: epw_outcome.groups_by_signal,
        secure_note_groups: note_groups,
        ssh_key_groups: ssh_groups,
        card_groups,
        identity_groups,
        trashed,
        merged: total_merged,
        totp_conflict_groups,
        // Set to zero at the item-dedup layer — populated by
        // `dedup_export_with_config` when it processes the top-level
        // `folders` array before calling us.
        folders_deduplicated: 0,
        output,
        living,
        audit_entries: combined_audit,
    }
}

/// Outcome of the empty-password login dedup pass. Aggregates the
/// information the orchestrator needs to fold into [`DedupStats`].
#[derive(Default)]
struct EmptyPasswordOutcome {
    groups: usize,
    trashed: usize,
    audit_entries: Vec<Value>,
    uris_merged: usize,
    totp_conflict_groups: usize,
    groups_by_signal: BTreeMap<SignalKind, usize>,
}

/// Pass 4.5 — group credential-less stubs (empty `login.password`)
/// that the strict pass deliberately skipped. Same merge semantics as
/// the strict pass: longer `passwordHistory` → newer `revisionDate` →
/// newer `creationDate` survivor selection, full URI/notes/fields
/// union onto the survivor, losers tagged with `deletedDate = now`
/// for routing into the trash sidecar.
///
/// Items that fail [`is_dedupable_empty_password_login`] (no signal
/// beyond their name, or filtered for the usual safety reasons) pass
/// through untouched. The strict pass's losers (which already carry
/// `deletedDate`) are also filtered out, so we never re-process them.
fn dedup_empty_password_logins(
    items: &mut Vec<Value>,
    folders: &HashMap<String, String>,
    now: &str,
    config: &DedupConfig,
) -> EmptyPasswordOutcome {
    use crate::merge::{SurvivorPatch, apply_survivor_patch, build_survivor_patch};

    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, item) in items.iter().enumerate() {
        if !is_dedupable_empty_password_login(item) {
            continue;
        }
        let base_key = empty_password_dedup_key(item);
        let key = if config.split_divergent_totps {
            let totp = item
                .get("login")
                .and_then(|l| l.get("totp"))
                .and_then(Value::as_str)
                .unwrap_or("");
            format!("{base_key}\0totp={totp}")
        } else {
            base_key
        };
        groups.entry(key).or_default().push(idx);
    }

    let mut dupe_groups: Vec<Vec<usize>> = groups.into_values().filter(|v| v.len() > 1).collect();
    dupe_groups.sort_by_key(|g| *g.first().unwrap_or(&0));

    let mut to_drop: HashSet<usize> = HashSet::new();
    let mut audit_entries: Vec<Value> = Vec::new();
    let mut survivor_patches: Vec<(usize, SurvivorPatch)> = Vec::new();
    let mut total_uris_merged = 0usize;
    let mut totp_conflict_groups = 0usize;
    let mut groups_by_signal: BTreeMap<SignalKind, usize> = BTreeMap::new();

    for group in &dupe_groups {
        let mut ordered = group.clone();
        ordered.sort_by(|a, b| {
            let a_hist = password_history_len(&items[*a]);
            let b_hist = password_history_len(&items[*b]);
            let a_rev = get_str(&items[*a], "revisionDate");
            let b_rev = get_str(&items[*b], "revisionDate");
            let a_cre = get_str(&items[*a], "creationDate");
            let b_cre = get_str(&items[*b], "creationDate");
            (b_hist, b_rev, b_cre).cmp(&(a_hist, a_rev, a_cre))
        });
        let keep_idx = ordered[0];
        let drop_idxs = &ordered[1..];

        let keep = &items[keep_idx];
        let drops: Vec<&Value> = drop_idxs.iter().map(|i| &items[*i]).collect();

        let signal_kind = SignalKind::classify(keep);
        *groups_by_signal.entry(signal_kind).or_insert(0) += 1;

        let patch = build_survivor_patch(keep, &drops, folders);
        let merged_here = patch.uri_additions.len();
        total_uris_merged += merged_here;
        if patch.totp.conflict {
            totp_conflict_groups += 1;
        }

        let keep_id = keep.get("id").cloned().unwrap_or(Value::Null);
        let keep_rev = keep.get("revisionDate").cloned().unwrap_or(Value::Null);
        let keep_folder = keep.get("folderId").cloned().unwrap_or(Value::Null);
        let keep_name_for_audit = Value::String(patch.longest_name.clone());
        let totp_conflict = patch.totp.conflict;
        let totp_kept_from_id = patch
            .totp
            .chosen_from_id
            .as_ref()
            .map(|s| Value::String(s.clone()))
            .unwrap_or(Value::Null);
        let fields_merged_count = patch.field_additions.len();
        let collections_merged_count = patch.collection_additions.len();
        let folder_note_added = patch.folder_note_line.is_some();
        let notes_merged_flag = patch.notes_merged;

        for &di in drop_idxs {
            to_drop.insert(di);
            let dropped = &items[di];
            audit_entries.push(json!({
                "item_kind": "empty_password_login",
                "signal_kind": signal_kind.as_str(),
                "removed_id": dropped.get("id").cloned().unwrap_or(Value::Null),
                "removed_name": dropped.get("name").cloned().unwrap_or(Value::Null),
                "removed_username": dropped
                    .get("login").and_then(|l| l.get("username"))
                    .cloned().unwrap_or(Value::Null),
                "removed_revisionDate": dropped.get("revisionDate").cloned().unwrap_or(Value::Null),
                "removed_creationDate": dropped.get("creationDate").cloned().unwrap_or(Value::Null),
                "removed_folderId": dropped.get("folderId").cloned().unwrap_or(Value::Null),
                "removed_totp_present": dropped
                    .get("login").and_then(|l| l.get("totp"))
                    .and_then(Value::as_str)
                    .map(|s| !s.is_empty()).unwrap_or(false),
                "kept_id": keep_id.clone(),
                "kept_name": keep_name_for_audit.clone(),
                "kept_revisionDate": keep_rev.clone(),
                "kept_folderId": keep_folder.clone(),
                "uris_merged_into_kept": merged_here,
                "totp_conflict": totp_conflict,
                "totp_kept_from_id": totp_kept_from_id.clone(),
                "notes_merged": notes_merged_flag,
                "fields_merged": fields_merged_count,
                "collections_merged": collections_merged_count,
                "folder_note_added": folder_note_added,
            }));
        }

        survivor_patches.push((keep_idx, patch));
    }

    for (keep_idx, patch) in survivor_patches {
        apply_survivor_patch(&mut items[keep_idx], patch);
    }
    for (i, item) in items.iter_mut().enumerate() {
        if to_drop.contains(&i)
            && let Some(obj) = item.as_object_mut()
        {
            obj.insert("deletedDate".to_string(), Value::String(now.to_string()));
        }
    }

    EmptyPasswordOutcome {
        groups: dupe_groups.len(),
        trashed: to_drop.len(),
        audit_entries,
        uris_merged: total_uris_merged,
        totp_conflict_groups,
        groups_by_signal,
    }
}

/// Second dedup pass dedicated to secure notes (`type: 2`).
///
/// Secure notes never entered [`dedup_key`] grouping — they have no
/// credentials. Instead they group by [`secure_note_key`] (normalized
/// name), pick a survivor by "longest notes body → newer revisionDate
/// → newer creationDate", and the drop's body (if it differs) is
/// appended to the survivor under a `=== Merged <ts> Source [...] ===`
/// header so nothing the user typed is lost.
///
/// Returns `(groups_collapsed, losers_trashed, per-entry audit records)`.
fn dedup_secure_notes(
    items: &mut Vec<Value>,
    folders: &HashMap<String, String>,
    now: &str,
) -> (usize, usize, Vec<Value>) {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, item) in items.iter().enumerate() {
        if !is_dedupable_secure_note(item) {
            continue;
        }
        groups.entry(secure_note_key(item)).or_default().push(idx);
    }
    let mut dupe_groups: Vec<Vec<usize>> = groups.into_values().filter(|v| v.len() > 1).collect();
    dupe_groups.sort_by_key(|g| *g.first().unwrap_or(&0));

    let mut to_drop: HashSet<usize> = HashSet::new();
    let mut audit_entries: Vec<Value> = Vec::new();
    let mut patches: Vec<(usize, SecureNotePatch)> = Vec::new();

    for group in &dupe_groups {
        let mut ordered = group.clone();
        // Survivor selection for secure notes:
        // 1. Prefer non-CSV origin (Bitwarden id > `apple-csv-…` id) so
        //    folder/favorite/fields on the BW side are retained.
        // 2. Then newer `revisionDate`, then newer `creationDate`.
        // Note: we don't rank by body length here because the strict key
        // (see [`crate::key::secure_note_key`]) guarantees every item in
        // the group already has the same trimmed body.
        ordered.sort_by(|a, b| {
            let a_pref = secure_note_non_csv_rank(&items[*a]);
            let b_pref = secure_note_non_csv_rank(&items[*b]);
            let a_rev = get_str(&items[*a], "revisionDate");
            let b_rev = get_str(&items[*b], "revisionDate");
            let a_cre = get_str(&items[*a], "creationDate");
            let b_cre = get_str(&items[*b], "creationDate");
            (b_pref, b_rev, b_cre).cmp(&(a_pref, a_rev, a_cre))
        });
        let keep_idx = ordered[0];
        let drop_idxs = &ordered[1..];

        let keep = &items[keep_idx];
        let drops: Vec<&Value> = drop_idxs.iter().map(|i| &items[*i]).collect();
        let patch = build_secure_note_patch(keep, &drops, folders);

        let keep_id = keep.get("id").cloned().unwrap_or(Value::Null);
        let keep_name_audit = Value::String(patch.longest_name.clone());
        let keep_rev = keep.get("revisionDate").cloned().unwrap_or(Value::Null);
        let keep_folder = keep.get("folderId").cloned().unwrap_or(Value::Null);
        let fields_merged = patch.field_additions.len();
        let collections_merged = patch.collection_additions.len();
        let folder_note_added = patch.folder_note_line.is_some();

        for &di in drop_idxs {
            to_drop.insert(di);
            let dropped = &items[di];
            audit_entries.push(json!({
                "item_kind": "secure_note",
                "removed_id": dropped.get("id").cloned().unwrap_or(Value::Null),
                "removed_name": dropped.get("name").cloned().unwrap_or(Value::Null),
                "removed_source": secure_note_source_label(dropped),
                "removed_revisionDate": dropped.get("revisionDate").cloned().unwrap_or(Value::Null),
                "removed_creationDate": dropped.get("creationDate").cloned().unwrap_or(Value::Null),
                "removed_folderId": dropped.get("folderId").cloned().unwrap_or(Value::Null),
                "kept_id": keep_id.clone(),
                "kept_name": keep_name_audit.clone(),
                "kept_revisionDate": keep_rev.clone(),
                "kept_folderId": keep_folder.clone(),
                "fields_merged": fields_merged,
                "collections_merged": collections_merged,
                "folder_note_added": folder_note_added,
            }));
        }

        patches.push((keep_idx, patch));
    }

    for (keep_idx, patch) in patches {
        apply_secure_note_patch(&mut items[keep_idx], patch);
    }
    for (i, item) in items.iter_mut().enumerate() {
        if to_drop.contains(&i)
            && let Some(obj) = item.as_object_mut()
        {
            obj.insert("deletedDate".to_string(), Value::String(now.to_string()));
        }
    }

    (dupe_groups.len(), to_drop.len(), audit_entries)
}

/// Higher rank = preferred as survivor. Non-CSV-origin items outrank
/// CSV-origin synthetic items so Bitwarden-side metadata (folderId,
/// fields, creationDate) survives by default when keys match.
fn secure_note_non_csv_rank(item: &Value) -> u8 {
    match item.get("id").and_then(Value::as_str) {
        Some(id) if id.starts_with("apple-csv-") => 0,
        _ => 1,
    }
}

/// SSH-key (`type: 5`) dedup — strict equality on the full `sshKey`
/// object + org. Thin wrapper over [`dedup_strict_metadata_pass`].
fn dedup_ssh_keys(
    items: &mut Vec<Value>,
    folders: &HashMap<String, String>,
    now: &str,
) -> (usize, usize, Vec<Value>) {
    dedup_strict_metadata_pass(items, folders, now, "ssh_key", is_dedupable_ssh_key, ssh_key_key)
}

/// Card (`type: 3`) dedup — strict equality on the full `card`
/// object (number, expiry, CVV, brand, cardholder name) + org.
fn dedup_cards(
    items: &mut Vec<Value>,
    folders: &HashMap<String, String>,
    now: &str,
) -> (usize, usize, Vec<Value>) {
    dedup_strict_metadata_pass(items, folders, now, "card", is_dedupable_card, card_key)
}

/// Identity (`type: 4`) dedup — strict equality on the full
/// `identity` object (name, address, email, phone, government IDs)
/// + org.
fn dedup_identities(
    items: &mut Vec<Value>,
    folders: &HashMap<String, String>,
    now: &str,
) -> (usize, usize, Vec<Value>) {
    dedup_strict_metadata_pass(
        items,
        folders,
        now,
        "identity",
        is_dedupable_identity,
        identity_key,
    )
}

/// Generic strict-equality dedup pass for non-login item types where
/// the credential / structured data is **part of the grouping key**
/// (SSH keys, cards, identities). Groups by `key_fn`, picks a
/// survivor by newer `revisionDate` then newer `creationDate`, and
/// merges only metadata (longest name, favorite OR, fields,
/// collections, folder note) onto the survivor — the type-specific
/// data block is byte-identical across the group by construction.
///
/// Returns `(groups_collapsed, items_trashed, audit_entries)`.
fn dedup_strict_metadata_pass(
    items: &mut [Value],
    folders: &HashMap<String, String>,
    now: &str,
    item_kind: &'static str,
    is_dedupable: fn(&Value) -> bool,
    key_fn: fn(&Value) -> String,
) -> (usize, usize, Vec<Value>) {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, item) in items.iter().enumerate() {
        if !is_dedupable(item) {
            continue;
        }
        groups.entry(key_fn(item)).or_default().push(idx);
    }
    let mut dupe_groups: Vec<Vec<usize>> = groups.into_values().filter(|v| v.len() > 1).collect();
    dupe_groups.sort_by_key(|g| *g.first().unwrap_or(&0));

    let mut to_drop: HashSet<usize> = HashSet::new();
    let mut audit_entries: Vec<Value> = Vec::new();
    let mut patches: Vec<(usize, MetadataPatch)> = Vec::new();

    for group in &dupe_groups {
        let mut ordered = group.clone();
        ordered.sort_by(|a, b| {
            let a_rev = get_str(&items[*a], "revisionDate");
            let b_rev = get_str(&items[*b], "revisionDate");
            let a_cre = get_str(&items[*a], "creationDate");
            let b_cre = get_str(&items[*b], "creationDate");
            (b_rev, b_cre).cmp(&(a_rev, a_cre))
        });
        let keep_idx = ordered[0];
        let drop_idxs = &ordered[1..];

        let keep = &items[keep_idx];
        let drops: Vec<&Value> = drop_idxs.iter().map(|i| &items[*i]).collect();
        let patch = build_metadata_patch(keep, &drops, folders);

        let keep_id = keep.get("id").cloned().unwrap_or(Value::Null);
        let keep_name_audit = Value::String(patch.longest_name.clone());
        let keep_rev = keep.get("revisionDate").cloned().unwrap_or(Value::Null);
        let keep_folder = keep.get("folderId").cloned().unwrap_or(Value::Null);
        let fields_merged = patch.field_additions.len();
        let collections_merged = patch.collection_additions.len();
        let folder_note_added = patch.folder_note_line.is_some();

        for &di in drop_idxs {
            to_drop.insert(di);
            let dropped = &items[di];
            audit_entries.push(json!({
                "item_kind": item_kind,
                "removed_id": dropped.get("id").cloned().unwrap_or(Value::Null),
                "removed_name": dropped.get("name").cloned().unwrap_or(Value::Null),
                "removed_revisionDate": dropped.get("revisionDate").cloned().unwrap_or(Value::Null),
                "removed_creationDate": dropped.get("creationDate").cloned().unwrap_or(Value::Null),
                "removed_folderId": dropped.get("folderId").cloned().unwrap_or(Value::Null),
                "kept_id": keep_id.clone(),
                "kept_name": keep_name_audit.clone(),
                "kept_revisionDate": keep_rev.clone(),
                "kept_folderId": keep_folder.clone(),
                "fields_merged": fields_merged,
                "collections_merged": collections_merged,
                "folder_note_added": folder_note_added,
            }));
        }

        patches.push((keep_idx, patch));
    }

    for (keep_idx, patch) in patches {
        apply_metadata_patch(&mut items[keep_idx], patch);
    }
    for (i, item) in items.iter_mut().enumerate() {
        if to_drop.contains(&i)
            && let Some(obj) = item.as_object_mut()
        {
            obj.insert("deletedDate".to_string(), Value::String(now.to_string()));
        }
    }

    (dupe_groups.len(), to_drop.len(), audit_entries)
}

fn password_history_len(item: &Value) -> usize {
    item.get("passwordHistory")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dedup_export_errors_on_missing_items() {
        // Malformed top-level input must fail loud — returning zeroed
        // stats would silently swallow "wrong file pointed at the tool"
        // mistakes upstream of a purge-and-reimport.
        let mut no_items = json!({"folders": []});
        let err = dedup_export(&mut no_items).unwrap_err();
        assert!(
            err.contains("missing"),
            "error must mention missing items: {err:?}"
        );
    }

    #[test]
    fn dedup_export_errors_on_non_array_items() {
        let mut bad = json!({"folders": [], "items": "oops"});
        let err = dedup_export(&mut bad).unwrap_err();
        assert!(
            err.contains("not an array"),
            "error must explain the shape issue: {err:?}"
        );
    }

    #[test]
    fn dedup_export_succeeds_on_empty_items_array() {
        // An empty but well-shaped export is valid — it's just a no-op.
        let mut empty = json!({"folders": [], "items": []});
        let s = dedup_export(&mut empty).unwrap();
        assert_eq!(s.total, 0);
        assert_eq!(s.output, 0);
    }

    #[test]
    fn extract_folder_names_handles_missing_or_malformed() {
        assert!(extract_folder_names(&json!({})).is_empty());
        assert!(extract_folder_names(&json!({"folders": null})).is_empty());
        let map = extract_folder_names(&json!({
            "folders": [
                {"id": "a", "name": "Alpha"},
                {"id": "b"},                 // missing name → stored as ""
                {"name": "no-id-dropped"},   // missing id → skipped
            ]
        }));
        assert_eq!(map.get("a"), Some(&"Alpha".to_string()));
        assert_eq!(map.get("b"), Some(&"".to_string()));
        assert!(map.get("no-id-dropped").is_none());
    }

    #[test]
    fn survivor_selection_longer_history_beats_newer_revision() {
        // `a` has richer passwordHistory but is older; `b` is newer but empty.
        // Longer history must win (primary tiebreaker).
        let mut items = vec![
            json!({
                "id": "aaaaaaaa",
                "type": 1, "name": "X",
                "revisionDate": "2025-01-01T00:00:00Z",
                "creationDate": "2024-01-01T00:00:00Z",
                "passwordHistory": [
                    {"lastUsedDate": "2024-06-01T00:00:00Z", "password": "old1"},
                    {"lastUsedDate": "2023-06-01T00:00:00Z", "password": "old2"},
                ],
                "login": {"username": "u", "password": "p"},
            }),
            json!({
                "id": "bbbbbbbb",
                "type": 1, "name": "X",
                "revisionDate": "2026-01-01T00:00:00Z",
                "creationDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p"},
            }),
        ];
        dedup_items(&mut items);
        // Both items still in array; loser is trashed, survivor is living.
        assert_eq!(items.len(), 2);
        let living: Vec<&Value> = items
            .iter()
            .filter(|i| i["deletedDate"].is_null())
            .collect();
        assert_eq!(living.len(), 1);
        assert_eq!(
            living[0].get("id").and_then(Value::as_str),
            Some("aaaaaaaa"),
            "item with longer passwordHistory must be the living survivor"
        );
        let trashed: Vec<&Value> = items
            .iter()
            .filter(|i| !i["deletedDate"].is_null())
            .collect();
        assert_eq!(trashed.len(), 1);
        assert_eq!(
            trashed[0].get("id").and_then(Value::as_str),
            Some("bbbbbbbb"),
            "loser must stay in the array with deletedDate set"
        );
    }

    #[test]
    fn audit_entries_one_per_trashed_item() {
        let mut items = vec![
            json!({
                "id": "a", "type": 1, "name": "X",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
            json!({
                "id": "b", "type": 1, "name": "X",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
            json!({
                "id": "c", "type": 1, "name": "X",
                "revisionDate": "2026-03-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.trashed, 2);
        assert_eq!(stats.audit_entries.len(), 2);
        assert_eq!(stats.living, 1, "one survivor, two trashed");
        assert_eq!(stats.output, 3, "array still holds all three");
    }

    #[test]
    fn split_divergent_totps_keeps_items_separate() {
        // With the opt-in flag set, two items identical on name/user/pw but
        // differing only in TOTP stay as separate living items instead of
        // collapsing. This protects against a bad revisionDate heuristic
        // picking the wrong secret for the survivor.
        let mut items = vec![
            json!({
                "id": "with-old", "type": 1, "name": "Acme",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u", "password": "p",
                    "totp": "otpauth://totp/A?secret=OLD"}
            }),
            json!({
                "id": "with-new", "type": 1, "name": "Acme",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p",
                    "totp": "otpauth://totp/A?secret=NEW"}
            }),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                split_divergent_totps: true,
                ..Default::default()
            },
        );
        assert_eq!(stats.trashed, 0, "divergent TOTPs must not collapse");
        assert_eq!(stats.groups, 0);
        assert_eq!(
            items.iter().filter(|i| i["deletedDate"].is_null()).count(),
            2,
            "both items stay living"
        );
    }

    #[test]
    fn divergent_totp_group_collapses_by_default_with_conflict_flag() {
        // Default config: the group collapses and the survivor gets the
        // newest TOTP by revisionDate. But `totp_conflict` is surfaced on
        // every audit entry for the group so reviewers can find it.
        let mut items = vec![
            json!({
                "id": "older", "type": 1, "name": "Acme",
                "revisionDate": "2025-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p",
                    "totp": "otpauth://totp/A?secret=OLD"}
            }),
            json!({
                "id": "newer", "type": 1, "name": "Acme",
                "revisionDate": "2026-06-01T00:00:00Z",
                "login": {"username": "u", "password": "p",
                    "totp": "otpauth://totp/A?secret=NEW"}
            }),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.groups, 1);
        assert_eq!(stats.trashed, 1);
        assert_eq!(stats.totp_conflict_groups, 1);
        assert_eq!(stats.audit_entries.len(), 1);
        let entry = &stats.audit_entries[0];
        assert_eq!(entry["totp_conflict"], true);
        assert_eq!(entry["totp_kept_from_id"], "newer");
        assert_eq!(entry["removed_totp_present"], true);
    }

    #[test]
    fn audit_entry_has_merge_sensitivity_flags() {
        // When a merge pulls in a distinct note / custom field / collection
        // from a drop, the audit entry for that drop records it so a reviewer
        // can spot which groups had non-trivial merges.
        let mut items = vec![
            json!({
                "id": "keep", "type": 1, "name": "X",
                "organizationId": "org-1",
                "collectionIds": ["c-A"],
                "notes": "note-from-keep",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
            json!({
                "id": "drop", "type": 1, "name": "X",
                "organizationId": "org-1",
                "collectionIds": ["c-B"],
                "notes": "note-from-drop",
                "fields": [{"name": "q", "value": "r", "type": 0}],
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.audit_entries.len(), 1);
        let entry = &stats.audit_entries[0];
        assert_eq!(entry["removed_id"], "drop");
        assert_eq!(entry["notes_merged"], true);
        assert_eq!(entry["fields_merged"], 1);
        assert_eq!(entry["collections_merged"], 1);
        assert_eq!(entry["folder_note_added"], false);
        assert_eq!(entry["totp_conflict"], false);
    }

    // ---------- empty-password dedup pass ----------

    fn epw_login(name: &str, user: &str, uri: Option<&str>) -> Value {
        let uris = match uri {
            Some(u) => json!([{"uri": u, "match": null}]),
            None => json!([]),
        };
        json!({
            "id": format!("id-{}-{}-{:?}", name, user, uri),
            "type": 1,
            "name": name,
            "revisionDate": "2026-01-01T00:00:00Z",
            "creationDate": "2026-01-01T00:00:00Z",
            "login": {
                "username": user,
                "password": "",
                "uris": uris,
            },
        })
    }

    #[test]
    fn epw_off_by_default_three_identical_stay_living() {
        let mut items = vec![
            epw_login("Acme", "u", Some("https://acme.com/")),
            epw_login("Acme", "u", Some("https://acme.com/")),
            epw_login("Acme", "u", Some("https://acme.com/")),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.empty_password_groups, 0);
        assert_eq!(stats.empty_password_trashed, 0);
        assert_eq!(stats.living, 3);
        assert_eq!(stats.trashed, 0);
    }

    #[test]
    fn epw_three_identical_collapse_when_flag_on() {
        let mut items = vec![
            epw_login("Acme", "u", Some("https://acme.com/")),
            epw_login("Acme", "u", Some("https://acme.com/")),
            epw_login("Acme", "u", Some("https://acme.com/")),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(stats.empty_password_groups, 1);
        assert_eq!(stats.empty_password_trashed, 2);
        assert_eq!(stats.living, 1);
        assert_eq!(stats.output, 3);
    }

    #[test]
    fn epw_username_only_signal_collapses_and_classifies() {
        let mut items = vec![
            epw_login("oura", "alex@example.test", None),
            epw_login("oura", "alex@example.test", None),
            epw_login("oura", "alex@example.test", None),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(stats.empty_password_groups, 1);
        assert_eq!(stats.empty_password_trashed, 2);
        assert_eq!(
            stats
                .empty_password_groups_by_signal
                .get(&SignalKind::UsernameOnly),
            Some(&1)
        );
        assert_eq!(stats.audit_entries.len(), 2);
        assert_eq!(stats.audit_entries[0]["item_kind"], "empty_password_login");
        assert_eq!(stats.audit_entries[0]["signal_kind"], "username_only");
    }

    #[test]
    fn epw_host_only_signal_collapses_and_classifies() {
        let mut items = vec![
            epw_login("Heat", "", Some("https://heatledger.com/")),
            epw_login("Heat", "", Some("https://heatledger.com/")),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(stats.empty_password_groups, 1);
        assert_eq!(
            stats.empty_password_groups_by_signal.get(&SignalKind::Host),
            Some(&1)
        );
        assert_eq!(stats.audit_entries[0]["signal_kind"], "host");
    }

    #[test]
    fn epw_fido2_signal_classification_beats_host_and_user() {
        let mut a = epw_login("Acme", "u", Some("https://acme.com/"));
        let mut b = epw_login("Acme", "u", Some("https://acme.com/"));
        a["id"] = json!("a");
        b["id"] = json!("b");
        a["login"]["fido2Credentials"] = json!([{"credentialId": "pk-1"}]);
        b["login"]["fido2Credentials"] = json!([{"credentialId": "pk-1"}]);
        let mut items = vec![a, b];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(stats.empty_password_groups, 1);
        assert_eq!(
            stats
                .empty_password_groups_by_signal
                .get(&SignalKind::Fido2),
            Some(&1)
        );
        assert_eq!(stats.audit_entries[0]["signal_kind"], "fido2");
    }

    #[test]
    fn epw_no_signal_items_pass_through() {
        let mut items = vec![
            epw_login("Acme", "", None),
            epw_login("Acme", "", None),
            epw_login("Acme", "", None),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(stats.empty_password_groups, 0);
        assert_eq!(stats.empty_password_trashed, 0);
        assert_eq!(stats.living, 3);
    }

    #[test]
    fn epw_diverging_fido2_keeps_items_split() {
        let mut a = epw_login("Pass", "u", Some("https://example.com/"));
        let mut b = epw_login("Pass", "u", Some("https://example.com/"));
        a["id"] = json!("a");
        b["id"] = json!("b");
        a["login"]["fido2Credentials"] = json!([{"credentialId": "pk-alice"}]);
        b["login"]["fido2Credentials"] = json!([{"credentialId": "pk-bob"}]);
        let mut items = vec![a, b];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(
            stats.empty_password_groups, 0,
            "divergent fido2 must keep items split"
        );
        assert_eq!(stats.living, 2);
    }

    #[test]
    fn epw_dns_vs_opaque_uri_stay_split() {
        let mut items = vec![
            epw_login("X", "", Some("https://example.com/")),
            epw_login("X", "", Some("example.com")),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(stats.empty_password_groups, 0);
        assert_eq!(stats.living, 2);
    }

    #[test]
    fn epw_port_bearing_separation() {
        let mut items = vec![
            epw_login("Internal", "", Some("https://internal.example.com:8443/")),
            epw_login("Internal", "", Some("https://internal.example.com:9090/")),
            epw_login("Internal", "", Some("https://internal.example.com/")),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(
            stats.empty_password_groups, 0,
            "items differing only in port must stay split"
        );
        assert_eq!(stats.living, 3);
    }

    #[test]
    fn epw_custom_scheme_byte_exact() {
        let mut items = vec![
            epw_login("MyApp", "u", Some("myapp://Login?token=abc")),
            epw_login("MyApp", "u", Some("myapp://login?token=def")),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(stats.empty_password_groups, 0);
        assert_eq!(stats.living, 2);
    }

    #[test]
    fn epw_does_not_cross_merge_with_strict_pass() {
        let mut items = vec![
            json!({
                "id": "non-empty",
                "type": 1, "name": "Acme",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "actual-pw",
                    "uris": [{"uri": "https://acme.com/"}]}
            }),
            epw_login("Acme", "u", Some("https://acme.com/")),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(stats.strict_login_groups, 0);
        assert_eq!(stats.empty_password_groups, 0);
        assert_eq!(stats.living, 2);
    }

    #[test]
    fn epw_combined_with_split_divergent_totps() {
        let mut items = vec![
            json!({
                "id": "with-old", "type": 1, "name": "Acme",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u", "password": "",
                    "uris": [{"uri": "https://acme.com/"}],
                    "totp": "otpauth://totp/A?secret=OLD"}
            }),
            json!({
                "id": "with-new", "type": 1, "name": "Acme",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "",
                    "uris": [{"uri": "https://acme.com/"}],
                    "totp": "otpauth://totp/A?secret=NEW"}
            }),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                split_divergent_totps: true,
            },
        );
        assert_eq!(stats.empty_password_groups, 0);
        assert_eq!(stats.living, 2);
    }

    #[test]
    fn epw_pre_existing_trashed_passes_through() {
        let mut items = vec![
            json!({
                "id": "already-trash", "type": 1, "name": "Old",
                "deletedDate": "2025-01-01T00:00:00Z",
                "revisionDate": "2024-12-01T00:00:00Z",
                "login": {"username": "u", "password": "",
                    "uris": [{"uri": "https://example.com/"}]}
            }),
            epw_login("Old", "u", Some("https://example.com/")),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(
            stats.empty_password_groups, 0,
            "the already-trashed item must not group with the living one"
        );
        let trashed = items
            .iter()
            .find(|i| i["id"].as_str() == Some("already-trash"))
            .unwrap();
        assert_eq!(
            trashed["deletedDate"].as_str(),
            Some("2025-01-01T00:00:00Z"),
            "pre-existing deletedDate must not be overwritten"
        );
    }

    #[test]
    fn epw_groups_sum_equals_total_groups() {
        let mut items = vec![
            json!({
                "id": "s1", "type": 1, "name": "A",
                "revisionDate": "2026-01-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
            json!({
                "id": "s2", "type": 1, "name": "A",
                "revisionDate": "2026-01-02T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
            epw_login("B", "v", Some("https://b.com/")),
            epw_login("B", "v", Some("https://b.com/")),
        ];
        let stats = dedup_items_with_config(
            &mut items,
            &DedupConfig {
                collapse_empty_passwords: true,
                ..Default::default()
            },
        );
        assert_eq!(stats.strict_login_groups, 1);
        assert_eq!(stats.empty_password_groups, 1);
        assert_eq!(stats.secure_note_groups, 0);
        assert_eq!(stats.ssh_key_groups, 0);
        assert_eq!(
            stats.groups,
            stats.strict_login_groups
                + stats.empty_password_groups
                + stats.secure_note_groups
                + stats.ssh_key_groups
        );
    }

    // ---------- card / identity dedup passes ----------

    #[test]
    fn cards_with_identical_block_collapse() {
        let mut items = vec![
            json!({
                "id": "c1", "type": 3, "name": "Visa Personal",
                "revisionDate": "2026-01-01T00:00:00Z",
                "card": {
                    "cardholderName": "Alex Orlov", "brand": "Visa",
                    "number": "4111111111111111", "expMonth": "12",
                    "expYear": "2030", "code": "123"
                }
            }),
            json!({
                "id": "c2", "type": 3, "name": "Visa Personal",
                "revisionDate": "2026-01-02T00:00:00Z",
                "card": {
                    "cardholderName": "Alex Orlov", "brand": "Visa",
                    "number": "4111111111111111", "expMonth": "12",
                    "expYear": "2030", "code": "123"
                }
            }),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.card_groups, 1);
        assert_eq!(stats.trashed, 1);
        assert_eq!(stats.living, 1);
        // Newer revisionDate wins as survivor.
        let living_id = items
            .iter()
            .find(|i| i["deletedDate"].is_null())
            .unwrap()["id"]
            .as_str()
            .unwrap();
        assert_eq!(living_id, "c2");
    }

    #[test]
    fn cards_with_different_cvv_stay_split() {
        let mut items = vec![
            json!({
                "id": "c1", "type": 3, "name": "Visa",
                "revisionDate": "2026-01-01T00:00:00Z",
                "card": {"cardholderName": "A", "brand": "Visa",
                    "number": "4111111111111111", "expMonth": "12",
                    "expYear": "2030", "code": "123"}
            }),
            json!({
                "id": "c2", "type": 3, "name": "Visa",
                "revisionDate": "2026-01-02T00:00:00Z",
                "card": {"cardholderName": "A", "brand": "Visa",
                    "number": "4111111111111111", "expMonth": "12",
                    "expYear": "2030", "code": "999"}
            }),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.card_groups, 0, "different CVV must keep cards split");
        assert_eq!(stats.living, 2);
    }

    #[test]
    fn identities_with_identical_block_collapse() {
        let mut items = vec![
            json!({
                "id": "i1", "type": 4, "name": "my",
                "revisionDate": "2026-01-01T00:00:00Z",
                "identity": {
                    "firstName": "Alex", "lastName": "Orlov",
                    "email": "alex@example.test", "city": "Zurich"
                }
            }),
            json!({
                "id": "i2", "type": 4, "name": "my",
                "revisionDate": "2026-01-02T00:00:00Z",
                "identity": {
                    "firstName": "Alex", "lastName": "Orlov",
                    "email": "alex@example.test", "city": "Zurich"
                }
            }),
            json!({
                "id": "i3", "type": 4, "name": "my",
                "revisionDate": "2026-01-03T00:00:00Z",
                "identity": {
                    "firstName": "Alex", "lastName": "Orlov",
                    "email": "alex@example.test", "city": "Zurich"
                }
            }),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.identity_groups, 1);
        assert_eq!(stats.trashed, 2);
        assert_eq!(stats.living, 1);
    }

    #[test]
    fn identities_with_different_address_stay_split() {
        let mut items = vec![
            json!({
                "id": "i1", "type": 4, "name": "home",
                "revisionDate": "2026-01-01T00:00:00Z",
                "identity": {"firstName": "Alex", "address1": "1 Example St"}
            }),
            json!({
                "id": "i2", "type": 4, "name": "home",
                "revisionDate": "2026-01-02T00:00:00Z",
                "identity": {"firstName": "Alex", "address1": "2 Other St"}
            }),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.identity_groups, 0);
        assert_eq!(stats.living, 2);
    }

    #[test]
    fn cards_and_identities_audit_entries_carry_correct_item_kind() {
        let mut items = vec![
            // Two identical cards
            json!({
                "id": "c1", "type": 3, "name": "Visa",
                "revisionDate": "2026-01-01T00:00:00Z",
                "card": {"number": "4111", "expMonth": "12", "expYear": "2030"}
            }),
            json!({
                "id": "c2", "type": 3, "name": "Visa",
                "revisionDate": "2026-01-02T00:00:00Z",
                "card": {"number": "4111", "expMonth": "12", "expYear": "2030"}
            }),
            // Two identical identities
            json!({
                "id": "i1", "type": 4, "name": "my",
                "revisionDate": "2026-01-01T00:00:00Z",
                "identity": {"firstName": "Alex"}
            }),
            json!({
                "id": "i2", "type": 4, "name": "my",
                "revisionDate": "2026-01-02T00:00:00Z",
                "identity": {"firstName": "Alex"}
            }),
        ];
        let stats = dedup_items(&mut items);
        assert_eq!(stats.card_groups, 1);
        assert_eq!(stats.identity_groups, 1);
        assert_eq!(stats.audit_entries.len(), 2);

        let card_entry = stats
            .audit_entries
            .iter()
            .find(|e| e["item_kind"] == "card")
            .expect("a card audit entry must exist");
        assert_eq!(card_entry["removed_id"], "c1");
        assert_eq!(card_entry["kept_id"], "c2");

        let identity_entry = stats
            .audit_entries
            .iter()
            .find(|e| e["item_kind"] == "identity")
            .expect("an identity audit entry must exist");
        assert_eq!(identity_entry["removed_id"], "i1");
        assert_eq!(identity_entry["kept_id"], "i2");
    }

    #[test]
    fn cards_preserve_card_block_byte_identical_on_survivor() {
        // Sanity: the survivor's `card` block is exactly what it was —
        // strict equality means every drop's block matched the keeper's
        // by construction, so we do NOT touch it.
        let mut items = vec![
            json!({
                "id": "c1", "type": 3, "name": "Visa",
                "revisionDate": "2026-01-01T00:00:00Z",
                "card": {"number": "4111", "expMonth": "12", "expYear": "2030", "code": "123"}
            }),
            json!({
                "id": "c2", "type": 3, "name": "Visa",
                "revisionDate": "2026-01-02T00:00:00Z",
                "card": {"number": "4111", "expMonth": "12", "expYear": "2030", "code": "123"}
            }),
        ];
        dedup_items(&mut items);
        let survivor = items
            .iter()
            .find(|i| i["deletedDate"].is_null())
            .unwrap();
        assert_eq!(survivor["card"]["number"], "4111");
        assert_eq!(survivor["card"]["expMonth"], "12");
        assert_eq!(survivor["card"]["code"], "123");
    }

    #[test]
    fn already_trashed_items_pass_through_untouched() {
        // Items that arrive with `deletedDate` set must be preserved
        // as-is — they are the user's existing Trash.
        let mut items = vec![
            json!({
                "id": "already-trash", "type": 1, "name": "Old",
                "deletedDate": "2025-01-01T00:00:00Z",
                "revisionDate": "2024-12-01T00:00:00Z",
                "login": {"username": "u", "password": "p"}
            }),
            json!({
                "id": "live", "type": 1, "name": "Live",
                "revisionDate": "2026-02-01T00:00:00Z",
                "login": {"username": "u2", "password": "p2"}
            }),
        ];
        dedup_items(&mut items);
        assert_eq!(items.len(), 2);
        let trashed = items
            .iter()
            .find(|i| i["id"].as_str() == Some("already-trash"))
            .unwrap();
        assert_eq!(
            trashed["deletedDate"].as_str(),
            Some("2025-01-01T00:00:00Z"),
            "pre-existing deletedDate must not be overwritten"
        );
    }
}
