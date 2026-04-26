// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! **"Is this a duplicate?"** — duplicate-identity rules.
//!
//! This module is the single source of truth for the dedup equality decision.
//! Every field that Bitwarden stores in a single-valued slot appears in the
//! key; items that disagree on any of them end up in different groups and
//! cannot be merged. Multi-valued or concatenable fields (notes, URIs,
//! passwordHistory, collectionIds, …) live in [`crate::merge`] instead.
//!
//! Key members:
//!
//! - name           (case-insensitive; trailing `(email@domain)` suffix is
//!                   stripped, because some Bitwarden clients append it to
//!                   disambiguate UI-level collisions)
//! - username       (trim-only — case is preserved)
//! - password       (exact)
//! - FIDO2 creds    (canonical serialized full objects, not just credentialIds —
//!                   different passkeys keep items distinct so no passkey is
//!                   ever overwritten)
//! - organizationId (personal vs org; never cross-dedup)
//!
//! **TOTP is deliberately not in the key.** A Bitwarden item has a single
//! `login.totp` slot, so two items sharing every credential field but
//! differing only in TOTP represent the same account with a rotated secret.
//! [`crate::merge`] picks the newest TOTP across the group; older rotations
//! are dropped (they no longer authenticate against the backend anyway).
//! This is the only field where dedup can displace user-entered data —
//! everything else is either in the key (distinct-preserving) or union-merged.

use std::collections::HashSet;

use serde_json::Value;

use crate::json_util::get_str;

/// Schemes whose host component we trust as a real DNS or IP authority.
/// All other schemes (custom schemes, mailto:, opaque identifiers) fall
/// through to [`HostKind::Opaque`] in [`host_of`] so we never case-fold
/// what may be a case-sensitive identifier (`myapp://Login` and
/// `myapp://login` stay distinct).
const DNS_ALLOWLIST_SCHEMES: &[&str] = &["http", "https", "ws", "wss"];

/// Classification of how a hostname-set entry was derived. Drives both
/// the per-key-token prefix in [`empty_password_dedup_key`] and the
/// audit `signal_kind` field on dedup losers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostKind {
    /// Confirmed DNS host parsed from an allowlisted authority-style
    /// URL. Lowercased — DNS is case-insensitive per RFC 1035 §2.3.3.
    Dns,
    /// IPv4 / IPv6 host literal from an allowlisted authority-style
    /// URL. Preserved exactly as parsed (`url::Url` already
    /// canonicalizes IPv6).
    Ip,
    /// `androidapp://com.example.app` — package name. **Case is
    /// preserved verbatim** per Android spec; same rule as
    /// [`crate::uris`].
    AndroidApp,
    /// Any other identifier we did not parse as a confirmed
    /// authority-style URL: bare reverse-DNS App IDs
    /// (`com.example.iosapp`), custom-scheme URIs (`myapp://login`),
    /// opaque strings. **Case is preserved verbatim** — these may be
    /// used by case-sensitive matchers downstream and we refuse to
    /// fold them.
    Opaque,
}

/// Duplicate-equality key for a Bitwarden login item.
///
/// **Invariants**:
///
/// - Distinct `(username, password)` pairs are never collapsed.
/// - Distinct FIDO2 credential sets are never collapsed — passkeys are
///   never overwritten.
/// - Personal items never merge with org-owned items.
///
/// TOTP is **not** in the key; items that differ only in TOTP represent
/// the same account with a rotated secret, and [`crate::merge`] keeps the
/// newest TOTP on the survivor.
pub fn dedup_key(item: &Value) -> String {
    let name = normalize_name(get_str(item, "name"));
    let login = item.get("login");
    let user = norm_user(
        login
            .and_then(|l| l.get("username"))
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    let pw = login
        .and_then(|l| l.get("password"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let fido2 = fido2_signature(item);
    let org_id = item
        .get("organizationId")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("{name}\0{user}\0{pw}\0{fido2}\0{org_id}")
}

/// Strip a trailing ` (something@else)` disambiguation suffix from a name and
/// lowercase the result.
///
/// Some Bitwarden clients append `(username)` to the name when two items share
/// the base name — e.g. `fastly-eng.okta.com` and
/// `fastly-eng.okta.com (aorlov@fastly.com)` are the same login with the
/// second entry carrying a cosmetic suffix. Without this normalization the two
/// entries would never group as duplicates.
///
/// Only suffixes whose parenthesized body contains `@` are stripped — plain
/// suffixes like `(prod)` or `(staging)` are kept because they convey a real
/// distinction.
pub fn normalize_name(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.ends_with(')') {
        if let Some(open) = trimmed.rfind('(') {
            let inner = &trimmed[open + 1..trimmed.len() - 1];
            if inner.contains('@') {
                return trimmed[..open].trim_end().to_lowercase();
            }
        }
    }
    trimmed.to_lowercase()
}

/// Return `true` when an empty-password login item carries at least
/// one identifying signal beyond its name (non-empty username,
/// non-empty URI host set, or a fido2 credential set). Items that
/// fail this check have nothing stable to group on and are left as
/// distinct living entries.
fn empty_password_signal_ok(item: &Value) -> bool {
    let login = item.get("login");
    let user_ok = login
        .and_then(|l| l.get("username"))
        .and_then(Value::as_str)
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let uri_ok = !uri_host_set(item).is_empty();
    let fido_ok = login
        .and_then(|l| l.get("fido2Credentials"))
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    user_ok || uri_ok || fido_ok
}

/// Return `true` for login (`type: 1`) items that the empty-password
/// dedup pass should consider for grouping.
///
/// The decision: collapse all three signal kinds (username, host,
/// fido2) when otherwise identical. The validation file (8519-item
/// vault) showed zero false-positive groups under this rule — every
/// observed cluster (the `oura` username-only group, the `heatledger`
/// host-only group, etc.) is genuinely the same account. Losers are
/// preserved in the trash sidecar so any future false positive on a
/// different vault is recoverable. Audit entries carry a
/// `signal_kind` field so reviewers can grep the riskier
/// (`username_only`) class.
///
/// Identical filters to [`skip_from_dedup`] EXCEPT the empty-password
/// rule is inverted (empty is required, not rejected), and the item
/// must carry at least one identifying signal beyond its name (see
/// [`empty_password_signal_ok`]).
pub fn is_dedupable_empty_password_login(item: &Value) -> bool {
    if item.get("type").and_then(Value::as_u64) != Some(1) {
        return false;
    }
    if item.get("deletedDate").is_some_and(|v| !v.is_null()) {
        return false;
    }
    if item.get("reprompt").and_then(Value::as_u64) == Some(1) {
        return false;
    }
    if get_str(item, "name").contains("[duplicate]") {
        return false;
    }
    let pw = item
        .get("login")
        .and_then(|l| l.get("password"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !pw.trim().is_empty() {
        return false; // strict pass already handled this
    }
    empty_password_signal_ok(item)
}

/// Dedup key for the empty-password pass.
///
/// Differs from [`dedup_key`] in two ways:
/// 1. Replaces the `password` slot with a constant `empty-pw` literal
///    so empty-password items never collide with non-empty-password
///    items even if the upstream caller forgets to filter.
/// 2. Adds a sorted hostname set extracted from `login.uris`. Each
///    entry is tagged with its [`HostKind`] in the key token so a DNS
///    `example.com` and an opaque `example.com` (e.g. as a bare App ID
///    string) never collide. URI host is part of the *grouping key*
///    but the full URI list is still union-merged onto the survivor.
pub fn empty_password_dedup_key(item: &Value) -> String {
    let name = normalize_name(get_str(item, "name"));
    let login = item.get("login");
    let user = norm_user(
        login
            .and_then(|l| l.get("username"))
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    let mut hosts: Vec<(HostKind, String)> = uri_host_set(item).into_iter().collect();
    hosts.sort();
    // Length-prefixed pair encoding: `<kind>:<len>:<host_token>` per
    // pair, separated by `\x1f` (ASCII unit-separator). Opaque host
    // tokens are arbitrary user strings, so a naive `join(",")` over
    // `<kind>:<host_token>` is delimiter-ambiguous — an opaque host
    // whose text happens to contain `,Opaque:` or `,Dns:` collides
    // with a two-host set under that scheme. The fix that matters
    // for safety is the length prefix on the host token: it lets
    // any reader (or any equality comparison against a different
    // input) consume exactly `<len>` bytes of host text regardless
    // of what those bytes contain, so two different `(HostKind,
    // host_token)` sets cannot serialize to the same string. The
    // `\x1f` separator is defensive: it lowers the chance of an
    // opaque token ever containing the pair delimiter, but the
    // encoding is unambiguous even without it because the length
    // prefix is the load-bearing safety mechanism.
    let host_blob = hosts
        .iter()
        .map(|(k, h)| format!("{k:?}:{}:{h}", h.len()))
        .collect::<Vec<_>>()
        .join("\x1f");
    let fido2 = fido2_signature(item);
    let org_id = item
        .get("organizationId")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("type=1\0empty-pw\0{name}\0{user}\0hosts={host_blob}\0{fido2}\0{org_id}")
}

/// Collect the set of `(HostKind, host_token)` pairs from an item's
/// `login.uris`. Used both by [`empty_password_dedup_key`] (in the
/// grouping key) and [`empty_password_signal_ok`] (to decide whether
/// the item has any URI-based identity).
pub(crate) fn uri_host_set(item: &Value) -> HashSet<(HostKind, String)> {
    let mut out = HashSet::new();
    let Some(arr) = item
        .get("login")
        .and_then(|l| l.get("uris"))
        .and_then(Value::as_array)
    else {
        return out;
    };
    for u in arr {
        let Some(uri) = u.get("uri").and_then(Value::as_str) else {
            continue;
        };
        if let Some(pair) = host_of(uri) {
            out.insert(pair);
        }
    }
    out
}

/// Classify and extract the host portion of a URI.
///
/// Returns `None` for empty / whitespace-only input. Otherwise returns
/// `(kind, host_token)` where `host_token` already includes any
/// explicit non-default port (e.g. `example.com:8443`) so a reviewer
/// scanning the dedup key can read it back as a single string.
///
/// - [`HostKind::AndroidApp`] for `androidapp://…` — package name
///   preserved verbatim (case-sensitive). Path / query / fragment
///   suffixes are stripped: `androidapp://com.example.app/login?x=1#y`
///   → `com.example.app`.
/// - [`HostKind::Dns`] for an allowlisted-scheme URL (`http(s)`,
///   `ws(s)`) whose host is a domain — host lowercased (DNS is
///   case-insensitive), non-default port preserved.
/// - [`HostKind::Ip`] for an allowlisted-scheme URL whose host is an
///   IPv4 or IPv6 literal — used as-is (`url::Url` canonicalizes
///   IPv6), non-default port preserved.
/// - [`HostKind::Opaque`] for everything else: schemes outside the
///   allowlist (`myapp://`, `mailto:`, custom URIs), bare reverse-DNS
///   App IDs, or unparseable strings. **Case preserved verbatim**.
///   Mirrors the [`crate::uris`] rule: do not case-fold identifiers we
///   do not recognize as DNS hosts.
pub fn host_of(uri: &str) -> Option<(HostKind, String)> {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("androidapp://") {
        let pkg_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let pkg = &rest[..pkg_end];
        if pkg.is_empty() {
            return None;
        }
        return Some((HostKind::AndroidApp, pkg.to_string()));
    }
    if let Ok(parsed) = url::Url::parse(trimmed) {
        let scheme = parsed.scheme();
        if DNS_ALLOWLIST_SCHEMES.contains(&scheme) {
            match parsed.host() {
                Some(url::Host::Domain(d)) if !d.is_empty() => {
                    return Some((HostKind::Dns, with_port(d.to_lowercase(), &parsed)));
                }
                Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)) => {
                    if let Some(h) = parsed.host_str() {
                        return Some((HostKind::Ip, with_port(h.to_string(), &parsed)));
                    }
                }
                _ => { /* fall through to Opaque */ }
            }
        }
        // Schemes outside the allowlist — even when url::Url extracted
        // a plausible-looking host, the identifier semantics are
        // unknown and may be case-sensitive. Treat as opaque.
    }
    Some((HostKind::Opaque, trimmed.to_string()))
}

/// Append the URL's explicit non-default port to `host` when present.
/// `url::Url::port()` returns `None` for the scheme's default port
/// (e.g. 443 for https), so this is a no-op for default-port URLs and
/// a `host:port` join for non-default ones. Non-default ports are
/// part of identity: `internal-svc:8080` and `internal-svc:9090` are
/// different services.
fn with_port(host: String, url: &url::Url) -> String {
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    }
}

/// Return `true` for login (`type: 1`) items that must never be grouped
/// for deduplication.
///
/// This is the safety floor for the login-dedup pass: non-login types
/// skip this path (they have their own grouping rules — see
/// [`is_dedupable_secure_note`]), master-password-gated items are left
/// alone, empty-password items would spuriously group on `""`, and
/// anything already tagged `[duplicate]` or sitting in the trash is
/// skipped.
pub fn skip_from_dedup(item: &Value) -> bool {
    if item.get("type").and_then(Value::as_u64) != Some(1) {
        return true;
    }
    if item.get("deletedDate").is_some_and(|v| !v.is_null()) {
        return true;
    }
    if item.get("reprompt").and_then(Value::as_u64) == Some(1) {
        return true;
    }
    if get_str(item, "name").contains("[duplicate]") {
        return true;
    }
    let pw = item
        .get("login")
        .and_then(|l| l.get("password"))
        .and_then(Value::as_str)
        .unwrap_or("");
    pw.trim().is_empty()
}

/// Return `true` when the item is a secure note (`type: 2`) that the
/// dedup pipeline should consider for grouping.
///
/// Secure notes dedup by [`secure_note_key`] — currently
/// `type=2 \0 normalize_name(name)`. Notes without a name cannot group
/// (we have nothing stable to hash on). Master-password-gated
/// (`reprompt == 1`) and already-trashed notes pass through untouched
/// for the same safety reasons as logins.
pub fn is_dedupable_secure_note(item: &Value) -> bool {
    if item.get("type").and_then(Value::as_u64) != Some(2) {
        return false;
    }
    if item.get("deletedDate").is_some_and(|v| !v.is_null()) {
        return false;
    }
    if item.get("reprompt").and_then(Value::as_u64) == Some(1) {
        return false;
    }
    if get_str(item, "name").contains("[duplicate]") {
        return false;
    }
    !get_str(item, "name").trim().is_empty()
}

/// Grouping key for secure notes.
///
/// **Strict-by-default**: two secure notes only collapse when they agree
/// on **note-name (normalized)**, **organizationId**, AND **canonicalized
/// notes body**. That narrows the dedup to literal duplicates — two
/// copies of the same note — and never merges semantically distinct
/// items that just happen to share a generic name like `Recovery`,
/// `Wallet`, or `credentials.txt`.
///
/// Fields and rationale:
///
/// - `type=2` prefix — secure notes never collide with login keys.
/// - [`normalize_note_name`] — case-fold + outer-trim, plus stripping
///   of zero-width / invisible format characters. Critically, **the
///   login-style `(email@…)` suffix stripping is NOT applied** here:
///   a title like `credentials (alice@example.com)` can be meaningful
///   content for a note, not cosmetic UI disambiguation.
/// - `organizationId` — personal (`""`/`null`) and org-owned notes
///   with the same name stay separate; different vaults, different
///   access control.
/// - [`canonicalize_note_body`] — outer-trim + zero-width strip on
///   the body. Different bodies mean different notes; visually
///   identical bodies that only differ in invisible Unicode noise
///   still collapse.
pub fn secure_note_key(item: &Value) -> String {
    let name = normalize_note_name(get_str(item, "name"));
    let org = item
        .get("organizationId")
        .and_then(Value::as_str)
        .unwrap_or("");
    let body = canonicalize_note_body(get_str(item, "notes"));
    format!("type=2\0name={name}\0org={org}\0body={body}")
}

/// Normalize a Secure Note title for the dedup key.
///
/// - Case-fold (ASCII-lowercase — conservative; full-Unicode casefold
///   would be semantically the same here for the scripts we care
///   about but brings a bigger dep surface).
/// - Trim Unicode whitespace (not just ASCII).
/// - Strip zero-width and default-ignorable characters (ZWSP, ZWNJ,
///   ZWJ, BOM, WJ, SHY, LRM, RLM, LRE, RLE, PDF). These are invisible
///   but byte-different — they cause "obvious duplicates" to survive
///   under pure `trim()` based keys.
///
/// Deliberately **does not** strip `(email@…)` suffixes — that rule
/// is login-specific and unsafe for secure-note titles where the
/// suffix may be meaningful content.
pub fn normalize_note_name(s: &str) -> String {
    scrub_invisible(s).trim().to_lowercase()
}

/// Canonicalize a Secure Note body for the dedup key.
///
/// Same invisible-character scrubbing as [`normalize_note_name`], plus
/// Unicode-aware outer-trim. Byte-identical stored body is preserved
/// elsewhere; this canonical form is used **only** for the key so
/// visually identical bodies that differ only in zero-width or NBSP
/// noise dedup cleanly.
pub fn canonicalize_note_body(s: &str) -> String {
    scrub_invisible(s).trim().to_string()
}

/// Return `true` when the item is an SSH key (`type: 5`) that the
/// dedup pipeline should consider for grouping.
///
/// SSH keys dedup by [`ssh_key_key`] — a canonicalized snapshot of the
/// `sshKey` object (public key + private key + fingerprint) plus the
/// organization id. Two items with the same SSH material collapse; any
/// byte-level difference in the key material keeps them separate. That
/// conservative bias is deliberate: private-key material is the most
/// sensitive field we touch, and "one of these two keys is subtly
/// different" is never a merge we want to guess at.
pub fn is_dedupable_ssh_key(item: &Value) -> bool {
    if item.get("type").and_then(Value::as_u64) != Some(5) {
        return false;
    }
    if item.get("deletedDate").is_some_and(|v| !v.is_null()) {
        return false;
    }
    if item.get("reprompt").and_then(Value::as_u64) == Some(1) {
        return false;
    }
    if get_str(item, "name").contains("[duplicate]") {
        return false;
    }
    // Refuse to group an SSH key without an sshKey block — the key
    // material is the only identity we trust here.
    let Some(ssh) = item.get("sshKey") else {
        return false;
    };
    let pub_key = ssh
        .get("publicKey")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    !pub_key.is_empty()
}

/// Grouping key for SSH keys.
///
/// Combines:
/// - `type=5` prefix — never collides with login / secure-note keys.
/// - Canonicalized `sshKey` object — the full object (public key,
///   private key, fingerprint) serialized in alphabetical-key order,
///   so any byte-level mismatch in the key material keeps items
///   distinct. Private keys are part of the identity on purpose:
///   a public-key collision with different private halves would
///   almost certainly be vault corruption, and we refuse to guess.
/// - `organizationId` — personal and org-owned SSH keys stay separate.
pub fn ssh_key_key(item: &Value) -> String {
    let ssh_sig = ssh_canonical_signature(item);
    let org = item
        .get("organizationId")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("type=5\0ssh={ssh_sig}\0org={org}")
}

/// Return `true` when the item is a card (`type: 3`) that the dedup
/// pipeline should consider for grouping.
///
/// Cards dedup by [`card_key`] — every field of the `card` object
/// (`cardholderName`, `brand`, `number`, `expMonth`, `expYear`,
/// `code`) plus the organization id participates in the key. Two
/// cards collapse only when **all** of those bytes are identical. A
/// stored card with a different CVV, a different expiry, or even a
/// trailing whitespace difference in the cardholder name keeps items
/// distinct.
///
/// The same safety floor applies as for logins: trashed, reprompt-
/// gated, and `[duplicate]`-tagged items pass through untouched.
/// Items whose `card` field is missing, `null`, or any non-object
/// JSON value are refused — there is nothing stable to group on, and
/// canonicalizing `null` would let every malformed `{"type":3,
/// "card":null}` item with the same name collapse onto a single
/// survivor (the REST decoder in `live_vault/cipher_codec.rs` can
/// emit that shape on incomplete cipher payloads).
pub fn is_dedupable_card(item: &Value) -> bool {
    if item.get("type").and_then(Value::as_u64) != Some(3) {
        return false;
    }
    if item.get("deletedDate").is_some_and(|v| !v.is_null()) {
        return false;
    }
    if item.get("reprompt").and_then(Value::as_u64) == Some(1) {
        return false;
    }
    if get_str(item, "name").contains("[duplicate]") {
        return false;
    }
    item.get("card").is_some_and(Value::is_object)
}

/// Grouping key for cards (`type: 3`).
///
/// Combines:
/// - `type=3` prefix — never collides with login / secure-note / SSH keys.
/// - Normalized name (case-fold, email-suffix strip — same rule
///   logins use, since cards saved via browser auto-fill often pick
///   up the `(email@…)` suffix).
/// - `organizationId` — personal and org-owned cards stay separate.
/// - Canonicalized full `card` object (alphabetical-key
///   serialization). Any byte-level mismatch in any populated field
///   keeps items distinct — same conservative bias as
///   [`ssh_key_key`]: when in doubt, never merge.
///
/// **Cross-source caveat**: the canonical signature distinguishes
/// `""`, `null`, and absent fields byte-exactly. The REST decoder
/// (`live_vault/cipher_codec.rs`) emits every card subfield as
/// either a string or `null`; `bw export --format json` may use a
/// different representation for unset fields. If you mix items from
/// the two paths in the same vault, otherwise-identical cards may
/// fail to collapse. The bias is over-splitting (safe) rather than
/// over-merging — run all items through one source path before
/// dedup if you want maximum collapse.
pub fn card_key(item: &Value) -> String {
    let name = normalize_name(get_str(item, "name"));
    let org = item
        .get("organizationId")
        .and_then(Value::as_str)
        .unwrap_or("");
    let card_sig = canonical_object_signature(item.get("card"));
    format!("type=3\0name={name}\0org={org}\0card={card_sig}")
}

/// Return `true` when the item is an identity (`type: 4`) that the
/// dedup pipeline should consider for grouping.
///
/// Identities dedup by [`identity_key`] — every field of the
/// `identity` object plus the organization id participates in the
/// key. Two identities collapse only when **all** of those bytes are
/// identical (same name, address, email, phone, government IDs,
/// etc.). Any mismatch in any field keeps items distinct.
///
/// Same safety floor as cards: trashed, reprompt-gated, and
/// `[duplicate]`-tagged items pass through; items whose `identity`
/// field is missing, `null`, or any non-object JSON value are
/// refused (canonicalizing `null` would let malformed records
/// collapse on name+org alone).
pub fn is_dedupable_identity(item: &Value) -> bool {
    if item.get("type").and_then(Value::as_u64) != Some(4) {
        return false;
    }
    if item.get("deletedDate").is_some_and(|v| !v.is_null()) {
        return false;
    }
    if item.get("reprompt").and_then(Value::as_u64) == Some(1) {
        return false;
    }
    if get_str(item, "name").contains("[duplicate]") {
        return false;
    }
    item.get("identity").is_some_and(Value::is_object)
}

/// Grouping key for identities (`type: 4`).
///
/// Combines:
/// - `type=4` prefix — never collides with other types.
/// - Normalized name (same rule as logins / cards).
/// - `organizationId` — personal vs org never cross-dedup.
/// - Canonicalized full `identity` object. Every populated field
///   (firstName/lastName/address/email/phone/ssn/passportNumber/
///   licenseNumber/etc.) participates; any byte-level mismatch
///   keeps items distinct.
///
/// Cross-source caveat: same as [`card_key`] — the canonical
/// signature distinguishes `""`, `null`, and absent fields, so
/// items from `bw export` and the REST API path may not collapse
/// against each other if the two emit different representations
/// for unset subfields. Bias is over-splitting (safe).
pub fn identity_key(item: &Value) -> String {
    let name = normalize_name(get_str(item, "name"));
    let org = item
        .get("organizationId")
        .and_then(Value::as_str)
        .unwrap_or("");
    let identity_sig = canonical_object_signature(item.get("identity"));
    format!("type=4\0name={name}\0org={org}\0identity={identity_sig}")
}

/// Canonical signature of an arbitrary JSON object — alphabetical
/// key order via `serde_json::Value`'s BTreeMap-backed Map. Used by
/// the strict-equality dedup keys for cards and identities. Returns
/// the empty string when the object is missing.
fn canonical_object_signature(obj: Option<&Value>) -> String {
    match obj {
        Some(v) => serde_json::to_string(v).unwrap_or_default(),
        None => String::new(),
    }
}

fn ssh_canonical_signature(item: &Value) -> String {
    let Some(ssh) = item.get("sshKey") else {
        return String::new();
    };
    // BTreeMap-backed Value serialization gives alphabetical keys,
    // which is the canonical form we need — matches the approach used
    // for `fido2_signature` above.
    serde_json::to_string(ssh).unwrap_or_default()
}

/// Strip invisible/default-ignorable characters that can make
/// byte-different strings render identically. Also folds non-ASCII
/// whitespace (NBSP, figure space, zero-width NBSP) to a regular
/// space so `trim()` handles edges correctly.
fn scrub_invisible(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            // Zero-width / default-ignorable code points.
            '\u{200B}' // ZERO WIDTH SPACE
            | '\u{200C}' // ZWNJ
            | '\u{200D}' // ZWJ
            | '\u{2060}' // WORD JOINER
            | '\u{FEFF}' // ZERO WIDTH NO-BREAK SPACE / BOM
            | '\u{00AD}' // SOFT HYPHEN
            | '\u{200E}' // LRM
            | '\u{200F}' // RLM
            | '\u{202A}' // LRE
            | '\u{202B}' // RLE
            | '\u{202C}' // PDF
            | '\u{202D}' // LRO
            | '\u{202E}' // RLO
            => { /* drop */ }
            // NBSP-like whitespace → fold to ASCII space so `trim`
            // handles the edges uniformly.
            '\u{00A0}' // NBSP
            | '\u{2007}' // FIGURE SPACE
            | '\u{202F}' // NARROW NBSP
            | '\u{205F}' // MEDIUM MATHEMATICAL SPACE
            | '\u{3000}' // IDEOGRAPHIC SPACE
            => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// Trim-only normalization for usernames. Case is preserved so
/// `Alice` and `alice` — which some backends treat as distinct
/// login identities — never collapse into the same dedup group.
fn norm_user(s: &str) -> String {
    s.trim().to_string()
}

/// Canonical signature of an item's FIDO2 / passkey credentials.
///
/// Includes the **entire** credential object (not just `credentialId`) so that
/// two items carrying the same `credentialId` but divergent metadata
/// (`counter`, `userHandle`, `keyType`, etc.) end up in different groups.
/// That keeps their metadata from being silently overwritten by the survivor.
///
/// Objects are sorted by `credentialId` first, then serialized. Any
/// non-deterministic key ordering inside a credential object yields a
/// different signature — that is deliberately conservative: when in doubt,
/// don't merge.
fn fido2_signature(item: &Value) -> String {
    let mut creds: Vec<Value> = item
        .get("login")
        .and_then(|l| l.get("fido2Credentials"))
        .and_then(Value::as_array)
        .map(|arr| arr.to_vec())
        .unwrap_or_default();
    creds.sort_by(|a, b| {
        let a_id = a.get("credentialId").and_then(Value::as_str).unwrap_or("");
        let b_id = b.get("credentialId").and_then(Value::as_str).unwrap_or("");
        a_id.cmp(b_id)
    });
    serde_json::to_string(&Value::Array(creds)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn login(name: &str, user: &str, pw: &str) -> Value {
        json!({
            "type": 1,
            "name": name,
            "login": { "username": user, "password": pw },
        })
    }

    #[test]
    fn norm_user_trims_but_preserves_case() {
        assert_eq!(norm_user("  Alice "), "Alice");
        assert_eq!(norm_user("alice"), "alice");
        assert_ne!(norm_user("Alice"), norm_user("alice"));
        assert_eq!(norm_user(""), "");
    }

    #[test]
    fn normalize_name_strips_email_suffix() {
        assert_eq!(
            normalize_name("fastly-eng.okta.com (aorlov@fastly.com)"),
            "fastly-eng.okta.com"
        );
        assert_eq!(normalize_name("Site (user@example.com)"), "site");
    }

    #[test]
    fn normalize_name_keeps_non_email_suffix() {
        assert_eq!(normalize_name("Acme (prod)"), "acme (prod)");
        assert_eq!(normalize_name("Service (staging)"), "service (staging)");
    }

    #[test]
    fn normalize_name_plain_name_unchanged_except_case() {
        assert_eq!(normalize_name("GitHub"), "github");
        assert_eq!(normalize_name(""), "");
    }

    #[test]
    fn dedup_key_matches_identical_items() {
        let a = login("GitHub", "a@b.com", "pw1");
        let b = login(" github ", "a@b.com", "pw1");
        assert_eq!(dedup_key(&a), dedup_key(&b));
    }

    #[test]
    fn dedup_key_differs_on_username_case() {
        let a = login("Site", "Alice", "pw");
        let b = login("Site", "alice", "pw");
        assert_ne!(
            dedup_key(&a),
            dedup_key(&b),
            "usernames differing only in case must stay separate"
        );
    }

    #[test]
    fn dedup_key_differs_on_password() {
        let a = login("GitHub", "a@b.com", "pw1");
        let b = login("GitHub", "a@b.com", "pw2");
        assert_ne!(dedup_key(&a), dedup_key(&b));
    }

    #[test]
    fn dedup_key_differs_on_username() {
        let a = login("Site", "alice@b.com", "pw");
        let b = login("Site", "bob@b.com", "pw");
        assert_ne!(
            dedup_key(&a),
            dedup_key(&b),
            "items with distinct usernames must stay separate"
        );
    }

    #[test]
    fn dedup_key_ignores_totp_differences() {
        // TOTP is intentionally out of the key — items differing only on TOTP
        // are the same account with a rotated secret. [`crate::merge`] picks
        // the newest TOTP for the survivor.
        let mut a = login("GitHub", "a@b.com", "pw");
        let mut b = login("GitHub", "a@b.com", "pw");
        a["login"]["totp"] = json!("otpauth://totp/A?secret=ABC");
        b["login"]["totp"] = json!("otpauth://totp/A?secret=XYZ");
        assert_eq!(
            dedup_key(&a),
            dedup_key(&b),
            "TOTP rotation must not prevent dedup"
        );
    }

    #[test]
    fn dedup_key_still_splits_on_passkey_even_when_totp_also_differs() {
        // Passkeys are strict-match. Even if TOTP-relaxation would otherwise
        // merge two items, a distinct FIDO2 credential on either side must
        // keep them separate so no passkey is overwritten.
        let mut a = login("GitHub", "a@b.com", "pw");
        let mut b = login("GitHub", "a@b.com", "pw");
        a["login"]["totp"] = json!("otpauth://totp/A?secret=ABC");
        b["login"]["totp"] = json!("otpauth://totp/A?secret=XYZ");
        a["login"]["fido2Credentials"] = json!([{"credentialId": "pk-alice"}]);
        b["login"]["fido2Credentials"] = json!([{"credentialId": "pk-bob"}]);
        assert_ne!(
            dedup_key(&a),
            dedup_key(&b),
            "distinct passkeys must keep items separate regardless of TOTP"
        );
    }

    #[test]
    fn dedup_key_matches_when_only_email_suffix_differs() {
        let a = login("fastly-eng.okta.com", "a@fastly.com", "pw");
        let b = login("fastly-eng.okta.com (a@fastly.com)", "a@fastly.com", "pw");
        assert_eq!(
            dedup_key(&a),
            dedup_key(&b),
            "name suffix ' (email)' must not prevent dedup"
        );
    }

    #[test]
    fn dedup_key_ignores_notes_fields_favorite() {
        let mut a = login("GitHub", "a@b.com", "pw");
        let mut b = login("GitHub", "a@b.com", "pw");
        a["notes"] = json!("note A");
        b["notes"] = json!("note B");
        a["favorite"] = json!(false);
        b["favorite"] = json!(true);
        a["fields"] = json!([{"name": "x", "value": "1", "type": 0}]);
        b["fields"] = json!([{"name": "y", "value": "2", "type": 0}]);
        assert_eq!(
            dedup_key(&a),
            dedup_key(&b),
            "notes/fields/favorite must no longer split the dedup key"
        );
    }

    #[test]
    fn dedup_key_differs_on_organization_id() {
        let mut a = login("GitHub", "a@b.com", "pw");
        let mut b = login("GitHub", "a@b.com", "pw");
        a["organizationId"] = json!(null);
        b["organizationId"] = json!("11111111-1111-1111-1111-111111111111");
        assert_ne!(
            dedup_key(&a),
            dedup_key(&b),
            "personal and org items must not cross-dedup"
        );
    }

    #[test]
    fn dedup_key_matches_when_both_personal() {
        let mut a = login("GitHub", "a@b.com", "pw");
        let mut b = login("GitHub", "a@b.com", "pw");
        a["organizationId"] = json!(null);
        b["organizationId"] = json!(null);
        assert_eq!(dedup_key(&a), dedup_key(&b));
    }

    #[test]
    fn fido2_metadata_divergence_keeps_items_distinct() {
        let a = json!({
            "type": 1, "name": "Passkey",
            "login": {"username": "u", "password": "p", "fido2Credentials": [{
                "credentialId": "cid-1", "counter": "1", "userHandle": "ua"
            }]}
        });
        let b = json!({
            "type": 1, "name": "Passkey",
            "login": {"username": "u", "password": "p", "fido2Credentials": [{
                "credentialId": "cid-1", "counter": "42", "userHandle": "ub"
            }]}
        });
        assert_ne!(
            dedup_key(&a),
            dedup_key(&b),
            "divergent FIDO2 metadata must keep items distinct"
        );
    }

    #[test]
    fn fido2_same_full_objects_group_identically() {
        let cred = json!({"credentialId": "cid-1", "counter": "7", "userHandle": "u"});
        let a = json!({
            "type": 1, "name": "Passkey",
            "login": {"username": "u", "password": "p", "fido2Credentials": [cred.clone()]}
        });
        let b = json!({
            "type": 1, "name": "Passkey",
            "login": {"username": "u", "password": "p", "fido2Credentials": [cred]}
        });
        assert_eq!(dedup_key(&a), dedup_key(&b));
    }

    #[test]
    fn skip_non_login_types() {
        assert!(skip_from_dedup(&json!({"type": 2})));
        assert!(skip_from_dedup(&json!({"type": 3})));
        assert!(skip_from_dedup(&json!({"type": 4})));
    }

    #[test]
    fn skip_reprompt_items() {
        let mut item = login("GitHub", "a@b.com", "pw");
        item["reprompt"] = json!(1);
        assert!(skip_from_dedup(&item));
    }

    #[test]
    fn skip_empty_password() {
        assert!(skip_from_dedup(&login("GitHub", "a@b.com", "")));
        assert!(skip_from_dedup(&login("GitHub", "a@b.com", "   ")));
    }

    #[test]
    fn skip_already_marked_duplicate() {
        assert!(skip_from_dedup(&login(
            "GitHub [duplicate]",
            "a@b.com",
            "pw"
        )));
    }

    #[test]
    fn skip_deleted_items() {
        let mut item = login("GitHub", "a@b.com", "pw");
        item["deletedDate"] = json!("2026-01-01T00:00:00Z");
        assert!(skip_from_dedup(&item));
    }

    #[test]
    fn secure_note_key_matches_normalized_names_with_identical_bodies() {
        // Same name (modulo trim/case) AND same trimmed body AND same
        // org → literal duplicate, dedup.
        let a = json!({"type": 2, "name": "Recovery codes", "notes": "AAA BBB"});
        let b = json!({"type": 2, "name": "  recovery codes  ", "notes": "AAA BBB"});
        assert_eq!(secure_note_key(&a), secure_note_key(&b));
    }

    #[test]
    fn secure_note_key_differs_on_body() {
        // Same name, different bodies → different groups, both preserved.
        // This is the safety floor that prevents merging unrelated items
        // that share a generic title like "Recovery" or "credentials.txt".
        let a = json!({"type": 2, "name": "Recovery", "notes": "codes for GitHub"});
        let b = json!({"type": 2, "name": "Recovery", "notes": "codes for GitLab"});
        assert_ne!(
            secure_note_key(&a),
            secure_note_key(&b),
            "secure notes with distinct bodies must not share a key"
        );
    }

    #[test]
    fn secure_note_key_body_is_trimmed() {
        // Whitespace around the body should not cause false separation.
        let a = json!({"type": 2, "name": "n", "notes": "body"});
        let b = json!({"type": 2, "name": "n", "notes": "  body  \n"});
        assert_eq!(secure_note_key(&a), secure_note_key(&b));
    }

    #[test]
    fn secure_note_key_does_not_strip_email_suffix() {
        // Secure-note titles keep `(email@…)` content — unlike login
        // names, the suffix can be meaningful on a note (e.g. which
        // account the recovery codes belong to). Two notes with
        // different email suffixes must stay separate.
        let a = json!({"type": 2, "name": "credentials", "notes": "codes"});
        let b = json!({"type": 2, "name": "credentials (alice@example.com)", "notes": "codes"});
        let c = json!({"type": 2, "name": "credentials (bob@example.com)", "notes": "codes"});
        assert_ne!(
            secure_note_key(&a),
            secure_note_key(&b),
            "'(email)' suffix must NOT be stripped for secure notes"
        );
        assert_ne!(
            secure_note_key(&b),
            secure_note_key(&c),
            "distinct email suffixes must keep notes separate"
        );
    }

    #[test]
    fn secure_note_key_ignores_zero_width_noise_in_name() {
        // Visually identical titles that differ only by invisible
        // Unicode (zero-width space, ZWJ, BOM) must still collapse.
        let a = json!({"type": 2, "name": "Recovery", "notes": "body"});
        let b = json!({"type": 2, "name": "Re\u{200B}co\u{FEFF}very", "notes": "body"});
        assert_eq!(
            secure_note_key(&a),
            secure_note_key(&b),
            "zero-width chars must not split a secure-note group"
        );
    }

    #[test]
    fn secure_note_key_folds_nbsp_whitespace_at_edges() {
        // NBSP and friends at edges must trim the same way ASCII space
        // does, so copy/paste whitespace quirks don't split groups.
        let a = json!({"type": 2, "name": "Note", "notes": "body"});
        let b = json!({"type": 2, "name": "\u{00A0}Note\u{00A0}", "notes": " body "});
        let c = json!({"type": 2, "name": "\u{3000}Note", "notes": "\u{2007}body\u{202F}"});
        assert_eq!(secure_note_key(&a), secure_note_key(&b));
        assert_eq!(secure_note_key(&a), secure_note_key(&c));
    }

    #[test]
    fn secure_note_key_ignores_zero_width_noise_in_body() {
        let a = json!({"type": 2, "name": "X", "notes": "abc"});
        let b = json!({"type": 2, "name": "X", "notes": "a\u{200B}b\u{200D}c"});
        assert_eq!(secure_note_key(&a), secure_note_key(&b));
    }

    fn ssh_key_item(pub_key: &str, priv_key: &str, fp: &str) -> Value {
        json!({
            "type": 5,
            "name": "laptop-ed25519",
            "sshKey": {
                "publicKey": pub_key,
                "privateKey": priv_key,
                "keyFingerprint": fp
            }
        })
    }

    #[test]
    fn ssh_key_key_matches_when_material_identical() {
        let a = ssh_key_item(
            "ssh-ed25519 AAAAC...alex",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nABC\n-----END-----",
            "SHA256:abc",
        );
        let b = ssh_key_item(
            "ssh-ed25519 AAAAC...alex",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nABC\n-----END-----",
            "SHA256:abc",
        );
        assert_eq!(ssh_key_key(&a), ssh_key_key(&b));
    }

    #[test]
    fn ssh_key_key_differs_when_private_key_differs() {
        // Same public key + different private key is almost certainly
        // corrupt state — never merge these items; keep them separate.
        let a = ssh_key_item(
            "ssh-ed25519 AAAAC...alex",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nONE\n-----END-----",
            "SHA256:abc",
        );
        let b = ssh_key_item(
            "ssh-ed25519 AAAAC...alex",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nTWO\n-----END-----",
            "SHA256:abc",
        );
        assert_ne!(ssh_key_key(&a), ssh_key_key(&b));
    }

    #[test]
    fn ssh_key_key_differs_when_public_key_differs() {
        let a = ssh_key_item("ssh-ed25519 AAA.ONE", "priv1", "SHA256:a");
        let b = ssh_key_item("ssh-ed25519 AAA.TWO", "priv2", "SHA256:b");
        assert_ne!(ssh_key_key(&a), ssh_key_key(&b));
    }

    #[test]
    fn is_dedupable_ssh_key_filters_non_type_5() {
        let a = ssh_key_item("pk", "priv", "fp");
        assert!(is_dedupable_ssh_key(&a));
        let mut not_ssh = a.clone();
        not_ssh["type"] = json!(1);
        assert!(!is_dedupable_ssh_key(&not_ssh));
    }

    #[test]
    fn is_dedupable_ssh_key_refuses_items_without_public_key() {
        // Without a publicKey we have no identity — refuse to group.
        let item = json!({
            "type": 5,
            "name": "orphan",
            "sshKey": {"publicKey": "", "privateKey": "priv"}
        });
        assert!(!is_dedupable_ssh_key(&item));
    }

    #[test]
    fn is_dedupable_ssh_key_skips_trashed_and_reprompt() {
        let mut item = ssh_key_item("pk", "priv", "fp");
        item["deletedDate"] = json!("2025-01-01T00:00:00Z");
        assert!(!is_dedupable_ssh_key(&item));
        let mut item = ssh_key_item("pk", "priv", "fp");
        item["reprompt"] = json!(1);
        assert!(!is_dedupable_ssh_key(&item));
    }

    #[test]
    fn ssh_key_key_separates_personal_and_org() {
        let mut a = ssh_key_item("pk", "priv", "fp");
        let mut b = ssh_key_item("pk", "priv", "fp");
        a["organizationId"] = Value::Null;
        b["organizationId"] = json!("11111111-1111-1111-1111-111111111111");
        assert_ne!(ssh_key_key(&a), ssh_key_key(&b));
    }

    #[test]
    fn secure_note_key_separates_personal_and_org() {
        // Personal and organization-owned notes sharing a name + body
        // must NOT collapse — they live in different vaults with
        // different access control.
        let mut personal = json!({"type": 2, "name": "Shared Wiki", "notes": "internal URL"});
        let mut org = personal.clone();
        personal["organizationId"] = Value::Null;
        org["organizationId"] = json!("11111111-1111-1111-1111-111111111111");
        assert_ne!(
            secure_note_key(&personal),
            secure_note_key(&org),
            "personal and org-owned secure notes must never cross-dedup"
        );
    }

    #[test]
    fn secure_note_key_distinct_from_login_key() {
        // A login and a secure note that happen to share a name must
        // never collide — their keys live in separate namespaces.
        let login = json!({
            "type": 1, "name": "credentials.txt",
            "login": {"username": "u", "password": "p"}
        });
        let note = json!({"type": 2, "name": "credentials.txt", "notes": "n"});
        assert_ne!(dedup_key(&login), secure_note_key(&note));
    }

    #[test]
    fn is_dedupable_secure_note_filters_non_type_2() {
        assert!(is_dedupable_secure_note(&json!({"type": 2, "name": "n"})));
        assert!(!is_dedupable_secure_note(&json!({"type": 1, "name": "n"})));
        assert!(!is_dedupable_secure_note(&json!({"type": 3, "name": "n"})));
    }

    // ---------- empty-password dedup pass: host_of ----------

    #[test]
    fn host_of_androidapp_strips_path_query_fragment() {
        assert_eq!(
            host_of("androidapp://com.Example.App/path"),
            Some((HostKind::AndroidApp, "com.Example.App".to_string())),
            "case must be preserved; path stripped"
        );
        assert_eq!(
            host_of("androidapp://com.example.app?x=1"),
            Some((HostKind::AndroidApp, "com.example.app".to_string())),
            "query string must not appear in the package token"
        );
        assert_eq!(
            host_of("androidapp://com.example.app#frag"),
            Some((HostKind::AndroidApp, "com.example.app".to_string())),
            "fragment must not appear in the package token"
        );
        assert_eq!(
            host_of("androidapp://com.Example.App/path?x=1#y"),
            Some((HostKind::AndroidApp, "com.Example.App".to_string())),
            "all three suffixes stripped at once"
        );
    }

    #[test]
    fn host_of_dns_lowercased_default_port_dropped() {
        assert_eq!(
            host_of("https://EXAMPLE.com/path?q=1"),
            Some((HostKind::Dns, "example.com".to_string())),
            "DNS lowercased per RFC 1035; default port absent because not explicit"
        );
        assert_eq!(
            host_of("https://example.com:443/"),
            Some((HostKind::Dns, "example.com".to_string())),
            "url::Url drops default port from port() for known schemes"
        );
    }

    #[test]
    fn host_of_preserves_non_default_port() {
        assert_eq!(
            host_of("https://example.com:8443/"),
            Some((HostKind::Dns, "example.com:8443".to_string())),
            "non-default port stays in the host token — port can be identity"
        );
        assert_eq!(
            host_of("http://example.com:8080/"),
            Some((HostKind::Dns, "example.com:8080".to_string()))
        );
    }

    #[test]
    fn host_of_ipv6_with_non_default_port() {
        assert_eq!(
            host_of("https://[2001:db8::1]:8443/"),
            Some((HostKind::Ip, "[2001:db8::1]:8443".to_string())),
            "IPv6 canonical form from url::Url, port preserved"
        );
    }

    #[test]
    fn host_of_ipv4_with_non_default_port() {
        assert_eq!(
            host_of("http://192.0.2.10:8080/"),
            Some((HostKind::Ip, "192.0.2.10:8080".to_string())),
        );
    }

    #[test]
    fn host_of_websocket_schemes_in_allowlist() {
        assert_eq!(
            host_of("ws://example.com/socket"),
            Some((HostKind::Dns, "example.com".to_string())),
            "ws is in the DNS allowlist"
        );
        assert_eq!(
            host_of("wss://example.com/socket"),
            Some((HostKind::Dns, "example.com".to_string())),
            "wss is in the DNS allowlist"
        );
    }

    #[test]
    fn host_of_bare_reverse_dns_app_id() {
        assert_eq!(
            host_of("com.example.iosapp"),
            Some((HostKind::Opaque, "com.example.iosapp".to_string())),
            "no scheme → opaque, case preserved"
        );
        assert_eq!(
            host_of("com.Example.iOSApp"),
            Some((HostKind::Opaque, "com.Example.iOSApp".to_string())),
            "case preserved verbatim — App IDs may be case-sensitive"
        );
    }

    #[test]
    fn host_of_custom_scheme_is_opaque_case_preserved() {
        // The regression test: url::Url WILL parse `myapp://Login?token=abc`
        // and extract `Login` as a host. The DNS allowlist must reject the
        // unknown scheme so we do NOT case-fold an identifier with unknown
        // semantics.
        assert_eq!(
            host_of("myapp://Login?token=abc"),
            Some((HostKind::Opaque, "myapp://Login?token=abc".to_string())),
            "custom scheme outside allowlist must stay opaque, case-exact"
        );
        assert_eq!(
            host_of("MYAPP://login"),
            Some((HostKind::Opaque, "MYAPP://login".to_string())),
            "scheme case preserved verbatim"
        );
        assert_eq!(
            host_of("mailto:user@example.com"),
            Some((HostKind::Opaque, "mailto:user@example.com".to_string())),
            "mailto: not in the allowlist"
        );
    }

    #[test]
    fn host_of_empty_or_whitespace_returns_none() {
        assert!(host_of("").is_none());
        assert!(host_of("   ").is_none());
        assert!(host_of("\t\n").is_none());
    }

    // ---------- empty-password dedup pass: key construction ----------

    fn empty_pw_login(name: &str, user: &str) -> Value {
        json!({
            "type": 1,
            "name": name,
            "login": { "username": user, "password": "" },
        })
    }

    fn with_uris(mut item: Value, uris: &[&str]) -> Value {
        let arr: Vec<Value> = uris
            .iter()
            .map(|u| json!({"uri": u, "match": null}))
            .collect();
        item["login"]["uris"] = Value::Array(arr);
        item
    }

    #[test]
    fn empty_pw_key_matches_when_only_uri_trailing_slash_differs() {
        let a = with_uris(
            empty_pw_login("Tribit", "alex@example.test"),
            &["https://www.tribit.com"],
        );
        let b = with_uris(
            empty_pw_login("Tribit", "alex@example.test"),
            &["https://www.tribit.com/"],
        );
        assert_eq!(empty_password_dedup_key(&a), empty_password_dedup_key(&b));
    }

    #[test]
    fn empty_pw_key_matches_when_http_vs_https_for_same_host() {
        let a = with_uris(
            empty_pw_login("Trade Republic", "u"),
            &["http://traderepublic.com"],
        );
        let b = with_uris(
            empty_pw_login("Trade Republic", "u"),
            &["https://traderepublic.com/"],
        );
        assert_eq!(empty_password_dedup_key(&a), empty_password_dedup_key(&b));
    }

    #[test]
    fn empty_pw_key_differs_on_different_hostnames() {
        let a = with_uris(empty_pw_login("Acme", "u"), &["https://example.com/"]);
        let b = with_uris(empty_pw_login("Acme", "u"), &["https://example.org/"]);
        assert_ne!(empty_password_dedup_key(&a), empty_password_dedup_key(&b));
    }

    #[test]
    fn empty_pw_key_differs_on_different_usernames() {
        let a = empty_pw_login("Acme", "alex@loxal.net");
        let b = empty_pw_login("Acme", "alexander.orlov@loxal.net");
        assert_ne!(empty_password_dedup_key(&a), empty_password_dedup_key(&b));
    }

    #[test]
    fn empty_pw_key_differs_on_org_id() {
        let mut a = empty_pw_login("Acme", "u");
        let mut b = empty_pw_login("Acme", "u");
        a["organizationId"] = Value::Null;
        b["organizationId"] = json!("11111111-1111-1111-1111-111111111111");
        assert_ne!(empty_password_dedup_key(&a), empty_password_dedup_key(&b));
    }

    #[test]
    fn empty_pw_key_differs_on_fido2_set() {
        let mut a = empty_pw_login("Acme", "u");
        let mut b = empty_pw_login("Acme", "u");
        a["login"]["fido2Credentials"] = json!([{"credentialId": "pk-alice"}]);
        b["login"]["fido2Credentials"] = json!([{"credentialId": "pk-bob"}]);
        assert_ne!(empty_password_dedup_key(&a), empty_password_dedup_key(&b));
    }

    #[test]
    fn empty_pw_key_strips_email_suffix_from_name() {
        let a = empty_pw_login("fastly-eng.okta.com", "a@fastly.com");
        let b = empty_pw_login("fastly-eng.okta.com (a@fastly.com)", "a@fastly.com");
        assert_eq!(empty_password_dedup_key(&a), empty_password_dedup_key(&b));
    }

    #[test]
    fn empty_pw_key_distinct_from_strict_key_for_same_item() {
        // `dedup_key` would key on password=""; the empty-pw key uses the
        // sentinel "empty-pw" string and adds host data. Same item must
        // produce different strings so the two passes never cross-merge.
        let item = empty_pw_login("Acme", "u");
        assert_ne!(dedup_key(&item), empty_password_dedup_key(&item));
    }

    #[test]
    fn empty_pw_key_dns_and_opaque_do_not_collide() {
        // An item carrying only a DNS URL `https://example.com/` and one
        // carrying only the bare opaque string `example.com` must produce
        // different keys — Dns:example.com vs Opaque:example.com.
        let a = with_uris(empty_pw_login("X", ""), &["https://example.com/"]);
        let b = with_uris(empty_pw_login("X", ""), &["example.com"]);
        assert_ne!(empty_password_dedup_key(&a), empty_password_dedup_key(&b));
    }

    #[test]
    fn empty_pw_key_dns_case_folded_androidapp_case_preserved() {
        // Three web URLs differing only in case → group together.
        let a = with_uris(empty_pw_login("Acme", "u"), &["https://Example.com"]);
        let b = with_uris(empty_pw_login("Acme", "u"), &["https://example.com"]);
        let c = with_uris(empty_pw_login("Acme", "u"), &["https://EXAMPLE.com"]);
        assert_eq!(empty_password_dedup_key(&a), empty_password_dedup_key(&b));
        assert_eq!(empty_password_dedup_key(&b), empty_password_dedup_key(&c));

        // Three Android packages differing only in case → all distinct.
        let p = with_uris(
            empty_pw_login("Acme", "u"),
            &["androidapp://com.Example.App"],
        );
        let q = with_uris(
            empty_pw_login("Acme", "u"),
            &["androidapp://com.example.app"],
        );
        let r = with_uris(
            empty_pw_login("Acme", "u"),
            &["androidapp://com.EXAMPLE.app"],
        );
        assert_ne!(empty_password_dedup_key(&p), empty_password_dedup_key(&q));
        assert_ne!(empty_password_dedup_key(&q), empty_password_dedup_key(&r));
        assert_ne!(empty_password_dedup_key(&p), empty_password_dedup_key(&r));
    }

    #[test]
    fn empty_pw_key_port_bearing_separation() {
        let a = with_uris(
            empty_pw_login("Internal", ""),
            &["https://internal.example.com:8443/"],
        );
        let b = with_uris(
            empty_pw_login("Internal", ""),
            &["https://internal.example.com:9090/"],
        );
        let c = with_uris(
            empty_pw_login("Internal", ""),
            &["https://internal.example.com/"],
        );
        let d = with_uris(
            empty_pw_login("Internal", ""),
            &["https://internal.example.com:443/"],
        ); // default port
        assert_ne!(empty_password_dedup_key(&a), empty_password_dedup_key(&b));
        assert_ne!(empty_password_dedup_key(&a), empty_password_dedup_key(&c));
        assert_ne!(empty_password_dedup_key(&b), empty_password_dedup_key(&c));
        // Default port is dropped by url::Url, so c and d collapse.
        assert_eq!(empty_password_dedup_key(&c), empty_password_dedup_key(&d));
    }

    #[test]
    fn empty_pw_key_host_set_encoding_unambiguous() {
        // Regression guard: opaque host tokens are arbitrary user
        // strings. A naive `join(",")` over `format!("{kind:?}:{h}")`
        // would let a single opaque host whose text happens to
        // contain delimiter-shaped bytes collide with a two-host set.
        // The length-prefixed encoding eliminates that ambiguity.
        let two_opaque = with_uris(empty_pw_login("X", ""), &["a", "b"]);
        let one_opaque_with_delim_in_value = with_uris(
            empty_pw_login("X", ""),
            &["a,Opaque:b"], // the literal collision shape from the reviewer
        );
        assert_ne!(
            empty_password_dedup_key(&two_opaque),
            empty_password_dedup_key(&one_opaque_with_delim_in_value),
            "host-set encoding must be unambiguous across delimiter-shaped tokens"
        );

        // Also try the unit-separator delimiter variant.
        let two_opaque_us = with_uris(empty_pw_login("X", ""), &["a", "b"]);
        let one_opaque_us = with_uris(empty_pw_login("X", ""), &["a\x1fOpaque:1:b"]);
        assert_ne!(
            empty_password_dedup_key(&two_opaque_us),
            empty_password_dedup_key(&one_opaque_us),
            "embedded \\x1f in an opaque token must not collide with a two-host set"
        );
    }

    #[test]
    fn empty_pw_key_custom_scheme_byte_exact() {
        // Two custom-scheme URLs differing only in case stay split — the
        // scheme is not in the DNS allowlist, so the entire URI is the
        // opaque token.
        let a = with_uris(empty_pw_login("MyApp", "u"), &["myapp://Login?token=abc"]);
        let b = with_uris(empty_pw_login("MyApp", "u"), &["myapp://login?token=def"]);
        assert_ne!(empty_password_dedup_key(&a), empty_password_dedup_key(&b));
    }

    // ---------- empty-password dedup pass: filtering ----------

    #[test]
    fn empty_pw_filter_skips_non_login_types() {
        assert!(!is_dedupable_empty_password_login(
            &json!({"type": 2, "name": "n"})
        ));
        assert!(!is_dedupable_empty_password_login(
            &json!({"type": 5, "name": "n"})
        ));
    }

    #[test]
    fn empty_pw_filter_skips_trashed_reprompt_duplicate_tagged() {
        let mut item = with_uris(empty_pw_login("Acme", "u"), &["https://acme.com/"]);
        assert!(is_dedupable_empty_password_login(&item));

        item["deletedDate"] = json!("2026-01-01T00:00:00Z");
        assert!(!is_dedupable_empty_password_login(&item));

        let mut item = with_uris(empty_pw_login("Acme", "u"), &["https://acme.com/"]);
        item["reprompt"] = json!(1);
        assert!(!is_dedupable_empty_password_login(&item));

        let item = with_uris(
            empty_pw_login("Acme [duplicate]", "u"),
            &["https://acme.com/"],
        );
        assert!(!is_dedupable_empty_password_login(&item));
    }

    #[test]
    fn empty_pw_filter_skips_non_empty_password() {
        // Strict pass already handles items with passwords. The
        // empty-password pass must defer to it — never run on an item
        // the strict pass already grouped.
        let item = json!({
            "type": 1, "name": "Acme",
            "login": {"username": "u", "password": "actual-pw"}
        });
        assert!(!is_dedupable_empty_password_login(&item));
    }

    #[test]
    fn empty_pw_filter_skips_no_signal_items() {
        // No username, no URIs, no fido2 → name is the only signal.
        // Refuse to group: validation file showed 30 such items must
        // survive untouched.
        let item = empty_pw_login("Acme", "");
        assert!(!is_dedupable_empty_password_login(&item));

        // Empty username + empty URI list (key present but no entries).
        let item = with_uris(empty_pw_login("Acme", ""), &[]);
        assert!(!is_dedupable_empty_password_login(&item));
    }

    #[test]
    fn empty_pw_filter_accepts_username_only_signal() {
        // The `oura` group from the validation file: same name, same
        // username, no URIs, no fido. Username alone is the riskiest
        // signal class but per design we still collapse — losers are
        // recoverable from the trash sidecar.
        let item = empty_pw_login("oura", "alex@example.test");
        assert!(is_dedupable_empty_password_login(&item));
    }

    #[test]
    fn empty_pw_filter_accepts_host_only_signal() {
        // The `heatledger.com` group from the validation file: empty
        // username, single URL.
        let item = with_uris(empty_pw_login("Heat", ""), &["https://heatledger.com/"]);
        assert!(is_dedupable_empty_password_login(&item));
    }

    #[test]
    fn empty_pw_filter_accepts_fido2_only_signal() {
        let mut item = empty_pw_login("Passkey", "");
        item["login"]["fido2Credentials"] = json!([{"credentialId": "pk-1"}]);
        assert!(is_dedupable_empty_password_login(&item));
    }

    #[test]
    fn is_dedupable_secure_note_rejects_untagged_cases() {
        let mut base = json!({"type": 2, "name": "n"});
        assert!(is_dedupable_secure_note(&base));
        // trashed already → skip
        base["deletedDate"] = json!("2026-01-01T00:00:00Z");
        assert!(!is_dedupable_secure_note(&base));
        // reprompt-gated → skip
        base["deletedDate"] = Value::Null;
        base["reprompt"] = json!(1);
        assert!(!is_dedupable_secure_note(&base));
        // already tagged → skip
        base["reprompt"] = json!(0);
        base["name"] = json!("n [duplicate]");
        assert!(!is_dedupable_secure_note(&base));
        // empty name → skip (nothing stable to group on)
        base["name"] = json!("   ");
        assert!(!is_dedupable_secure_note(&base));
    }

    // ---------- card dedup ----------

    fn card_item(name: &str, number: &str, exp_month: &str, exp_year: &str, code: &str) -> Value {
        json!({
            "type": 3,
            "name": name,
            "card": {
                "cardholderName": "Alex Orlov",
                "brand": "Visa",
                "number": number,
                "expMonth": exp_month,
                "expYear": exp_year,
                "code": code,
            }
        })
    }

    #[test]
    fn card_key_matches_when_card_block_byte_identical() {
        let a = card_item("Visa Personal", "4111111111111111", "12", "2030", "123");
        let b = card_item("Visa Personal", "4111111111111111", "12", "2030", "123");
        assert_eq!(card_key(&a), card_key(&b));
    }

    #[test]
    fn card_key_differs_on_number_expiry_or_cvv() {
        let base = card_item("Visa", "4111111111111111", "12", "2030", "123");
        let mut diff_num = base.clone();
        diff_num["card"]["number"] = json!("4111111111110000");
        assert_ne!(card_key(&base), card_key(&diff_num));

        let mut diff_exp = base.clone();
        diff_exp["card"]["expMonth"] = json!("11");
        assert_ne!(card_key(&base), card_key(&diff_exp));

        let mut diff_cvv = base.clone();
        diff_cvv["card"]["code"] = json!("999");
        assert_ne!(card_key(&base), card_key(&diff_cvv));
    }

    #[test]
    fn card_key_differs_on_cardholder_whitespace() {
        // Trailing-space difference in cardholder name keeps items
        // distinct — we never merge stored card data on near-equality.
        let a = card_item("Visa", "4111111111111111", "12", "2030", "123");
        let mut b = a.clone();
        b["card"]["cardholderName"] = json!("Alex Orlov ");
        assert_ne!(card_key(&a), card_key(&b));
    }

    #[test]
    fn card_key_strips_email_suffix_from_name() {
        let mut a = card_item("Visa Personal", "4111", "12", "2030", "123");
        let mut b = card_item("Visa Personal (alex@example.test)", "4111", "12", "2030", "123");
        a["organizationId"] = Value::Null;
        b["organizationId"] = Value::Null;
        assert_eq!(card_key(&a), card_key(&b));
    }

    #[test]
    fn card_key_separates_personal_and_org() {
        let mut a = card_item("Visa", "4111", "12", "2030", "123");
        let mut b = card_item("Visa", "4111", "12", "2030", "123");
        a["organizationId"] = Value::Null;
        b["organizationId"] = json!("11111111-1111-1111-1111-111111111111");
        assert_ne!(card_key(&a), card_key(&b));
    }

    #[test]
    fn is_dedupable_card_filters_correctly() {
        let base = card_item("Visa", "4111", "12", "2030", "123");
        assert!(is_dedupable_card(&base));

        // Non-card type
        let mut not_card = base.clone();
        not_card["type"] = json!(1);
        assert!(!is_dedupable_card(&not_card));

        // Trashed
        let mut trashed = base.clone();
        trashed["deletedDate"] = json!("2026-01-01T00:00:00Z");
        assert!(!is_dedupable_card(&trashed));

        // Reprompt-gated
        let mut reprompt = base.clone();
        reprompt["reprompt"] = json!(1);
        assert!(!is_dedupable_card(&reprompt));

        // Already-tagged
        let mut tagged = base.clone();
        tagged["name"] = json!("Visa [duplicate]");
        assert!(!is_dedupable_card(&tagged));

        // Missing card block — refuse to group on item-level metadata alone
        let no_block = json!({"type": 3, "name": "Visa"});
        assert!(!is_dedupable_card(&no_block));
    }

    #[test]
    fn is_dedupable_card_rejects_null_or_non_object_block() {
        // Regression guard: the REST decoder
        // (live_vault/cipher_codec.rs) can emit `{"type": 3,
        // "card": null}` for malformed/incomplete cipher payloads.
        // Without an `is_object` check, multiple such items with
        // the same name + org would canonicalize to `card=null` and
        // collapse onto a single survivor. Refuse to consider them.
        let null_block = json!({"type": 3, "name": "Visa", "card": null});
        assert!(!is_dedupable_card(&null_block));

        let array_block = json!({"type": 3, "name": "Visa", "card": []});
        assert!(!is_dedupable_card(&array_block));

        let string_block = json!({"type": 3, "name": "Visa", "card": "junk"});
        assert!(!is_dedupable_card(&string_block));

        let bool_block = json!({"type": 3, "name": "Visa", "card": false});
        assert!(!is_dedupable_card(&bool_block));
    }

    #[test]
    fn card_key_distinct_from_other_type_keys() {
        // type=3 prefix must not collide with login / note / ssh-key namespaces.
        let card = card_item("X", "4111", "12", "2030", "123");
        assert!(card_key(&card).starts_with("type=3\0"));
    }

    // ---------- identity dedup ----------

    fn identity_item(name: &str, first: &str, last: &str, email: &str) -> Value {
        json!({
            "type": 4,
            "name": name,
            "identity": {
                "firstName": first,
                "lastName": last,
                "email": email,
                "address1": "1 Example St",
                "city": "Zurich",
                "country": "CH",
            }
        })
    }

    #[test]
    fn identity_key_matches_when_identity_block_byte_identical() {
        let a = identity_item("my", "Alexander", "Orlov", "alex@example.test");
        let b = identity_item("my", "Alexander", "Orlov", "alex@example.test");
        assert_eq!(identity_key(&a), identity_key(&b));
    }

    #[test]
    fn identity_key_differs_on_any_field() {
        let base = identity_item("my", "Alexander", "Orlov", "alex@example.test");
        let mut diff_first = base.clone();
        diff_first["identity"]["firstName"] = json!("Alex");
        assert_ne!(identity_key(&base), identity_key(&diff_first));

        let mut diff_email = base.clone();
        diff_email["identity"]["email"] = json!("other@example.test");
        assert_ne!(identity_key(&base), identity_key(&diff_email));

        let mut diff_addr = base.clone();
        diff_addr["identity"]["address1"] = json!("2 Other St");
        assert_ne!(identity_key(&base), identity_key(&diff_addr));
    }

    #[test]
    fn identity_key_separates_personal_and_org() {
        let mut a = identity_item("my", "Alex", "Orlov", "u@example.test");
        let mut b = identity_item("my", "Alex", "Orlov", "u@example.test");
        a["organizationId"] = Value::Null;
        b["organizationId"] = json!("11111111-1111-1111-1111-111111111111");
        assert_ne!(identity_key(&a), identity_key(&b));
    }

    #[test]
    fn is_dedupable_identity_filters_correctly() {
        let base = identity_item("my", "Alex", "Orlov", "u@example.test");
        assert!(is_dedupable_identity(&base));

        let mut not_identity = base.clone();
        not_identity["type"] = json!(1);
        assert!(!is_dedupable_identity(&not_identity));

        let mut trashed = base.clone();
        trashed["deletedDate"] = json!("2026-01-01T00:00:00Z");
        assert!(!is_dedupable_identity(&trashed));

        let mut reprompt = base.clone();
        reprompt["reprompt"] = json!(1);
        assert!(!is_dedupable_identity(&reprompt));

        let no_block = json!({"type": 4, "name": "x"});
        assert!(!is_dedupable_identity(&no_block));
    }

    #[test]
    fn is_dedupable_identity_rejects_null_or_non_object_block() {
        // Same regression guard as cards — `{"type":4,"identity":null}`
        // would otherwise canonicalize to `identity=null` and let
        // every malformed-identity item with a shared name collapse.
        let null_block = json!({"type": 4, "name": "my", "identity": null});
        assert!(!is_dedupable_identity(&null_block));

        let array_block = json!({"type": 4, "name": "my", "identity": []});
        assert!(!is_dedupable_identity(&array_block));

        let number_block = json!({"type": 4, "name": "my", "identity": 42});
        assert!(!is_dedupable_identity(&number_block));
    }

    #[test]
    fn identity_key_distinct_from_card_key() {
        let card = card_item("X", "4111", "12", "2030", "123");
        let identity = identity_item("X", "Alex", "Orlov", "u@example.test");
        // Different type prefix → different namespace even with same name.
        assert_ne!(card_key(&card), identity_key(&identity));
    }
}
