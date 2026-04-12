# bitwarden-dedup

Rust CLI that deduplicates a Bitwarden JSON vault export into an import-ready
file. Strict matching, URI merging, and full preservation of TOTP secrets,
FIDO2 credentials, notes, custom fields, and password history.

## Why strict matching

A loose dedup key (just `name + username`) will mis-match unrelated accounts
that happen to share a display name. On a real vault with ~1,700 logins, the
loose approach produces dozens of false-positive groups where the passwords
actually differ — those are separate accounts, not duplicates.

`bitwarden-dedup` drops an item only when **every** safety-relevant field
matches the item it will be merged into:

| Field | Matching rule |
|---|---|
| `name` | case-insensitive, trimmed |
| `login.username` | case-insensitive, trimmed |
| `login.password` | exact |
| `login.totp` | exact |
| `login.fido2Credentials` (credential ids) | exact set |
| `notes` | trimmed |
| `fields` (custom fields) | `(name, value, type, linkedId)` tuples, order-insensitive — `linkedId` is the Bitwarden integer that identifies a Linked field's target (`100` = Username, `101` = Password, confirmed from live API) |
| `favorite` | exact |
| `organizationId` | exact — personal and organization items never cross-dedup (they live in different vaults with different access control) |

For each duplicate group, the item with the newest `revisionDate` wins the
tiebreak (fallback: `creationDate`). Any URIs present on dropped items but
missing from the kept item are merged into the kept item so no login URL is
ever lost.

Items that are **never** grouped (passed through unchanged):

- non-login types (cards, identities, secure notes)
- items with `reprompt == 1` (master-password gated — too sensitive to
  auto-merge)
- items with an empty password (would spuriously group on `""`)
- items whose name already contains `[duplicate]`
- deleted items (trash)

## Usage

```bash
# Put your export somewhere gitignored (the vault/ dir is excluded)
mkdir -p vault
mv ~/Downloads/bitwarden_export_*.json vault/

# Run the dedup
cargo run --release --bin bitwarden-dedup -- \
  --input vault/bitwarden_export.json
```

By default, output and audit files are written next to the input:

- `vault/bitwarden_export.dedup.json` — import-ready
- `vault/bitwarden_export.dedup.audit.json` — per-group record

Override with `--output` / `--audit` (point at `/tmp/` or `vault/`, never
at `examples/`):

```bash
cargo run --release --bin bitwarden-dedup -- \
  --input vault/bitwarden_export.json \
  --output /tmp/cleaned.json \
  --audit /tmp/cleaned.audit.json
```

`--input`, `--output`, and `--audit` must resolve to three distinct paths;
if any collide (e.g. `--output` equals `--input`) the tool errors out
before touching the filesystem so your backup can't be overwritten. Pass
`--force` to bypass the check — it will warn to stderr and proceed.

On Unix the deduplicated output and audit files are created with
`0o600` (owner-only read/write), because both contain plaintext credential
material. If a pre-existing file has looser permissions, it is chmod'd
back to `0o600` after write.

## Import workflow (Bitwarden web vault)

> **Read this first.** Bitwarden's Import feature **never deduplicates
> against the existing vault** — every record in the JSON is created as a
> new item, even if a matching item already exists. This is documented in
> the [Bitwarden Import & Export FAQs][bw-faqs]. If you skip the Purge
> step below, importing a cleaned file on top of your current vault
> simply adds every cleaned item as a second copy; your vault item
> count will roughly equal the cleaned count plus the pre-existing
> count. Purge is load-bearing.

1. Keep the **original** export as your backup — the `.gitignore` keeps it
   local and it's already on disk.
2. Bitwarden web vault → **Settings → My Account → Purge Vault**.
3. **Tools → Import Data → Bitwarden (json)** → select the `.dedup.json`.
4. Open 2–3 TOTP items (GitHub, a banking site, etc.) to confirm codes
   generate. TOTP secrets, FIDO2 passkeys, and custom fields are preserved
   verbatim on the kept items, so codes should match immediately.

Item `id` fields in the JSON are informational only — Bitwarden regenerates
all ids on import, so audit-file `kept_id` / `removed_id` values will NOT
match the post-import vault. The `name` + `username` + `revisionDate` tuple
is what you use to cross-reference an item after re-import.

[bw-faqs]: https://bitwarden.com/help/import-export-faqs/

## Security

The crate's `.gitignore` excludes every pattern that could leak vault data:

```
bitwarden_export_*.json
*.dedup.json
*.dedup.audit.json
vault/
```

**Never weaken these patterns.** The audit JSON only contains ids, names, and
dates (no passwords or TOTP seeds), but the export and dedup outputs contain
plaintext credentials and passkey material.

## Build & test

A `justfile` ships with the crate — `just` (or `just --list`) prints the
recipes. The most common ones:

```bash
just build              # cargo build --release
just test               # full test suite (lib + both bins + integration + leak-guard)
just example            # run bitwarden-dedup against the committed synthetic fixture
just dedup <path>       # run bitwarden-dedup on a real export
just redact <in> <out>  # produce a locally-redacted replica of a real export
just regenerate-example # rewrite examples/bitwarden_export_20260411172632.json from the builder
just leak-guard         # run only the allowlist scan on the committed fixture
just check              # cargo fmt --check + cargo clippy -D warnings
```

Direct invocation also works:

```bash
cargo build --release
cargo test
./target/release/bitwarden-dedup --input <path>
```

## Example fixture

`examples/bitwarden_export_20260411172632.json` is a small (~22 item, ~17 KB) **fully
synthetic** fixture. Nothing in it originates from a real vault — it is
constructed by `build_curated_fixture()` in `tests/fixture.rs` and
exercises every code path the dedup tool cares about:

- a unique login (passes through)
- an exact duplicate pair (drops one, merges no URIs)
- a URI-divergent pair (drops one, merges one URI)
- an Android URI pair (drops one, merges one Android URI)
- a match-mode-divergent pair (drops one, merges one same-URI-different-mode)
- a triple duplicate (drops two, merges no URIs)
- a same-name-same-username-different-password pair (NOT merged)
- a login with a TOTP seed
- a reprompt-gated login (skipped)
- an empty-password login (skipped)
- an already-tagged `[duplicate]` login (skipped)
- a soft-deleted login (skipped)
- a card, an identity, and a secure note (skipped — non-login types)

Three integration tests guard the fixture:

- **`example_fixture_counts_match_readme`** — asserts the exact dedup counts
  below so the README can't drift from the code.
- **`example_fixture_matches_generator`** — fails if someone hand-edits the
  committed JSON without updating the builder, forcing the two to stay in
  sync via `just regenerate-example`.
- **`example_fixture_no_leaked_strings`** — walks every string in the
  committed JSON and requires each one to match a synthetic-placeholder
  allowlist (synthetic emails at `@example.test`, `redacted-password-*`,
  `redacted-totp-seed-*`, `https://service*.example.test/*`,
  `androidapp://com.example.*`, zero-prefixed UUIDs, ISO 8601 dates, and a
  small set of known literal names like `Folder 01`, `REDACTED`, etc.).
  If anything that looks even slightly like a real identifier lands in
  the committed file, this test fails loudly.

```bash
# Run the dedup tool against the committed example
./target/release/bitwarden-dedup --input examples/bitwarden_export_20260411172632.json \
    --output /tmp/example.dedup.json \
    --audit /tmp/example.dedup.audit.json
```

Expected output on the committed fixture — these exact numbers are asserted
by `tests/fixture.rs` so the docs can't drift from the code:

```
Input:         examples/bitwarden_export_20260411172632.json
               22 items total, 7 skipped from dedup
Groups:        5 strict duplicate groups
Removed:       6 items (kept newest by revisionDate)
URIs merged:   3 unique URLs preserved from dropped items
Output:        /tmp/example.dedup.json
               16 items
```

### Regenerating the committed fixture

The committed fixture is code-generated, not redacted from a real vault.
To rewrite `examples/bitwarden_export_20260411172632.json` from `build_curated_fixture()`:

```bash
just regenerate-example
```

After regenerating, `cargo test` will fail loudly if any of the guard
tests above no longer hold. Update the builder, the counts assertion, and
the README in the same commit when numbers legitimately change.

### Locally redacting a real vault (NOT committed)

`bitwarden-redact` is a second binary (`src/bin/bitwarden-redact.rs`) that
produces a synthesized replica of your real export. Its output is meant
for LOCAL sharing with a reviewer, not for commit — it matches the
`*.dedup.json` / `vault/` gitignore patterns.

```bash
# Output MUST go to /tmp or vault/ — never into examples/.
just redact vault/bitwarden_export.json /tmp/redacted.json
```

`bitwarden-redact` enforces this at the binary level: if the `--output`
path resolves inside a git repository AND the filename does not end in
`.redacted.json` AND the path is not under a `vault/` directory, the
tool refuses to write and prints a clear error. The check guards
against the common accidental commit where a user types `--output
sample.json` from the crate root. Pass `--force` to override with a
warning — but there is almost never a good reason to do so, because
the redacted replica still reveals vault-shape metadata (item count,
type distribution, URI counts, match modes, custom field counts) even
though it strips every credential.

All scrubbed custom-field and URI fields are coerced through concrete
Rust types (`as_i64`, `as_bool`, `as_str`) rather than cloned verbatim,
so a future Bitwarden export containing a nonstandard value in
`type`, `reprompt`, `favorite`, `linkedId`, or a URI `match` mode will
collapse to a safe default in the redactor output instead of being
copied through.

What the redactor strips (always replaced with a synthetic placeholder):

- credential material: `login.password`, `login.totp`, `login.fido2Credentials`,
  `login.uris[].uri`
- PII: `login.username`, `notes`, `fields[].name`, `fields[].value`,
  `passwordHistory`, `card.*`, `identity.*`
- vault-origin identifiers: **`id`, `folderId`, `folders[].name`**
- vault-origin timestamps: **`creationDate`, `revisionDate`, `deletedDate`**
  (synthesized from a rank computed inside each duplicate group so the
  dedup tiebreak still picks the same winner)
- org metadata: **`organizationId`, `collectionIds`** (always forced to null)

What the redactor preserves (structural metadata needed for schema
fidelity): `type`, `reprompt`, `favorite`, URI counts per item, URI match
modes, and custom field counts + types.

## Privacy policy for this repository

No committed file in this crate — including the README — may contain
data derived from a real Bitwarden vault. That includes not just
secrets and website domains, but also aggregate statistics (item
counts, duplicate-group counts, per-field totals), real item ids,
folder ids, organization metadata, and real timestamps.

The committed `examples/bitwarden_export_20260411172632.json` fixture is the only
permitted example artifact, and it is produced exclusively by
`tests/fixture.rs::build_curated_fixture()` which synthesizes every
field from constants. The `bitwarden-redact` binary is a local
reviewer-convenience tool; its output matches the `*.redacted.json`,
`*.dedup.json`, and `vault/` gitignore patterns and must never be
placed under `examples/`.

Three integration tests keep this policy enforceable:

- `example_fixture_matches_generator` — the on-disk file must match
  what `build_curated_fixture()` produces, so hand-editing is caught.
- `example_fixture_no_leaked_strings` — every string in the committed
  JSON must match a shape-checked synthetic-placeholder allowlist,
  not a loose prefix.
- `examples_directory_contains_only_fixture` — the `examples/`
  directory may contain only `bitwarden_export_20260411172632.json`.
