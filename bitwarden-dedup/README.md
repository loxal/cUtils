# bitwarden-dedup

Rust CLI that deduplicates a Bitwarden JSON vault export into an import-ready
file. Strict matching, URI merging, and full preservation of TOTP secrets,
FIDO2 credentials, notes, custom fields, and password history.

> **Nothing is ever removed.** Dedup losers get `deletedDate = now` set and
> stay in the output array so Bitwarden shows them in the **Trash** folder
> after import. You can audit every merge and recover any false positive
> by hand — no irreversible data loss.

> **100 % offline.** This tool runs entirely on your machine. It makes
> **zero network connections** — no HTTP calls, no DNS lookups, no
> telemetry, no update checks, no cloud APIs. Your vault data never
> leaves your filesystem. The only I/O is reading the export JSON from
> disk, processing it in memory, and writing the results back to disk.
> This is verifiable: the crate depends only on `clap` (CLI parsing) and
> `serde_json` (JSON parsing) — neither of which provides network
> capability, and neither does any transitive dependency in `Cargo.lock`.

## Quick start

**Step 1 — Export your vault from Bitwarden.**

In the Bitwarden web vault (`vault.bitwarden.com`) or the desktop app:
**Tools → Export Vault → File format: JSON**. Enter your master
password when prompted. This downloads a file named
`bitwarden_export_YYYYMMDDHHMMSS.json` to your `~/Downloads/` folder.

**Step 2 — Move the export into the `vault/` directory.**

```bash
cd bitwarden-dedup
mkdir -p vault
mv ~/Downloads/bitwarden_export_*.json vault/
```

The `vault/` directory is gitignored — nothing you put there will ever
be committed. The export file contains **plaintext passwords, TOTP
seeds, and passkey material**, so keep it here (or in `/tmp/`) and
nowhere else inside the repository.

**Step 3 — Run the dedup.**

```bash
just build
just dedup
```

`just dedup` automatically picks the latest `bitwarden_export_*.json`
file in `vault/` by sorting on the zero-padded timestamp infix (so
if you have multiple exports, the newest one wins). The output and
audit files are written next to the input:

- `vault/bitwarden_export_<ts>.dedup.json` — the deduplicated,
  import-ready file
- `vault/bitwarden_export_<ts>.dedup.audit.json` — per-removal record
  (ids, names, dates — no passwords or TOTP seeds)

**Step 4 — Import the cleaned file back into Bitwarden.**

See the [Import workflow](#import-workflow-bitwarden-web-vault) section
below — the critical step is **Purge Vault before Import**, because
Bitwarden's import always creates new items (it never deduplicates
against the existing vault).

## Why strict matching

A loose dedup key (just `name + username`) will mis-match unrelated accounts
that happen to share a display name. On a real vault with ~1,700 logins, the
loose approach produces dozens of false-positive groups where the passwords
actually differ — those are separate accounts, not duplicates.

`bitwarden-dedup` drops an item only when **every** dedup-key field matches,
and every other piece of information from the dropped item is merged into the
survivor so nothing the user typed is lost.

**Dedup key — items with any of these differences never group:**

| Field | Matching rule |
|---|---|
| `name` | case-insensitive, trimmed, with trailing `(email@address)` disambiguation suffix stripped (e.g. `okta.com (alice@corp.com)` groups with `okta.com`) |
| `login.username` | trimmed; case is **preserved** — `Alice` and `alice` never collapse, because some backends treat usernames as case-sensitive |
| `login.password` | exact |
| `login.fido2Credentials` | canonical equality of the full credential objects (not just `credentialId`); divergent `counter` / `userHandle` / key metadata keeps items distinct — **passkeys are never overwritten by merge** |
| `organizationId` | exact — personal and organization items never cross-dedup (they live in different vaults with different access control) |

**Survivor-merge fields — retained from every item in the duplicate group:**

| Field | Merge rule |
|---|---|
| `login.totp` | single-slot in Bitwarden; the **newest** non-empty TOTP across the group wins (by `revisionDate`). Older rotations are intentionally dropped — they no longer authenticate against the backend. Presence beats absence: a survivor without a TOTP inherits any drop's. This is the only field dedup can displace |
| `notes` | union of distinct non-empty bodies joined by `\n---\n`; dedup key is the trimmed body, but the **raw** text (including surrounding whitespace) is preserved in the output |
| `fields` (custom fields) | union by `(name, value, type, linkedId)` tuple — `linkedId` is the Bitwarden integer that identifies a Linked field's target (`100` = Username, `101` = Password, confirmed from live API) |
| `passwordHistory` | union by `(lastUsedDate, password)`, sorted newest-first after merge |
| `login.uris` | union by `(uri, match_mode)` — different detection modes on the same URL survive as separate entries |
| `collectionIds` | set union across the group — Bitwarden natively supports multiple collection memberships, so unioning is lossless |
| `folderId` | survivor's folder wins (Bitwarden allows one folder per item); any dropped items with a different folder leave a `[bitwarden-dedup] originally also in folder: <names>` line prepended to `notes` so the placement hint survives import |
| `favorite` | logical OR — any item favorited in the group → survivor favorited |
| `name` | longest raw name in the group wins (ties keep the survivor's own name) |

**Survivor selection** — when two items share every key field:

1. Longer `passwordHistory` array wins (captures more rotation records)
2. Then newer `revisionDate`
3. Then newer `creationDate`

Items that are **never** grouped (passed through unchanged):

- non-login types (cards, identities, secure notes)
- items with `reprompt == 1` (master-password gated — too sensitive to
  auto-merge)
- items with an empty password (would spuriously group on `""`)
- items whose name already contains `[duplicate]`
- deleted items (trash)

## Advanced usage

Override the default sibling output/audit paths (point at `/tmp/` or
`vault/`, never at `examples/`):

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

## Merging an Apple Passwords CSV export

Apple's Passwords app (macOS Sequoia / iOS 18+) exports a 6-column CSV
(`Title, URL, Username, Password, Notes, OTPAuth`). The
`bitwarden-merge-icloud` binary merges that CSV into a Bitwarden JSON
vault, producing `<bitwarden_stem>-with-icloud-credentials.json` with the
same dedup rules applied across both sources.

```bash
# Auto-discover the latest bitwarden_export_*.json + newest *-Passwords.csv
# in vault/, emit <bitwarden_stem>-with-icloud-credentials.json nearby.
just merge-with-icloud-credentials-csv

# Or specify explicit paths (bitwarden, icloud, output, audit are positional
# but named by order — use the underlying binary for full clarity):
cargo run --release --bin bitwarden-merge-icloud -- \
  --bitwarden vault/bitwarden_export_20260421040622.json \
  --icloud    vault/2026-04-23-Passwords.csv
```

### What merges

Each CSV row becomes a synthetic Bitwarden item
(`type: 1` login when it has URL/username/password/OTP; `type: 2` secure
note if only Title+Notes). These are appended to the Bitwarden `items`
array, then the shared dedup pipeline runs:

- **Credentials** already present in Bitwarden are preserved; CSV
  duplicates collapse and the loser is trashed (see below).
- **URIs** union across the group — a CSV row that adds a new URL merges
  that URL into the existing Bitwarden item.
- **Notes** union with the usual `\n---\n` separator; raw whitespace
  preserved on the survivor.
- **TOTP** — newest wins by `revisionDate`. Fresh CSV imports stamp
  `revisionDate = now`, so CSV TOTPs override older Bitwarden ones;
  older secrets are preserved in Trash (recoverable).
- **Passkeys / FIDO2** are part of the strict dedup key, so two items
  with different passkey sets never collapse. Any passkey already on a
  Bitwarden item is preserved untouched.
- **Custom fields, passwordHistory, collectionIds, folder hints,
  favorite flag** — all merged exactly as they are for pure-Bitwarden
  dedup runs.

### What is **not** merged

Apple's CSV export does not contain the following, so this tool cannot
transfer them — they remain in iCloud Keychain only:

- **Passkeys / FIDO2** credentials — Apple does not export them to CSV.
- **Wi-Fi passwords** — stored in a separate vault section, excluded
  from CSV export.
- **Sign-in-with-Apple** tokens — excluded from CSV export.
- **Deleted (recently-removed) items** — the CSV is an active-only
  snapshot. Apple's "Recently Deleted" list for Passwords is not part
  of the export.

The tool prints this caveat to stdout at the end of every run.

### Trashing semantics (applies to both dedup and merge)

Dedup never removes an item. Losers get `deletedDate = <ISO-8601 now>`
and stay in the output array, so after you import into Bitwarden they
appear in the **Trash** folder. If you spot a false positive, restore
it from Trash — no data is ever lost. This applies to:

- Items dropped when two Bitwarden items turn out to be duplicates.
- Items dropped when a CSV row collapses with a Bitwarden item (either
  the CSV copy or the existing one becomes the loser, depending on
  `passwordHistory` length and `revisionDate`).
- Items that arrived already trashed in the input (they pass through
  with their original `deletedDate` intact).

Audit counts for a run appear both in stdout and in
`<bitwarden_stem>-with-icloud-credentials.audit.json`:
`combined_trashed_count`, `combined_living_count`, `duplicate_groups`,
`uris_merged_into_kept_total`, plus one entry per trashed item.

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
