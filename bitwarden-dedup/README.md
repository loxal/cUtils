# bitwarden-dedup

Rust CLI that deduplicates a Bitwarden JSON vault export into an import-ready
file. Strict matching, URI merging, and full preservation of TOTP secrets,
FIDO2 credentials, notes, custom fields, and password history.

> **Nothing is ever removed.** Dedup losers get `deletedDate = now` set
> and are split into a **sidecar file** (`*.dedup.trashed.json` /
> `*-with-icloud-credentials.trashed.json`) — same Bitwarden-JSON
> shape, not auto-imported. The main output file contains **only
> living items** so Bitwarden's active view stays clean after import
> regardless of how the target client version handles `deletedDate`.
> The sidecar is your offline recovery copy; import it separately
> only if you want to populate Bitwarden's Trash folder.

> **JSON-path tools are 100 % offline.** The original four binaries
> (`bitwarden-dedup`, `bitwarden-merge-icloud`, `bitwarden-redact`,
> `bitwarden-move-to-folder`) run entirely on your machine, with zero
> network calls, telemetry, update checks, or cloud APIs. They read a
> JSON export, process it in memory, and write the results back to
> disk. Use these whenever you can.
>
> **Live-vault backups use two different source paths.**
>
> - **`just backup-vault-encrypted`** — writes the raw encrypted
>   `/api/sync` body to `vault/bitwarden_encrypted-export_<UTC-ts>.json`
>   (0o600, gitignored). No master password requested; cron-friendly.
>   This is a forensic/API snapshot from `https://api.bitwarden.com`
>   or `.eu` using the personal API key in `vault/bitwarden_api_key.env`.
> - **`just backup-vault-decrypted`** — uses the same REST/API-key
>   path, then prompts for the master password locally and decrypts
>   every cipher field. Raw `/api/sync` contains Trash and Archive;
>   the dedup-ready output filters Trash by default to match official
>   `bw export --format json` semantics and preserves Archive via
>   `archivedDate`. Use `--include-trash` only for forensic snapshots;
>   those files are suffixed `-with-trash.json` and skipped by
>   `just dedup` auto-discovery.
> - **`just backup-vault-decrypted-via-bw-cli`** — cross-check path
>   through the official CLI's own export command: `bw sync --force`,
>   then `bw --raw export --format json`. Same `bw export` contract
>   as the direct-REST sibling (Trash filtered, Archive preserved),
>   so for the same server state the two backups should agree on id
>   sets and per-cipher field tuples. Prerequisite: the Bitwarden CLI
>   is logged in and unlocked
>   (`export BW_SESSION="$(bw unlock --raw)"`).
>
> The decrypted output is **plaintext-sensitive** (passwords, TOTP
> seeds, FIDO2 material in the clear) — same risk profile as
> `bw export --format json`. Treat accordingly: never share, delete
> after use, never commit.

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
  import-ready file (LIVING items only, `deletedDate: null` on every
  entry — ready to import cleanly into Bitwarden's active vault)
- `vault/bitwarden_export_<ts>.dedup.trashed.json` — dedup losers and
  any items that arrived pre-trashed, in the same Bitwarden-JSON
  shape; NOT auto-imported, kept as an offline recovery copy
- `vault/bitwarden_export_<ts>.dedup.audit.json` — per-removal record
  (ids, names, dates — no passwords or TOTP seeds)

> **Merging an Apple Passwords CSV at the same time?** Skip `just dedup`
> and run `just merge-with-icloud-credentials-csv` instead. The merge
> recipe runs the full dedup pipeline internally on the combined
> (Bitwarden + iCloud) set, so it deduplicates the Bitwarden side for
> you in one pass. See [Merging an Apple Passwords CSV
> export](#merging-an-apple-passwords-csv-export).

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
| `login.totp` | single-slot in Bitwarden; the **newest** non-empty TOTP across the group wins (by `revisionDate`). Older rotations are intentionally dropped — they no longer authenticate against the backend. Presence beats absence: a survivor without a TOTP inherits any drop's. This is the only field dedup can displace — see the [TOTP caveat](#a-note-on-the-totp-heuristic) below |
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

Items that are **never** grouped (passed through byte-identical):

- items with `reprompt == 1` (master-password gated — too sensitive to
  auto-merge)
- items with an empty password whose **only** identifying signal is
  their name (no username, no URI host, no fido2 credential). The
  [empty-password dedup pass](#empty-password-dedup-pass) runs by
  default and groups credential-less stubs that share at least one
  of `{username, URI hostname, fido2}`; pass `--keep-empty-password-stubs`
  if you'd rather inspect every stub by hand.
- items whose name already contains `[duplicate]`
- already-trashed items (their `deletedDate` is preserved as-is)

### SSH keys (`type: 5`) dedup

SSH keys dedup in their own pass under a strict key: two `type: 5`
items only collapse when they carry **exactly the same** `sshKey`
object — public key, private key, and fingerprint are all part of the
grouping key, plus the organization id. Any byte-level mismatch in the
key material keeps items separate (a public-key collision with
divergent private halves is almost certainly vault corruption, not a
merge candidate).

Survivor selection is the simplest possible: newer `revisionDate`,
then newer `creationDate`. The surviving SSH key's key material is
never modified — only name (longest raw name wins), favorite (OR),
custom-field union, collection-id union, and folder-disambiguation
note get merged.

### Cards (`type: 3`) dedup

Cards run through the same strict-equality pass as SSH keys. Two
cards collapse only when **every byte** of the `card` block matches
— `cardholderName`, `brand`, `number`, `expMonth`, `expYear`, `code`
(CVV) — plus a normalized name and the organization id. Any
mismatch in any field keeps items distinct: a different CVV, a
different expiry month, even a trailing space in the cardholder
name keeps the items separate. This is intentionally conservative;
the cost of over-merging stored card data is the wrong card on
file, and that's a class of error worth refusing.

Survivor selection: newer `revisionDate`, then newer `creationDate`.
The surviving card's `card` block is byte-identical to every drop's
by construction (everything is in the grouping key), so the survivor
keeps its own block untouched. Only metadata merges: longest name,
favorite OR, custom-field union, collection-id union, and folder
disambiguation note. Audit entries carry `"item_kind": "card"`.

### Identities (`type: 4`) dedup

Identities follow the same strict-equality pattern. Every populated
field of the `identity` block participates in the grouping key:
`title`, `firstName`, `middleName`, `lastName`, `address1..3`,
`city`, `state`, `postalCode`, `country`, `company`, `email`,
`phone`, `ssn`, `username`, `passportNumber`, `licenseNumber`. Plus
the normalized name and organization id. Any mismatch in any
populated field keeps items distinct.

Same survivor-selection and merge rules as cards — the `identity`
block is byte-identical across the group, only metadata merges onto
the survivor. Audit entries carry `"item_kind": "identity"`.

> Both passes run by default — there is no opt-in flag. The strict-
> equality bar is the safety floor: we only collapse items that are
> indistinguishable in every credential-relevant field. Losers route
> to the trash sidecar like every other dedup loser, so any
> disagreement with a merge is recoverable.

### Folder dedup

The top-level `folders` array gets its own small dedup pass before
item dedup runs. Two folders with the same normalized name (case-fold
+ trim + invisible-character scrub — see [Secure Notes
dedup](#secure-notes-type-2-dedup) for the normalization rule set)
collapse to one survivor per name; every item's `folderId` is then
remapped to the surviving folder's id so references stay valid after
import. The survivor per group is the folder that appears first in
input order — Bitwarden exports don't carry a `revisionDate` on
folders, so there is no better tiebreak.

Most useful when an earlier additive import left your export with
multiple copies of the same folder (e.g. two `main` folders). The
audit JSON reports `folders_deduplicated` so you can grep for runs
that collapsed any folders.

### Secure Notes (`type: 2`) dedup

Secure notes also dedup, but under a **deliberately strict key** — name
alone is too aggressive for notes (generic titles like `Recovery`,
`Wallet`, `API keys`, `credentials.txt` are common), so the key
includes the trimmed body and the organization id. Only literal
duplicates collapse; semantically distinct items that happen to share
a name stay as separate living items.

- **Grouping key**: `(normalize_note_name(name), organizationId,
  canonicalize_note_body(notes))`.
  - `normalize_note_name` folds case, trims Unicode whitespace, and
    strips invisible / default-ignorable characters (ZWSP, ZWNJ,
    BOM, soft hyphen, bidi overrides, …). It **intentionally does
    NOT** strip `(email@…)` suffixes the way login-name
    normalization does — for a note title, that suffix can be
    meaningful content.
  - `organizationId` keeps personal and org-owned notes in separate
    groups — different vaults, different access control.
  - `canonicalize_note_body` applies the same invisible-character
    scrubbing plus Unicode-aware outer-trim. Different bodies mean
    different notes.
- **Survivor selection**: non-CSV origin first (Bitwarden id >
  `apple-csv-…`, so folder/favorite/fields on the BW side are
  retained), then newer `revisionDate`, then newer `creationDate`.
- **Other fields**: longest raw name wins, favorite OR, custom
  fields union, collection-id union, folder disambiguation note
  (same as logins — a drop in a different folder leaves
  `[bitwarden-dedup] originally also in folder: …` on the survivor).
- **Trash**: losers get `deletedDate = now` and are split into the
  trash sidecar file alongside the main output; full recovery path
  if you disagree with a merge.

Secure notes and logins live in separate key namespaces — a login
named `credentials.txt` and a secure note named `credentials.txt`
never collide.

**If you have same-name secure notes with divergent bodies that you
*know* are the same concept** (e.g. two copies of the Wi-Fi router
password where one has a trailing timestamp), the tool will keep them
as separate items on purpose. Reconcile by hand in the Bitwarden UI
after import; the safer default here is to under-merge rather than
risk a semantic false positive on a generic title.

### A note on the TOTP heuristic

`revisionDate` is the **item-level** last-modified timestamp — Bitwarden
touches it when you edit notes, toggle the favorite flag, add a URL,
etc. It is *not* a TOTP-specific timestamp. So the "newest TOTP wins"
rule can in principle put the wrong live secret on the survivor when an
item carrying an older TOTP had some other field edited recently.

Mitigations already baked in:

- Losers are **trashed, not deleted** — every TOTP still reaches the
  output inside its original item, preserved in the trash sidecar
  file that accompanies the main output.
- The audit file surfaces every affected group. Each entry carries
  `totp_conflict` (bool), `totp_kept_from_id` (which item contributed
  the survivor's TOTP), and `removed_totp_present` (did the trashed
  item carry its own TOTP). A top-level `totp_conflict_groups` count
  also appears.

If you would rather not auto-collapse any group whose TOTPs diverge,
pass `--split-divergent-totps`. With the flag set, items that differ
only in `login.totp` stay as separate living items; you can reconcile
them by hand. The flag is propagated to both `bitwarden-dedup` and
`bitwarden-merge-icloud`, and both `just` recipes expose the safer
mode without dropping to raw `cargo run`:

```bash
just dedup-split-totps                             # plain dedup
just merge-with-icloud-credentials-csv-split-totps # iCloud merge
```

### Empty-password dedup pass

Runs by default. Targets credential-less stubs the strict pass
deliberately skips — items with an empty `login.password`, typically
from browser auto-save loops where the same domain gets saved
repeatedly without a password, leaving 10–30 identical entries. To
preserve the older conservative behavior (every stub stays as a
separate living item), pass `--keep-empty-password-stubs` or run
`just dedup-keep-empty-password-stubs`.

The pass requires **all** of the following to match before collapsing:

| Field | Match rule |
|---|---|
| `name` | same `normalize_name` rule as the strict pass (case-fold, email-suffix strip) |
| `organizationId` | exact — personal and org items never cross-dedup |
| `login.username` | trim-only, case preserved |
| URI host set | sorted set of `(HostKind, host_token)` pairs from `login.uris`. Hosts pulled via `host_of` (see below). |
| `login.fido2Credentials` | canonical full credential equality, same as the strict pass |

It also requires **at least one** of `{username, URI host set, fido2}`
to be non-empty. An item with empty password + empty username +
empty URI list + no fido2 has nothing to group on beyond the
display name; the pass refuses to collapse such items.

**URI hostname extraction (`host_of`)** mirrors the no-case-folding
policy already used by `src/uris.rs`:

- `http`, `https`, `ws`, `wss` URLs → host pulled by `url::Url`,
  lowercased (DNS is case-insensitive). **Non-default ports preserved**
  in the host token (`example.com:8443` stays distinct from
  `example.com`).
- `androidapp://com.example.app/...` → package name preserved
  verbatim (Android packages are case-sensitive). Path / query /
  fragment stripped.
- Anything else (custom schemes like `myapp://`, bare reverse-DNS
  App IDs, unparseable strings) → the entire URI is preserved
  case-exact and tagged as opaque. Critically, this means
  `myapp://Login?token=abc` and `myapp://login?token=def` stay split
  — we do not case-fold identifiers from unknown-scheme URIs.

**Survivor selection and merge rules** are identical to the strict
pass: longer `passwordHistory` → newer `revisionDate` → newer
`creationDate`; URIs/notes/fields/passwordHistory/collections all
union onto the survivor; folder disambiguation note added when a
drop sat in a different folder; favorite is OR'd; longest raw name
wins. Trash routing is identical too — losers carry `deletedDate =
now` and split into the trash sidecar.

**Audit entries** for this pass carry `"item_kind":
"empty_password_login"` plus a `"signal_kind"` field (`"fido2"`,
`"host"`, or `"username_only"`) so reviewers can grep the riskier
classes:

```bash
# Spot-check the weakest evidence class — username-only groups.
jq '.entries[] | select(.signal_kind == "username_only")' \
   vault/bitwarden_export_<ts>.dedup.audit.json
```

`username_only` is the weakest signal class because two distinct
accounts at different sites that happen to share an email-as-username
display name could in principle collapse. The trash sidecar preserves
every loser fully, so any false positive is recoverable. The audit
JSON additionally surfaces a `"empty_password_groups_by_signal":
{"fido2": F, "host": H, "username_only": U}` summary at the top level.

> Tradeoff: the pass collapses items that look like the same account
> but happen to be unfilled (e.g. you started typing the password but
> didn't save). The loser's URIs, notes, custom fields, and password
> history all union onto the survivor, so nothing the user typed is
> lost. If you would rather hand-reconcile such groups, pass
> `--keep-empty-password-stubs` (or run
> `just dedup-keep-empty-password-stubs`) — every stub then survives
> as its own living item.

### A note on the note-body heuristic

Note merging deduplicates by the **trimmed** body (`raw.trim()`), but
stores the survivor's **raw** text byte-for-byte. That means two notes
differing only by surrounding whitespace collapse to a single preserved
variant — acceptable for all vaults we've seen, but it does erase
formatting-only distinctions if you deliberately use surrounding
whitespace inside notes.

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

> **`just dedup` is not required before `just merge-with-icloud-credentials-csv`.**
> The merge recipe runs the full dedup pipeline internally on the
> combined (Bitwarden + CSV) set in one pass, so it already deduplicates
> the Bitwarden side for you. The output
> `<bitwarden_stem>-with-icloud-credentials.json` is self-contained and
> import-ready — you do not also need to consume a separate `.dedup.json`.
>
> Run `just dedup` on its own only when (a) you have no iCloud CSV to
> merge and want pure Bitwarden cleanup, or (b) you want to review an
> intermediate Bitwarden-only artifact before adding iCloud data.

```bash
# Auto-discover the latest bitwarden_export_*.json + newest *-Passwords.csv
# in vault/, emit <bitwarden_stem>-with-icloud-credentials.json nearby.
just merge-with-icloud-credentials-csv

# Same as above but with the safer --split-divergent-totps mode: items that
# differ only in login.totp stay as separate living items instead of auto-
# collapsing by revisionDate. See "A note on the TOTP heuristic" above.
just merge-with-icloud-credentials-csv-split-totps

# Or specify explicit paths (bitwarden, icloud, output, audit are positional
# but named by order — use the underlying binary for full clarity):
cargo run --release --bin bitwarden-merge-icloud -- \
  --bitwarden vault/bitwarden_export_20260421040622.json \
  --icloud    vault/2026-04-23-Passwords.csv
```

### Fail-fast validation

The iCloud merge path feeds straight into a purge-and-reimport, so the
tool rejects obviously wrong inputs loudly rather than best-efforting
them through:

- **Wrong CSV header** — missing any of the six Apple columns (`Title`,
  `URL`, `Username`, `Password`, `Notes`, `OTPAuth`) aborts before
  anything is written. Extra unknown columns are still accepted for
  forward-compat with future Apple releases.
- **Malformed CSV quoting** — an export that ends inside a quoted field
  is refused (unterminated quote = almost certainly truncated file).
- **Non-array `items`** — if the Bitwarden JSON carries an `items` field
  that is not an array, the tool refuses to silently overwrite it.
  Missing `items` entirely is allowed (bootstraps a fresh array).
- **Atomic writes** — output and audit files land via a same-directory
  temp file + `rename()`, so an interrupted write never leaves a
  partially-populated file at the destination path.

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
- **Secure Notes (`type: 2`)** — a note-only CSV row (Title + Notes,
  no credentials) becomes its own `type: 2` Secure Note item. After
  the CSV rows are appended, the shared dedup pipeline runs a
  dedicated Secure-Note pass that only collapses **literal
  duplicates** — same `normalize_name(name)`, same `organizationId`,
  same trimmed `notes` body. Bitwarden-origin secure notes outrank
  same-named CSV rows as the survivor, so folder / favorite / fields
  stay on the Bitwarden side by default. CSV rows whose body
  *differs* from every existing Bitwarden note of the same name stay
  as separate living items — the tool deliberately under-merges
  rather than risk a semantic false positive. See
  [Secure Notes dedup](#secure-notes-type-2-dedup) for the full rule set.

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

### Trashing semantics: two output files (applies to both dedup and merge)

Dedup never removes an item. Every input item lands in one of two
output files, never deleted from disk:

- `<stem>.dedup.json` (or `<stem>-with-icloud-credentials.json` for
  the merge path) — **LIVING items only**. Every entry has
  `deletedDate: null`. This is the file you import into Bitwarden;
  its active vault will exactly match these items after a
  purge-and-reimport.
- `<stem>.dedup.trashed.json` (or
  `<stem>-with-icloud-credentials.trashed.json`) — **trashed
  losers**, same Bitwarden-JSON top-level shape, every entry carries
  a non-null `deletedDate`. This file is **not imported
  automatically**. It is your offline recovery copy: if you disagree
  with any merge, look here to find the loser's full contents. If
  your Bitwarden client version reliably honors `deletedDate` on
  import, you can import this sidecar separately to populate the
  Trash folder; if not, keep it as a local reference only.

**Why the split?** Bitwarden's JSON importer handles `deletedDate`
inconsistently across client versions — some put the items in Trash,
others import them as active, producing visible duplicates in the
Secure Notes / Logins views. Keeping trashed items out of the main
`items` array is the only way to guarantee a clean active vault after
import regardless of Bitwarden version.

Items routed to the sidecar:

- Losers from duplicate login groups (same credentials).
- Losers from duplicate Secure Note groups (same name + body + org).
- CSV rows that collapsed with an existing Bitwarden item.
- Items that arrived already trashed in the input (their original
  `deletedDate` is preserved as-is).

Audit counts for a run appear both in stdout and in
`<bitwarden_stem>-with-icloud-credentials.audit.json`:
`combined_trashed_count`, `combined_living_count`, `duplicate_groups`,
`totp_conflict_groups`, `uris_merged_into_kept_total`, plus one entry per
trashed item with per-group merge-sensitivity flags (`totp_conflict`,
`totp_kept_from_id`, `notes_merged`, `fields_merged`, `collections_merged`,
`folder_note_added`, `removed_totp_present`). Grep the audit for
`"totp_conflict": true` to review every group where dedup had to pick
between multiple TOTPs — or rerun with `--split-divergent-totps` to
skip such collapses altogether.

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
               22 items total, 7 skipped by strict pass
Groups:        5 total dedup groups
                 strict login: 5
Trashed:       6 items routed out of the active `items` array (survivor picked by longer passwordHistory, then newer revisionDate)
URIs merged:   3 unique URLs preserved from dropped items
               (notes, custom fields, TOTP, passwordHistory, collections, folders — all merged into survivors)
Output:        /tmp/example.dedup.json
               15 items — all living (clean import into Bitwarden's active vault)
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
- vault-origin timestamps: **`creationDate`, `revisionDate`, `deletedDate`, `archivedDate`**
  (synthesized from a rank computed inside each duplicate group so the
  dedup tiebreak still picks the same winner)
- org metadata: **`organizationId`, `collectionIds`** (always forced to null)

What the redactor preserves (structural metadata needed for schema
fidelity): `type`, `reprompt`, `favorite`, URI counts per item, URI match
modes, and custom field counts + types.

## Support

If `bitwarden-dedup` saved you an evening of manual cleanup, rescued a vault
from runaway duplicates, or replaced a fragile spreadsheet workflow, a
one-time **$1–2** tip is the realistic value of an hour of someone else's
tooling work — and a meaningful signal that this kind of careful, offline,
secret-respecting CLI work is worth maintaining.

→ [github.com/sponsors/loxal](https://github.com/sponsors/loxal)

The binaries themselves stay free, offline, and nag-free: no telemetry, no
upsell, no donate prompt at runtime. The link lives here in the README and
nowhere else. Use it only if (and when) the tool actually pulled its weight
for you.

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
