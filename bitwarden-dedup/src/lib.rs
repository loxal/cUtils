// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Shared library for the `bitwarden-dedup` binaries.
//!
//! Both the main `bitwarden-dedup` binary and the `bitwarden-redact` binary
//! need to agree on what constitutes a "duplicate" in a Bitwarden export.
//! This crate is the single source of truth for that decision.
//!
//! The code is organised around three questions:
//!
//! - **"Is this a duplicate?"** — [`key`] holds the dedup equality rules
//!   ([`dedup_key`], [`normalize_name`], [`skip_from_dedup`], FIDO2
//!   signature, username normalization).
//! - **"What data is merged into the survivor?"** — [`merge`] owns the
//!   survivor-patching rules (notes, URIs, passwordHistory, custom fields,
//!   collectionIds, folder disambiguation notes, favorite flag).
//! - **"Which item survives, and what's the audit trail?"** — [`pipeline`]
//!   orchestrates the four-pass run and builds [`DedupStats`].
//!
//! URI-set logic lives in [`uris`] because both the key layer and the merge
//! layer treat URIs as opaque strings with no case folding.
//!
//! URIs are treated as opaque strings with no case folding. That matters for
//! `androidapp://` URIs where the package-name segment is case-sensitive by
//! Android spec.

mod icloud;
pub mod io_util;
mod json_util;
mod key;
pub mod live_vault;
mod merge;
mod pipeline;
mod time_util;
mod uris;

pub use icloud::{
    MergeStats, merge_icloud_csv_into_export, merge_icloud_csv_into_export_with_config,
};
pub use key::{dedup_key, normalize_name, skip_from_dedup};
pub use pipeline::{
    DedupConfig, DedupStats, dedup_export, dedup_export_with_config, dedup_items,
    dedup_items_with_config,
};
pub use uris::{uri_pairs, uris_to_merge};
