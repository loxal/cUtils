// Copyright 2026 Alexander Orlov <alexander.orlov@loxal.net>

//! Structural correctness gate for the Phase 1b decrypt path.
//!
//! Validates the integration contract that matters most: **JSON
//! emitted by `decrypt_sync_to_export_shape` is consumable by the
//! existing JSON-path dedup pipeline** (`dedup_export_with_config`).
//!
//! If a future change to `cipher_codec` accidentally drops a field
//! name, renames `secureNote` to `secure_note`, emits an array
//! where the dedup pipeline expects an object, etc., this test
//! fails — even if the cipher_codec's own unit tests still pass,
//! because the dedup pipeline has its own (stricter) shape
//! expectations.
//!
//! This is the "would `just dedup` work on the output?" gate the
//! audit asked for, expressed as a Rust test rather than an
//! external fixture comparison. It runs on every `cargo test`.

use std::num::NonZeroU32;

use bitwarden_dedup::live_vault::cipher_codec::decrypt_sync_to_export_shape;
use bitwarden_dedup::live_vault::crypto::{
    KdfParams, SymmetricKey, derive_master_key, stretch_master_key,
};
use bitwarden_dedup::{DedupConfig, dedup_export_with_config};
use secrecy::SecretString;

/// End-to-end: build a synthetic /api/sync with one cipher of each
/// type the dedup pipeline cares about (login, secureNote, sshKey),
/// decrypt it, then feed the decrypted output through
/// `dedup_export_with_config`. Both the decrypt AND the dedup
/// pipeline must succeed; any shape mismatch fails the test.
#[test]
fn decrypted_output_runs_through_dedup_pipeline_without_error() {
    let pw = SecretString::new("67t9b5g67$%Dh89n".to_string().into());
    let kdf = KdfParams::Argon2id {
        iterations: NonZeroU32::new(4).unwrap(),
        memory_mib: NonZeroU32::new(32).unwrap(),
        parallelism: NonZeroU32::new(2).unwrap(),
    };
    let mk = derive_master_key(&pw, "test_key", kdf).unwrap();
    let stretched = stretch_master_key(&mk);

    // Synthetic 64-byte user key (the same one used by the
    // cipher_codec end-to-end test).
    let user_key = symmetric_key_from_split([0xa5u8; 32], [0xa5u8; 32]);
    let uk_bytes = vec![0xa5u8; 64];
    let user_key_str = encrypt_for_test(&stretched, b"deterministic-iv-1", &uk_bytes);

    // Encrypt a few cipher fields under the user key — one each of
    // login, secureNote, sshKey (the three types `bitwarden-dedup`
    // operates on).
    let login_name = encrypt_for_test(&user_key, b"deterministic-iv-2", b"GitHub");
    let login_user = encrypt_for_test(&user_key, b"deterministic-iv-3", b"alex@example.test");
    let login_pwd = encrypt_for_test(&user_key, b"deterministic-iv-4", b"hunter2");
    let login_uri = encrypt_for_test(&user_key, b"deterministic-iv-5", b"https://github.com");

    let note_name = encrypt_for_test(&user_key, b"deterministic-iv-6", b"Recovery codes");
    let note_body = encrypt_for_test(&user_key, b"deterministic-iv-7", b"abc-def-ghi-jkl-mno-pqr");

    let ssh_name = encrypt_for_test(&user_key, b"deterministic-iv-8", b"laptop-ed25519");
    let ssh_priv = encrypt_for_test(
        &user_key,
        b"deterministic-iv-9",
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
    );
    let ssh_pub = encrypt_for_test(&user_key, b"deterministic-iv-a", b"ssh-ed25519 AAAA fake");
    let ssh_fp = encrypt_for_test(&user_key, b"deterministic-iv-b", b"SHA256:abcd");

    let sync_body = format!(
        r#"{{
            "profile": {{
                "email": "test_key",
                "key": "{user_key_str}"
            }},
            "folders": [],
            "ciphers": [
                {{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "type": 1,
                    "name": "{login_name}",
                    "login": {{
                        "username": "{login_user}",
                        "password": "{login_pwd}",
                        "uris": [{{ "uri": "{login_uri}", "match": null }}]
                    }}
                }},
                {{
                    "id": "00000000-0000-0000-0000-000000000002",
                    "type": 2,
                    "name": "{note_name}",
                    "notes": "{note_body}",
                    "secureNote": {{ "type": 0 }}
                }},
                {{
                    "id": "00000000-0000-0000-0000-000000000003",
                    "type": 5,
                    "name": "{ssh_name}",
                    "sshKey": {{
                        "privateKey": "{ssh_priv}",
                        "publicKey": "{ssh_pub}",
                        "keyFingerprint": "{ssh_fp}"
                    }}
                }}
            ]
        }}"#,
    );

    // Decrypt — exercises the full cipher_codec pipeline.
    let mut decrypted = decrypt_sync_to_export_shape(&sync_body, kdf, &pw)
        .expect("decrypt_sync_to_export_shape must succeed on a well-formed synthetic vault")
        .value;

    // Sanity-check the produced shape before handing to dedup.
    let items = decrypted["items"].as_array().expect("items must be array");
    assert_eq!(items.len(), 3, "expected 3 items in decrypted output");
    assert_eq!(decrypted["encrypted"], serde_json::json!(false));
    assert!(decrypted["folders"].is_array());

    // STRUCTURAL GATE: feed produced JSON through the dedup
    // pipeline. The pipeline parses every item, walks logins +
    // secureNotes + sshKeys, and runs the dedup decision. Any
    // shape mismatch (renamed field, wrong type, missing required
    // sub-object) fails here.
    let stats = dedup_export_with_config(&mut decrypted, &DedupConfig::default())
        .expect("dedup pipeline must consume cipher_codec's JSON output without error");

    // No duplicates in this synthetic input, so trashed=0,
    // groups=0. The dedup pipeline saw 3 items.
    assert_eq!(stats.total, 3);
    assert_eq!(stats.trashed, 0);
    assert_eq!(stats.groups, 0);
}

/// As above but with TWO duplicate logins, to ensure the shape is
/// rich enough that the dedup pipeline actually identifies and
/// merges duplicates (catches the case where our shape is "valid
/// enough" to parse but missing fields the dedup key needs).
#[test]
fn decrypted_output_lets_dedup_pipeline_actually_dedup() {
    let pw = SecretString::new("67t9b5g67$%Dh89n".to_string().into());
    let kdf = KdfParams::Argon2id {
        iterations: NonZeroU32::new(4).unwrap(),
        memory_mib: NonZeroU32::new(32).unwrap(),
        parallelism: NonZeroU32::new(2).unwrap(),
    };
    let mk = derive_master_key(&pw, "test_key", kdf).unwrap();
    let stretched = stretch_master_key(&mk);

    let user_key = symmetric_key_from_split([0xa5u8; 32], [0xa5u8; 32]);
    let uk_bytes = vec![0xa5u8; 64];
    let user_key_str = encrypt_for_test(&stretched, b"deterministic-iv-A", &uk_bytes);

    // Two logins identical on (name, username, password) — must
    // collapse to one survivor + one trashed.
    let same_name = encrypt_for_test(&user_key, b"deterministic-iv-B", b"Gmail");
    let same_user = encrypt_for_test(&user_key, b"deterministic-iv-C", b"alex@example.test");
    let same_pwd = encrypt_for_test(&user_key, b"deterministic-iv-D", b"hunter2");
    // Same plaintext encrypted under different IVs → two different
    // ciphertexts. Both must decrypt to identical strings.
    let same_name_2 = encrypt_for_test(&user_key, b"deterministic-iv-E", b"Gmail");
    let same_user_2 = encrypt_for_test(&user_key, b"deterministic-iv-F", b"alex@example.test");
    let same_pwd_2 = encrypt_for_test(&user_key, b"deterministic-iv-G", b"hunter2");

    let sync_body = format!(
        r#"{{
            "profile": {{
                "email": "test_key",
                "key": "{user_key_str}"
            }},
            "folders": [],
            "ciphers": [
                {{
                    "id": "00000000-0000-0000-0000-000000000010",
                    "type": 1,
                    "name": "{same_name}",
                    "revisionDate": "2026-04-25T00:00:00Z",
                    "login": {{
                        "username": "{same_user}",
                        "password": "{same_pwd}",
                        "uris": null
                    }}
                }},
                {{
                    "id": "00000000-0000-0000-0000-000000000011",
                    "type": 1,
                    "name": "{same_name_2}",
                    "revisionDate": "2026-04-26T00:00:00Z",
                    "login": {{
                        "username": "{same_user_2}",
                        "password": "{same_pwd_2}",
                        "uris": null
                    }}
                }}
            ]
        }}"#,
    );

    let mut decrypted = decrypt_sync_to_export_shape(&sync_body, kdf, &pw)
        .unwrap()
        .value;
    let stats = dedup_export_with_config(&mut decrypted, &DedupConfig::default()).unwrap();

    assert_eq!(stats.total, 2, "two items in input");
    assert_eq!(
        stats.groups, 1,
        "the two identical-credentials items must form one duplicate group"
    );
    assert_eq!(
        stats.trashed, 1,
        "one of the pair gets trashed (deletedDate stamped)"
    );
}

#[test]
fn decrypted_archived_duplicate_survives_dedup_unchanged() {
    let pw = SecretString::new("67t9b5g67$%Dh89n".to_string().into());
    let kdf = KdfParams::Argon2id {
        iterations: NonZeroU32::new(4).unwrap(),
        memory_mib: NonZeroU32::new(32).unwrap(),
        parallelism: NonZeroU32::new(2).unwrap(),
    };
    let mk = derive_master_key(&pw, "test_key", kdf).unwrap();
    let stretched = stretch_master_key(&mk);

    let user_key = symmetric_key_from_split([0xa5u8; 32], [0xa5u8; 32]);
    let uk_bytes = vec![0xa5u8; 64];
    let user_key_str = encrypt_for_test(&stretched, b"archive-test-iv-A", &uk_bytes);

    // Two logins identical on the dedup key, except the second is
    // archived. Archive is a visibility state that Bitwarden exports;
    // dedup must preserve it rather than merging it into the active twin.
    let name_1 = encrypt_for_test(&user_key, b"archive-test-iv-B", b"ArchiveTwin");
    let user_1 = encrypt_for_test(&user_key, b"archive-test-iv-C", b"alex@example.test");
    let pwd_1 = encrypt_for_test(&user_key, b"archive-test-iv-D", b"hunter2");
    let name_2 = encrypt_for_test(&user_key, b"archive-test-iv-E", b"ArchiveTwin");
    let user_2 = encrypt_for_test(&user_key, b"archive-test-iv-F", b"alex@example.test");
    let pwd_2 = encrypt_for_test(&user_key, b"archive-test-iv-G", b"hunter2");

    let sync_body = format!(
        r#"{{
            "profile": {{
                "email": "test_key",
                "key": "{user_key_str}"
            }},
            "folders": [],
            "ciphers": [
                {{
                    "id": "00000000-0000-0000-0000-000000000020",
                    "type": 1,
                    "name": "{name_1}",
                    "revisionDate": "2026-04-25T00:00:00Z",
                    "login": {{
                        "username": "{user_1}",
                        "password": "{pwd_1}",
                        "uris": null
                    }}
                }},
                {{
                    "id": "00000000-0000-0000-0000-000000000021",
                    "type": 1,
                    "name": "{name_2}",
                    "revisionDate": "2026-04-26T00:00:00Z",
                    "archivedDate": "2026-04-27T12:00:00Z",
                    "login": {{
                        "username": "{user_2}",
                        "password": "{pwd_2}",
                        "uris": null
                    }}
                }}
            ]
        }}"#,
    );

    let mut decrypted = decrypt_sync_to_export_shape(&sync_body, kdf, &pw)
        .unwrap()
        .value;
    let stats = dedup_export_with_config(&mut decrypted, &DedupConfig::default()).unwrap();

    assert_eq!(stats.total, 2);
    assert_eq!(
        stats.groups, 0,
        "archived items must not enter dedup groups"
    );
    assert_eq!(stats.trashed, 0);

    let items = decrypted["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let archived = items
        .iter()
        .find(|item| item["id"] == "00000000-0000-0000-0000-000000000021")
        .expect("archived twin must survive");
    assert_eq!(
        archived["archivedDate"],
        serde_json::json!("2026-04-27T12:00:00Z")
    );
    assert!(items.iter().all(|item| item["deletedDate"].is_null()));
}

// -----------------------------------------------------------------
// Test helpers — duplicated from cipher_codec tests because those
// helpers are private to the module. Kept minimal.
// -----------------------------------------------------------------

fn symmetric_key_from_split(enc: [u8; 32], mac: [u8; 32]) -> SymmetricKey {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&enc);
    buf.extend_from_slice(&mac);
    SymmetricKey::from_bytes_zeroizing(&mut buf).unwrap()
}

fn encrypt_for_test(key: &SymmetricKey, iv_seed: &[u8], plaintext: &[u8]) -> String {
    use aes::Aes256;
    use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut iv = [0u8; 16];
    for (i, b) in iv_seed.iter().take(16).enumerate() {
        iv[i] = *b;
    }
    let cipher = cbc::Encryptor::<Aes256>::new(key.enc().into(), &iv.into());
    let pt_len = plaintext.len();
    let mut buf = vec![0u8; pt_len + 16];
    buf[..pt_len].copy_from_slice(plaintext);
    let ct_len = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .unwrap()
        .len();
    buf.truncate(ct_len);

    let mut hmac = HmacSha256::new_from_slice(key.mac()).unwrap();
    hmac.update(&iv);
    hmac.update(&buf);
    let mac = hmac.finalize().into_bytes();

    format!(
        "2.{}|{}|{}",
        B64.encode(iv),
        B64.encode(&buf),
        B64.encode(mac.as_slice())
    )
}
