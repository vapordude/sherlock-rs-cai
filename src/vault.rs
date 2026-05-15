//! Encrypted SQLite vault.
//!
//! Holds accumulated profile evidence across scans. The DB file is encrypted
//! at rest by SQLCipher (linked via the `bundled-sqlcipher-vendored-openssl`
//! feature of `rusqlite`). The encryption key is derived from a user
//! passphrase using Argon2id; the passphrase never touches disk and the
//! derived key only lives in memory inside `secrecy::SecretBox<[u8;32]>`
//! (zeroized on drop).
//!
//! Lifecycle:
//!   * **Uninitialized** — no `vault.salt` file exists. Frontend prompts the
//!     user to create a vault; first `init(passphrase)` generates a 16-byte
//!     salt, writes it, derives the key, opens the DB, runs the migrator.
//!   * **Locked** — salt exists, DB exists, but no in-memory key. Frontend
//!     prompts for the passphrase; `unlock(passphrase)` re-derives the key
//!     and probes the DB to verify the passphrase.
//!   * **Unlocked** — `Connection` is alive. Any `vault::*` operation runs.
//!     `lock()` drops the connection and zeroizes the key.

#![cfg(feature = "vault")]
// A handful of small helpers (`audit`, `format_age`, and a couple of
// constants used only by the schema string) are not yet wired through
// public APIs but are part of the module's internal contract for the
// next commit which adds evidence-write endpoints.
#![allow(dead_code)]

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use rusqlite::OptionalExtension;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio_rusqlite::Connection as AsyncConnection;
use zeroize::Zeroizing;

/// Argon2id parameters following the OWASP 2024+ recommendation for
/// interactive (login-style) workloads — 64 MiB / 3 iterations / 4 lanes /
/// 32-byte output.
const ARGON2_MEM_KIB: u32 = 65_536;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_OUTPUT_LEN: usize = 32;

const SALT_LEN: usize = 16;

const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Shared vault state. Lives inside `AppState`; cheap to clone (everything
/// is behind locks or `Arc`).
pub struct VaultState {
    pub salt_path: PathBuf,
    pub db_path: PathBuf,
    pub lock_timeout: Duration,
    inner: RwLock<Inner>,
}

struct Inner {
    /// `Some` when unlocked. `None` when locked.
    handle: Option<Unlocked>,
    /// Updated by the `touch` middleware on every API call.
    last_activity: Instant,
}

struct Unlocked {
    conn: AsyncConnection,
    /// Held to bind the lifetime of the derived key to the `Unlocked`
    /// state — when this struct drops, `Zeroizing` wipes it.
    _key: Zeroizing<[u8; ARGON2_OUTPUT_LEN]>,
    opened_at: Instant,
}

/// Public status payload — frontend reads this to choose the modal.
#[derive(serde::Serialize, Debug, Clone)]
pub struct VaultStatus {
    pub initialized: bool,
    pub locked: bool,
    pub opened_at: Option<String>,
    pub idle_seconds_until_lock: Option<u64>,
}

impl VaultState {
    pub fn new(dir: &Path) -> Arc<Self> {
        Arc::new(Self {
            salt_path: dir.join("vault.salt"),
            db_path: dir.join("vault.db"),
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
            inner: RwLock::new(Inner {
                handle: None,
                last_activity: Instant::now(),
            }),
        })
    }

    /// Whether `vault.salt` exists. A populated salt is the marker that the
    /// vault has ever been initialized.
    pub async fn is_initialized(&self) -> bool {
        tokio::fs::metadata(&self.salt_path).await.is_ok()
    }

    pub async fn is_locked(&self) -> bool {
        self.inner.read().await.handle.is_none()
    }

    /// Touched on every authenticated request — wakes the idle-lock timer.
    pub async fn touch(&self) {
        self.inner.write().await.last_activity = Instant::now();
    }

    /// Returns a JSON-shaped status snapshot.
    pub async fn status(&self) -> VaultStatus {
        let initialized = self.is_initialized().await;
        let g = self.inner.read().await;
        let (locked, opened_at, idle_seconds_until_lock) = match &g.handle {
            None => (true, None, None),
            Some(u) => {
                let idle = g.last_activity.elapsed();
                let remaining = self.lock_timeout.saturating_sub(idle);
                (
                    false,
                    Some(format_age(u.opened_at.elapsed())),
                    Some(remaining.as_secs()),
                )
            }
        };
        VaultStatus {
            initialized,
            locked,
            opened_at,
            idle_seconds_until_lock,
        }
    }

    /// Create a new vault. Generates a random salt, derives the key,
    /// opens the SQLCipher DB, runs the migrator, and stashes the
    /// connection. 409-equivalent if a salt file already exists.
    pub async fn init(&self, passphrase: &str) -> Result<()> {
        if self.is_initialized().await {
            anyhow::bail!("vault already initialized");
        }
        if let Some(parent) = self.salt_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Random 16-byte salt; only written *after* the DB opens cleanly so
        // we never end up with a salt-without-DB orphan on disk.
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);

        let key = derive_key(passphrase, &salt).context("argon2 KDF failed")?;
        let conn = open_locked(&self.db_path, &key)
            .await
            .context("open vault db")?;
        migrate(&conn).await.context("run vault migrations")?;

        tokio::fs::write(&self.salt_path, B64.encode(salt)).await?;

        // audit_log: vault initialized.
        let _ = audit(&conn, "vault_init", None).await;

        let mut g = self.inner.write().await;
        g.handle = Some(Unlocked {
            conn,
            _key: key,
            opened_at: Instant::now(),
        });
        g.last_activity = Instant::now();
        Ok(())
    }

    /// Open an existing vault. Returns `Err` with a passphrase-error
    /// classification when the derived key fails the probe query.
    pub async fn unlock(&self, passphrase: &str) -> Result<()> {
        if !self.is_initialized().await {
            anyhow::bail!("vault not initialized");
        }
        let salt_b64 = tokio::fs::read_to_string(&self.salt_path).await?;
        let salt_bytes = B64
            .decode(salt_b64.trim())
            .context("vault.salt is not valid base64")?;
        if salt_bytes.len() != SALT_LEN {
            anyhow::bail!("vault.salt has wrong length");
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_bytes);

        let key = derive_key(passphrase, &salt).context("argon2 KDF failed")?;
        let conn = open_locked(&self.db_path, &key)
            .await
            .context("open vault db")?;

        // Probe: a SELECT against sqlite_master fails with SQLITE_NOTADB on
        // a wrong-key open. We treat that as the canonical "wrong
        // passphrase" signal and surface it as a tagged error so the
        // endpoint layer can return a 401 cleanly.
        let probe = conn
            .call(|c| {
                c.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(Into::into)
            })
            .await;
        if probe.is_err() {
            // Drop the connection (and the key) before returning so a
            // brute-force attacker doesn't get to keep a guess in memory.
            drop(conn);
            anyhow::bail!("wrong passphrase");
        }

        let _ = audit(&conn, "vault_unlock", None).await;

        let mut g = self.inner.write().await;
        g.handle = Some(Unlocked {
            conn,
            _key: key,
            opened_at: Instant::now(),
        });
        g.last_activity = Instant::now();
        Ok(())
    }

    /// Drop the in-memory key and connection. Idempotent.
    pub async fn lock(&self) -> Result<()> {
        let mut g = self.inner.write().await;
        if let Some(u) = g.handle.take() {
            let _ = audit(&u.conn, "vault_lock", None).await;
            // Drop both `conn` and `_key`; `Zeroizing` wipes the bytes.
            drop(u);
        }
        Ok(())
    }

    /// Lock the vault if the idle timer has elapsed since the last `touch`.
    /// Called periodically from the background tick task in `main.rs`.
    pub async fn maybe_auto_lock(&self) -> bool {
        let should_lock = {
            let g = self.inner.read().await;
            g.handle.is_some() && g.last_activity.elapsed() >= self.lock_timeout
        };
        if should_lock {
            let _ = self.lock().await;
        }
        should_lock
    }

    /// Run a callback against the underlying `tokio_rusqlite::Connection`
    /// only if the vault is unlocked. The callback is the standard
    /// `tokio_rusqlite` closure signature.
    pub async fn with_conn<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut rusqlite::Connection) -> tokio_rusqlite::Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let g = self.inner.read().await;
        let conn = match &g.handle {
            Some(h) => h.conn.clone(),
            None => anyhow::bail!("vault locked"),
        };
        drop(g);
        Ok(conn.call(f).await?)
    }
}

/// Record the start of a scan and return its `scan_id`. Stored unencrypted-
/// at-row-level but DB-encrypted at rest by SQLCipher. Caller emits
/// `record_scan_finish` once all per-site results have streamed back.
pub async fn record_scan_start(
    vault: &VaultState,
    usernames_json: String,
    site_count: usize,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = time::OffsetDateTime::now_utc().to_string();
    let id_clone = id.clone();
    vault
        .with_conn(move |c| {
            c.execute(
                "INSERT INTO scans (id, started_at, usernames, site_count, hits) VALUES (?1, ?2, ?3, ?4, 0)",
                rusqlite::params![id_clone, now, usernames_json, site_count as i64],
            )?;
            Ok(())
        })
        .await?;
    Ok(id)
}

pub async fn record_scan_finish(vault: &VaultState, scan_id: &str, hits: usize) -> Result<()> {
    let scan_id = scan_id.to_string();
    let now = time::OffsetDateTime::now_utc().to_string();
    vault
        .with_conn(move |c| {
            c.execute(
                "UPDATE scans SET finished_at = ?1, hits = ?2 WHERE id = ?3",
                rusqlite::params![now, hits as i64, scan_id],
            )?;
            Ok(())
        })
        .await?;
    Ok(())
}

/// Write a single `scan_results` row for any verdict — claimed, available,
/// unknown, tentative, illegal, waf — so the scan's full trace stays
/// recoverable later.
#[allow(clippy::too_many_arguments)]
pub async fn record_scan_result(
    vault: &VaultState,
    scan_id: &str,
    username: &str,
    site_name: &str,
    site_url: &str,
    status: &str,
    confidence: u8,
    response_time_ms: Option<u64>,
    body_sha256: Option<&str>,
) -> Result<()> {
    let scan_id = scan_id.to_string();
    let username = username.to_string();
    let site_name = site_name.to_string();
    let site_url = site_url.to_string();
    let status = status.to_string();
    let body_sha256 = body_sha256.map(str::to_string);
    let seen_at = time::OffsetDateTime::now_utc().to_string();
    vault
        .with_conn(move |c| {
            c.execute(
                "INSERT INTO scan_results
                    (scan_id, username, site_name, site_url, status, confidence,
                     response_time_ms, body_sha256, seen_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                rusqlite::params![
                    scan_id,
                    username,
                    site_name,
                    site_url,
                    status,
                    confidence as i64,
                    response_time_ms.map(|v| v as i64),
                    body_sha256,
                    seen_at,
                ],
            )?;
            Ok(())
        })
        .await?;
    Ok(())
}

/// A correlation proposal — what we'd accumulate, who'd be linked to what.
/// Either applied immediately (when `auto_accept && score >= threshold`) or
/// queued as a `pending_merges` row for human review.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Proposal {
    /// `new_profile` | `accumulate` | `cross_site_correlation`
    pub kind: String,
    pub scan_id: String,
    pub username: String,
    pub site_name: String,
    pub site_url: String,
    /// `Some` for accumulate/cross-site; `None` for new_profile (a fresh
    /// profile will be created on accept).
    pub target_profile_id: Option<String>,
    /// Suggested label when creating a new profile.
    pub new_label: Option<String>,
    /// `(field, value, confidence)` rows to insert against the target profile.
    pub evidence: Vec<EvidenceRow>,
    /// Human-readable explanation for the review UI.
    pub rationale: String,
    /// 0..1 — drives the auto-accept threshold gate.
    pub score: f64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct EvidenceRow {
    pub field: String,
    pub value: String,
    pub confidence: u8,
}

/// Auto-accept threshold. Proposals at or above this score skip the
/// pending-review queue when the user has enabled `auto_accept` for the
/// current scan. Tuned conservatively — false positives at this level
/// would erode the user's trust in the system.
pub const AUTO_ACCEPT_THRESHOLD: f64 = 0.80;

/// Examine extracted evidence from a claimed hit, decide one of:
///   * **NewProfile** — no profile matches; suggest creating one (score 1.0
///     because there's no ambiguity to resolve).
///   * **Accumulate** — username already attached to an existing profile;
///     append evidence there (score 0.9).
///   * **CrossSiteCorrelation** — high-signal field (`avatar_url`,
///     `display_name`, or `full_name`) shares its value with another
///     profile's existing evidence; suggest linking (score = fraction of
///     high-signal fields matched).
///
/// `auto_accept=true` AND `score >= AUTO_ACCEPT_THRESHOLD` ⇒ apply now and
/// write an `auto_accept` audit-log row. Otherwise queue in
/// `pending_merges` for human review.
#[allow(clippy::too_many_arguments)]
pub async fn propose_or_apply(
    vault: &VaultState,
    scan_id: &str,
    username: &str,
    site_name: &str,
    site_url: &str,
    extracted: &std::collections::HashMap<String, crate::result::ExtractedValue>,
    confidence: u8,
    auto_accept: bool,
) -> Result<ProposalOutcome> {
    let evidence_rows = evidence_rows_from_extracted(extracted, confidence);
    if evidence_rows.is_empty() {
        return Ok(ProposalOutcome::NoEvidence);
    }
    let proposal =
        decide_proposal(vault, scan_id, username, site_name, site_url, &evidence_rows).await?;

    if auto_accept && proposal.score >= AUTO_ACCEPT_THRESHOLD {
        let profile_id = apply_proposal(vault, &proposal).await?;
        let detail = format!(
            "auto_accept score={:.2} kind={} site={}",
            proposal.score, proposal.kind, site_name
        );
        let _ = audit_with_vault(vault, "auto_accept", Some(&detail)).await;
        Ok(ProposalOutcome::Applied { profile_id })
    } else {
        let pending_id = queue_pending(vault, &proposal).await?;
        Ok(ProposalOutcome::Queued { pending_id })
    }
}

#[derive(serde::Serialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposalOutcome {
    NoEvidence,
    Queued { pending_id: i64 },
    Applied { profile_id: String },
}

fn evidence_rows_from_extracted(
    extracted: &std::collections::HashMap<String, crate::result::ExtractedValue>,
    confidence: u8,
) -> Vec<EvidenceRow> {
    use crate::result::ExtractedValue;
    let mut out = Vec::new();
    for (field, val) in extracted {
        match val {
            ExtractedValue::One(s) if !s.is_empty() => out.push(EvidenceRow {
                field: field.clone(),
                value: s.clone(),
                confidence,
            }),
            ExtractedValue::Many(vs) => {
                for v in vs {
                    if !v.is_empty() {
                        out.push(EvidenceRow {
                            field: field.clone(),
                            value: v.clone(),
                            confidence,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    out
}

async fn decide_proposal(
    vault: &VaultState,
    scan_id: &str,
    username: &str,
    site_name: &str,
    site_url: &str,
    evidence: &[EvidenceRow],
) -> Result<Proposal> {
    // 1. Look for an existing profile that already has this username in its
    //    evidence — straightforward accumulation.
    let username_match = find_profile_by_username(vault, username).await?;

    // 2. High-signal field correlation: collect distinct profile IDs whose
    //    evidence contains any (avatar_url|full_name|display_name) =
    //    incoming value. A match is high-confidence because these fields are
    //    rarely duplicated across unrelated people.
    let high_signal_fields = ["avatar_url", "full_name", "display_name"];
    let mut matched_profiles: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut high_signal_total = 0;
    let mut high_signal_matched = 0;
    for ev in evidence {
        if high_signal_fields.contains(&ev.field.as_str()) {
            high_signal_total += 1;
            let pids = find_profiles_by_field_value(vault, &ev.field, &ev.value).await?;
            if !pids.is_empty() {
                high_signal_matched += 1;
                matched_profiles.extend(pids);
            }
        }
    }

    // Decide. Prefer username-based accumulation when the username matches
    // an existing profile AND no cross-site correlation contradicts it.
    if let Some(profile_id) = username_match {
        return Ok(Proposal {
            kind: "accumulate".into(),
            scan_id: scan_id.into(),
            username: username.into(),
            site_name: site_name.into(),
            site_url: site_url.into(),
            target_profile_id: Some(profile_id),
            new_label: None,
            evidence: evidence.to_vec(),
            rationale: format!(
                "Username '{username}' already attached to this profile; appending evidence from {site_name}."
            ),
            score: 0.90,
        });
    }
    // Cross-site correlation — high-signal fields match an existing profile.
    if let Some(profile_id) = matched_profiles.iter().next().cloned() {
        let score = if high_signal_total == 0 {
            0.0
        } else {
            high_signal_matched as f64 / high_signal_total as f64
        };
        return Ok(Proposal {
            kind: "cross_site_correlation".into(),
            scan_id: scan_id.into(),
            username: username.into(),
            site_name: site_name.into(),
            site_url: site_url.into(),
            target_profile_id: Some(profile_id),
            new_label: None,
            evidence: evidence.to_vec(),
            rationale: format!(
                "{high_signal_matched}/{high_signal_total} high-signal fields (avatar_url / full_name / display_name) match an existing profile."
            ),
            score,
        });
    }
    // Brand-new profile.
    Ok(Proposal {
        kind: "new_profile".into(),
        scan_id: scan_id.into(),
        username: username.into(),
        site_name: site_name.into(),
        site_url: site_url.into(),
        target_profile_id: None,
        new_label: Some(username.into()),
        evidence: evidence.to_vec(),
        rationale: format!("No prior profile for '{username}'; suggesting a new profile."),
        score: 1.0,
    })
}

async fn find_profile_by_username(vault: &VaultState, username: &str) -> Result<Option<String>> {
    let username = username.to_string();
    vault
        .with_conn(move |c| {
            let row: Option<String> = c
                .prepare("SELECT profile_id FROM evidence WHERE username = ?1 AND profile_id IS NOT NULL LIMIT 1")?
                .query_row(rusqlite::params![username], |r| r.get(0))
                .optional()?;
            Ok(row)
        })
        .await
}

async fn find_profiles_by_field_value(
    vault: &VaultState,
    field: &str,
    value: &str,
) -> Result<Vec<String>> {
    let field = field.to_string();
    let value = value.to_string();
    vault
        .with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT DISTINCT profile_id FROM evidence
                 WHERE field = ?1 AND value = ?2 AND profile_id IS NOT NULL",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![field, value], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect::<Vec<_>>();
            Ok(rows)
        })
        .await
}

/// Apply a proposal — creating the profile if needed and inserting one
/// row per `EvidenceRow`. Returns the resulting `profile_id`. Used both on
/// auto-accept and on explicit `POST /api/review/:id/accept`.
async fn apply_proposal(vault: &VaultState, p: &Proposal) -> Result<String> {
    let proposal = p.clone();
    vault
        .with_conn(move |c| {
            let tx = c.transaction()?;
            let profile_id = match &proposal.target_profile_id {
                Some(id) => id.clone(),
                None => {
                    let id = uuid::Uuid::new_v4().to_string();
                    let now = time::OffsetDateTime::now_utc().to_string();
                    tx.execute(
                        "INSERT INTO profiles (id, label, created_at, updated_at)
                         VALUES (?1, ?2, ?3, ?3)",
                        rusqlite::params![id, proposal.new_label.clone().unwrap_or_default(), now],
                    )?;
                    id
                }
            };
            let now = time::OffsetDateTime::now_utc().to_string();
            for ev in &proposal.evidence {
                tx.execute(
                    "INSERT OR IGNORE INTO evidence
                        (profile_id, scan_id, username, site_name, site_url,
                         field, value, confidence, seen_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    rusqlite::params![
                        profile_id,
                        proposal.scan_id,
                        proposal.username,
                        proposal.site_name,
                        proposal.site_url,
                        ev.field,
                        ev.value,
                        ev.confidence as i64,
                        now
                    ],
                )?;
            }
            tx.execute(
                "UPDATE profiles SET updated_at = ?1 WHERE id = ?2",
                rusqlite::params![now, profile_id],
            )?;
            tx.commit()?;
            Ok(profile_id)
        })
        .await
}

async fn queue_pending(vault: &VaultState, p: &Proposal) -> Result<i64> {
    let proposal = p.clone();
    vault
        .with_conn(move |c| {
            let candidate_json = serde_json::to_string(&proposal).unwrap_or_default();
            let now = time::OffsetDateTime::now_utc().to_string();
            c.execute(
                "INSERT INTO pending_merges
                    (kind, proposed_at, profile_id, candidate, rationale, score)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![
                    proposal.kind,
                    now,
                    proposal.target_profile_id,
                    candidate_json,
                    proposal.rationale,
                    proposal.score
                ],
            )?;
            Ok(c.last_insert_rowid())
        })
        .await
}

pub async fn list_profiles(vault: &VaultState) -> Result<Vec<serde_json::Value>> {
    vault
        .with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT p.id, p.label, p.created_at, p.updated_at,
                        (SELECT COUNT(*) FROM evidence e WHERE e.profile_id = p.id) as evidence_count
                 FROM profiles p ORDER BY p.updated_at DESC",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(serde_json::json!({
                        "id":             r.get::<_, String>(0)?,
                        "label":          r.get::<_, String>(1)?,
                        "created_at":     r.get::<_, String>(2)?,
                        "updated_at":     r.get::<_, String>(3)?,
                        "evidence_count": r.get::<_, i64>(4)?,
                    }))
                })?
                .filter_map(|r| r.ok())
                .collect();
            Ok(rows)
        })
        .await
}

pub async fn get_profile(vault: &VaultState, id: &str) -> Result<serde_json::Value> {
    let id = id.to_string();
    vault
        .with_conn(move |c| {
            let id_clone = id.clone();
            let profile: Option<serde_json::Value> = c
                .prepare("SELECT id, label, created_at, updated_at, note FROM profiles WHERE id = ?1")?
                .query_row(rusqlite::params![id_clone], |r| {
                    Ok(serde_json::json!({
                        "id":         r.get::<_, String>(0)?,
                        "label":      r.get::<_, String>(1)?,
                        "created_at": r.get::<_, String>(2)?,
                        "updated_at": r.get::<_, String>(3)?,
                        "note":       r.get::<_, Option<String>>(4)?,
                    }))
                })
                .optional()?;
            let Some(mut profile) = profile else {
                return Ok(serde_json::Value::Null);
            };
            let mut stmt = c.prepare(
                "SELECT site_name, site_url, username, field, value, confidence, seen_at
                 FROM evidence WHERE profile_id = ?1 ORDER BY seen_at DESC",
            )?;
            let evidence: Vec<serde_json::Value> = stmt
                .query_map(rusqlite::params![id], |r| {
                    Ok(serde_json::json!({
                        "site_name":  r.get::<_, String>(0)?,
                        "site_url":   r.get::<_, String>(1)?,
                        "username":   r.get::<_, String>(2)?,
                        "field":      r.get::<_, String>(3)?,
                        "value":      r.get::<_, String>(4)?,
                        "confidence": r.get::<_, i64>(5)?,
                        "seen_at":    r.get::<_, String>(6)?,
                    }))
                })?
                .filter_map(|r| r.ok())
                .collect();
            if let Some(map) = profile.as_object_mut() {
                map.insert("evidence".into(), serde_json::Value::Array(evidence));
            }
            Ok(profile)
        })
        .await
}

pub async fn list_pending(vault: &VaultState) -> Result<Vec<serde_json::Value>> {
    vault
        .with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT id, kind, proposed_at, profile_id, candidate, rationale, score
                 FROM pending_merges WHERE state = 'pending'
                 ORDER BY proposed_at DESC",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    let candidate_str: String = r.get(4)?;
                    let candidate: serde_json::Value =
                        serde_json::from_str(&candidate_str).unwrap_or(serde_json::Value::Null);
                    Ok(serde_json::json!({
                        "id":          r.get::<_, i64>(0)?,
                        "kind":        r.get::<_, String>(1)?,
                        "proposed_at": r.get::<_, String>(2)?,
                        "profile_id":  r.get::<_, Option<String>>(3)?,
                        "candidate":   candidate,
                        "rationale":   r.get::<_, String>(5)?,
                        "score":       r.get::<_, f64>(6)?,
                    }))
                })?
                .filter_map(|r| r.ok())
                .collect();
            Ok(rows)
        })
        .await
}

pub async fn count_pending(vault: &VaultState) -> Result<i64> {
    vault
        .with_conn(|c| {
            let n: i64 = c.query_row(
                "SELECT COUNT(*) FROM pending_merges WHERE state = 'pending'",
                [],
                |r| r.get(0),
            )?;
            Ok(n)
        })
        .await
}

pub async fn accept_pending(vault: &VaultState, id: i64, note: Option<String>) -> Result<String> {
    let candidate_json: String = vault
        .with_conn(move |c| {
            let row: Option<(String, String)> = c
                .prepare("SELECT candidate, state FROM pending_merges WHERE id = ?1")?
                .query_row(rusqlite::params![id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            match row {
                Some((c_str, s)) if s == "pending" => Ok(c_str),
                Some(_) => Err(tokio_rusqlite::Error::Other(
                    "already resolved".to_string().into(),
                )),
                None => Err(tokio_rusqlite::Error::Other(
                    "not found".to_string().into(),
                )),
            }
        })
        .await?;
    let proposal: Proposal = serde_json::from_str(&candidate_json)?;
    let profile_id = apply_proposal(vault, &proposal).await?;
    let note_clone = note.clone();
    vault
        .with_conn(move |c| {
            let now = time::OffsetDateTime::now_utc().to_string();
            c.execute(
                "UPDATE pending_merges
                   SET state = 'accepted', resolved_at = ?1, resolved_note = ?2
                 WHERE id = ?3",
                rusqlite::params![now, note_clone, id],
            )?;
            Ok(())
        })
        .await?;
    let detail = format!("accepted pending#{id} note={:?}", note);
    let _ = audit_with_vault(vault, "review_accept", Some(&detail)).await;
    Ok(profile_id)
}

pub async fn reject_pending(vault: &VaultState, id: i64, note: Option<String>) -> Result<()> {
    let note_clone = note.clone();
    vault
        .with_conn(move |c| {
            let now = time::OffsetDateTime::now_utc().to_string();
            let updated = c.execute(
                "UPDATE pending_merges
                   SET state = 'rejected', resolved_at = ?1, resolved_note = ?2
                 WHERE id = ?3 AND state = 'pending'",
                rusqlite::params![now, note_clone, id],
            )?;
            if updated == 0 {
                return Err(tokio_rusqlite::Error::Other(
                    "not pending or not found".to_string().into(),
                ));
            }
            Ok(())
        })
        .await?;
    let detail = format!("rejected pending#{id} note={:?}", note);
    let _ = audit_with_vault(vault, "review_reject", Some(&detail)).await;
    Ok(())
}

pub async fn list_audit(vault: &VaultState, limit: i64) -> Result<Vec<serde_json::Value>> {
    vault
        .with_conn(move |c| {
            let mut stmt =
                c.prepare("SELECT id, at, action, detail FROM audit_log ORDER BY id DESC LIMIT ?1")?;
            let rows = stmt
                .query_map(rusqlite::params![limit], |r| {
                    Ok(serde_json::json!({
                        "id":     r.get::<_, i64>(0)?,
                        "at":     r.get::<_, String>(1)?,
                        "action": r.get::<_, String>(2)?,
                        "detail": r.get::<_, Option<String>>(3)?,
                    }))
                })?
                .filter_map(|r| r.ok())
                .collect();
            Ok(rows)
        })
        .await
}

async fn audit_with_vault(vault: &VaultState, action: &str, detail: Option<&str>) -> Result<()> {
    let action = action.to_string();
    let detail = detail.map(str::to_string);
    vault
        .with_conn(move |c| {
            c.execute(
                "INSERT INTO audit_log (at, action, detail) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    time::OffsetDateTime::now_utc().to_string(),
                    action,
                    detail
                ],
            )?;
            Ok(())
        })
        .await
}

/// Argon2id KDF — `(passphrase, salt) -> 32-byte key`. Key bytes are
/// wrapped in `Zeroizing` so they're wiped on drop even if the caller
/// forgets to.
pub fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; ARGON2_OUTPUT_LEN]>> {
    let params = Params::new(ARGON2_MEM_KIB, ARGON2_TIME_COST, ARGON2_PARALLELISM, Some(ARGON2_OUTPUT_LEN))
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; ARGON2_OUTPUT_LEN]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;
    Ok(out)
}

async fn open_locked(
    db_path: &Path,
    key: &Zeroizing<[u8; ARGON2_OUTPUT_LEN]>,
) -> Result<AsyncConnection> {
    // Encode key as the SQLCipher hex literal: x'...' — preferred over the
    // passphrase form because we already have raw bytes from Argon2.
    let key_hex = encode_hex(&**key);
    let conn = AsyncConnection::open(db_path).await?;
    conn.call(move |c| {
        c.execute_batch(&format!(
            "PRAGMA key = \"x'{key_hex}'\"; PRAGMA cipher_page_size = 4096;"
        ))?;
        Ok(())
    })
    .await?;
    Ok(conn)
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Schema migrator. Reads `PRAGMA user_version`, applies each step in
/// order, sets the new version. Initial install lands on v1.
async fn migrate(conn: &AsyncConnection) -> Result<()> {
    conn.call(|c| {
        let current: i64 = c.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current < 1 {
            c.execute_batch(SCHEMA_V1)?;
            c.pragma_update(None, "user_version", 1)?;
        }
        // Future migrations append `if current < 2 { ... }` blocks here.
        Ok(())
    })
    .await?;
    Ok(())
}

async fn audit(conn: &AsyncConnection, action: &str, detail: Option<&str>) -> Result<()> {
    let action = action.to_string();
    let detail = detail.map(str::to_string);
    conn.call(move |c| {
        c.execute(
            "INSERT INTO audit_log (at, action, detail) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                time::OffsetDateTime::now_utc().to_string(),
                action,
                detail
            ],
        )?;
        Ok(())
    })
    .await?;
    Ok(())
}

fn format_age(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);

CREATE TABLE IF NOT EXISTS profiles (
    id            TEXT PRIMARY KEY,
    label         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    note          TEXT
);
CREATE INDEX IF NOT EXISTS idx_profiles_label ON profiles(label);

CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    usernames     TEXT NOT NULL,
    site_count    INTEGER NOT NULL,
    hits          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);

CREATE TABLE IF NOT EXISTS scan_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    username      TEXT NOT NULL,
    site_name     TEXT NOT NULL,
    site_url      TEXT NOT NULL,
    status        TEXT NOT NULL,
    confidence    INTEGER NOT NULL,
    response_time_ms INTEGER,
    body_sha256   TEXT,
    seen_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_user ON scan_results(username);

CREATE TABLE IF NOT EXISTS evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id    TEXT REFERENCES profiles(id) ON DELETE CASCADE,
    scan_id       TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    username      TEXT NOT NULL,
    site_name     TEXT NOT NULL,
    site_url      TEXT NOT NULL,
    field         TEXT NOT NULL,
    value         TEXT NOT NULL,
    confidence    INTEGER NOT NULL,
    seen_at       TEXT NOT NULL,
    UNIQUE(profile_id, site_name, username, field, value)
);
CREATE INDEX IF NOT EXISTS idx_evidence_profile ON evidence(profile_id);
CREATE INDEX IF NOT EXISTS idx_evidence_field_value ON evidence(field, value);

CREATE TABLE IF NOT EXISTS pending_merges (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL,
    proposed_at   TEXT NOT NULL,
    profile_id    TEXT,
    candidate     TEXT NOT NULL,
    rationale     TEXT NOT NULL,
    score         REAL NOT NULL,
    state         TEXT NOT NULL DEFAULT 'pending',
    resolved_at   TEXT,
    resolved_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_pending_state ON pending_merges(state, proposed_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    at            TEXT NOT NULL,
    action        TEXT NOT NULL,
    detail        TEXT
);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_is_deterministic_and_32_bytes() {
        let salt = [0u8; SALT_LEN];
        let k1 = derive_key("hunter2", &salt).expect("kdf 1");
        let k2 = derive_key("hunter2", &salt).expect("kdf 2");
        assert_eq!(*k1, *k2);
        assert_ne!(*k1, [0u8; 32]);
    }

    #[test]
    fn derive_key_differs_on_different_passphrase() {
        let salt = [0u8; SALT_LEN];
        let k1 = derive_key("alpha", &salt).expect("kdf 1");
        let k2 = derive_key("bravo", &salt).expect("kdf 2");
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn derive_key_differs_on_different_salt() {
        let s1 = [1u8; SALT_LEN];
        let s2 = [2u8; SALT_LEN];
        let k1 = derive_key("alpha", &s1).expect("kdf 1");
        let k2 = derive_key("alpha", &s2).expect("kdf 2");
        assert_ne!(*k1, *k2);
    }

    #[tokio::test]
    async fn full_init_unlock_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let v = VaultState::new(dir.path());
        assert!(!v.is_initialized().await);
        assert!(v.is_locked().await);

        v.init("correct-passphrase").await.expect("init should succeed");
        assert!(v.is_initialized().await);
        assert!(!v.is_locked().await);

        v.lock().await.expect("lock");
        assert!(v.is_locked().await);
        assert!(v.is_initialized().await);

        // Wrong passphrase: unlock should fail and vault stays locked.
        let err = v.unlock("wrong-passphrase").await.unwrap_err();
        assert!(err.to_string().contains("wrong passphrase"));
        assert!(v.is_locked().await);

        // Correct passphrase: unlock works.
        v.unlock("correct-passphrase").await.expect("unlock");
        assert!(!v.is_locked().await);
    }

    /// End-to-end: open a vault → record a scan → simulate a hit with
    /// extracted fields → propose-or-apply (with auto-accept on) → assert
    /// the profile materialized + audit_log recorded the auto-accept.
    #[tokio::test]
    async fn auto_accept_flow_creates_profile_and_audits() {
        use crate::result::ExtractedValue;

        let dir = tempfile::tempdir().unwrap();
        let v = VaultState::new(dir.path());
        v.init("test-pass-12345").await.unwrap();

        let scan_id = record_scan_start(&v, r#"["alice"]"#.into(), 1).await.unwrap();
        record_scan_result(
            &v,
            &scan_id,
            "alice",
            "GitHub",
            "https://github.com/alice",
            "claimed",
            95,
            Some(150),
            Some("abcdef"),
        )
        .await
        .unwrap();

        let mut extracted = std::collections::HashMap::new();
        extracted.insert(
            "avatar_url".to_string(),
            ExtractedValue::One("https://cdn/alice.png".into()),
        );
        extracted.insert(
            "display_name".to_string(),
            ExtractedValue::One("Alice Example".into()),
        );

        let outcome = propose_or_apply(
            &v,
            &scan_id,
            "alice",
            "GitHub",
            "https://github.com/alice",
            &extracted,
            95,
            true, // auto_accept
        )
        .await
        .unwrap();

        match outcome {
            ProposalOutcome::Applied { ref profile_id } => {
                assert!(!profile_id.is_empty());
            }
            other => panic!("expected Applied, got {other:?}"),
        }

        record_scan_finish(&v, &scan_id, 1).await.unwrap();

        let profiles = list_profiles(&v).await.unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0]["label"], "alice");
        assert_eq!(profiles[0]["evidence_count"].as_i64().unwrap(), 2);

        // Pending queue stays empty because auto-accept short-circuited.
        let pending_n = count_pending(&v).await.unwrap();
        assert_eq!(pending_n, 0);

        // Audit log records the auto_accept.
        let audit = list_audit(&v, 50).await.unwrap();
        let has_auto = audit
            .iter()
            .any(|r| r["action"].as_str() == Some("auto_accept"));
        assert!(has_auto, "expected an auto_accept audit row, got {audit:?}");
    }

    /// Same scenario but with auto_accept=false: the proposal must queue
    /// for review, and explicit accept_pending must materialize the profile.
    #[tokio::test]
    async fn queue_then_accept_creates_profile() {
        use crate::result::ExtractedValue;

        let dir = tempfile::tempdir().unwrap();
        let v = VaultState::new(dir.path());
        v.init("test-pass-12345").await.unwrap();

        let scan_id = record_scan_start(&v, r#"["bob"]"#.into(), 1).await.unwrap();
        let mut extracted = std::collections::HashMap::new();
        extracted.insert("bio".into(), ExtractedValue::One("hello".into()));

        let outcome = propose_or_apply(
            &v,
            &scan_id,
            "bob",
            "GitHub",
            "https://github.com/bob",
            &extracted,
            80,
            false, // queue, don't auto-apply
        )
        .await
        .unwrap();

        let pending_id = match outcome {
            ProposalOutcome::Queued { pending_id } => pending_id,
            other => panic!("expected Queued, got {other:?}"),
        };
        assert_eq!(count_pending(&v).await.unwrap(), 1);
        assert_eq!(list_profiles(&v).await.unwrap().len(), 0);

        // Reject path: state flips, no profile created.
        // (Re-create a second proposal for the accept path so this test
        // also exercises rejection without interfering.)
        let mut extracted2 = std::collections::HashMap::new();
        extracted2.insert("bio".into(), ExtractedValue::One("world".into()));
        let queued2 = propose_or_apply(
            &v,
            &scan_id,
            "bob2",
            "GitHub",
            "https://github.com/bob2",
            &extracted2,
            80,
            false,
        )
        .await
        .unwrap();
        let reject_id = match queued2 {
            ProposalOutcome::Queued { pending_id } => pending_id,
            other => panic!("expected Queued, got {other:?}"),
        };
        reject_pending(&v, reject_id, Some("nope".into()))
            .await
            .unwrap();

        // Accept the first: profile materializes.
        let profile_id = accept_pending(&v, pending_id, Some("looks good".into()))
            .await
            .unwrap();
        assert!(!profile_id.is_empty());

        let profiles = list_profiles(&v).await.unwrap();
        assert_eq!(profiles.len(), 1);

        // Pending queue is empty (one accepted, one rejected — neither
        // remains in 'pending' state).
        assert_eq!(count_pending(&v).await.unwrap(), 0);

        // Audit log records both review_accept and review_reject.
        let audit = list_audit(&v, 50).await.unwrap();
        let actions: Vec<&str> = audit
            .iter()
            .filter_map(|r| r["action"].as_str())
            .collect();
        assert!(actions.contains(&"review_accept"));
        assert!(actions.contains(&"review_reject"));
    }
}
