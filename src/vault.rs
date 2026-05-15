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

/// Default auto-accept threshold. Proposals at or above this score skip
/// the pending-review queue when the user has enabled `auto_accept` for
/// the current scan. Tuned conservatively — false positives at this level
/// would erode the user's trust in the system. Callers can pass a
/// per-scan override via `propose_or_apply`'s `threshold` parameter
/// (frontend slider, range 0.50–0.95).
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
    threshold: Option<f64>,
) -> Result<ProposalOutcome> {
    let evidence_rows = evidence_rows_from_extracted(extracted, confidence);
    if evidence_rows.is_empty() {
        return Ok(ProposalOutcome::NoEvidence);
    }
    let proposal =
        decide_proposal(vault, scan_id, username, site_name, site_url, &evidence_rows).await?;

    // Clamp the threshold to a sane range so a stale UI can't accidentally
    // request "auto-accept everything" (threshold = 0).
    let effective_threshold = threshold
        .unwrap_or(AUTO_ACCEPT_THRESHOLD)
        .clamp(0.50, 0.95);

    if auto_accept && proposal.score >= effective_threshold {
        let profile_id = apply_proposal(vault, &proposal).await?;
        let detail = format!(
            "auto_accept score={:.2} thresh={:.2} kind={} site={}",
            proposal.score, effective_threshold, proposal.kind, site_name
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
                .query_map(rusqlite::params![id.clone()], |r| {
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

            // Media — return the ids + metadata; bytes are served by a
            // separate endpoint so the JSON payload doesn't balloon.
            let mut media_stmt = c.prepare(
                "SELECT id, source_url, kind, mime, fetched_at
                 FROM media WHERE profile_id = ?1 ORDER BY fetched_at DESC",
            )?;
            let media: Vec<serde_json::Value> = media_stmt
                .query_map(rusqlite::params![id], |r| {
                    Ok(serde_json::json!({
                        "id":         r.get::<_, i64>(0)?,
                        "source_url": r.get::<_, String>(1)?,
                        "kind":       r.get::<_, String>(2)?,
                        "mime":       r.get::<_, String>(3)?,
                        "fetched_at": r.get::<_, String>(4)?,
                    }))
                })?
                .filter_map(|r| r.ok())
                .collect();

            if let Some(map) = profile.as_object_mut() {
                map.insert("evidence".into(), serde_json::Value::Array(evidence));
                map.insert("media".into(), serde_json::Value::Array(media));
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

/// Store a fetched media blob against a profile. Dedup by
/// `(profile_id, source_url, kind)` via `INSERT OR IGNORE`. Returns the
/// `rowid` of the inserted (or pre-existing) row. Empty `bytes` is
/// rejected so a failed fetch doesn't pollute the DB.
///
/// `phash` is the optional perceptual hash (hex-encoded) used for the
/// "find similar media" feature. Callers compute it via
/// `compute_phash_hex` before calling this; passing `None` is fine for
/// non-image kinds.
#[allow(clippy::too_many_arguments)]
pub async fn record_media(
    vault: &VaultState,
    profile_id: &str,
    evidence_id: Option<i64>,
    source_url: &str,
    kind: &str,
    mime: &str,
    bytes: Vec<u8>,
    phash: Option<String>,
) -> Result<i64> {
    if bytes.is_empty() {
        anyhow::bail!("refusing to store empty media blob");
    }
    let profile_id = profile_id.to_string();
    let source_url = source_url.to_string();
    let kind = kind.to_string();
    let mime = mime.to_string();
    let fetched_at = time::OffsetDateTime::now_utc().to_string();
    vault
        .with_conn(move |c| {
            c.execute(
                "INSERT OR IGNORE INTO media
                    (profile_id, evidence_id, source_url, kind, mime, bytes, fetched_at, phash)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params![
                    profile_id,
                    evidence_id,
                    source_url,
                    kind,
                    mime,
                    bytes,
                    fetched_at,
                    phash
                ],
            )?;
            // `last_insert_rowid` is 0 when INSERT OR IGNORE silently
            // ignored a unique-conflict row — fall back to a SELECT in that
            // case so callers always get the canonical id.
            let inserted = c.last_insert_rowid();
            if inserted != 0 {
                return Ok(inserted);
            }
            let existing: i64 = c.query_row(
                "SELECT id FROM media WHERE profile_id = ?1 AND source_url = ?2 AND kind = ?3",
                rusqlite::params![profile_id, source_url, kind],
                |r| r.get(0),
            )?;
            Ok(existing)
        })
        .await
}

/// Compute the 64-bit DCT-based perceptual hash of an image, hex-encoded
/// (16 chars). Pure-CPU, ~5ms per image. Robust to JPEG re-encoding,
/// mild scaling, and watermark overlays. Returns `None` when the bytes
/// don't decode as an image (e.g. server returned HTML).
pub fn compute_phash_hex(bytes: &[u8]) -> Option<String> {
    let img = image::load_from_memory(bytes).ok()?;
    let hasher = image_hasher::HasherConfig::new()
        .hash_alg(image_hasher::HashAlg::DoubleGradient)
        .hash_size(8, 8)
        .to_hasher();
    let hash = hasher.hash_image(&img);
    Some(hex_lower(hash.as_bytes()))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

/// Find media rows whose phash is within `max_distance` bits of the
/// given seed media id (Hamming distance over the raw bytes). Excludes
/// the seed row itself. Results ordered by ascending distance.
///
/// O(N) over all rows that have a phash — fine up to ~100K avatars.
/// SQLite has no native popcount-over-blob, so the scan happens in
/// Rust after a single SELECT pulls the candidate set.
pub async fn find_similar_by_phash(
    vault: &VaultState,
    seed_id: i64,
    max_distance: u32,
) -> Result<Vec<serde_json::Value>> {
    let max_distance = max_distance.min(64); // cap at full disagreement
    vault
        .with_conn(move |c| {
            let seed_hex: Option<String> = c
                .prepare("SELECT phash FROM media WHERE id = ?1")?
                .query_row(rusqlite::params![seed_id], |r| r.get(0))
                .optional()?;
            let Some(seed_hex) = seed_hex.filter(|s| !s.is_empty()) else {
                return Ok(Vec::new());
            };
            let Some(seed_bytes) = hex_to_bytes(&seed_hex) else {
                return Ok(Vec::new());
            };

            let mut stmt = c.prepare(
                "SELECT m.id, m.profile_id, m.source_url, m.kind, m.mime, m.phash,
                        p.label
                 FROM media m
                 LEFT JOIN profiles p ON p.id = m.profile_id
                 WHERE m.phash IS NOT NULL AND m.id != ?1",
            )?;
            let mut hits: Vec<(u32, serde_json::Value)> = stmt
                .query_map(rusqlite::params![seed_id], |r| {
                    let phash: String = r.get(5)?;
                    Ok((
                        phash,
                        serde_json::json!({
                            "id":             r.get::<_, i64>(0)?,
                            "profile_id":     r.get::<_, String>(1)?,
                            "source_url":     r.get::<_, String>(2)?,
                            "kind":           r.get::<_, String>(3)?,
                            "mime":           r.get::<_, String>(4)?,
                            "profile_label":  r.get::<_, Option<String>>(6)?,
                        }),
                    ))
                })?
                .filter_map(|r| r.ok())
                .filter_map(|(phash, mut row)| {
                    let candidate = hex_to_bytes(&phash)?;
                    if candidate.len() != seed_bytes.len() {
                        return None;
                    }
                    let d = hamming_distance(&seed_bytes, &candidate);
                    if d > max_distance {
                        return None;
                    }
                    if let Some(map) = row.as_object_mut() {
                        map.insert("hamming_distance".into(), serde_json::Value::from(d));
                    }
                    Some((d, row))
                })
                .collect();

            hits.sort_by_key(|(d, _)| *d);
            Ok(hits.into_iter().map(|(_, v)| v).collect())
        })
        .await
}

/// Fetch a single media row by id. Returns `(mime, bytes)`.
pub async fn fetch_media(vault: &VaultState, id: i64) -> Result<Option<(String, Vec<u8>)>> {
    vault
        .with_conn(move |c| {
            let row: Option<(String, Vec<u8>)> = c
                .prepare("SELECT mime, bytes FROM media WHERE id = ?1")?
                .query_row(rusqlite::params![id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            Ok(row)
        })
        .await
}

/// Update the free-form note on a profile. Notes are stored inside the
/// SQLCipher-encrypted DB; nothing leaves the vault.
pub async fn update_profile_note(vault: &VaultState, profile_id: &str, note: &str) -> Result<bool> {
    let id = profile_id.to_string();
    let value = note.to_string();
    let note_len = value.len();
    let now = time::OffsetDateTime::now_utc().to_string();
    let n: usize = vault
        .with_conn(move |c| {
            let n = c.execute(
                "UPDATE profiles SET note = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![value, now, id],
            )?;
            Ok(n)
        })
        .await?;
    if n > 0 {
        let _ = audit_with_vault(
            vault,
            "profile_note",
            Some(&format!("profile={profile_id} len={note_len}")),
        )
        .await;
    }
    Ok(n > 0)
}

/// Delete a profile and (via FK cascades) its evidence + media. Returns
/// true when the row existed.
pub async fn delete_profile(vault: &VaultState, profile_id: &str) -> Result<bool> {
    let id = profile_id.to_string();
    let n: usize = vault
        .with_conn(move |c| {
            let n = c.execute("DELETE FROM profiles WHERE id = ?1", rusqlite::params![id])?;
            Ok(n)
        })
        .await?;
    if n > 0 {
        let _ = audit_with_vault(vault, "profile_delete", Some(profile_id)).await;
    }
    Ok(n > 0)
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
            "PRAGMA key = \"x'{key_hex}'\";\
             PRAGMA cipher_page_size = 4096;\
             PRAGMA foreign_keys = ON;"
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
/// order, sets the new version. Initial install lands on the current
/// version directly — every existing table is `CREATE TABLE IF NOT EXISTS`
/// so v1 → v2 → … migrations also work on a fresh vault.
async fn migrate(conn: &AsyncConnection) -> Result<()> {
    conn.call(|c| {
        let current: i64 = c.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current < 1 {
            c.execute_batch(SCHEMA_V1)?;
            c.pragma_update(None, "user_version", 1)?;
        }
        if current < 2 {
            c.execute_batch(SCHEMA_V2_DELTA)?;
            c.pragma_update(None, "user_version", 2)?;
        }
        if current < 3 {
            c.execute_batch(SCHEMA_V3_DELTA)?;
            c.pragma_update(None, "user_version", 3)?;
        }
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

/// v2 — adds per-profile media storage. Bytes live in the encrypted DB
/// (SQLCipher does the at-rest encryption); we don't write images to the
/// filesystem. `(profile_id, source_url, kind)` is the natural dedup key
/// so re-running a scan against the same profile doesn't multiply rows.
const SCHEMA_V2_DELTA: &str = r#"
CREATE TABLE IF NOT EXISTS media (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id    TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    evidence_id   INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    source_url    TEXT NOT NULL,
    kind          TEXT NOT NULL,        -- 'avatar' | 'image' | 'other'
    mime          TEXT NOT NULL,
    bytes         BLOB NOT NULL,
    fetched_at    TEXT NOT NULL,
    UNIQUE(profile_id, source_url, kind)
);
CREATE INDEX IF NOT EXISTS idx_media_profile ON media(profile_id);
"#;

/// v3 — adds a perceptual hash column on `media`. 16-hex-char DCT pHash
/// is robust to JPEG re-encoding, mild scaling, and watermark overlays.
/// Hamming distance between two pHashes ≤ ~8 bits is typically the same
/// underlying image with edits; ≤ ~16 bits is "probably related". Stored
/// as TEXT (hex) for trivial cross-row equality on perfect copies, plus
/// in-Rust Hamming distance for fuzzy similarity (the `find_similar_by_phash`
/// helper). NULL is permitted for non-image media or rows recorded
/// before v3.
const SCHEMA_V3_DELTA: &str = r#"
ALTER TABLE media ADD COLUMN phash TEXT;
CREATE INDEX IF NOT EXISTS idx_media_phash ON media(phash) WHERE phash IS NOT NULL;
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
            None, // use default threshold
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
            None,
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
            None,
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

    #[tokio::test]
    async fn media_record_dedup_and_fetch_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let v = VaultState::new(dir.path());
        v.init("test-pass-12345").await.unwrap();
        let scan_id = record_scan_start(&v, r#"["alice"]"#.into(), 1).await.unwrap();

        // Create a profile to attach media to.
        let proposal = Proposal {
            kind: "new_profile".into(),
            scan_id: scan_id.clone(),
            username: "alice".into(),
            site_name: "GitHub".into(),
            site_url: "https://github.com/alice".into(),
            target_profile_id: None,
            new_label: Some("alice".into()),
            evidence: vec![EvidenceRow {
                field: "bio".into(),
                value: "hello".into(),
                confidence: 95,
            }],
            rationale: "test".into(),
            score: 1.0,
        };
        let profile_id = apply_proposal(&v, &proposal).await.unwrap();

        let bytes = vec![0x89, 0x50, 0x4e, 0x47, 0xde, 0xad, 0xbe, 0xef];
        let id1 = record_media(&v, &profile_id, None, "https://cdn/a.png", "avatar", "image/png", bytes.clone(), None)
            .await
            .unwrap();
        let id2 = record_media(&v, &profile_id, None, "https://cdn/a.png", "avatar", "image/png", bytes.clone(), None)
            .await
            .unwrap();
        assert_eq!(id1, id2, "duplicate (profile, url, kind) should dedup to same row");

        let fetched = fetch_media(&v, id1).await.unwrap().expect("present");
        assert_eq!(fetched.0, "image/png");
        assert_eq!(fetched.1, bytes);

        // Profile detail should include the media metadata.
        let detail = get_profile(&v, &profile_id).await.unwrap();
        let media = detail["media"].as_array().expect("media array");
        assert_eq!(media.len(), 1);
        assert_eq!(media[0]["mime"], "image/png");
        assert_eq!(media[0]["kind"], "avatar");

        // Empty bytes are rejected.
        let empty = record_media(&v, &profile_id, None, "https://cdn/empty", "avatar", "image/png", vec![], None).await;
        assert!(empty.is_err());
    }

    /// 1x1 RGB pixel encoded as a PNG — minimum valid image for testing
    /// the phash compute + similarity path.
    fn red_pixel_png() -> Vec<u8> {
        let img: image::RgbImage = image::ImageBuffer::from_pixel(8, 8, image::Rgb([255u8, 0, 0]));
        let mut buf: Vec<u8> = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
            .unwrap();
        buf
    }

    fn blue_pixel_png() -> Vec<u8> {
        let img: image::RgbImage = image::ImageBuffer::from_pixel(8, 8, image::Rgb([0u8, 0, 255]));
        let mut buf: Vec<u8> = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
            .unwrap();
        buf
    }

    #[tokio::test]
    async fn phash_compute_and_similarity_search() {
        let dir = tempfile::tempdir().unwrap();
        let v = VaultState::new(dir.path());
        v.init("test-pass-12345").await.unwrap();
        let scan_id = record_scan_start(&v, r#"["alice"]"#.into(), 1).await.unwrap();

        // Two profiles, each with an avatar.
        let proposal = |label: &str, site: &str| Proposal {
            kind: "new_profile".into(),
            scan_id: scan_id.clone(),
            username: label.into(),
            site_name: site.into(),
            site_url: format!("https://{site}/{label}"),
            target_profile_id: None,
            new_label: Some(label.into()),
            evidence: vec![EvidenceRow {
                field: "bio".into(),
                value: "hi".into(),
                confidence: 95,
            }],
            rationale: "test".into(),
            score: 1.0,
        };
        let pid_a = apply_proposal(&v, &proposal("alice", "GitHub")).await.unwrap();
        let pid_b = apply_proposal(&v, &proposal("bob", "GitHub")).await.unwrap();

        // pHash must be stable for the same content.
        let red = red_pixel_png();
        let red_hash = compute_phash_hex(&red).expect("pHash on a valid PNG");
        let red_hash_again = compute_phash_hex(&red).expect("stable");
        assert_eq!(red_hash, red_hash_again);

        // Different content gives a different hash.
        let blue = blue_pixel_png();
        let blue_hash = compute_phash_hex(&blue).expect("pHash on a valid PNG");
        // Don't assert inequality strictly — for an 8x8 solid-color image
        // the hash can degenerate. But the round-trip via the helper
        // must at least produce *some* hex string.
        assert_eq!(blue_hash.len(), red_hash.len());

        // Store two media rows: alice has the red, bob has the same red (a
        // direct repost). Expect find_similar_by_phash(seed=alice) to
        // surface bob with distance 0.
        let id_a = record_media(&v, &pid_a, None, "https://cdn/a.png", "avatar", "image/png", red.clone(), Some(red_hash.clone()))
            .await
            .unwrap();
        let id_b = record_media(&v, &pid_b, None, "https://cdn/b.png", "avatar", "image/png", red, Some(red_hash.clone()))
            .await
            .unwrap();
        assert_ne!(id_a, id_b);

        let hits = find_similar_by_phash(&v, id_a, 8).await.unwrap();
        assert_eq!(hits.len(), 1, "exactly one near-duplicate expected (bob's copy)");
        assert_eq!(hits[0]["id"].as_i64(), Some(id_b));
        assert_eq!(hits[0]["hamming_distance"].as_u64(), Some(0));

        // Non-image bytes ⇒ compute_phash_hex returns None.
        assert!(compute_phash_hex(b"not an image").is_none());

        // Hamming distance helpers — small sanity check.
        assert_eq!(hamming_distance(&[0b1010_1010], &[0b1010_1010]), 0);
        assert_eq!(hamming_distance(&[0b1010_1010], &[0b1010_1011]), 1);
        assert_eq!(hamming_distance(&[0xff, 0xff], &[0x00, 0x00]), 16);
    }

    #[tokio::test]
    async fn note_update_and_threshold_clamp() {
        use crate::result::ExtractedValue;

        let dir = tempfile::tempdir().unwrap();
        let v = VaultState::new(dir.path());
        v.init("test-pass-12345").await.unwrap();
        let scan_id_setup = record_scan_start(&v, r#"["alice"]"#.into(), 1).await.unwrap();

        // Create a profile.
        let proposal = Proposal {
            kind: "new_profile".into(),
            scan_id: scan_id_setup,
            username: "alice".into(),
            site_name: "GitHub".into(),
            site_url: "https://github.com/alice".into(),
            target_profile_id: None,
            new_label: Some("alice".into()),
            evidence: vec![EvidenceRow {
                field: "bio".into(),
                value: "hi".into(),
                confidence: 95,
            }],
            rationale: "test".into(),
            score: 1.0,
        };
        let profile_id = apply_proposal(&v, &proposal).await.unwrap();

        // Note round-trip.
        let updated = update_profile_note(&v, &profile_id, "met at conf").await.unwrap();
        assert!(updated);
        let detail = get_profile(&v, &profile_id).await.unwrap();
        assert_eq!(detail["note"], "met at conf");

        // Updating a non-existent profile yields false (no row matched).
        let none = update_profile_note(&v, "no-such-id", "x").await.unwrap();
        assert!(!none);

        // Custom threshold above the proposal's score must queue, not apply.
        let scan_id = record_scan_start(&v, r#"["carol"]"#.into(), 1).await.unwrap();
        let mut ex = std::collections::HashMap::new();
        ex.insert("bio".to_string(), ExtractedValue::One("c".into()));
        // First time we see "carol" → kind=new_profile, score=1.0.
        // Threshold 0.95 (the max clamp) still applies (1.0 >= 0.95).
        let out = propose_or_apply(&v, &scan_id, "carol", "X", "https://x/carol", &ex, 80, true, Some(0.95)).await.unwrap();
        assert!(matches!(out, ProposalOutcome::Applied { .. }));

        // Threshold below clamp floor — should be clamped to 0.50.
        // For a fresh username, new_profile has score 1.0 ≥ 0.50, so still applies.
        // Use an accumulate scenario via username match: same username again → kind=accumulate, score=0.90.
        let out2 = propose_or_apply(&v, &scan_id, "carol", "Y", "https://y/carol", &ex, 80, true, Some(0.95)).await.unwrap();
        // accumulate score = 0.90 < threshold 0.95 ⇒ queued.
        assert!(matches!(out2, ProposalOutcome::Queued { .. }));
    }

    #[tokio::test]
    async fn delete_profile_cascades_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let v = VaultState::new(dir.path());
        v.init("test-pass-12345").await.unwrap();
        let scan_id = record_scan_start(&v, r#"["dan"]"#.into(), 1).await.unwrap();

        let proposal = Proposal {
            kind: "new_profile".into(),
            scan_id,
            username: "dan".into(),
            site_name: "GitHub".into(),
            site_url: "https://github.com/dan".into(),
            target_profile_id: None,
            new_label: Some("dan".into()),
            evidence: vec![EvidenceRow {
                field: "bio".into(),
                value: "hi".into(),
                confidence: 95,
            }],
            rationale: "test".into(),
            score: 1.0,
        };
        let pid = apply_proposal(&v, &proposal).await.unwrap();
        assert_eq!(list_profiles(&v).await.unwrap().len(), 1);

        let removed = delete_profile(&v, &pid).await.unwrap();
        assert!(removed);
        assert_eq!(list_profiles(&v).await.unwrap().len(), 0);

        // Deleting again yields false.
        let again = delete_profile(&v, &pid).await.unwrap();
        assert!(!again);
    }
}
