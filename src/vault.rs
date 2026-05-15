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
}
