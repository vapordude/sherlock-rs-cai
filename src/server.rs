use crate::checker::{self, CheckConfig};
use crate::export;
use crate::result::{QueryResult, QueryStatus};
use crate::sites::{self, SiteData};
use axum::extract::{Query, State};
use axum::http::header;
#[cfg(feature = "vault")]
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;
use tower_http::limit::RequestBodyLimitLayer;

#[cfg(feature = "vault")]
use crate::vault::VaultState;

const FRONTEND_HTML: &str = include_str!("../frontend/index.html");

/// Maximum body size for any POST payload. Default axum cap is 2 MiB which
/// is too tight for vault-aware exports and bulk-note imports — 10 MiB is
/// a generous floor without inviting DoS.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Shared application state orchestrating in-memory caching across Axum handlers.
///
/// Per-request scan results are *not* held here — exports are stateless and
/// receive the result set from the client over a POST body, so concurrent
/// users never collide on a shared `last_results` vector.
pub struct AppState {
    pub sites: RwLock<Option<Arc<HashMap<String, SiteData>>>>,
    pub load_error: RwLock<Option<String>>,
    #[cfg(feature = "vault")]
    pub vault: Arc<VaultState>,
}

impl AppState {
    /// Initializes a new empty state, locking until the asynchronous target definition parsing finishes.
    pub fn new() -> Self {
        Self {
            sites: RwLock::new(None),
            load_error: RwLock::new(None),
            #[cfg(feature = "vault")]
            vault: VaultState::new(&data_dir_for_vault()),
        }
    }
}

#[cfg(feature = "vault")]
fn data_dir_for_vault() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("sherlock-rs")
}

/// Configures and yields the application's root Axum router binding core application endpoints to underlying handlers.
pub fn create_router(state: Arc<AppState>) -> Router {
    let router = Router::new()
        .route("/", get(index_handler))
        .route("/api/status", get(status_handler))
        .route("/api/search", get(search_handler))
        .route("/api/export/csv", post(export_csv_handler))
        .route("/api/export/txt", post(export_txt_handler))
        .route("/api/update-db", post(update_db_handler));

    #[cfg(feature = "vault")]
    let router = router
        .route("/api/vault/status", get(vault_status_handler))
        .route("/api/vault/init", post(vault_init_handler))
        .route("/api/vault/unlock", post(vault_unlock_handler))
        .route("/api/vault/lock", post(vault_lock_handler))
        .route("/api/profiles", get(profiles_list_handler))
        .route("/api/profiles/:id", get(profile_detail_handler))
        .route("/api/profiles/:id", axum::routing::delete(profile_delete_handler))
        .route("/api/profiles/:id/note", post(profile_note_handler))
        .route("/api/media/:id", get(media_get_handler))
        .route("/api/media/:id/similar", get(media_similar_handler))
        .route("/api/review/pending", get(review_pending_handler))
        .route("/api/review/count", get(review_count_handler))
        .route("/api/review/:id/accept", post(review_accept_handler))
        .route("/api/review/:id/reject", post(review_reject_handler))
        .route("/api/audit", get(audit_handler));

    router
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .with_state(state)
}

/// Renders the primary application user interface dynamically injected at compile-time.
async fn index_handler() -> Html<&'static str> {
    Html(FRONTEND_HTML)
}

#[derive(Serialize)]
struct StatusResponse {
    ready: bool,
    sites_count: usize,
    error: Option<String>,
}

/// Retrieves the target initialization state of the underlying backend instance.
async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let sites = state.sites.read().await;
    let error = state.load_error.read().await;
    Json(StatusResponse {
        ready: sites.is_some(),
        sites_count: sites.as_ref().map(|s| s.len()).unwrap_or(0),
        error: error.clone(),
    })
}

#[derive(Deserialize)]
struct SearchParams {
    usernames: String, // comma/newline-separated list
    timeout: Option<u64>,
    nsfw: Option<bool>,
    proxy: Option<String>,
    /// Persist evidence + scan rows to the encrypted vault. Requires the
    /// vault to be unlocked; silently ignored when locked or feature-off.
    #[serde(default)]
    #[cfg_attr(not(feature = "vault"), allow(dead_code))]
    save_evidence: bool,
    /// Trust mode: high-confidence correlation/accumulation proposals
    /// (score ≥ AUTO_ACCEPT_THRESHOLD) are applied immediately instead of
    /// queued for human review. Every auto-application still writes to
    /// `audit_log` so the action is reviewable after the fact.
    #[serde(default)]
    #[cfg_attr(not(feature = "vault"), allow(dead_code))]
    auto_accept: bool,
    /// Override the default 0.80 auto-accept threshold. Clamped to
    /// [0.50, 0.95] server-side. Has no effect when `auto_accept=false`.
    #[serde(default)]
    #[cfg_attr(not(feature = "vault"), allow(dead_code))]
    auto_accept_threshold: Option<f64>,
    /// When set, fetch any `avatar_url` extracted from a `Claimed` hit and
    /// store the bytes (under SQLCipher encryption) against the profile.
    /// Only fires on the auto-accept path — queued proposals don't
    /// pre-fetch media to keep the UI snappy.
    #[serde(default)]
    #[cfg_attr(not(feature = "vault"), allow(dead_code))]
    download_media: bool,
}

#[derive(Serialize)]
struct SseResultData {
    username: String,
    site_name: String,
    url_main: String,
    site_url: String,
    status: String,
    response_time_ms: Option<u64>,
    checked: usize,
    total: usize,
    /// Verdict confidence 0..=100 (see `checker::determine_status_v2`).
    confidence: u8,
    /// Extracted profile fields when present (only on `Claimed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    extracted: Option<std::collections::HashMap<String, crate::result::ExtractedValue>>,
}

/// Parses a comma/newline/semicolon-separated list of usernames into a
/// deduplicated, trimmed, length-capped vector. Order is preserved.
fn parse_usernames(raw: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    raw.split([',', '\n', ';'])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && seen.insert(s.clone()))
        .take(10)
        .collect()
}

/// Inputs needed by the background scan task spawned from `search_handler`.
struct SearchTaskArgs {
    usernames: Vec<String>,
    sites: Arc<HashMap<String, SiteData>>,
    total: usize,
    config: CheckConfig,
    sse_tx: tokio::sync::mpsc::Sender<Result<Event, Infallible>>,
    #[cfg(feature = "vault")]
    vault_ctx: Option<VaultScanCtx>,
}

#[cfg(feature = "vault")]
#[derive(Clone)]
struct VaultScanCtx {
    vault: Arc<VaultState>,
    auto_accept: bool,
    auto_accept_threshold: Option<f64>,
    download_media: bool,
}

/// Drives the per-username checker fan-out and forwards SSE events to the
/// client. Owns its inputs; touches no shared state.
fn spawn_search_task(args: SearchTaskArgs) {
    let SearchTaskArgs {
        usernames,
        sites,
        total,
        config,
        sse_tx,
        #[cfg(feature = "vault")]
        vault_ctx,
    } = args;

    tokio::spawn(async move {
        // ── Optional: start a scan row in the vault ──────────────────────────
        #[cfg(feature = "vault")]
        let scan_id = match &vault_ctx {
            Some(ctx) => {
                let usernames_json = serde_json::to_string(&usernames).unwrap_or_default();
                crate::vault::record_scan_start(&ctx.vault, usernames_json, total).await.ok()
            }
            None => None,
        };
        #[cfg(feature = "vault")]
        let mut total_hits = 0usize;
        #[cfg(feature = "vault")]
        let mut auto_accepted = 0usize;
        #[cfg(feature = "vault")]
        let mut queued = 0usize;

        for username in &usernames {
            // ── username_start ────────────────────────────────────────────────
            let start_json = serde_json::to_string(&serde_json::json!({
                "username": username,
                "total": total,
            }))
            .unwrap_or_default();

            if sse_tx
                .send(Ok(Event::default()
                    .event("username_start")
                    .data(start_json)))
                .await
                .is_err()
            {
                return;
            }

            // ── Run checker ───────────────────────────────────────────────────
            let (checker_tx, mut checker_rx) = tokio::sync::mpsc::channel::<QueryResult>(300);

            let sites_clone = sites.clone();
            let uname = username.clone();
            let task_config = CheckConfig {
                timeout_secs: config.timeout_secs,
                include_nsfw: config.include_nsfw,
                proxy: config.proxy.clone(),
            };

            tokio::spawn(async move {
                checker::check_username(&uname, &sites_clone, &task_config, checker_tx).await;
            });

            let mut checked = 0usize;
            let mut found = 0usize;

            while let Some(result) = checker_rx.recv().await {
                checked += 1;
                if result.status == QueryStatus::Claimed {
                    found += 1;
                    #[cfg(feature = "vault")]
                    {
                        total_hits += 1;
                    }
                }

                // ── Optional: persist this row + propose vault accumulations ──
                #[cfg(feature = "vault")]
                if let (Some(ctx), Some(sid)) = (&vault_ctx, &scan_id) {
                    let _ = crate::vault::record_scan_result(
                        &ctx.vault,
                        sid,
                        username,
                        &result.site_name,
                        &result.site_url,
                        result.status.as_str(),
                        result.confidence,
                        result.response_time_ms,
                        result.body_sha256.as_deref(),
                    )
                    .await;
                    if result.status == QueryStatus::Claimed {
                        if let Some(extracted) = &result.extracted {
                            match crate::vault::propose_or_apply(
                                &ctx.vault,
                                sid,
                                username,
                                &result.site_name,
                                &result.site_url,
                                extracted,
                                result.confidence,
                                ctx.auto_accept,
                                ctx.auto_accept_threshold,
                            )
                            .await
                            {
                                Ok(crate::vault::ProposalOutcome::Applied { profile_id }) => {
                                    auto_accepted += 1;
                                    // Opt-in media fetch (avatars only, V1).
                                    if ctx.download_media {
                                        if let Some(crate::result::ExtractedValue::One(url)) =
                                            extracted.get("avatar_url")
                                        {
                                            let _ = fetch_and_store_avatar(
                                                &ctx.vault,
                                                &profile_id,
                                                url,
                                            )
                                            .await;
                                        }
                                    }
                                }
                                Ok(crate::vault::ProposalOutcome::Queued { .. }) => {
                                    queued += 1;
                                }
                                _ => {}
                            }
                        }
                    }
                }

                let event_data = SseResultData {
                    username: username.clone(),
                    site_name: result.site_name,
                    url_main: result.url_main,
                    site_url: result.site_url,
                    status: result.status.as_str().to_string(),
                    response_time_ms: result.response_time_ms,
                    checked,
                    total,
                    confidence: result.confidence,
                    extracted: result.extracted,
                };

                let json = serde_json::to_string(&event_data).unwrap_or_default();
                if sse_tx
                    .send(Ok(Event::default().event("result").data(json)))
                    .await
                    .is_err()
                {
                    return;
                }
            }

            // ── username_done ─────────────────────────────────────────────────
            let done_json = serde_json::to_string(&serde_json::json!({
                "username": username,
                "found": found,
                "checked": checked,
            }))
            .unwrap_or_default();

            if sse_tx
                .send(Ok(Event::default().event("username_done").data(done_json)))
                .await
                .is_err()
            {
                return;
            }
        }

        // ── Optional: finalise the scan row in the vault ────────────────────
        #[cfg(feature = "vault")]
        let vault_summary = match (&vault_ctx, &scan_id) {
            (Some(ctx), Some(sid)) => {
                let _ = crate::vault::record_scan_finish(&ctx.vault, sid, total_hits).await;
                Some(serde_json::json!({
                    "scan_id":       sid,
                    "auto_accepted": auto_accepted,
                    "queued":        queued,
                }))
            }
            _ => None,
        };
        #[cfg(not(feature = "vault"))]
        let vault_summary: Option<serde_json::Value> = None;

        // ── Overall done ──────────────────────────────────────────────────────
        let _ = sse_tx
            .send(Ok(Event::default().event("done").data(
                serde_json::to_string(&serde_json::json!({
                    "total_usernames": usernames.len(),
                    "vault":           vault_summary,
                }))
                .unwrap_or_default(),
            )))
            .await;
    });
}

/// Executes a live scan spanning active sites, streaming SSE events to the client.
async fn search_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let (sse_tx, sse_rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(500);

    let usernames = parse_usernames(&params.usernames);
    if usernames.is_empty() {
        let (_, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(1);
        return Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default());
    }

    let sites_guard = state.sites.read().await;
    let sites = sites_guard.clone().unwrap_or_default();
    drop(sites_guard);

    let include_nsfw = params.nsfw.unwrap_or(false);
    let total: usize = sites
        .values()
        .filter(|s| include_nsfw || !s.is_nsfw.unwrap_or(false))
        .count();

    // Capture vault context only when the user opted in AND the vault is
    // unlocked. Locked vault silently skips evidence writes — the search
    // still runs, the UI shows a "vault locked" banner.
    #[cfg(feature = "vault")]
    let vault_ctx = if params.save_evidence && !state.vault.is_locked().await {
        Some(VaultScanCtx {
            vault: state.vault.clone(),
            auto_accept: params.auto_accept,
            auto_accept_threshold: params.auto_accept_threshold,
            download_media: params.download_media,
        })
    } else {
        None
    };

    spawn_search_task(SearchTaskArgs {
        usernames,
        sites,
        total,
        config: CheckConfig {
            timeout_secs: params.timeout.unwrap_or(30),
            include_nsfw,
            proxy: params.proxy.clone(),
        },
        sse_tx,
        #[cfg(feature = "vault")]
        vault_ctx,
    });

    Sse::new(ReceiverStream::new(sse_rx)).keep_alive(KeepAlive::default())
}

/// Formats a client-supplied result set into CSV. Stateless: the caller POSTs
/// the rows it wants exported, so concurrent users never share a buffer.
async fn export_csv_handler(Json(results): Json<Vec<QueryResult>>) -> impl IntoResponse {
    let csv_data = export::to_csv(&results);
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"sherlock_results.csv\"",
            ),
        ],
        csv_data,
    )
}

/// Formats a client-supplied result set into a human-readable text report.
/// Stateless — see `export_csv_handler`.
async fn export_txt_handler(Json(results): Json<Vec<QueryResult>>) -> impl IntoResponse {
    let txt_data = export::to_txt(&results);
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"sherlock_results.txt\"",
            ),
        ],
        txt_data,
    )
}

#[derive(Serialize)]
struct UpdateResponse {
    success: bool,
    sites_count: usize,
    error: Option<String>,
}

/// Restarts the target definition parser forcing a hard download replacing all in-memory structures locally.
async fn update_db_handler(State(state): State<Arc<AppState>>) -> Json<UpdateResponse> {
    match sites::download_sites().await {
        Ok(new_sites) => {
            let count = new_sites.len();
            *state.sites.write().await = Some(Arc::new(new_sites));
            *state.load_error.write().await = None;
            Json(UpdateResponse {
                success: true,
                sites_count: count,
                error: None,
            })
        }
        Err(e) => Json(UpdateResponse {
            success: false,
            sites_count: 0,
            error: Some(e.to_string()),
        }),
    }
}

// ── Vault endpoints ──────────────────────────────────────────────────────────
// Gated behind the `vault` feature so a `--no-default-features` build doesn't
// pull in SQLCipher. The frontend feature-detects these via /api/vault/status.

#[cfg(feature = "vault")]
#[derive(Deserialize)]
struct PassphraseBody {
    passphrase: String,
}

#[cfg(feature = "vault")]
async fn vault_status_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let status = state.vault.status().await;
    Json(status)
}

#[cfg(feature = "vault")]
async fn vault_init_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PassphraseBody>,
) -> impl IntoResponse {
    if body.passphrase.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "passphrase must be at least 8 characters",
                "recovery": "none — there is no passphrase recovery; choose carefully"
            })),
        );
    }
    match state.vault.init(&body.passphrase).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "warning": "Forgetting this passphrase means permanent data loss. There is no recovery."
            })),
        ),
        Err(e) if e.to_string().contains("already initialized") => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "vault already initialized"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
async fn vault_unlock_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PassphraseBody>,
) -> impl IntoResponse {
    match state.vault.unlock(&body.passphrase).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) if e.to_string().contains("wrong passphrase") => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "wrong passphrase"})),
        ),
        Err(e) if e.to_string().contains("not initialized") => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "vault not initialized"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
async fn vault_lock_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.vault.lock().await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// ── Media fetch helper ───────────────────────────────────────────────────────

/// Fetch the avatar URL with a tight timeout + a 2 MiB body cap, then
/// hand the bytes off to the vault. Non-fatal — a failed fetch is logged
/// to stderr and the search continues. Only image MIME types are stored
/// to avoid surprises (no `text/html` blobs sneaking into the gallery).
#[cfg(feature = "vault")]
async fn fetch_and_store_avatar(
    vault: &std::sync::Arc<VaultState>,
    profile_id: &str,
    url: &str,
) -> anyhow::Result<()> {
    const MAX_BYTES: usize = 2 * 1024 * 1024;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("avatar fetch HTTP {}", resp.status());
    }
    let mime = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| "application/octet-stream".to_string());
    if !mime.starts_with("image/") {
        anyhow::bail!("non-image content-type {mime}");
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_BYTES {
        anyhow::bail!("avatar too large ({} bytes)", bytes.len());
    }
    let bytes_vec = bytes.to_vec();
    // pHash is best-effort — a failure to compute (corrupt bytes, unusual
    // format) leaves the row with phash=NULL but the bytes are still stored
    // and served by /api/media/:id.
    let phash = crate::vault::compute_phash_hex(&bytes_vec);
    crate::vault::record_media(
        vault,
        profile_id,
        None,
        url,
        "avatar",
        &mime,
        bytes_vec,
        phash,
    )
    .await?;
    Ok(())
}

// ── Profiles / Review / Audit (vault feature only) ───────────────────────────

#[cfg(feature = "vault")]
fn vault_locked_response() -> (StatusCode, Json<serde_json::Value>) {
    // 423 Locked is the canonical HTTP code for "resource is locked".
    (
        StatusCode::LOCKED,
        Json(serde_json::json!({"error": "vault locked"})),
    )
}

#[cfg(feature = "vault")]
async fn profiles_list_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.vault.is_locked().await {
        return vault_locked_response();
    }
    match crate::vault::list_profiles(&state.vault).await {
        Ok(rows) => (StatusCode::OK, Json(serde_json::json!({"profiles": rows}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
async fn profile_detail_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.vault.is_locked().await {
        return vault_locked_response();
    }
    match crate::vault::get_profile(&state.vault, &id).await {
        Ok(serde_json::Value::Null) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        ),
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
async fn review_pending_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.vault.is_locked().await {
        return vault_locked_response();
    }
    match crate::vault::list_pending(&state.vault).await {
        Ok(rows) => (StatusCode::OK, Json(serde_json::json!({"pending": rows}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
async fn review_count_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.vault.is_locked().await {
        return (StatusCode::OK, Json(serde_json::json!({"count": 0, "locked": true})));
    }
    match crate::vault::count_pending(&state.vault).await {
        Ok(n) => (StatusCode::OK, Json(serde_json::json!({"count": n, "locked": false}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
#[derive(Deserialize, Default)]
struct ReviewActionBody {
    #[serde(default)]
    note: Option<String>,
}

#[cfg(feature = "vault")]
async fn review_accept_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    body: Option<Json<ReviewActionBody>>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.vault.is_locked().await {
        return vault_locked_response();
    }
    let note = body.and_then(|b| b.0.note);
    match crate::vault::accept_pending(&state.vault, id, note).await {
        Ok(profile_id) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "profile_id": profile_id})),
        ),
        Err(e) if e.to_string().contains("already resolved") => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "already resolved"})),
        ),
        Err(e) if e.to_string().contains("not found") => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
async fn review_reject_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    body: Option<Json<ReviewActionBody>>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.vault.is_locked().await {
        return vault_locked_response();
    }
    let note = body.and_then(|b| b.0.note);
    match crate::vault::reject_pending(&state.vault, id, note).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Err(e) if e.to_string().contains("not pending") => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "not pending or not found"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
async fn audit_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.vault.is_locked().await {
        return vault_locked_response();
    }
    match crate::vault::list_audit(&state.vault, 200).await {
        Ok(rows) => (StatusCode::OK, Json(serde_json::json!({"audit": rows}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
#[derive(Deserialize)]
struct NoteBody {
    note: String,
}

#[cfg(feature = "vault")]
async fn profile_note_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<NoteBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.vault.is_locked().await {
        return vault_locked_response();
    }
    if body.note.len() > 64 * 1024 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "note exceeds 64 KiB"})),
        );
    }
    match crate::vault::update_profile_note(&state.vault, &id, &body.note).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "profile not found"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
async fn profile_delete_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.vault.is_locked().await {
        return vault_locked_response();
    }
    match crate::vault::delete_profile(&state.vault, &id).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "profile not found"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
#[derive(Deserialize)]
struct SimilarQuery {
    /// Hamming-distance cap (over the 64-bit phash). Default 8 — covers
    /// re-encodes, mild scaling, and watermark overlays without flooding
    /// the result list. Server-side clamped to [0, 32].
    #[serde(default)]
    max_distance: Option<u32>,
}

#[cfg(feature = "vault")]
async fn media_similar_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Query(q): Query<SimilarQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.vault.is_locked().await {
        return vault_locked_response();
    }
    let max_distance = q.max_distance.unwrap_or(8).min(32);
    match crate::vault::find_similar_by_phash(&state.vault, id, max_distance).await {
        Ok(hits) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "seed_id":      id,
                "max_distance": max_distance,
                "matches":      hits,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

#[cfg(feature = "vault")]
async fn media_get_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if state.vault.is_locked().await {
        return vault_locked_response().into_response();
    }
    match crate::vault::fetch_media(&state.vault, id).await {
        Ok(Some((mime, bytes))) => (
            [
                (header::CONTENT_TYPE, mime),
                // Cache aggressively — these bytes are immutable per id.
                (header::CACHE_CONTROL, "private, max-age=3600".into()),
            ],
            bytes,
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
