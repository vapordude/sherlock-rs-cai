use crate::checker::{self, CheckConfig};
use crate::export;
use crate::result::{QueryResult, QueryStatus};
use crate::sites::{self, SiteData};
use axum::extract::{Query, State};
use axum::http::header;
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

const FRONTEND_HTML: &str = include_str!("../frontend/index.html");

/// Shared application state orchestrating in-memory caching across Axum handlers.
///
/// Per-request scan results are *not* held here — exports are stateless and
/// receive the result set from the client over a POST body, so concurrent
/// users never collide on a shared `last_results` vector.
pub struct AppState {
    pub sites: RwLock<Option<Arc<HashMap<String, SiteData>>>>,
    pub load_error: RwLock<Option<String>>,
}

impl AppState {
    /// Initializes a new empty state, locking until the asynchronous target definition parsing finishes.
    pub fn new() -> Self {
        Self {
            sites: RwLock::new(None),
            load_error: RwLock::new(None),
        }
    }
}

/// Configures and yields the application's root Axum router binding core application endpoints to underlying handlers.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/api/status", get(status_handler))
        .route("/api/search", get(search_handler))
        .route("/api/export/csv", post(export_csv_handler))
        .route("/api/export/txt", post(export_txt_handler))
        .route("/api/update-db", post(update_db_handler))
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
}

/// Parses a comma/newline/semicolon-separated list of usernames into a
/// deduplicated, trimmed, length-capped vector. Order is preserved.
fn parse_usernames(raw: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    raw.split(|c: char| c == ',' || c == '\n' || c == ';')
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
    } = args;

    tokio::spawn(async move {
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
            let (checker_tx, mut checker_rx) =
                tokio::sync::mpsc::channel::<QueryResult>(300);

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
                .send(Ok(Event::default()
                    .event("username_done")
                    .data(done_json)))
                .await
                .is_err()
            {
                return;
            }
        }

        // ── Overall done ──────────────────────────────────────────────────────
        let _ = sse_tx
            .send(Ok(Event::default().event("done").data(
                serde_json::to_string(&serde_json::json!({
                    "total_usernames": usernames.len(),
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
