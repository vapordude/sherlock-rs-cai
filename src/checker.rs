use crate::result::{QueryResult, QueryStatus};
use crate::sites::{Detection, SiteData};
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::sleep;

/// ── 25 real browser User-Agents ─────────────────────────────────────────────
/// A curated list of real, modern browser `User-Agent` strings used
/// to rotate identities dynamically and reduce bot detection blocks.
const USER_AGENTS: &[&str] = &[
    // Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    // Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    // Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    // Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    // Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    // Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    // Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    // Edge macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    // Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    // Safari iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    // Chrome Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    // Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0",
    // Brave (same UA as Chrome, different internals)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
];

fn random_ua() -> &'static str {
    USER_AGENTS
        .choose(&mut rand::thread_rng())
        .copied()
        .unwrap_or(USER_AGENTS[0])
}

// ── WAF signatures ────────────────────────────────────────────────────────────
const WAF_SIGNATURES: &[&str] = &[
    "attention required! | cloudflare",
    "cf-browser-verification",
    "please wait... | cloudflare",
    "just a moment...",
    "checking your browser",
    "pardon our interruption",
    "access denied | ",
    "_cf_chl_opt",
];

/// Execution configuration passed to the engine during a target scan.
pub struct CheckConfig {
    pub timeout_secs: u64,
    pub include_nsfw: bool,
    pub proxy: Option<String>,
}

/// The core orchestration function managing a concurrent scan across
/// all configured sites for a single username target. It enforces NSFW filters,
/// regex validations, rotates proxies/user-agents, and delegates individual site
/// checks to sub-tasks utilizing exponential backoffs upon failures.
pub async fn check_username(
    username: &str,
    sites: &HashMap<String, SiteData>,
    config: &CheckConfig,
    tx: mpsc::Sender<QueryResult>,
) {
    let base_ua = random_ua();

    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .user_agent(base_ua)
        .danger_accept_invalid_certs(false);

    let mut client_no_redir_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .user_agent(base_ua)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(false);

    if let Some(proxy_url) = &config.proxy {
        if !proxy_url.is_empty() {
            if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
                client_builder = client_builder.proxy(proxy.clone());
                client_no_redir_builder = client_no_redir_builder.proxy(proxy);
            }
        }
    }

    let client = client_builder.build().unwrap_or_default();
    let client_no_redir = client_no_redir_builder.build().unwrap_or_default();

    let semaphore = Arc::new(Semaphore::new(20));
    let (result_tx, mut result_rx) = mpsc::channel::<QueryResult>(300);

    for (name, site) in sites.iter() {
        if !config.include_nsfw && site.is_nsfw.unwrap_or(false) {
            continue;
        }

        if let Some(re) = &site.compiled_regex {
            if !re.is_match(username) {
                let _ = result_tx
                    .send(QueryResult {
                        username: username.to_string(),
                        site_name: name.clone(),
                        url_main: site.url_main.clone(),
                        site_url: site.format_url(username),
                        status: QueryStatus::Illegal,
                        response_time_ms: None,
                        context: Some("Invalid username format for this site".into()),
                        confidence: 100,
                        extracted: None,
                        body_sha256: None,
                    })
                    .await;
                continue;
            }
        }

        let name = name.clone();
        let site = site.clone();
        let username = username.to_string();
        let c = client.clone();
        let cnr = client_no_redir.clone();
        let sem = semaphore.clone();
        let rtx = result_tx.clone();

        tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("Semaphore closed unexpectedly");
            let result = check_site_with_retry(&name, &site, &username, &c, &cnr).await;
            let _ = rtx.send(result).await;
        });
    }

    drop(result_tx);

    while let Some(result) = result_rx.recv().await {
        if tx.send(result).await.is_err() {
            break;
        }
    }
}

/// ── Retry wrapper: up to 3 attempts with exponential backoff ─────────────────
/// Wraps individual site requests with robust retry logic, firing up to 3 attempts
/// spaced by an exponential backoff specifically for network layer errors (timeouts,
/// DNS failures). Legitimate HTTP responses (even 403 or 404) skip retries immediately.
async fn check_site_with_retry(
    name: &str,
    site: &SiteData,
    username: &str,
    client: &reqwest::Client,
    client_no_redir: &reqwest::Client,
) -> QueryResult {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last: Option<QueryResult> = None;

    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            // Exponential backoff: 500ms → 1000ms
            sleep(Duration::from_millis(500 * (1u64 << (attempt - 1)))).await;
        }

        let result = check_site(name, site, username, client, client_no_redir).await;

        let is_network_error = matches!(result.status, QueryStatus::Unknown)
            && result
                .context
                .as_deref()
                .map(|c| c.starts_with("NET:"))
                .unwrap_or(false);

        if !is_network_error {
            return result;
        }

        last = Some(result);
    }

    // All retries exhausted — clean context for display
    let mut final_result = last.unwrap_or_else(|| QueryResult {
        username: username.to_string(),
        site_name: name.to_string(),
        url_main: site.url_main.clone(),
        site_url: site.format_url(username),
        status: QueryStatus::Unknown,
        response_time_ms: None,
        context: Some("All retries exhausted with no result".into()),
        confidence: 0,
        extracted: None,
        body_sha256: None,
    });
    if let Some(ctx) = final_result.context.as_mut() {
        if let Some(stripped) = ctx.strip_prefix("NET: ") {
            *ctx = format!("{} (after {} retries)", stripped, MAX_ATTEMPTS - 1);
        }
    }
    final_result
}

/// ── Core request function ─────────────────────────────────────────────────────
/// Formats the final URL payload and executes a single HTTP request evaluating
/// if the specified username is actively present on the target site.
/// Captures WAF signatures and specific HTTP return codes or error messages.
async fn check_site(
    name: &str,
    site: &SiteData,
    username: &str,
    client: &reqwest::Client,
    client_no_redir: &reqwest::Client,
) -> QueryResult {
    let url = site.format_url(username);
    let probe_url = site
        .url_probe
        .as_ref()
        .map(|u| u.replace("{}", username))
        .unwrap_or_else(|| url.clone());

    let active_client = if site.error_type == "response_url" {
        client_no_redir
    } else {
        client
    };

    let method = match site.request_method.as_deref() {
        Some("POST") => reqwest::Method::POST,
        Some("HEAD") => reqwest::Method::HEAD,
        Some("PUT") => reqwest::Method::PUT,
        _ => reqwest::Method::GET,
    };

    let start = Instant::now();

    // Override UA per request for rotation
    let mut request = active_client
        .request(method, &probe_url)
        .header(reqwest::header::USER_AGENT, random_ua());

    if let Some(headers) = &site.headers {
        for (k, v) in headers {
            request = request.header(k.as_str(), v.as_str());
        }
    }

    if let Some(payload) = &site.request_payload {
        let payload_str = serde_json::to_string(payload)
            .unwrap_or_default()
            .replace("{}", username);
        request = request
            .header("Content-Type", "application/json")
            .body(payload_str);
    }

    match request.send().await {
        Ok(response) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let status_code = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            let (status, confidence) = determine_status_v2(site, status_code, &body);
            let body_sha256 = Some(body_excerpt_sha256(&body));

            // Run profile extractors only on positively-claimed profiles.
            // Tentative is deliberately excluded — a contradictory rule
            // would yield unreliable extraction.
            let extracted = if matches!(status, QueryStatus::Claimed)
                && !site.compiled_extractors.is_empty()
            {
                let map = crate::extract::run_extractors(&body, &site.compiled_extractors);
                if map.is_empty() {
                    None
                } else {
                    Some(map)
                }
            } else {
                None
            };

            QueryResult {
                username: username.to_string(),
                site_name: name.to_string(),
                url_main: site.url_main.clone(),
                site_url: url,
                status,
                response_time_ms: Some(elapsed),
                context: None,
                confidence,
                extracted,
                body_sha256,
            }
        }
        Err(e) => {
            let elapsed = start.elapsed().as_millis() as u64;
            // Tag network errors so retry logic can identify them
            let prefix = if e.is_timeout() || e.is_connect() {
                "NET: "
            } else {
                "Error: "
            };
            QueryResult {
                username: username.to_string(),
                site_name: name.to_string(),
                url_main: site.url_main.clone(),
                site_url: url,
                status: QueryStatus::Unknown,
                response_time_ms: Some(elapsed),
                context: Some(format!("{}{}", prefix, e)),
                confidence: 0,
                extracted: None,
                body_sha256: None,
            }
        }
    }
}

fn detect_waf(body: &str) -> bool {
    let lower = body.to_lowercase();
    WAF_SIGNATURES.iter().any(|&sig| lower.contains(sig))
}

/// SHA-256 of the first 64 KiB of the response body, hex-encoded. Used by
/// the vault layer for cross-scan evidence dedup ("we saw this exact page
/// already"). Bounded so we don't hash megabyte responses on every probe.
fn body_excerpt_sha256(body: &str) -> String {
    const MAX: usize = 64 * 1024;
    let cap = body.len().min(MAX);
    let mut hasher = Sha256::new();
    hasher.update(&body.as_bytes()[..cap]);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

/// Decide a site's status, returning verdict + confidence (0..=100). WAF is
/// always checked first and wins. When `site.detection` is populated the
/// new dual-pattern rules apply; otherwise we fall through to the legacy
/// Sherlock single-pattern logic, mapping its verdicts to coarser
/// confidence buckets (70/80/30) to reflect that single-pattern detection
/// is less robust.
fn determine_status_v2(site: &SiteData, status_code: u16, body: &str) -> (QueryStatus, u8) {
    if detect_waf(body) {
        return (QueryStatus::Waf, 0);
    }
    if let Some(d) = &site.detection {
        return dual_pattern_decision(d, status_code, body);
    }
    let legacy = determine_status_legacy(site, status_code, body);
    let confidence = match legacy {
        QueryStatus::Claimed => 70,
        QueryStatus::Available => 80,
        _ => 30,
    };
    (legacy, confidence)
}

/// WhatsMyName-style dual-pattern decision. Truth table:
///
///   E  M  | Verdict    | Confidence
///   ──────┼────────────┼───────────
///   ✓  ✗  | Claimed    | 95
///   ✗  ✓  | Available  | 95
///   ✓  ✓  | Tentative  | 40   (rule needs updating — site likely changed)
///   ✗  ✗  | Unknown    | 20
///
/// `E` is true when (e_code matches if set) AND (e_string is in body if set).
/// `M` analogous for the missing pair. Constraints that are unset are
/// vacuously satisfied — so a rule with only `e_string` works fine. Worked
/// examples:
///
///   e_code=200, e_string="profile", m_code=404, m_string=None
///     200 body containing "profile"     ⇒ E=t, M=f ⇒ Claimed/95
///     404 body                          ⇒ E=f, M=t ⇒ Available/95
///     200 body without "profile"        ⇒ E=f, M=f ⇒ Unknown/20
///
///   e_string="hello"  (no codes set on either side)
///     anything containing "hello"       ⇒ E=t, M=t ⇒ Tentative/40
///         (because M had no constraints, it's vacuously satisfied)
fn dual_pattern_decision(d: &Detection, status_code: u16, body: &str) -> (QueryStatus, u8) {
    let e_match = d.e_code.map(|c| c == status_code).unwrap_or(true)
        && d.e_string
            .as_deref()
            .map(|s| body.contains(s))
            .unwrap_or(true);
    let m_match = d.m_code.map(|c| c == status_code).unwrap_or(true)
        && d.m_string
            .as_deref()
            .map(|s| body.contains(s))
            .unwrap_or(true);

    match (e_match, m_match) {
        (true, false) => (QueryStatus::Claimed, 95),
        (false, true) => (QueryStatus::Available, 95),
        (true, true) => (QueryStatus::Tentative, 40),
        (false, false) => (QueryStatus::Unknown, 20),
    }
}

/// The original Sherlock single-pattern decision, preserved verbatim. Used
/// when a site has no `Detection` block (i.e. unconverted Sherlock data).
fn determine_status_legacy(site: &SiteData, status_code: u16, body: &str) -> QueryStatus {
    match site.error_type.as_str() {
        "status_code" => {
            let is_error = site
                .error_code
                .as_ref()
                .map(|ec| ec.matches(status_code))
                .unwrap_or(status_code == 404);

            if is_error {
                QueryStatus::Available
            } else if (200..300).contains(&status_code) {
                QueryStatus::Claimed
            } else {
                QueryStatus::Unknown
            }
        }
        "message" => {
            if let Some(error_msgs) = &site.error_msg {
                let has_error = error_msgs.as_vec().iter().any(|msg| body.contains(msg));
                if has_error {
                    QueryStatus::Available
                } else if (200..300).contains(&status_code) {
                    QueryStatus::Claimed
                } else {
                    QueryStatus::Unknown
                }
            } else {
                QueryStatus::Unknown
            }
        }
        "response_url" => {
            if (200..300).contains(&status_code) {
                QueryStatus::Claimed
            } else {
                QueryStatus::Available
            }
        }
        _ => QueryStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(e_code: Option<u16>, e_str: Option<&str>, m_code: Option<u16>, m_str: Option<&str>) -> Detection {
        Detection {
            e_code,
            e_string: e_str.map(str::to_string),
            m_code,
            m_string: m_str.map(str::to_string),
        }
    }

    #[test]
    fn dual_pattern_claimed_when_only_exists_matches() {
        let d = det(Some(200), Some("profile"), Some(404), None);
        assert_eq!(
            dual_pattern_decision(&d, 200, "<html>profile</html>"),
            (QueryStatus::Claimed, 95)
        );
    }

    #[test]
    fn dual_pattern_available_when_only_missing_matches() {
        let d = det(Some(200), Some("profile"), Some(404), None);
        assert_eq!(
            dual_pattern_decision(&d, 404, ""),
            (QueryStatus::Available, 95)
        );
    }

    #[test]
    fn dual_pattern_tentative_when_both_match() {
        let d = det(None, Some("hello"), None, None); // M is vacuously true
        assert_eq!(
            dual_pattern_decision(&d, 200, "hello world"),
            (QueryStatus::Tentative, 40)
        );
    }

    #[test]
    fn dual_pattern_unknown_when_neither_matches() {
        let d = det(Some(200), Some("alpha"), Some(404), Some("beta"));
        assert_eq!(
            dual_pattern_decision(&d, 500, "neither here"),
            (QueryStatus::Unknown, 20)
        );
    }

    #[test]
    fn body_excerpt_sha256_is_stable_and_truncated() {
        let small = body_excerpt_sha256("hello");
        // Identical inputs hash identically.
        assert_eq!(small, body_excerpt_sha256("hello"));
        // A body longer than the 64 KiB excerpt only sees the first 64 KiB.
        let big = "x".repeat(70_000);
        let trunc = "x".repeat(64 * 1024);
        assert_eq!(body_excerpt_sha256(&big), body_excerpt_sha256(&trunc));
        // Length is always 64 hex chars.
        assert_eq!(small.len(), 64);
    }
}
