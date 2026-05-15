use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

const SHERLOCK_URL: &str = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json";
const WHATSMYNAME_URL: &str =
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json";

/// Curated subset of profile-extraction rules in a simplified, Maigret-inspired
/// shape. Vendored rather than fetched upstream because the full Maigret
/// `data.json` uses `engine: shared-template` indirections that we don't yet
/// resolve, and it pulls ~3 MB of records we don't need. Populated
/// incrementally; an empty file is a perfectly valid no-op.
const MAIGRET_SUBSET_JSON: &str = include_str!("maigret_subset.json");

/// Canonical extractor-field vocabulary. Unknown fields are dropped at parse
/// time so the encrypted vault never accumulates garbage keys. Kept in sync
/// with the documentation in `Extractor::field` and `extract.rs`.
const CANONICAL_FIELDS: &[&str] = &[
    "avatar_url",
    "bio",
    "display_name",
    "full_name",
    "location",
    "signup_date",
    "post_count",
    "follower_count",
    "following_count",
    "verified",
    "is_private",
    "last_seen",
    "external_links",
];

#[allow(dead_code)] // Used by parse_maigret + future extractor pipeline.
pub(crate) fn is_canonical_field(field: &str) -> bool {
    CANONICAL_FIELDS.contains(&field)
}

/// Represents the error message(s) expected from a site when a username is not found.
///
/// Can be either a single string or a list of possible string errors.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ErrorMsg {
    Single(String),
    Multiple(Vec<String>),
}

impl ErrorMsg {
    /// Converts the `ErrorMsg` into a vector of string slices for unified processing.
    pub fn as_vec(&self) -> Vec<&str> {
        match self {
            ErrorMsg::Single(s) => vec![s.as_str()],
            ErrorMsg::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

/// Represents the HTTP error code(s) indicating that a username does not exist.
///
/// It can either be a single HTTP status code or an array of valid codes.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ErrorCode {
    Single(u16),
    Multiple(Vec<u16>),
}

impl ErrorCode {
    /// Checks if a given HTTP status code is present in this `ErrorCode` definition.
    pub fn matches(&self, code: u16) -> bool {
        match self {
            ErrorCode::Single(c) => *c == code,
            ErrorCode::Multiple(codes) => codes.contains(&code),
        }
    }
}

/// The definition of a specific social media site's detection logic, structure,
/// and metadata matching the standard Sherlock database format.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct SiteData {
    #[serde(rename = "errorMsg")]
    pub error_msg: Option<ErrorMsg>,
    #[serde(rename = "errorType")]
    pub error_type: String,
    #[serde(rename = "errorCode")]
    pub error_code: Option<ErrorCode>,
    #[serde(rename = "errorUrl")]
    pub error_url: Option<String>,
    pub url: String,
    #[serde(rename = "urlMain")]
    pub url_main: String,
    #[serde(rename = "urlProbe")]
    pub url_probe: Option<String>,
    pub username_claimed: Option<String>,
    pub username_unclaimed: Option<String>,
    #[serde(rename = "regexCheck")]
    pub regex_check: Option<String>,
    #[serde(rename = "isNSFW")]
    pub is_nsfw: Option<bool>,
    pub headers: Option<HashMap<String, String>>,
    pub request_method: Option<String>,
    pub request_payload: Option<serde_json::Value>,
    /// Regex compiled once at parse time from `regex_check`. Skipped during
    /// (de)serialization — the on-disk `data.json` keeps only the source
    /// pattern, and this is rebuilt on every load.
    #[serde(skip)]
    pub compiled_regex: Option<Regex>,

    // ── Additive fields: enable WMN-style detection and Maigret-style extraction ──
    // All optional, all `#[serde(default)]`, so existing Sherlock `data.json`
    // (which has none of these fields) continues to deserialize unchanged.
    /// WhatsMyName-style dual-pattern detection. When present, this
    /// supersedes the legacy `error_type`/`error_code`/`error_msg` triple
    /// for classification — see `checker::dual_pattern_decision`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection: Option<Detection>,
    /// Maigret-style profile extractors. Each one pulls a single field
    /// (e.g. `avatar_url`, `bio`) from a `Claimed` response via CSS
    /// selector and optional regex post-filter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extractors: Vec<Extractor>,
    /// Free-form categorisation (WMN's `cat`, Maigret's `tags`). Used for
    /// filtering in the UI.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// Which upstream supplied this record. `Merged` indicates two or more
    /// sources contributed and `merge_site` combined them.
    #[serde(default)]
    pub source: SiteSource,
    /// Per-extractor compiled selector + regex, rebuilt at load time.
    /// Skipped during (de)serialization for the same reason as `compiled_regex`.
    #[serde(skip)]
    // Consumed by checker.rs / extract.rs in subsequent commits.
    #[allow(dead_code)]
    pub compiled_extractors: Vec<CompiledExtractor>,
}

impl SiteData {
    /// Substitutes the `{}` placeholder in `self.url` with the given username.
    pub fn format_url(&self, username: &str) -> String {
        self.url.replace("{}", username)
    }
}

/// WhatsMyName-style dual-pattern detection rule. A site is `Claimed` iff
/// the exists-pattern matches AND the missing-pattern doesn't (and vice
/// versa for `Available`). Either half may be omitted — a missing
/// constraint is vacuously satisfied.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Detection {
    /// HTTP status code asserting the profile exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e_code: Option<u16>,
    /// Substring whose presence in the body asserts the profile exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e_string: Option<String>,
    /// HTTP status code asserting the profile is missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m_code: Option<u16>,
    /// Substring whose presence in the body asserts the profile is missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m_string: Option<String>,
}

/// Maigret-style profile field extractor. One rule produces one named
/// field on a `Claimed` response; the field name must be in the canonical
/// vocabulary (see `extract::is_canonical_field`).
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Extractor {
    /// Canonical field name (e.g. `avatar_url`, `bio`, `display_name`).
    pub field: String,
    /// CSS selector evaluated against the response body. `None` matches
    /// the document root (rare — usually combined with a regex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    /// Attribute to read from the matched element. Defaults to the
    /// element's text content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    /// Optional post-extraction regex; capture group 1 is the value. Used
    /// to strip surrounding text from numeric counts, parse dates, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Whether to collect every match (becomes `Vec<String>` in the
    /// extracted output) or just the first.
    #[serde(default, skip_serializing_if = "is_false")]
    pub multi: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Compiled form of `Extractor` — built once at load time so the request
/// hot path doesn't re-parse CSS selectors or regex.
// Consumed by extract.rs in a subsequent commit.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct CompiledExtractor {
    pub field: String,
    pub selector: scraper::Selector,
    pub attribute: Option<String>,
    pub regex: Option<Regex>,
    pub multi: bool,
}

/// Which upstream supplied a given `SiteData` record.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SiteSource {
    /// The default — preserves backwards compatibility with Sherlock
    /// `data.json` files that have no explicit `source` key.
    #[default]
    Sherlock,
    Whatsmyname,
    Maigret,
    Custom,
    /// Two or more sources contributed and `merge_site` combined them.
    Merged,
}

/// Determines the local application data directory to cache site lists.
fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sherlock-rs")
}

/// Loads the target site database. Prefers the unified `data.merged.json`
/// cache if present; falls back to the legacy `data.json` from previous
/// versions; otherwise downloads from all configured upstreams.
pub async fn load_sites() -> Result<HashMap<String, SiteData>> {
    let dir = data_dir();
    let merged = dir.join("data.merged.json");
    let legacy = dir.join("data.json");

    if merged.exists() {
        let json = tokio::fs::read_to_string(&merged).await?;
        return parse_sherlock(&json);
    }
    if legacy.exists() {
        // Silent upgrade path: load the old cache so the user isn't stuck
        // waiting on network, but trigger a background re-download to land
        // the merged cache on next start.
        let json = tokio::fs::read_to_string(&legacy).await?;
        let sites = parse_sherlock(&json)?;
        tokio::spawn(async move {
            let _ = download_sites().await;
        });
        return Ok(sites);
    }
    download_sites().await
}

/// Fetches all configured upstreams in parallel, merges them by normalized
/// domain, layers in embedded custom sites and any `sites.d/*.json`
/// overrides, persists the unified cache and a meta sidecar, and returns
/// the merged map.
///
/// Individual upstream failures are non-fatal — we log to stderr and carry
/// on with whatever succeeded. If everything fails AND we have no prior
/// cache, the caller surfaces the error.
pub async fn download_sites() -> Result<HashMap<String, SiteData>> {
    let dir = data_dir();
    tokio::fs::create_dir_all(&dir).await?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let (sherlock_res, wmn_res) = tokio::join!(
        fetch_text(&client, SHERLOCK_URL),
        fetch_text(&client, WHATSMYNAME_URL),
    );

    let mut sherlock_count = 0usize;
    let mut wmn_count = 0usize;
    let mut maigret_count = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut sites: HashMap<String, SiteData> = HashMap::new();

    // ── Sherlock ──────────────────────────────────────────────────────────
    match sherlock_res.and_then(|j| parse_sherlock(&j)) {
        Ok(s) => {
            sherlock_count = s.len();
            sites = s;
        }
        Err(e) => errors.push(format!("sherlock: {e}")),
    }

    // ── WhatsMyName ───────────────────────────────────────────────────────
    match wmn_res.and_then(|j| parse_wmn(&j)) {
        Ok(w) => {
            wmn_count = w.len();
            merge_into(&mut sites, w);
        }
        Err(e) => errors.push(format!("whatsmyname: {e}")),
    }

    // ── Maigret subset (vendored at compile time) ────────────────────────
    match parse_maigret(MAIGRET_SUBSET_JSON) {
        Ok(m) => {
            maigret_count = m.len();
            merge_into(&mut sites, m);
        }
        Err(e) => errors.push(format!("maigret: {e}")),
    }

    // ── Built-in custom sites (NSFW defaults) ─────────────────────────────
    let custom_json = include_str!("custom_sites.json");
    if let Ok(custom_sites) = parse_sherlock(custom_json) {
        for (k, mut v) in custom_sites {
            v.is_nsfw = Some(true);
            v.source = SiteSource::Custom;
            sites.insert(k, v);
        }
    }

    // ── User overrides from ~/.local/share/sherlock-rs/sites.d/*.json ────
    let sites_d = dir.join("sites.d");
    if sites_d.exists() && sites_d.is_dir() {
        if let Ok(mut entries) = tokio::fs::read_dir(&sites_d).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(content) = tokio::fs::read_to_string(&path).await {
                        if let Ok(external_sites) = parse_sherlock(&content) {
                            for (k, v) in external_sites {
                                sites.insert(k, v);
                            }
                        }
                    }
                }
            }
        }
    } else {
        let _ = tokio::fs::create_dir_all(&sites_d).await;
    }

    if sites.is_empty() {
        anyhow::bail!(
            "no sites loaded from any source; errors: [{}]",
            errors.join("; ")
        );
    }

    if let Ok(merged_json) = serde_json::to_string(&sites) {
        let _ = tokio::fs::write(dir.join("data.merged.json"), &merged_json).await;
    }
    let meta = serde_json::json!({
        "fetched_at":     time::OffsetDateTime::now_utc().to_string(),
        "sherlock_count": sherlock_count,
        "wmn_count":      wmn_count,
        "maigret_count":  maigret_count,
        "total":          sites.len(),
        "errors":         errors,
    });
    let _ = tokio::fs::write(
        dir.join("data.merged.meta.json"),
        serde_json::to_string_pretty(&meta).unwrap_or_default(),
    )
    .await;

    Ok(sites)
}

async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {} from {}", resp.status(), url);
    }
    Ok(resp.text().await?)
}

/// Lowercase + strip `https?://`, leading `www.`, and trailing `/`.
/// Used as the dedup key when merging records from multiple upstreams.
fn normalize_domain(url_main: &str) -> Option<String> {
    let s = url_main.trim().to_ascii_lowercase();
    let after_scheme = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(&s);
    let host = after_scheme.split('/').next()?;
    let host = host.strip_prefix("www.").unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Merge `incoming` into `existing`, deduplicating by normalized domain. If a
/// domain already exists, `merge_site` combines fields with the precedence
/// rules documented on that function.
fn merge_into(existing: &mut HashMap<String, SiteData>, incoming: HashMap<String, SiteData>) {
    // Build a domain → existing-key index once so duplicate detection is O(1).
    let mut by_domain: HashMap<String, String> = HashMap::new();
    for (k, v) in existing.iter() {
        if let Some(d) = normalize_domain(&v.url_main) {
            by_domain.insert(d, k.clone());
        }
    }

    for (incoming_key, incoming_site) in incoming {
        let domain = normalize_domain(&incoming_site.url_main);
        match domain.as_ref().and_then(|d| by_domain.get(d)).cloned() {
            Some(existing_key) => {
                // Same domain — merge in place. Take the existing record
                // out, combine, put it back under its original key.
                if let Some(prev) = existing.remove(&existing_key) {
                    let merged = merge_site(prev, incoming_site);
                    existing.insert(existing_key, merged);
                }
            }
            None => {
                if let Some(d) = domain {
                    by_domain.insert(d, incoming_key.clone());
                }
                existing.insert(incoming_key, incoming_site);
            }
        }
    }
}

/// Merge two SiteData records describing the same domain. Precedence rules:
///
///   1. WMN-style `detection` beats Sherlock's `error_type`/`error_code`/
///      `error_msg` triple when both present. Sherlock fields are kept as
///      fallback. The synthetic `error_type = "dual_pattern"` routes the
///      checker through `dual_pattern_decision`.
///   2. Extractors are unioned by field name; on a duplicate field, the
///      incoming record wins (WMN > Maigret > Sherlock in upstream loop order).
///   3. `categories` is the set-union.
///   4. `is_nsfw` is sticky OR — once flagged, stays flagged.
///   5. `headers`, `request_method`, `request_payload`: prefer whichever side
///      has a populated `detection` block (the dual-pattern source is usually
///      the one with current scrape semantics).
///   6. `source = Merged`.
fn merge_site(a: SiteData, b: SiteData) -> SiteData {
    let detection = b.detection.clone().or_else(|| a.detection.clone());
    let prefer_b = b.detection.is_some();

    let error_type = if detection.is_some() {
        "dual_pattern".to_string()
    } else if !a.error_type.is_empty() {
        a.error_type.clone()
    } else {
        b.error_type.clone()
    };

    // Extractor union by field name, b wins on collision.
    let mut extractors: HashMap<String, Extractor> = HashMap::new();
    for ex in a.extractors.into_iter().chain(b.extractors.into_iter()) {
        extractors.insert(ex.field.clone(), ex);
    }
    let extractors: Vec<Extractor> = extractors.into_values().collect();

    // Category set-union, stable order preserved.
    let mut categories: Vec<String> = a.categories.clone();
    for c in b.categories {
        if !categories.contains(&c) {
            categories.push(c);
        }
    }

    let is_nsfw = match (a.is_nsfw, b.is_nsfw) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), _) | (_, Some(false)) => Some(false),
        _ => None,
    };

    let (headers, request_method, request_payload) = if prefer_b {
        (
            b.headers.or(a.headers),
            b.request_method.or(a.request_method),
            b.request_payload.or(a.request_payload),
        )
    } else {
        (
            a.headers.or(b.headers),
            a.request_method.or(b.request_method),
            a.request_payload.or(b.request_payload),
        )
    };

    SiteData {
        error_msg: a.error_msg.or(b.error_msg),
        error_type,
        error_code: a.error_code.or(b.error_code),
        error_url: a.error_url.or(b.error_url),
        url: if prefer_b { b.url } else { a.url },
        url_main: if prefer_b { b.url_main } else { a.url_main },
        url_probe: a.url_probe.or(b.url_probe),
        username_claimed: a.username_claimed.or(b.username_claimed),
        username_unclaimed: a.username_unclaimed.or(b.username_unclaimed),
        regex_check: a.regex_check.or(b.regex_check),
        is_nsfw,
        headers,
        request_method,
        request_payload,
        compiled_regex: None, // recompiled below
        detection,
        extractors,
        categories,
        source: SiteSource::Merged,
        compiled_extractors: Vec::new(),
    }
}

/// Parse the upstream Sherlock `data.json` (top-level `{ site_name: { ... } }`
/// shape). Strips the `$schema` key, drops entries that fail to deserialize.
/// Compiles each `regex_check` once.
fn parse_sherlock(json: &str) -> Result<HashMap<String, SiteData>> {
    let raw: HashMap<String, serde_json::Value> = serde_json::from_str(json)?;
    let mut sites: HashMap<String, SiteData> = raw
        .into_iter()
        .filter(|(k, _)| k != "$schema")
        .filter_map(|(k, v)| serde_json::from_value(v).ok().map(|s| (k, s)))
        .collect();

    for site in sites.values_mut() {
        // `source` defaults to Sherlock via `#[derive(Default)]`, but the JSON
        // may have explicitly set it on a re-load of the merged cache; trust
        // whatever was there.
        if let Some(pattern) = &site.regex_check {
            site.compiled_regex = Regex::new(pattern).ok();
        }
    }

    Ok(sites)
}

#[derive(Deserialize)]
struct WmnFile {
    sites: Vec<WmnSite>,
}

#[derive(Deserialize)]
struct WmnSite {
    name: String,
    uri_check: String,
    #[serde(default)]
    e_code: Option<u16>,
    #[serde(default)]
    e_string: Option<String>,
    #[serde(default)]
    m_code: Option<u16>,
    #[serde(default)]
    m_string: Option<String>,
    #[serde(default)]
    cat: Option<String>,
    #[serde(default)]
    post_body: Option<String>,
}

/// Parse the WhatsMyName `wmn-data.json` shape (`{"sites": [ { name,
/// uri_check, e_code, e_string, m_code, m_string, cat, ... } ]}`). The
/// placeholder `{account}` is normalized to Sherlock's `{}` so `format_url`
/// works unchanged. Each record carries a synthetic `error_type =
/// "dual_pattern"` and a populated `Detection` block.
fn parse_wmn(json: &str) -> Result<HashMap<String, SiteData>> {
    let parsed: WmnFile = serde_json::from_str(json)?;
    let mut out = HashMap::new();
    for w in parsed.sites {
        let url = w.uri_check.replace("{account}", "{}");
        let url_main = normalize_domain(&url)
            .map(|d| format!("https://{d}"))
            .unwrap_or_else(|| url.clone());
        let detection = Some(Detection {
            e_code: w.e_code,
            e_string: w.e_string,
            m_code: w.m_code,
            m_string: w.m_string,
        });
        let categories = w.cat.map(|c| vec![c]).unwrap_or_default();
        let site = SiteData {
            error_msg: None,
            error_type: "dual_pattern".to_string(),
            error_code: None,
            error_url: None,
            url,
            url_main,
            url_probe: None,
            username_claimed: None,
            username_unclaimed: None,
            regex_check: None,
            is_nsfw: None,
            headers: None,
            request_method: w.post_body.as_ref().map(|_| "POST".to_string()),
            request_payload: w
                .post_body
                .as_ref()
                .map(|s| serde_json::Value::String(s.clone())),
            compiled_regex: None,
            detection,
            extractors: Vec::new(),
            categories,
            source: SiteSource::Whatsmyname,
            compiled_extractors: Vec::new(),
        };
        out.insert(w.name, site);
    }
    Ok(out)
}

#[derive(Deserialize)]
struct MaigretSiteEntry {
    url: String,
    url_main: String,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    detection: Option<Detection>,
    #[serde(default)]
    extractors: Vec<Extractor>,
}

/// Parse the simplified vendored Maigret subset. Format is
/// `{ "<site>": { url, url_main, categories?, detection?, extractors? } }`,
/// with an optional `_meta` key documenting the schema (silently dropped).
/// Unknown extractor fields are stripped (see `is_canonical_field`) so the
/// vault vocabulary stays controlled.
fn parse_maigret(json: &str) -> Result<HashMap<String, SiteData>> {
    let raw: HashMap<String, serde_json::Value> = serde_json::from_str(json)?;
    let mut out = HashMap::new();
    for (name, value) in raw {
        if name.starts_with('_') {
            continue;
        }
        let entry: MaigretSiteEntry = match serde_json::from_value(value) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let extractors: Vec<Extractor> = entry
            .extractors
            .into_iter()
            .filter(|e| is_canonical_field(&e.field))
            .collect();

        let site = SiteData {
            error_msg: None,
            error_type: if entry.detection.is_some() {
                "dual_pattern".to_string()
            } else {
                "status_code".to_string()
            },
            error_code: None,
            error_url: None,
            url: entry.url,
            url_main: entry.url_main,
            url_probe: None,
            username_claimed: None,
            username_unclaimed: None,
            regex_check: None,
            is_nsfw: None,
            headers: None,
            request_method: None,
            request_payload: None,
            compiled_regex: None,
            detection: entry.detection,
            extractors,
            categories: entry.categories,
            source: SiteSource::Maigret,
            compiled_extractors: Vec::new(),
        };
        out.insert(name, site);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_domain_strips_scheme_www_and_trailing_slash() {
        assert_eq!(
            normalize_domain("https://www.GitHub.com/"),
            Some("github.com".into())
        );
        assert_eq!(
            normalize_domain("http://example.org"),
            Some("example.org".into())
        );
        assert_eq!(normalize_domain(""), None);
    }

    #[test]
    fn merge_site_wmn_wins_detection_and_sticky_nsfw() {
        let mut sherlock = SiteData {
            error_msg: None,
            error_type: "status_code".into(),
            error_code: None,
            error_url: None,
            url: "https://example.com/{}".into(),
            url_main: "https://example.com".into(),
            url_probe: None,
            username_claimed: None,
            username_unclaimed: None,
            regex_check: None,
            is_nsfw: Some(true),
            headers: None,
            request_method: None,
            request_payload: None,
            compiled_regex: None,
            detection: None,
            extractors: vec![],
            categories: vec!["legacy".into()],
            source: SiteSource::Sherlock,
            compiled_extractors: vec![],
        };
        sherlock.error_msg = Some(ErrorMsg::Single("not found".into()));

        let wmn = SiteData {
            error_msg: None,
            error_type: "dual_pattern".into(),
            error_code: None,
            error_url: None,
            url: "https://example.com/{}".into(),
            url_main: "https://example.com".into(),
            url_probe: None,
            username_claimed: None,
            username_unclaimed: None,
            regex_check: None,
            is_nsfw: None,
            headers: None,
            request_method: None,
            request_payload: None,
            compiled_regex: None,
            detection: Some(Detection {
                e_code: Some(200),
                e_string: Some("hello".into()),
                m_code: Some(404),
                m_string: None,
            }),
            extractors: vec![],
            categories: vec!["social".into()],
            source: SiteSource::Whatsmyname,
            compiled_extractors: vec![],
        };

        let merged = merge_site(sherlock, wmn);
        assert_eq!(merged.error_type, "dual_pattern");
        assert!(merged.detection.is_some());
        assert_eq!(merged.is_nsfw, Some(true));
        assert!(merged.categories.contains(&"legacy".into()));
        assert!(merged.categories.contains(&"social".into()));
        assert_eq!(merged.source, SiteSource::Merged);
    }
}
