use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The determined state indicating whether a username profile exists on a site.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum QueryStatus {
    /// The target username was definitively found on this platform.
    Claimed,
    /// The platform actively indicated the target username does not exist.
    Available,
    /// The query encountered an unexpected error, timeout, or an unparseable response.
    Unknown,
    /// The target username format violated the site's documented regex constraints.
    Illegal,
    /// A Web Application Firewall dynamically intercepted the request.
    Waf,
    /// Dual-pattern detection found contradictory signals — both the
    /// exists-pattern and the not-found-pattern matched. Surface to the user
    /// for review but don't treat as canonical. Usually means the site
    /// changed its HTML and the rule needs updating.
    Tentative,
}

impl QueryStatus {
    /// Serializes the enum variant into its frontend string representation.
    pub fn as_str(&self) -> &str {
        match self {
            QueryStatus::Claimed => "claimed",
            QueryStatus::Available => "available",
            QueryStatus::Unknown => "unknown",
            QueryStatus::Illegal => "illegal",
            QueryStatus::Waf => "waf",
            QueryStatus::Tentative => "tentative",
        }
    }
}

/// A single field's extracted value. Most fields are scalars (display name,
/// avatar URL); a handful (`external_links`) yield lists. Untagged so JSON
/// is the natural representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ExtractedValue {
    One(String),
    Many(Vec<String>),
}

/// The unified response model produced by the checker engine mapping a single target query payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// The active username being checked.
    pub username: String,
    /// The display name of the social platform.
    pub site_name: String,
    /// The platform's root index page URL.
    pub url_main: String,
    /// The exact profile URL payload where the username was checked.
    pub site_url: String,
    /// The ultimate resolution status determined by the engine logic.
    pub status: QueryStatus,
    /// Total execution duration of the query attempt (in milliseconds).
    pub response_time_ms: Option<u64>,
    /// Additional context regarding the query response, capturing localized exceptions or detailed error strings.
    pub context: Option<String>,
    /// Confidence in the verdict, 0..=100. Dual-pattern hits with both
    /// signals agreeing score 95; legacy single-pattern Sherlock-style hits
    /// score 70-80; WAF blocks and unknowns are low.
    #[serde(default)]
    pub confidence: u8,
    /// Profile fields extracted from a `Claimed` response by the per-site
    /// `Extractor` rules. Field names are restricted to the canonical
    /// vocabulary (see `sites::is_canonical_field`). `None` if no extractors
    /// fired or the verdict wasn't `Claimed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted: Option<HashMap<String, ExtractedValue>>,
    /// SHA-256 of the first 64 KiB of the response body. Used for cross-scan
    /// evidence dedup ("we already saw this exact page for this user")
    /// without storing the full body. `None` when the body wasn't fetched
    /// (e.g. illegal username, WAF).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<String>,
}
