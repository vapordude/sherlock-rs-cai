use serde::{Deserialize, Serialize};

/// The determined state indicating whether a username profile exists on a site.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
        }
    }
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
}
