use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

const DATA_URL: &str = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json";
const WMN_DATA_URL: &str =
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json";

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
pub struct WmnData {
    pub sites: Vec<WmnSite>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct WmnSite {
    pub name: String,
    pub uri_check: String,
    pub e_code: u16,
    pub e_string: String,
    pub m_string: String,
    pub m_code: u16,
    pub cat: String,
    pub known: Vec<String>,
}

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
}

/// Determines the local application data directory to cache site lists.
fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sherlock-rs")
}

/// Loads the target site database either from local cache (`data.json`)
/// or downloads the latest database if no cache is found.
pub async fn load_sites() -> Result<HashMap<String, SiteData>> {
    let path = data_dir().join("data.json");
    if path.exists() {
        let json = tokio::fs::read_to_string(&path).await?;
        return parse_sites(&json);
    }
    download_sites().await
}

/// Connects to the upstream Sherlock repository, downloads the latest list
/// of site definitions (`data.json`), and stores it locally. It merges these
/// definitions with embedded custom sites and dynamically loads any additional
/// files from the `sites.d` configuration directory.
pub async fn download_sites() -> Result<HashMap<String, SiteData>> {
    let dir = data_dir();
    tokio::fs::create_dir_all(&dir).await?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let json = client.get(DATA_URL).send().await?.text().await?;
    let mut sites = parse_sites(&json)?;

    // Add WhatsMyName data
    if let Ok(wmn_res) = client.get(WMN_DATA_URL).send().await {
        if let Ok(wmn_json) = wmn_res.text().await {
            if let Ok(wmn_data) = serde_json::from_str::<WmnData>(&wmn_json) {
                for site in wmn_data.sites {
                    let mut is_valid = true;
                    let error_type = if site.e_code == 200 && !site.e_string.is_empty() {
                        "message".to_string()
                    } else if site.e_code != 200 {
                        "status_code".to_string()
                    } else {
                        is_valid = false;
                        "".to_string()
                    };

                    if is_valid {
                        let url = site.uri_check.replace("{account}", "{}");
                        // extract url_main (e.g. from https://example.com/u/{} to https://example.com/)
                        let url_main = url.split('/').take(3).collect::<Vec<_>>().join("/") + "/";

                        let error_msg = if error_type == "message" {
                            if !site.m_string.is_empty() {
                                Some(ErrorMsg::Single(site.m_string))
                            } else {
                                Some(ErrorMsg::Single(site.e_string)) // Fallback if m_string is empty
                            }
                        } else {
                            None
                        };

                        let error_code = if error_type == "status_code" {
                            Some(ErrorCode::Single(site.e_code))
                        } else {
                            None
                        };

                        let site_data = SiteData {
                            error_msg,
                            error_type,
                            error_code,
                            error_url: None,
                            url: url.clone(),
                            url_main,
                            url_probe: None,
                            username_claimed: site.known.first().cloned(),
                            username_unclaimed: Some(
                                "invalid_unclaimed_test_123456789".to_string(),
                            ),
                            regex_check: None,
                            is_nsfw: if site.cat == "porn" { Some(true) } else { None },
                            headers: None,
                            request_method: None,
                            request_payload: None,
                        };

                        let key = format!("[WMN] {}", site.name);
                        sites.insert(key, site_data);
                    }
                }
            }
        }
    }

    // Add built-in custom sites
    let custom_json = include_str!("custom_sites.json");
    if let Ok(custom_sites) = parse_sites(custom_json) {
        for (k, mut v) in custom_sites {
            v.is_nsfw = Some(true); // default to true since these look like NSFW sites
            sites.insert(k, v);
        }
    }

    // Modularisation: dynamically load from sites.d directory
    let sites_d = dir.join("sites.d");
    if sites_d.exists() && sites_d.is_dir() {
        if let Ok(mut entries) = tokio::fs::read_dir(&sites_d).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(content) = tokio::fs::read_to_string(&path).await {
                        if let Ok(external_sites) = parse_sites(&content) {
                            for (k, v) in external_sites {
                                sites.insert(k, v);
                            }
                        }
                    }
                }
            }
        }
    } else {
        // Create the directory if it doesn't exist to show users where to place files
        let _ = tokio::fs::create_dir_all(&sites_d).await;
    }

    // Convert back to string and save the comprehensive map
    if let Ok(merged_json) = serde_json::to_string(&sites) {
        tokio::fs::write(dir.join("data.json"), &merged_json).await?;
    }

    Ok(sites)
}

/// Helper function to safely parse a raw json string into a `SiteData` Hashmap,
/// stripping extraneous keys like `$schema`.
fn parse_sites(json: &str) -> Result<HashMap<String, SiteData>> {
    let raw: HashMap<String, serde_json::Value> = serde_json::from_str(json)?;
    let sites = raw
        .into_iter()
        .filter(|(k, _)| k != "$schema")
        .filter_map(|(k, v)| serde_json::from_value(v).ok().map(|s| (k, s)))
        .collect();
    Ok(sites)
}
