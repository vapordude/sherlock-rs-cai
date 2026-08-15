use crate::result::{QueryResult, QueryStatus};
use std::collections::{HashMap, HashSet};

fn sanitize_csv_field(s: &str) -> String {
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{}", s)
    } else {
        s.to_string()
    }
}

pub fn to_csv(results: &[QueryResult]) -> String {
    let mut wtr = csv::Writer::from_writer(vec![]);
    let _ = wtr.write_record(["Username", "Site", "URL", "Status", "Response Time (ms)"]);
    for r in results {
        let _ = wtr.write_record([
            sanitize_csv_field(&r.username),
            sanitize_csv_field(&r.site_name),
            sanitize_csv_field(&r.site_url),
            r.status.as_str().to_string(),
            r.response_time_ms
                .map(|t| t.to_string())
                .unwrap_or_default(),
        ]);
    }
    String::from_utf8(wtr.into_inner().unwrap_or_default()).unwrap_or_default()
}

pub fn to_txt(results: &[QueryResult]) -> String {
    let mut by_username: HashMap<&str, Vec<&QueryResult>> = HashMap::new();
    for r in results {
        by_username.entry(r.username.as_str()).or_default().push(r);
    }

    // Preserve insertion order
    let mut usernames: Vec<&str> = Vec::new();
    let mut seen = HashSet::new();
    for r in results {
        if seen.insert(r.username.as_str()) {
            usernames.push(&r.username);
        }
    }

    let mut out = String::from("Sherlock-RS — Results\n");
    out.push_str(&"=".repeat(50));
    out.push('\n');

    for username in usernames {
        let user_results = &by_username[username];
        let found: Vec<_> = user_results
            .iter()
            .filter(|r| r.status == QueryStatus::Claimed)
            .collect();

        out.push_str(&format!(
            "\n[{}] — Found on {} site(s):\n",
            username,
            found.len()
        ));
        for r in &found {
            out.push_str(&format!("  [+] {}: {}\n", r.site_name, r.site_url));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_csv_empty() {
        let results = vec![];
        let csv = to_csv(&results);
        assert_eq!(csv, "Username,Site,URL,Status,Response Time (ms)\n");
    }

    #[test]
    fn test_to_csv_normal() {
        let results = vec![QueryResult {
            username: "johndoe".to_string(),
            site_name: "GitHub".to_string(),
            url_main: "https://github.com/".to_string(),
            site_url: "https://github.com/johndoe".to_string(),
            status: QueryStatus::Claimed,
            response_time_ms: Some(150),
            context: None,
            confidence: 100,
            extracted: None,
            body_sha256: None,
        }];
        let csv = to_csv(&results);
        assert_eq!(csv, "Username,Site,URL,Status,Response Time (ms)\njohndoe,GitHub,https://github.com/johndoe,claimed,150\n");
    }

    #[test]
    fn test_to_csv_sanitized() {
        let results = vec![QueryResult {
            username: "=cmd|' /C calc'!A0".to_string(),
            site_name: "+BadSite".to_string(),
            site_url: "@https://bad.com".to_string(),
            url_main: "https://bad.com".to_string(),
            status: QueryStatus::Available,
            response_time_ms: None,
            context: None,
            confidence: 100,
            extracted: None,
            body_sha256: None,
        }];
        let csv = to_csv(&results);
        assert_eq!(csv, "Username,Site,URL,Status,Response Time (ms)\n\'=cmd|\' /C calc\'!A0,\'+BadSite,\'@https://bad.com,available,\n");
    }
}
