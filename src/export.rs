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
            r.response_time_ms.map(|t| t.to_string()).unwrap_or_default(),
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
    use crate::result::QueryStatus;

    #[test]
    fn test_to_txt() {
        let results = vec![
            QueryResult {
                username: "testuser".to_string(),
                site_name: "TestSite".to_string(),
                url_main: "https://testsite.com".to_string(),
                site_url: "https://testsite.com/testuser".to_string(),
                status: QueryStatus::Claimed,
                response_time_ms: Some(100),
                context: None,
                confidence: 100,
                extracted: None,
                body_sha256: None,
            },
            QueryResult {
                username: "testuser".to_string(),
                site_name: "AnotherSite".to_string(),
                url_main: "https://anothersite.com".to_string(),
                site_url: "https://anothersite.com/testuser".to_string(),
                status: QueryStatus::Available,
                response_time_ms: Some(150),
                context: None,
                confidence: 100,
                extracted: None,
                body_sha256: None,
            },
        ];

        let txt = to_txt(&results);

        assert!(txt.contains("Sherlock-RS — Results"));
        assert!(txt.contains("="));
        assert!(txt.contains("[testuser] — Found on 1 site(s):"));
        assert!(txt.contains("  [+] TestSite: https://testsite.com/testuser"));

        // The non-claimed status should not be present
        assert!(!txt.contains("AnotherSite"));
    }

    #[test]
    fn test_to_txt_multiple_users() {
        let results = vec![
            QueryResult {
                username: "user1".to_string(),
                site_name: "Site1".to_string(),
                url_main: "https://site1.com".to_string(),
                site_url: "https://site1.com/user1".to_string(),
                status: QueryStatus::Claimed,
                response_time_ms: Some(100),
                context: None,
                confidence: 100,
                extracted: None,
                body_sha256: None,
            },
            QueryResult {
                username: "user2".to_string(),
                site_name: "Site2".to_string(),
                url_main: "https://site2.com".to_string(),
                site_url: "https://site2.com/user2".to_string(),
                status: QueryStatus::Claimed,
                response_time_ms: Some(150),
                context: None,
                confidence: 100,
                extracted: None,
                body_sha256: None,
            },
        ];

        let txt = to_txt(&results);

        assert!(txt.contains("[user1] — Found on 1 site(s):"));
        assert!(txt.contains("  [+] Site1: https://site1.com/user1"));

        assert!(txt.contains("[user2] — Found on 1 site(s):"));
        assert!(txt.contains("  [+] Site2: https://site2.com/user2"));

        // Check insertion order preservation
        let pos_user1 = txt.find("[user1]").unwrap();
        let pos_user2 = txt.find("[user2]").unwrap();
        assert!(pos_user1 < pos_user2);
    }

    #[test]
    fn test_to_txt_empty() {
        let results: Vec<QueryResult> = vec![];
        let txt = to_txt(&results);

        assert!(txt.contains("Sherlock-RS — Results"));
        assert!(txt.contains("="));
        // Should not contain any user sections
        assert!(!txt.contains("Found on"));
    }
}
