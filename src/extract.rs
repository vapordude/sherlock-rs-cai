//! Profile-field extractor pipeline.
//!
//! Each `SiteData` carries zero or more `Extractor` rules describing how to
//! pull a single canonical field (`avatar_url`, `bio`, `display_name`, …)
//! from the response body of a `Claimed` profile. This module compiles those
//! rules once at site-load time and applies them per request.
//!
//! Only fields in the canonical vocabulary (see `sites::is_canonical_field`)
//! are ever produced — the loader strips unknown field names so this stage
//! never sees them.

use crate::result::ExtractedValue;
use crate::sites::{CompiledExtractor, Extractor};
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashMap;

/// Compile a raw `Extractor` (CSS selector + optional regex strings) into a
/// `CompiledExtractor` (parsed `scraper::Selector` + parsed `Regex`). Failed
/// CSS-selector parses return `None` and the rule is dropped at load time.
/// Failed regex parses likewise drop the regex portion only, since a missing
/// regex is a valid configuration.
pub fn compile_extractor(raw: &Extractor) -> Option<CompiledExtractor> {
    let selector = match raw.selector.as_deref() {
        Some(s) => Selector::parse(s).ok()?,
        // Match-everything selector — rarely useful, but we accept it for
        // rules that work purely off a regex.
        None => Selector::parse("*").ok()?,
    };
    let regex = raw.regex.as_deref().and_then(|p| Regex::new(p).ok());
    Some(CompiledExtractor {
        field: raw.field.clone(),
        selector,
        attribute: raw.attribute.clone(),
        regex,
        multi: raw.multi,
    })
}

/// Run every compiled extractor against `body` and return the canonical
/// field map. Empty input or zero matches produce an empty map; the caller
/// can decide whether to set `QueryResult.extracted = None` or `Some({})`.
pub fn run_extractors(
    body: &str,
    exs: &[CompiledExtractor],
) -> HashMap<String, ExtractedValue> {
    let mut out = HashMap::new();
    if exs.is_empty() || body.is_empty() {
        return out;
    }
    let doc = Html::parse_document(body);
    for ex in exs {
        let values = collect(&doc, ex);
        if values.is_empty() {
            continue;
        }
        if ex.multi {
            out.insert(ex.field.clone(), ExtractedValue::Many(values));
        } else {
            // First match wins for non-multi extractors.
            out.insert(
                ex.field.clone(),
                ExtractedValue::One(values.into_iter().next().unwrap()),
            );
        }
    }
    out
}

fn collect(doc: &Html, ex: &CompiledExtractor) -> Vec<String> {
    let mut out = Vec::new();
    for el in doc.select(&ex.selector) {
        let raw = match ex.attribute.as_deref() {
            Some(attr) => el.value().attr(attr).map(str::to_string),
            None => Some(el.text().collect::<String>().trim().to_string()),
        };
        let Some(value) = raw else { continue };
        if value.is_empty() {
            continue;
        }
        let filtered = match &ex.regex {
            Some(re) => re
                .captures(&value)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string()),
            None => Some(value),
        };
        if let Some(v) = filtered {
            if !v.is_empty() {
                out.push(v);
            }
            if !ex.multi {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(field: &str, selector: &str, attr: Option<&str>, regex: Option<&str>, multi: bool) -> CompiledExtractor {
        compile_extractor(&Extractor {
            field: field.to_string(),
            selector: Some(selector.to_string()),
            attribute: attr.map(str::to_string),
            regex: regex.map(str::to_string),
            multi,
        })
        .expect("test selector should parse")
    }

    const HTML: &str = r#"
        <html><body>
            <img class="avatar" src="https://cdn/avatar.png" />
            <span class="name">Jane Doe</span>
            <div class="bio">Hello world</div>
            <li class="link"><a href="https://a.example">A</a></li>
            <li class="link"><a href="https://b.example">B</a></li>
            <span class="followers">1,234 followers</span>
        </body></html>
    "#;

    #[test]
    fn extracts_attribute_value() {
        let exs = vec![make("avatar_url", "img.avatar", Some("src"), None, false)];
        let out = run_extractors(HTML, &exs);
        assert_eq!(
            out.get("avatar_url"),
            Some(&ExtractedValue::One("https://cdn/avatar.png".to_string()))
        );
    }

    #[test]
    fn extracts_text_content() {
        let exs = vec![make("display_name", "span.name", None, None, false)];
        let out = run_extractors(HTML, &exs);
        assert_eq!(
            out.get("display_name"),
            Some(&ExtractedValue::One("Jane Doe".to_string()))
        );
    }

    #[test]
    fn extracts_multi_into_vec() {
        let exs = vec![make(
            "external_links",
            "li.link a",
            Some("href"),
            None,
            true,
        )];
        let out = run_extractors(HTML, &exs);
        let Some(ExtractedValue::Many(links)) = out.get("external_links") else {
            panic!("expected Many, got {:?}", out.get("external_links"));
        };
        assert_eq!(links.len(), 2);
        assert!(links.contains(&"https://a.example".to_string()));
    }

    #[test]
    fn regex_postfilter_captures_group_one() {
        let exs = vec![make(
            "follower_count",
            "span.followers",
            None,
            Some(r"([\d,]+)\s+followers"),
            false,
        )];
        let out = run_extractors(HTML, &exs);
        assert_eq!(
            out.get("follower_count"),
            Some(&ExtractedValue::One("1,234".to_string()))
        );
    }

    #[test]
    fn missing_field_yields_no_entry() {
        let exs = vec![make("bio", "div.nothing-here", None, None, false)];
        let out = run_extractors(HTML, &exs);
        assert!(out.is_empty());
    }
}
