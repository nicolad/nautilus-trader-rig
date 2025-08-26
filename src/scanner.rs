use crate::patterns::all_patterns;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Issue {
    pub pattern_id: &'static str,
    pub name: &'static str,
    pub severity: &'static str,
    pub category: &'static str,
    pub line: usize,
    pub col: usize,
    pub excerpt: String,
}

static REGEX_CACHE: Lazy<HashMap<&'static str, Regex>> = Lazy::new(|| {
    let mut m = HashMap::new();
    for p in all_patterns() {
        m.insert(p.id, Regex::new(p.expr).expect(p.id));
    }
    m
});

static REQUIRE_CACHE: Lazy<HashMap<&'static str, Vec<Regex>>> = Lazy::new(|| {
    let mut m = HashMap::new();
    for p in all_patterns() {
        if !p.requires_all.is_empty() {
            let v = p
                .requires_all
                .iter()
                .map(|r| Regex::new(r).expect(p.id))
                .collect::<Vec<_>>();
            m.insert(p.id, v);
        }
    }
    m
});

/// Scan a Rust source string and return all issues found.
/// - Simple, line-based matching for speed and predictability.
/// - A pattern may also require additional regexes to be present anywhere in the file (`requires_all`).
pub fn scan(source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    let requires_ok: HashMap<&'static str, bool> = all_patterns()
        .iter()
        .map(|p| {
            let ok = if let Some(reqs) = REQUIRE_CACHE.get(p.id) {
                reqs.iter().all(|rr| rr.is_match(source))
            } else {
                true
            };
            (p.id, ok)
        })
        .collect();

    for (lineno, line) in source.lines().enumerate() {
        // We intentionally also scan comments/strings; this is a static smell finder.
        for p in all_patterns() {
            if !requires_ok[p.id] {
                continue;
            }
            let re = &REGEX_CACHE[p.id];
            for m in re.find_iter(line) {
                let col = m.start() + 1;
                issues.push(Issue {
                    pattern_id: p.id,
                    name: p.name,
                    severity: p.severity.as_str(),
                    category: p.category.as_str(),
                    line: lineno + 1,
                    col,
                    excerpt: trim_excerpt(line),
                });
            }
        }
    }
    issues
}

fn trim_excerpt(line: &str) -> String {
    const MAX: usize = 180;
    if line.len() <= MAX {
        line.to_string()
    } else {
        let mut s = line[..MAX].to_string();
        s.push_str("…");
        s
    }
}
