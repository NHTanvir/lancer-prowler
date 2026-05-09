//! Mutelist loader and applier — parity with upstream `--mutelist-file`.
//!
//! The schema mirrors the upstream YAML schema:
//!
//! ```yaml
//! Mutelist:
//!   Accounts:
//!     "012345678901":
//!       Checks:
//!         iam_user_mfa_enabled_console_access:
//!           Regions:
//!             - us-east-1
//!           Resources:
//!             - "arn:aws:iam::012345678901:user/break-glass"
//!           Tags: []
//!           Description: "Approved break-glass user, MFA off by design."
//!     "*":
//!       Checks:
//!         s3_bucket_object_lock:
//!           Regions: ["*"]
//!           Resources: ["*"]
//! ```
//!
//! Matching semantics:
//! - Account `"*"` matches any account.
//! - A pattern in `Regions` / `Resources` / `Tags` containing `*` is treated as
//!   a simple glob (`*` = any sequence of chars).
//! - An entry without `Resources` or with `Resources: ["*"]` matches everything.
//!
//! Findings that match are *not* deleted — they are flipped to `Status::Muted`
//! so they remain in the report (counted separately from PASS/FAIL).

use crate::models::{CheckReport, Status};
use anyhow::Context;
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct CheckMute {
    pub regions: Vec<String>,
    pub resources: Vec<String>,
    pub tags: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct AccountMutes {
    pub checks: BTreeMap<String, CheckMute>,
}

#[derive(Debug, Default, Clone)]
pub struct Mutelist {
    pub accounts: BTreeMap<String, AccountMutes>,
}

impl Mutelist {
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read mutelist file: {path}"))?;
        Self::parse_yaml(&content)
            .with_context(|| format!("Failed to parse mutelist YAML: {path}"))
    }

    /// Minimalist YAML parser specifically scoped to the mutelist schema. Avoids
    /// pulling in a heavy YAML dependency. Whitespace-sensitive but tolerates
    /// quoted account IDs (used because they often look numeric).
    pub fn parse_yaml(input: &str) -> anyhow::Result<Self> {
        let mut list = Mutelist::default();
        let mut current_account: Option<String> = None;
        let mut current_check: Option<String> = None;
        let mut current_field: Option<String> = None;
        let mut in_accounts = false;
        let mut in_checks = false;

        for raw_line in input.lines() {
            // Strip comments (anything after a `#` that isn't inside quotes).
            let line = strip_comment(raw_line);
            if line.trim().is_empty() {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            let trimmed = line.trim_start();

            // List-item shortcut.
            if let Some(rest) = trimmed.strip_prefix("- ") {
                let val = unquote(rest.trim());
                if let (Some(acct), Some(chk), Some(field)) =
                    (&current_account, &current_check, &current_field)
                {
                    let entry = list
                        .accounts
                        .entry(acct.clone())
                        .or_default()
                        .checks
                        .entry(chk.clone())
                        .or_default();
                    match field.as_str() {
                        "Regions" => entry.regions.push(val),
                        "Resources" => entry.resources.push(val),
                        "Tags" => entry.tags.push(val),
                        _ => {}
                    }
                }
                continue;
            }

            // key: value or key:
            let (key, value) = match trimmed.split_once(':') {
                Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
                None => continue,
            };

            // Inline list e.g. Regions: ["us-east-1", "us-west-2"]
            if value.starts_with('[') && value.ends_with(']') {
                let inner = &value[1..value.len() - 1];
                let items: Vec<String> = inner
                    .split(',')
                    .map(|s| unquote(s.trim()))
                    .filter(|s| !s.is_empty())
                    .collect();
                if let (Some(acct), Some(chk)) = (&current_account, &current_check) {
                    let entry = list
                        .accounts
                        .entry(acct.clone())
                        .or_default()
                        .checks
                        .entry(chk.clone())
                        .or_default();
                    match key.as_str() {
                        "Regions" => entry.regions.extend(items),
                        "Resources" => entry.resources.extend(items),
                        "Tags" => entry.tags.extend(items),
                        _ => {}
                    }
                }
                current_field = Some(key);
                continue;
            }

            match key.as_str() {
                "Mutelist" if indent == 0 => {
                    // root
                }
                "Accounts" => {
                    in_accounts = true;
                    in_checks = false;
                    current_account = None;
                    current_check = None;
                }
                "Checks" if in_accounts => {
                    in_checks = true;
                    current_check = None;
                }
                "Description" if current_check.is_some() => {
                    if let (Some(acct), Some(chk)) = (&current_account, &current_check) {
                        let entry = list
                            .accounts
                            .entry(acct.clone())
                            .or_default()
                            .checks
                            .entry(chk.clone())
                            .or_default();
                        entry.description = Some(unquote(&value));
                    }
                }
                "Regions" | "Resources" | "Tags" => {
                    current_field = Some(key);
                    if value.is_empty() {
                        // block follows
                    }
                }
                _ => {
                    if in_accounts && !in_checks {
                        current_account = Some(unquote(&key));
                    } else if in_checks {
                        current_check = Some(unquote(&key));
                    }
                }
            }
        }
        Ok(list)
    }

    /// Apply the mutelist to a set of findings — mutating each finding's
    /// `status` to `Muted` when it matches. Returns the count of muted entries.
    pub fn apply(&self, findings: &mut [CheckReport]) -> usize {
        let mut count = 0;
        for f in findings.iter_mut() {
            if self.matches_finding(f) {
                f.status = Status::Muted;
                count += 1;
            }
        }
        count
    }

    pub fn matches_finding(&self, f: &CheckReport) -> bool {
        for (account_pat, account_mutes) in &self.accounts {
            if !glob_match(account_pat, &f.account_id) {
                continue;
            }
            for (check_pat, mute) in &account_mutes.checks {
                if !glob_match(check_pat, &f.check_id) {
                    continue;
                }
                let region_ok = mute.regions.is_empty()
                    || mute
                        .regions
                        .iter()
                        .any(|p| glob_match(p, &f.region));
                let resource_ok = mute.resources.is_empty()
                    || mute
                        .resources
                        .iter()
                        .any(|p| glob_match(p, &f.resource_arn) || glob_match(p, &f.resource_id));
                if region_ok && resource_ok {
                    return true;
                }
            }
        }
        false
    }
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn strip_comment(line: &str) -> String {
    let mut out = String::new();
    let mut in_single = false;
    let mut in_double = false;
    for ch in line.chars() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => break,
            _ => {}
        }
        out.push(ch);
    }
    out
}

fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == value {
        return true;
    }
    // Very small glob: split on `*` and ensure all parts appear in order.
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut idx = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 && !value[idx..].starts_with(part) {
            return false;
        } else if i == parts.len() - 1 && !value.ends_with(part) {
            return false;
        } else {
            match value[idx..].find(part) {
                Some(pos) => idx += pos + part.len(),
                None => return false,
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_mutelist() {
        let yaml = r#"
Mutelist:
  Accounts:
    "012345678901":
      Checks:
        iam_user_mfa_enabled_console_access:
          Regions:
            - us-east-1
          Resources:
            - "arn:aws:iam::012345678901:user/break-glass"
          Description: "Approved break-glass user"
"#;
        let m = Mutelist::parse_yaml(yaml).unwrap();
        let acct = m.accounts.get("012345678901").unwrap();
        let chk = acct
            .checks
            .get("iam_user_mfa_enabled_console_access")
            .unwrap();
        assert_eq!(chk.regions, vec!["us-east-1".to_string()]);
        assert_eq!(
            chk.resources,
            vec!["arn:aws:iam::012345678901:user/break-glass".to_string()]
        );
        assert_eq!(
            chk.description.as_deref(),
            Some("Approved break-glass user")
        );
    }

    #[test]
    fn glob_matches_wildcard() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("arn:aws:s3:::*", "arn:aws:s3:::my-bucket"));
        assert!(!glob_match("arn:aws:s3:::*", "arn:aws:iam::user"));
    }
}
