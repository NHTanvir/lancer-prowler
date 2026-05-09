use anyhow::Context;
use serde::Deserialize;
use std::path::Path;

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ComplianceFramework {
    pub framework: String,
    pub version: String,
    pub provider: String,
    pub requirements: Vec<Requirement>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Requirement {
    pub id: String,
    pub description: String,
    pub checks: Vec<String>,
    #[serde(default)]
    pub attributes: Vec<serde_json::Value>,
}

#[allow(dead_code)]
pub fn load_framework(path: &str) -> anyhow::Result<ComplianceFramework> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read compliance framework file: {path}"))?;
    parse_framework(&content, path)
}

/// Custom-framework loader (plan line 251). Accepts both JSON and a very small
/// YAML subset matching the JSON shape (`Framework: name`, `Version: x`, etc.).
/// JSON is parsed by serde_json; YAML falls back to a hand-rolled converter.
pub fn parse_framework(content: &str, source: &str) -> anyhow::Result<ComplianceFramework> {
    // JSON first.
    if let Ok(fw) = serde_json::from_str::<ComplianceFramework>(content) {
        return Ok(fw);
    }
    // YAML fallback (lightweight; supports the schema lancer-prowler emits).
    if source.ends_with(".yaml") || source.ends_with(".yml") || content.contains("Requirements:") {
        if let Some(fw) = parse_yaml_framework(content) {
            return Ok(fw);
        }
    }
    anyhow::bail!("Failed to parse compliance framework: {source}");
}

fn parse_yaml_framework(content: &str) -> Option<ComplianceFramework> {
    let mut framework = String::new();
    let mut version = String::new();
    let mut provider = String::new();
    let mut requirements: Vec<Requirement> = Vec::new();
    let mut current: Option<Requirement> = None;
    let mut in_checks = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Framework:") {
            framework = unquote(rest.trim());
        } else if let Some(rest) = trimmed.strip_prefix("Version:") {
            version = unquote(rest.trim());
        } else if let Some(rest) = trimmed.strip_prefix("Provider:") {
            provider = unquote(rest.trim());
        } else if trimmed.starts_with("- Id:") {
            if let Some(prev) = current.take() {
                requirements.push(prev);
            }
            let id_val = trimmed
                .strip_prefix("- Id:")
                .map(|s| unquote(s.trim()))
                .unwrap_or_default();
            current = Some(Requirement {
                id: id_val,
                description: String::new(),
                checks: vec![],
                attributes: vec![],
            });
            in_checks = false;
        } else if let Some(rest) = trimmed.strip_prefix("Description:") {
            if let Some(req) = current.as_mut() {
                req.description = unquote(rest.trim());
            }
            in_checks = false;
        } else if trimmed.starts_with("Checks:") {
            in_checks = true;
        } else if in_checks && trimmed.starts_with("- ") {
            if let Some(req) = current.as_mut() {
                req.checks.push(unquote(&trimmed[2..]));
            }
        } else {
            in_checks = false;
        }
    }
    if let Some(prev) = current.take() {
        requirements.push(prev);
    }
    if framework.is_empty() && requirements.is_empty() {
        return None;
    }
    Some(ComplianceFramework {
        framework,
        version,
        provider,
        requirements,
    })
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

#[allow(dead_code)]
pub fn load_all_frameworks(dir: &str) -> anyhow::Result<Vec<ComplianceFramework>> {
    let dir_path = Path::new(dir);
    anyhow::ensure!(
        dir_path.is_dir(),
        "Compliance directory does not exist: {dir}"
    );

    let mut frameworks = Vec::new();

    for entry in std::fs::read_dir(dir_path)
        .with_context(|| format!("Failed to read compliance directory: {dir}"))?
    {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "json" | "yaml" | "yml") {
            continue;
        }
        let path_str = path
            .to_str()
            .with_context(|| format!("Non-UTF-8 path: {path:?}"))?;
        match load_framework(path_str) {
            Ok(fw) => frameworks.push(fw),
            Err(e) => tracing::warn!("Skipping {path_str}: {e:#}"),
        }
    }
    Ok(frameworks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yaml_custom_framework() {
        let yaml = r#"
Framework: My Custom Framework
Version: 1.0
Provider: aws
Requirements:
  - Id: custom-1
    Description: A custom requirement.
    Checks:
      - iam_root_mfa_enabled
"#;
        let fw = parse_yaml_framework(yaml).unwrap();
        assert_eq!(fw.framework, "My Custom Framework");
        assert_eq!(fw.version, "1.0");
        assert_eq!(fw.provider, "aws");
        assert_eq!(fw.requirements.len(), 1);
        assert_eq!(fw.requirements[0].id, "custom-1");
        assert_eq!(fw.requirements[0].checks, vec!["iam_root_mfa_enabled"]);
    }
}
