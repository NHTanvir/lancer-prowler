use anyhow::Context;
use serde::Deserialize;
use std::path::Path;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ComplianceFramework {
    pub framework: String,
    pub version: String,
    pub provider: String,
    pub requirements: Vec<Requirement>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
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

    let framework: ComplianceFramework = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse compliance framework JSON: {path}"))?;

    Ok(framework)
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

        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let path_str = path
                .to_str()
                .with_context(|| format!("Non-UTF-8 path: {path:?}"))?;

            let framework = load_framework(path_str)?;
            frameworks.push(framework);
        }
    }

    Ok(frameworks)
}
