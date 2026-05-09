pub mod asff;
pub mod console;
pub mod csv_output;
pub mod html_output;
pub mod json_ocsf;
pub mod markdown;
pub mod sarif;

use crate::models::CheckReport;
use anyhow::bail;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Console,
    Csv,
    JsonOcsf,
    JsonAsff,
    Html,
    Sarif,
    Markdown,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OutputFormat::Console => "console",
            OutputFormat::Csv => "csv",
            OutputFormat::JsonOcsf => "json-ocsf",
            OutputFormat::JsonAsff => "json-asff",
            OutputFormat::Html => "html",
            OutputFormat::Sarif => "sarif",
            OutputFormat::Markdown => "markdown",
        };
        write!(f, "{s}")
    }
}

impl OutputFormat {
    pub fn default_extension(&self) -> &'static str {
        match self {
            OutputFormat::Console => "log",
            OutputFormat::Csv => "csv",
            OutputFormat::JsonOcsf => "ocsf.json",
            OutputFormat::JsonAsff => "asff.json",
            OutputFormat::Html => "html",
            OutputFormat::Sarif => "sarif.json",
            OutputFormat::Markdown => "md",
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "console" | "text" => Ok(OutputFormat::Console),
            "csv" => Ok(OutputFormat::Csv),
            "json-ocsf" | "json_ocsf" | "ocsf" => Ok(OutputFormat::JsonOcsf),
            "json-asff" | "json_asff" | "asff" => Ok(OutputFormat::JsonAsff),
            "html" => Ok(OutputFormat::Html),
            "sarif" => Ok(OutputFormat::Sarif),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            other => bail!("Unknown output format: {other}"),
        }
    }
}

pub fn write_findings(
    findings: &[CheckReport],
    format: OutputFormat,
    path: Option<&str>,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Console => {
            console::print_findings(findings);
        }
        OutputFormat::Csv => {
            let dest = path.unwrap_or("findings.csv");
            csv_output::write_csv(findings, dest)?;
            println!("CSV written to: {dest}");
        }
        OutputFormat::JsonOcsf => {
            let dest = path.unwrap_or("findings.ocsf.json");
            json_ocsf::write_json_ocsf(findings, dest)?;
            println!("OCSF JSON written to: {dest}");
        }
        OutputFormat::JsonAsff => {
            let dest = path.unwrap_or("findings.asff.json");
            asff::write_asff(findings, dest)?;
            println!("ASFF JSON written to: {dest}");
        }
        OutputFormat::Html => {
            let dest = path.unwrap_or("findings.html");
            html_output::write_html(findings, dest)?;
            println!("HTML written to: {dest}");
        }
        OutputFormat::Sarif => {
            let dest = path.unwrap_or("findings.sarif.json");
            sarif::write_sarif(findings, dest)?;
            println!("SARIF written to: {dest}");
        }
        OutputFormat::Markdown => {
            let dest = path.unwrap_or("findings.md");
            markdown::write_markdown(findings, dest)?;
            println!("Markdown written to: {dest}");
        }
    }
    Ok(())
}

/// Write the same set of findings to multiple destinations at once.
/// Uses `base` as the filename stem when present, falling back to default names.
pub fn write_findings_multi(
    findings: &[CheckReport],
    formats: &[OutputFormat],
    base: Option<&str>,
    directory: Option<&str>,
) -> anyhow::Result<()> {
    use std::path::PathBuf;
    if formats.is_empty() {
        return Ok(());
    }

    for format in formats {
        if matches!(format, OutputFormat::Console) {
            console::print_findings(findings);
            continue;
        }
        let mut path = PathBuf::new();
        if let Some(d) = directory {
            path.push(d);
            std::fs::create_dir_all(&path).ok();
        }
        let filename = match base {
            Some(b) => format!("{b}.{}", format.default_extension()),
            None => format!("findings.{}", format.default_extension()),
        };
        path.push(filename);
        let path_str = path.to_string_lossy().to_string();
        write_findings(findings, format.clone(), Some(&path_str))?;
    }
    Ok(())
}
