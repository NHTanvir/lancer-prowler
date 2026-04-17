pub mod console;
pub mod csv_output;
pub mod json_ocsf;

use crate::models::CheckReport;
use anyhow::bail;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Console,
    Csv,
    JsonOcsf,
    Html,
}

impl std::str::FromStr for OutputFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "console" => Ok(OutputFormat::Console),
            "csv" => Ok(OutputFormat::Csv),
            "json-ocsf" | "json_ocsf" => Ok(OutputFormat::JsonOcsf),
            "html" => Ok(OutputFormat::Html),
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
        OutputFormat::Html => {
            bail!("HTML output is not yet implemented (Week 2)");
        }
    }
    Ok(())
}
