use crate::models::{CheckReport, Status};
use comfy_table::{Cell, Color, Table, Attribute, ContentArrangement};
use indicatif::{ProgressBar, ProgressStyle};

pub fn print_findings(findings: &[CheckReport]) {
    if findings.is_empty() {
        println!("No findings to display.");
        return;
    }

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        "CHECK ID",
        "STATUS",
        "SEVERITY",
        "RESOURCE",
        "REGION",
        "ACCOUNT",
        "DETAILS",
    ]);

    for finding in findings {
        let status_cell = match finding.status {
            Status::Pass => Cell::new("PASS").fg(Color::Green),
            Status::Fail => Cell::new("FAIL").fg(Color::Red).add_attribute(Attribute::Bold),
            Status::Muted => Cell::new("MUTED").fg(Color::Yellow),
            Status::Unknown => Cell::new("UNKNOWN").fg(Color::Grey),
        };

        table.add_row(vec![
            Cell::new(&finding.check_id),
            status_cell,
            Cell::new(finding.severity.to_string()),
            Cell::new(&finding.resource_id),
            Cell::new(&finding.region),
            Cell::new(&finding.account_id),
            Cell::new(&finding.status_extended),
        ]);
    }

    println!("{table}");

    let pass_count = findings.iter().filter(|f| f.status == Status::Pass).count();
    let fail_count = findings.iter().filter(|f| f.status == Status::Fail).count();
    println!("\nSummary: {} total | {} passed | {} failed", findings.len(), pass_count, fail_count);
}

#[allow(dead_code)]
pub fn create_scan_progress(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} checks ({eta})",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-"),
    );
    pb
}
