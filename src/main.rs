//! lancer-prowler — Cloud Security Posture Management in Rust.

mod check;
mod cli;
mod compliance;
mod models;
mod output;
mod provider;

use anyhow::Context;
use clap::Parser;
use cli::{Cli, Commands, OutputFormatArg};
use output::{write_findings, OutputFormat};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => {
            println!(
                "lancer-prowler scan — provider: {} | regions: {} | services: {} | checks: {}",
                args.provider,
                if args.region.is_empty() { "all".to_string() } else { args.region.join(", ") },
                if args.service.is_empty() { "all".to_string() } else { args.service.join(", ") },
                if args.check.is_empty() { "all".to_string() } else { args.check.join(", ") },
            );

            println!("No checks implemented yet — cloud SDK integration comes in Week 2+.");

            let findings: Vec<models::CheckReport> = vec![];

            let format = match args.output_format {
                OutputFormatArg::Console => OutputFormat::Console,
                OutputFormatArg::Csv => OutputFormat::Csv,
                OutputFormatArg::JsonOcsf => OutputFormat::JsonOcsf,
                OutputFormatArg::Html => OutputFormat::Html,
            };

            write_findings(&findings, format, args.output_path.as_deref())
                .context("Failed to write findings")?;
        }

        Commands::ListChecks(args) => {
            println!("Available checks:");
            println!("  (none registered yet — check implementations arrive in Week 2+)");
            if let Some(p) = &args.provider {
                println!("  Provider filter: {p}");
            }
            if let Some(s) = &args.service {
                println!("  Service filter: {s}");
            }
        }

        Commands::ListServices(args) => {
            println!("Available services:");
            println!("  (none registered yet — service implementations arrive in Week 2+)");
            if let Some(p) = &args.provider {
                println!("  Provider filter: {p}");
            }
        }

        Commands::Version => {
            println!(
                "lancer-prowler v{} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_DESCRIPTION"),
            );
        }
    }

    Ok(())
}
