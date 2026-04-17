//! lancer-prowler — Cloud Security Posture Management in Rust.

mod check;
mod cli;
mod compliance;
mod models;
mod output;
mod provider;
mod providers;

use anyhow::Context;
use clap::Parser;
use cli::{Cli, Commands, OutputFormatArg, ProviderArg};
use output::{write_findings, OutputFormat};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => {
            let format = match args.output_format {
                OutputFormatArg::Console => OutputFormat::Console,
                OutputFormatArg::Csv => OutputFormat::Csv,
                OutputFormatArg::JsonOcsf => OutputFormat::JsonOcsf,
                OutputFormatArg::Html => OutputFormat::Html,
            };

            match args.provider {
                ProviderArg::Aws => {
                    println!("lancer-prowler scan — provider: aws");

                    let provider =
                        providers::aws::AwsProvider::new(args.region.clone())
                            .await
                            .context("Failed to initialize AWS provider")?;

                    println!(
                        "  Account ID : {}",
                        provider.account_id
                    );
                    println!(
                        "  Identity   : {}",
                        provider.identity_arn
                    );
                    println!(
                        "  Regions    : {} region(s) — {}",
                        provider.regions.len(),
                        if provider.regions.len() <= 5 {
                            provider.regions.join(", ")
                        } else {
                            format!(
                                "{} … and {} more",
                                provider.regions[..5].join(", "),
                                provider.regions.len() - 5
                            )
                        }
                    );

                    let findings = run_scan(&provider).await;

                    write_findings(&findings, format, args.output_path.as_deref())
                        .context("Failed to write findings")?;
                }

                other => {
                    println!(
                        "lancer-prowler scan — provider: {other} | \
                         regions: {} | services: {} | checks: {}",
                        if args.region.is_empty() {
                            "all".to_string()
                        } else {
                            args.region.join(", ")
                        },
                        if args.service.is_empty() {
                            "all".to_string()
                        } else {
                            args.service.join(", ")
                        },
                        if args.check.is_empty() {
                            "all".to_string()
                        } else {
                            args.check.join(", ")
                        },
                    );
                    println!(
                        "Provider '{other}' is not yet implemented — \
                         only 'aws' is supported in Week 2."
                    );

                    let findings: Vec<models::CheckReport> = vec![];
                    write_findings(&findings, format, args.output_path.as_deref())
                        .context("Failed to write findings")?;
                }
            }
        }

        Commands::ListChecks(args) => {
            println!("Available checks:");
            println!("  (none registered yet — check implementations arrive in Week 3+)");
            if let Some(p) = &args.provider {
                println!("  Provider filter: {p}");
            }
            if let Some(s) = &args.service {
                println!("  Service filter: {s}");
            }
        }

        Commands::ListServices(args) => {
            println!("Available services:");
            println!("  iam  — AWS Identity and Access Management (Week 2)");
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

/// Placeholder scan runner — Week 3 will register checks and drive this loop.
async fn run_scan(
    _provider: &providers::aws::AwsProvider,
) -> Vec<models::CheckReport> {
    println!("  [scan] No checks registered yet — Week 3 will add IAM checks.");
    vec![]
}
