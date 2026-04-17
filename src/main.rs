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
use models::CheckReport;
use output::{write_findings, OutputFormat};

use providers::aws::checks::iam::{
    iam_avoid_root_usage::IamAvoidRootUsage,
    iam_aws_attached_policy_no_administrative_privileges::IamAwsAttachedPolicyNoAdministrativePrivileges,
    iam_check_saml_providers_sts::IamCheckSamlProvidersSts,
    iam_customer_attached_policy_no_administrative_privileges::IamCustomerAttachedPolicyNoAdministrativePrivileges,
    iam_inline_policy_no_administrative_privileges::IamInlinePolicyNoAdministrativePrivileges,
    iam_no_root_access_key::IamNoRootAccessKey,
    iam_password_policy_expires_passwords_within_90_days_or_less::IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess,
    iam_password_policy_lowercase::IamPasswordPolicyLowercase,
    iam_password_policy_minimum_length_14::IamPasswordPolicyMinimumLength14,
    iam_password_policy_number::IamPasswordPolicyNumber,
    iam_password_policy_reuse_24::IamPasswordPolicyReuse24,
    iam_password_policy_symbol::IamPasswordPolicySymbol,
    iam_password_policy_uppercase::IamPasswordPolicyUppercase,
    iam_policy_allows_privilege_escalation::IamPolicyAllowsPrivilegeEscalation,
    iam_policy_attached_only_to_group_or_roles::IamPolicyAttachedOnlyToGroupOrRoles,
    iam_policy_no_full_access_to_cloudtrail::IamPolicyNoFullAccessToCloudTrail,
    iam_policy_no_full_access_to_kms::IamPolicyNoFullAccessToKms,
    iam_role_cross_account_readonlyaccess_policy::IamRoleCrossAccountReadonlyAccessPolicy,
    iam_root_hardware_mfa_enabled::IamRootHardwareMfaEnabled,
    iam_root_mfa_enabled::IamRootMfaEnabled,
    iam_rotate_access_key_90_days::IamRotateAccessKey90Days,
    iam_support_role_created::IamSupportRoleCreated,
    iam_user_mfa_enabled_console_access::IamUserMfaEnabledConsoleAccess,
    iam_user_no_setup_initial_access_key::IamUserNoSetupInitialAccessKey,
    iam_user_two_active_access_key::IamUserTwoActiveAccessKey,
};
use providers::aws::services::iam::IamService;

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
                         only 'aws' is supported."
                    );

                    let findings: Vec<models::CheckReport> = vec![];
                    write_findings(&findings, format, args.output_path.as_deref())
                        .context("Failed to write findings")?;
                }
            }
        }

        Commands::ListChecks(args) => {
            let checks = all_iam_checks();
            println!("Available checks ({} total):", checks.len());
            for c in &checks {
                let meta = c.metadata();
                let provider_filter = args
                    .provider
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                let service_filter = args.service.as_deref().unwrap_or("").to_string();
                if (!provider_filter.is_empty() && meta.provider != provider_filter)
                    || (!service_filter.is_empty() && meta.service != service_filter)
                {
                    continue;
                }
                println!(
                    "  [{:8}] {} — {}",
                    meta.severity,
                    meta.id,
                    meta.name
                );
            }
        }

        Commands::ListServices(args) => {
            println!("Available services:");
            println!("  iam  — AWS Identity and Access Management");
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

/// Build the complete list of IAM check instances.
fn all_iam_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(IamRootMfaEnabled),
        Box::new(IamRootHardwareMfaEnabled),
        Box::new(IamNoRootAccessKey),
        Box::new(IamAvoidRootUsage),
        Box::new(IamPasswordPolicyMinimumLength14),
        Box::new(IamPasswordPolicyUppercase),
        Box::new(IamPasswordPolicyLowercase),
        Box::new(IamPasswordPolicySymbol),
        Box::new(IamPasswordPolicyNumber),
        Box::new(IamPasswordPolicyReuse24),
        Box::new(IamPasswordPolicyExpiresPasswordsWithin90DaysOrLess),
        Box::new(IamUserMfaEnabledConsoleAccess),
        Box::new(IamUserNoSetupInitialAccessKey),
        Box::new(IamUserTwoActiveAccessKey),
        Box::new(IamRotateAccessKey90Days),
        Box::new(IamInlinePolicyNoAdministrativePrivileges),
        Box::new(IamCustomerAttachedPolicyNoAdministrativePrivileges),
        Box::new(IamAwsAttachedPolicyNoAdministrativePrivileges),
        Box::new(IamPolicyAttachedOnlyToGroupOrRoles),
        Box::new(IamPolicyNoFullAccessToCloudTrail),
        Box::new(IamPolicyNoFullAccessToKms),
        Box::new(IamCheckSamlProvidersSts),
        Box::new(IamSupportRoleCreated),
        Box::new(IamRoleCrossAccountReadonlyAccessPolicy),
        Box::new(IamPolicyAllowsPrivilegeEscalation),
    ]
}

/// Run all IAM checks against a live AWS account.
async fn run_scan(provider: &providers::aws::AwsProvider) -> Vec<CheckReport> {
    println!("  [scan] Fetching IAM state…");

    let iam_service = match IamService::new(&provider.config, provider.account_id.clone()).await {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching IAM state: {:#}", e);
            return vec![];
        }
    };

    println!(
        "  [scan] IAM state fetched — {} users, {} roles, {} groups, {} policies, {} credential report rows",
        iam_service.users.len(),
        iam_service.roles.len(),
        iam_service.groups.len(),
        iam_service.policies.len(),
        iam_service.credential_report.len(),
    );

    let checks = all_iam_checks();
    println!("  [scan] Running {} IAM checks…", checks.len());

    let mut findings: Vec<CheckReport> = Vec::new();
    for c in &checks {
        let results = c.execute(&iam_service);
        findings.extend(results);
    }

    let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
    let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
    println!(
        "  [scan] Complete — {} findings ({} PASS, {} FAIL)",
        findings.len(),
        pass,
        fail
    );

    findings
}
