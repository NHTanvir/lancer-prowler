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
use providers::aws::checks::ec2::{
    ec2_ami_public::Ec2AmiPublic,
    ec2_ebs_default_encryption::Ec2EbsDefaultEncryption,
    ec2_ebs_public_snapshot::Ec2EbsPublicSnapshot,
    ec2_ebs_snapshot_encrypted::Ec2EbsSnapshotEncrypted,
    ec2_ebs_volume_encryption::Ec2EbsVolumeEncryption,
    ec2_elastic_ip_unassigned::Ec2ElasticIpUnassigned,
    ec2_instance_imdsv2_enabled::Ec2InstanceImdsv2Enabled,
    ec2_instance_internet_facing_with_instance_profile::Ec2InstanceInternetFacingWithInstanceProfile,
    ec2_instance_managed_by_ssm::Ec2InstanceManagedBySsm,
    ec2_instance_paravirtual_type::Ec2InstanceParavirtualType,
    ec2_instance_public_ip::Ec2InstancePublicIp,
    ec2_instance_secrets_user_data::Ec2InstanceSecretsUserData,
    ec2_securitygroup_allow_ingress_from_internet_to_any_port::Ec2SecuritygroupAllowIngressFromInternetToAnyPort,
    ec2_securitygroup_allow_ingress_from_internet_to_port_22::Ec2SecuritygroupAllowIngressFromInternetToPort22,
    ec2_securitygroup_allow_ingress_from_internet_to_port_3389::Ec2SecuritygroupAllowIngressFromInternetToPort3389,
    ec2_securitygroup_allow_wide_open_public_ipv4::Ec2SecuritygroupAllowWideOpenPublicIpv4,
    ec2_securitygroup_default_restrict_traffic::Ec2SecuritygroupDefaultRestrictTraffic,
    ec2_securitygroup_not_used::Ec2SecuritygroupNotUsed,
};
use providers::aws::checks::s3::{
    s3_account_level_public_access_blocks::S3AccountLevelPublicAccessBlocks,
    s3_bucket_acl_prohibited::S3BucketAclProhibited,
    s3_bucket_cross_account_access::S3BucketCrossAccountAccess,
    s3_bucket_default_encryption::S3BucketDefaultEncryption,
    s3_bucket_kms_encryption::S3BucketKmsEncryption,
    s3_bucket_level_public_access_block::S3BucketLevelPublicAccessBlock,
    s3_bucket_no_mfa_delete::S3BucketNoMfaDelete,
    s3_bucket_object_lock::S3BucketObjectLock,
    s3_bucket_object_versioning::S3BucketObjectVersioning,
    s3_bucket_public_access::S3BucketPublicAccess,
    s3_bucket_secure_transport_policy::S3BucketSecureTransportPolicy,
    s3_bucket_server_access_logging_enabled::S3BucketServerAccessLoggingEnabled,
};
use providers::aws::services::ec2::Ec2Service;
use providers::aws::services::iam::IamService;
use providers::aws::services::s3::S3Service;

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

/// Build the complete list of S3 check instances.
fn all_s3_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(S3BucketPublicAccess),
        Box::new(S3BucketAclProhibited),
        Box::new(S3AccountLevelPublicAccessBlocks),
        Box::new(S3BucketLevelPublicAccessBlock),
        Box::new(S3BucketDefaultEncryption),
        Box::new(S3BucketKmsEncryption),
        Box::new(S3BucketSecureTransportPolicy),
        Box::new(S3BucketServerAccessLoggingEnabled),
        Box::new(S3BucketNoMfaDelete),
        Box::new(S3BucketObjectVersioning),
        Box::new(S3BucketObjectLock),
        Box::new(S3BucketCrossAccountAccess),
    ]
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

/// Build the complete list of EC2 check instances.
fn all_ec2_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(Ec2SecuritygroupAllowIngressFromInternetToAnyPort),
        Box::new(Ec2SecuritygroupAllowIngressFromInternetToPort22),
        Box::new(Ec2SecuritygroupAllowIngressFromInternetToPort3389),
        Box::new(Ec2SecuritygroupDefaultRestrictTraffic),
        Box::new(Ec2SecuritygroupNotUsed),
        Box::new(Ec2SecuritygroupAllowWideOpenPublicIpv4),
        Box::new(Ec2EbsDefaultEncryption),
        Box::new(Ec2EbsVolumeEncryption),
        Box::new(Ec2EbsSnapshotEncrypted),
        Box::new(Ec2EbsPublicSnapshot),
        Box::new(Ec2InstanceImdsv2Enabled),
        Box::new(Ec2InstancePublicIp),
        Box::new(Ec2InstanceSecretsUserData),
        Box::new(Ec2InstanceParavirtualType),
        Box::new(Ec2InstanceManagedBySsm),
        Box::new(Ec2InstanceInternetFacingWithInstanceProfile),
        Box::new(Ec2AmiPublic),
        Box::new(Ec2ElasticIpUnassigned),
    ]
}

/// Run all checks (IAM + S3 + EC2) against a live AWS account.
async fn run_scan(provider: &providers::aws::AwsProvider) -> Vec<CheckReport> {
    let mut findings: Vec<CheckReport> = Vec::new();

    // ── IAM ──────────────────────────────────────────────────────────────────
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

    let iam_checks = all_iam_checks();
    println!("  [scan] Running {} IAM checks…", iam_checks.len());
    for c in &iam_checks {
        findings.extend(c.execute(&iam_service));
    }

    // ── S3 ───────────────────────────────────────────────────────────────────
    println!("  [scan] Fetching S3 state…");
    let s3_service = match S3Service::new(&provider.config, provider.account_id.clone()).await {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching S3 state: {:#}", e);
            // Don't abort the whole scan — IAM findings are still valid
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (IAM only) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] S3 state fetched — {} buckets",
        s3_service.buckets.len(),
    );

    let s3_checks = all_s3_checks();
    println!("  [scan] Running {} S3 checks…", s3_checks.len());
    for c in &s3_checks {
        findings.extend(c.execute(&s3_service));
    }

    // ── EC2 ──────────────────────────────────────────────────────────────────
    println!("  [scan] Fetching EC2 state…");
    let ec2_service = match Ec2Service::new(
        &provider.config,
        provider.account_id.clone(),
        provider.regions(),
    )
    .await
    {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching EC2 state: {:#}", e);
            // Don't abort the whole scan — IAM + S3 findings are still valid
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (IAM + S3 only) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] EC2 state fetched — {} security groups, {} instances, {} volumes, \
         {} snapshots, {} AMIs, {} elastic IPs",
        ec2_service.security_groups.len(),
        ec2_service.instances.len(),
        ec2_service.ebs_volumes.len(),
        ec2_service.ebs_snapshots.len(),
        ec2_service.amis.len(),
        ec2_service.elastic_ips.len(),
    );

    let ec2_checks = all_ec2_checks();
    println!("  [scan] Running {} EC2 checks…", ec2_checks.len());
    for c in &ec2_checks {
        findings.extend(c.execute(&ec2_service));
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
