//! lancer-prowler — Cloud Security Posture Management in Rust.

mod check;
mod cli;
mod compliance;
mod gui;
mod ingest;
mod lancer_server;
mod models;
mod mutelist;
mod output;
mod provider;
mod providers;
mod security_hub;
mod self_test;
mod slack;
mod tui;

use anyhow::Context;
use clap::Parser;
use cli::{Cli, Commands, OutputFormatArg, ProviderArg, StatusArg};
use models::{CheckReport, Severity, Status};
use output::{write_findings, write_findings_multi, OutputFormat};
use provider::Provider;

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
use providers::aws::checks::awsconfig::{
    config_delivery_channel_exists::ConfigDeliveryChannelExists,
    config_recorder_all_regions_enabled::ConfigRecorderAllRegionsEnabled,
    config_recorder_using_all_supported_resource_types::ConfigRecorderUsingAllSupportedResourceTypes,
};
use providers::aws::checks::cloudtrail::{
    cloudtrail_cloudwatch_logging_enabled::CloudtrailCloudwatchLoggingEnabled,
    cloudtrail_kms_encryption_enabled::CloudtrailKmsEncryptionEnabled,
    cloudtrail_log_file_validation_enabled::CloudtrailLogFileValidationEnabled,
    cloudtrail_logs_s3_bucket_is_not_publicly_accessible::CloudtrailLogsS3BucketIsNotPubliclyAccessible,
    cloudtrail_multi_region_enabled::CloudtrailMultiRegionEnabled,
    cloudtrail_s3_dataevents_read_enabled::CloudtrailS3DataeventsReadEnabled,
    cloudtrail_s3_dataevents_write_enabled::CloudtrailS3DataeventsWriteEnabled,
    cloudtrail_threat_detection_enumeration::CloudtrailThreatDetectionEnumeration,
    cloudtrail_threat_detection_privilege_escalation::CloudtrailThreatDetectionPrivilegeEscalation,
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
use providers::aws::checks::kms::{
    kms_cmk_not_pending_deletion::KmsCmkNotPendingDeletion,
    kms_cmk_rotation_enabled::KmsCmkRotationEnabled,
    kms_key_not_disabled::KmsKeyNotDisabled,
};
use providers::aws::checks::vpc::{
    vpc_different_regions::VpcDifferentRegions,
    vpc_endpoint_connections_trust_boundaries::VpcEndpointConnectionsTrustBoundaries,
    vpc_flow_logs_enabled::VpcFlowLogsEnabled,
    vpc_peering_routing_tables_with_least_privilege::VpcPeeringRoutingTablesWithLeastPrivilege,
    vpc_subnet_no_public_ip_by_default::VpcSubnetNoPublicIpByDefault,
};
use providers::aws::checks::rds::{
    rds_instance_backup_enabled::RdsInstanceBackupEnabled,
    rds_instance_default_admin::RdsInstanceDefaultAdmin,
    rds_instance_encrypted::RdsInstanceEncrypted,
    rds_instance_minor_version_upgrade_enabled::RdsInstanceMinorVersionUpgradeEnabled,
    rds_instance_multi_az::RdsInstanceMultiAz,
    rds_instance_public_access::RdsInstancePublicAccess,
    rds_instance_storage_encrypted::RdsInstanceStorageEncrypted,
    rds_snapshots_encrypted::RdsSnapshotsEncrypted,
    rds_snapshots_public_access::RdsSnapshotsPublicAccess,
};
use providers::aws::checks::lambda::{
    lambda_function_environment_variables_encrypted::LambdaFunctionEnvironmentVariablesEncrypted,
    lambda_function_in_vpc::LambdaFunctionInVpc,
    lambda_function_not_publicly_accessible::LambdaFunctionNotPubliclyAccessible,
    lambda_function_url_public::LambdaFunctionUrlPublic,
};
use providers::aws::checks::guardduty::{
    guardduty_is_enabled::GuardDutyIsEnabled,
    guardduty_finding_publishing_frequency_six_hours_or_less::GuardDutyFindingPublishingFrequencySixHoursOrLess,
};
use providers::aws::checks::securityhub::{
    securityhub_enabled::SecurityHubEnabled,
    securityhub_auto_enable_controls::SecurityHubAutoEnableControls,
};
use providers::aws::checks::secretsmanager::{
    secretsmanager_secret_rotation_enabled::SecretsManagerSecretRotationEnabled,
    secretsmanager_secret_encrypted_with_cmk::SecretsManagerSecretEncryptedWithCmk,
    secretsmanager_secret_unused_45_days::SecretsManagerSecretUnused45Days,
};
use providers::aws::checks::elbv2::{
    elbv2_internet_facing::Elbv2InternetFacing,
    elbv2_access_logs_enabled::Elbv2AccessLogsEnabled,
    elbv2_deletion_protection_enabled::Elbv2DeletionProtectionEnabled,
    elbv2_insecure_listener_protocols::Elbv2InsecureListenerProtocols,
    elbv2_listener_uses_secure_ssl_policy::Elbv2ListenerUsesSecureSslPolicy,
};
// ── Kubernetes imports ────────────────────────────────────────────────────────
use providers::kubernetes::checks::rbac::{
    rbac_cluster_admin_bindings::RbacClusterAdminBindings,
    rbac_wildcard_verbs::RbacWildcardVerbs,
    rbac_bind_cluster_admin_role::RbacBindClusterAdminRole,
    rbac_no_anonymous_access::RbacNoAnonymousAccess,
    rbac_service_account_least_privilege::RbacServiceAccountLeastPrivilege,
    rbac_no_cluster_admin_default::RbacNoClusterAdminDefault,
};
use providers::kubernetes::checks::workloads::{
    workloads_no_privileged_containers::WorkloadsNoPrivilegedContainers,
    workloads_no_privilege_escalation::WorkloadsNoPrivilegeEscalation,
    workloads_run_as_non_root::WorkloadsRunAsNonRoot,
    workloads_read_only_root_filesystem::WorkloadsReadOnlyRootFilesystem,
    workloads_no_host_network::WorkloadsNoHostNetwork,
    workloads_no_host_pid_namespace::WorkloadsNoHostPidNamespace,
    workloads_resource_limits_set::WorkloadsResourceLimitsSet,
    workloads_no_root_capabilities::WorkloadsNoRootCapabilities,
    workloads_automount_service_account_token::WorkloadsAutomountServiceAccountToken,
};
use providers::kubernetes::checks::network::{
    network_namespace_has_network_policy::NetworkNamespaceHasNetworkPolicy,
    network_default_deny_policy::NetworkDefaultDenyPolicy,
    network_no_exposed_dashboard::NetworkNoExposedDashboard,
    network_pods_ingress_traffic_restricted::NetworkPodsIngressTrafficRestricted,
    network_pods_egress_traffic_restricted::NetworkPodsEgressTrafficRestricted,
};
use providers::kubernetes::services::rbac::RbacService;
use providers::kubernetes::services::workloads::WorkloadsService;
use providers::kubernetes::services::network::NetworkService;
// ── GCP imports ───────────────────────────────────────────────────────────────
use providers::gcp::checks::iam::{
    iam_no_service_account_with_admin_privileges::IamNoServiceAccountWithAdminPrivileges,
    iam_service_account_key_not_user_managed::IamServiceAccountKeyNotUserManaged,
    iam_avoid_primitive_roles::IamAvoidPrimitiveRoles,
    iam_project_has_owner::IamProjectHasOwner,
    iam_no_public_access::IamNoPublicAccess,
    iam_sa_no_admin_privileges::IamSaNoAdminPrivileges,
    iam_service_account_key_rotation_90_days::IamServiceAccountKeyRotation90Days,
    iam_workload_identity_federation_enabled::IamWorkloadIdentityFederationEnabled,
};
use providers::gcp::checks::storage::{
    storage_bucket_uniform_bucket_level_access::StorageBucketUniformBucketLevelAccess,
    storage_bucket_public_access_prevention::StorageBucketPublicAccessPrevention,
    storage_bucket_versioning_enabled::StorageBucketVersioningEnabled,
    storage_bucket_logging_enabled::StorageBucketLoggingEnabled,
    storage_bucket_kms_encryption::StorageBucketKmsEncryption,
    storage_bucket_retention_policy::StorageBucketRetentionPolicy,
    storage_bucket_not_publicly_accessible::StorageBucketNotPubliclyAccessible,
    storage_bucket_label_environment::StorageBucketLabelEnvironment,
};
use providers::gcp::checks::compute::{
    compute_instance_ip_forwarding_disabled::ComputeInstanceIpForwardingDisabled,
    compute_instance_serial_port_disabled::ComputeInstanceSerialPortDisabled,
    compute_instance_oslogin_enabled::ComputeInstanceOsloginEnabled,
    compute_instance_shielded_vm_enabled::ComputeInstanceShieldedVmEnabled,
    compute_instance_no_public_ip::ComputeInstanceNoPublicIp,
    compute_instance_default_service_account::ComputeInstanceDefaultServiceAccount,
    compute_instance_default_service_account_full_access::ComputeInstanceDefaultServiceAccountFullAccess,
    compute_firewall_rule_no_ingress_0_0_0_0_22::ComputeFirewallRuleNoIngress0000022,
    compute_firewall_rule_no_ingress_0_0_0_0_3389::ComputeFirewallRuleNoIngress000003389,
};
use providers::gcp::services::iam::GcpIamService;
use providers::gcp::services::storage::GcpStorageService;
use providers::gcp::services::compute::GcpComputeService;
// ── Azure imports ─────────────────────────────────────────────────────────────
use providers::azure::checks::storage::{
    storage_account_secure_transfer_required::StorageAccountSecureTransferRequired,
    storage_account_minimum_tls_version_1_2::StorageAccountMinimumTlsVersion12,
    storage_account_public_access_level_is_private::StorageAccountPublicAccessLevelIsPrivate,
    storage_account_default_network_access_rule_deny::StorageAccountDefaultNetworkAccessRuleDeny,
    storage_account_customer_managed_key::StorageAccountCustomerManagedKey,
    storage_account_infrastructure_encryption_enabled::StorageAccountInfrastructureEncryptionEnabled,
    storage_account_blob_soft_delete_enabled::StorageAccountBlobSoftDeleteEnabled,
    storage_account_container_soft_delete_enabled::StorageAccountContainerSoftDeleteEnabled,
    storage_account_versioning_enabled::StorageAccountVersioningEnabled,
    storage_account_shared_key_access_disabled::StorageAccountSharedKeyAccessDisabled,
};
use providers::azure::checks::keyvault::{
    keyvault_soft_delete_enabled::KeyVaultSoftDeleteEnabled,
    keyvault_purge_protection_enabled::KeyVaultPurgeProtectionEnabled,
    keyvault_public_network_access_disabled::KeyVaultPublicNetworkAccessDisabled,
    keyvault_rbac_authorization_enabled::KeyVaultRbacAuthorizationEnabled,
    keyvault_default_network_access_rule_deny::KeyVaultDefaultNetworkAccessRuleDeny,
    keyvault_premium_sku::KeyVaultPremiumSku,
    keyvault_recoverable::KeyVaultRecoverable,
    keyvault_logging_enabled::KeyVaultLoggingEnabled,
    keyvault_private_endpoint::KeyVaultPrivateEndpoint,
    keyvault_key_expiration_set::KeyVaultKeyExpirationSet,
};
use providers::azure::checks::compute::{
    compute_vm_os_disk_encryption_enabled::ComputeVmOsDiskEncryptionEnabled,
    compute_vm_data_disks_encrypted::ComputeVmDataDisksEncrypted,
    compute_vm_managed_identity_enabled::ComputeVmManagedIdentityEnabled,
    compute_vm_boot_diagnostics_enabled::ComputeVmBootDiagnosticsEnabled,
    compute_vm_os_automatic_patching::ComputeVmOsAutomaticPatching,
    compute_vm_availability_zone_enabled::ComputeVmAvailabilityZoneEnabled,
    compute_vm_disaster_recovery::ComputeVmDisasterRecovery,
    compute_vm_endpoint_protection::ComputeVmEndpointProtection,
    compute_vm_network_security_group::ComputeVmNetworkSecurityGroup,
    compute_vm_public_ip_address::ComputeVmPublicIpAddress,
};
use providers::azure::services::storage::StorageService as AzureStorageService;
use providers::azure::services::keyvault::KeyVaultService;
use providers::azure::services::compute::ComputeService as AzureComputeService;

use providers::aws::services::awsconfig::AwsConfigService;
use providers::aws::services::cloudtrail::CloudtrailService;
use providers::aws::services::ec2::Ec2Service;
use providers::aws::services::elbv2::Elbv2Service;
use providers::aws::services::guardduty::GuardDutyService;
use providers::aws::services::iam::IamService;
use providers::aws::services::kms::KmsService;
use providers::aws::services::lambda::LambdaService;
use providers::aws::services::rds::RdsService;
use providers::aws::services::s3::S3Service;
use providers::aws::services::secretsmanager::SecretsManagerService;
use providers::aws::services::securityhub::SecurityHubService;
use providers::aws::services::vpc::VpcService;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging(&cli)?;

    if cli.self_test {
        let code = self_test::run_self_test();
        std::process::exit(code);
    }

    if !cli.no_banner && !cli.quiet {
        print_banner();
    }

    // No subcommand → GUI mode (unless --cli was set, in which case fall through
    // to the CLI surface with a default help-style print).
    let Cli {
        cli: cli_flag,
        no_banner: _,
        ignore_exit_code_3,
        quiet,
        verbose: _,
        log_level: _,
        log_file: _,
        config_file: _,
        self_test: _,
        command,
    } = cli;

    let command = match command {
        Some(c) => c,
        None => {
            if cli_flag {
                println!(
                    "lancer-prowler {} — use --help to see commands.",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            let server = lancer_server::Server::launch().ok();
            return gui::launch(Vec::new(), server);
        }
    };

    let scan_context = ScanContext {
        quiet,
        ignore_exit_code_3,
    };

    match command {
        Commands::Scan(args) => run_scan_command(&scan_context, args).await?,
        Commands::ListChecks(args) => list_checks(args, false),
        Commands::ListChecksJson(args) => list_checks(args, true),
        Commands::ListServices(args) => list_services(args),
        Commands::ListCompliance(args) => list_compliance(args),
        Commands::ListComplianceRequirements(args) => list_compliance_requirements(args)?,
        Commands::ListCategories => list_categories(),
        Commands::ListFixer => list_fixer(),
        Commands::Ingest(args) => run_ingest(&scan_context, args)?,
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

struct ScanContext {
    quiet: bool,
    ignore_exit_code_3: bool,
}

fn init_logging(cli: &Cli) -> anyhow::Result<()> {
    let level = if cli.verbose {
        "debug"
    } else if cli.quiet {
        "error"
    } else {
        cli.log_level.as_str()
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));

    if let Some(path) = cli.log_file.as_ref() {
        if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(file)
                .with_ansi(false)
                .init();
            return Ok(());
        }
    }

    tracing_subscriber::fmt().with_env_filter(filter).init();
    Ok(())
}

fn print_banner() {
    println!("┌────────────────────────────────────────────────────────────────┐");
    println!("│  lancer-prowler v{:<46}│", env!("CARGO_PKG_VERSION"));
    println!("│  Cloud Security Posture Management — Lancer ecosystem clone.   │");
    println!("└────────────────────────────────────────────────────────────────┘");
}

fn resolve_output_formats(args: &cli::ScanArgs) -> Vec<OutputFormat> {
    if args.output_formats.is_empty() {
        // No --output-formats: keep the legacy single-format behaviour
        // (console-only by default) so existing invocations don't surprise.
        vec![OutputFormat::Console]
    } else {
        args.output_formats
            .iter()
            .map(arg_to_format)
            .collect()
    }
}

fn arg_to_format(f: &OutputFormatArg) -> OutputFormat {
    match f {
        OutputFormatArg::Console => OutputFormat::Console,
        OutputFormatArg::Csv => OutputFormat::Csv,
        OutputFormatArg::JsonOcsf => OutputFormat::JsonOcsf,
        OutputFormatArg::JsonAsff => OutputFormat::JsonAsff,
        OutputFormatArg::Html => OutputFormat::Html,
        OutputFormatArg::Sarif => OutputFormat::Sarif,
        OutputFormatArg::Markdown => OutputFormat::Markdown,
    }
}

fn resolve_output_filename(args: &cli::ScanArgs) -> Option<String> {
    if let Some(base) = args.output_filename.as_ref() {
        let stamp = if args.unix_timestamp {
            chrono::Utc::now().timestamp().to_string()
        } else {
            chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
        };
        return Some(format!("{base}-{stamp}"));
    }
    None
}

fn read_checks_file(path: &str) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read --checks-file: {path}"))?;
    Ok(content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

async fn run_scan_command(ctx: &ScanContext, mut args: cli::ScanArgs) -> anyhow::Result<()> {
    if args.fix {
        anyhow::bail!(
            "--fix / --fixer requested but lancer-prowler is a READ-ONLY clone. \
             Auto-remediation is intentionally not implemented per the parity \
             contract. Use upstream `prowler fixer` for write actions."
        );
    }

    if let Some(checks_file) = args.checks_file.clone() {
        let extra = read_checks_file(&checks_file)?;
        args.check.extend(extra);
    }

    let mutelist = if let Some(path) = args.mutelist_file.as_ref() {
        Some(
            mutelist::Mutelist::load_from_file(path)
                .with_context(|| format!("Failed to load mutelist: {path}"))?,
        )
    } else {
        None
    };

    let formats = resolve_output_formats(&args);
    let output_base = resolve_output_filename(&args);

    let mut findings: Vec<CheckReport> = match args.provider {
        ProviderArg::Aws => run_aws_scan(&args).await?,
        ProviderArg::Azure => run_azure_scan(&args)?,
        ProviderArg::Gcp => run_gcp_scan(&args)?,
        ProviderArg::Kubernetes => run_kubernetes_scan(&args)?,
        ProviderArg::M365 => providers::m365::run_stub_scan(
            &providers::m365::M365Provider::new_stub(
                args.tenant_id.clone().unwrap_or_else(|| "unknown-tenant".to_string()),
            ),
        ),
        ProviderArg::Github => providers::github::run_stub_scan(
            &providers::github::GithubProvider::new_stub(
                std::env::var("GITHUB_ORG").unwrap_or_else(|_| "unknown-org".to_string()),
            ),
        ),
        ProviderArg::Oci => providers::oci::run_stub_scan(
            &providers::oci::OciProvider::new_stub(
                std::env::var("OCI_TENANCY_ID").unwrap_or_else(|_| "unknown-tenancy".to_string()),
            ),
        ),
        ProviderArg::Alibaba => providers::alibaba::run_stub_scan(
            &providers::alibaba::AlibabaProvider::new_stub(
                std::env::var("ALIBABA_ACCOUNT_ID").unwrap_or_else(|_| "unknown-acct".to_string()),
            ),
        ),
        ProviderArg::Cloudflare => providers::cloudflare::run_stub_scan(
            &providers::cloudflare::CloudflareProvider::new_stub(
                std::env::var("CLOUDFLARE_ACCOUNT_ID").unwrap_or_else(|_| "unknown-acct".to_string()),
            ),
        ),
        ProviderArg::Iac => {
            let root = std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| ".".to_string());
            providers::iac::scan_directory(&root)
        }
        ProviderArg::ContainerImage => providers::container_image::run_stub_scan(
            &providers::container_image::ContainerImageProvider::new_stub(
                std::env::var("CONTAINER_IMAGE_REF")
                    .unwrap_or_else(|_| "alpine:latest".to_string()),
            ),
        ),
    };

    // ── filters ──────────────────────────────────────────────────────────────
    findings = filter_findings(findings, &args);

    // ── mutelist ─────────────────────────────────────────────────────────────
    if let Some(m) = &mutelist {
        let n = m.apply(&mut findings);
        if !ctx.quiet {
            println!("  [mute] {n} finding(s) muted by mutelist");
        }
    }

    // ── Security Hub upload (AWS only) ───────────────────────────────────────
    if args.upload_security_hub && matches!(args.provider, ProviderArg::Aws) {
        if let Ok(provider) = providers::aws::AwsProvider::new(args.region.clone()).await {
            if !ctx.quiet {
                println!(
                    "  [upload] Uploading {} findings to AWS Security Hub ({})…",
                    findings.len(),
                    &args.security_hub_region
                );
            }
            security_hub::upload_findings_to_security_hub(
                &provider.config,
                &findings,
                &provider.account_id,
                &args.security_hub_region,
            )
            .await
            .context("Failed to upload findings to Security Hub")?;
            if !ctx.quiet {
                println!("  [upload] Security Hub upload complete.");
            }
        }
    }

    // ── outputs ──────────────────────────────────────────────────────────────
    if args.tui {
        tui::TuiApp::run(findings.clone()).context("TUI dashboard error")?;
    }
    if formats.len() == 1 && output_base.is_none() && args.output_directory.is_none() {
        write_findings(&findings, formats[0].clone(), None)?;
    } else {
        write_findings_multi(
            &findings,
            &formats,
            output_base.as_deref(),
            args.output_directory.as_deref(),
        )?;
    }

    // ── Slack notification ───────────────────────────────────────────────────
    if args.slack {
        if let Some(url) = slack::resolve_webhook(&args.slack_webhook) {
            slack::post_summary(&url, &findings)?;
        } else {
            tracing::warn!(
                "--slack requested but no webhook URL configured (set SLACK_WEBHOOK_URL or --slack-webhook)"
            );
        }
    }

    // ── exit code 3 on failures ──────────────────────────────────────────────
    let any_fail = findings.iter().any(|f| f.status == Status::Fail);
    if any_fail && !ctx.ignore_exit_code_3 {
        std::process::exit(3);
    }

    Ok(())
}

fn filter_findings(mut findings: Vec<CheckReport>, args: &cli::ScanArgs) -> Vec<CheckReport> {
    if !args.check.is_empty() {
        findings.retain(|f| args.check.iter().any(|c| c == &f.check_id));
    }
    if !args.exclude_checks.is_empty() {
        findings.retain(|f| !args.exclude_checks.iter().any(|c| c == &f.check_id));
    }
    if !args.service.is_empty() {
        findings.retain(|f| args.service.iter().any(|s| s == &f.service));
    }
    if !args.exclude_service.is_empty() {
        findings.retain(|f| !args.exclude_service.iter().any(|s| s == &f.service));
    }
    if !args.compliance.is_empty() {
        findings.retain(|f| {
            f.compliance
                .iter()
                .any(|c| args.compliance.iter().any(|wanted| &c.framework == wanted))
        });
    }
    if let Some(min) = args.severity.as_ref() {
        findings.retain(|f| severity_rank(&f.severity) >= min.rank());
    }
    if let Some(status) = args.status.as_ref() {
        findings.retain(|f| matches_status(&f.status, status));
    }
    findings
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Informational => 1,
    }
}

fn matches_status(s: &Status, arg: &StatusArg) -> bool {
    matches!(
        (s, arg),
        (Status::Pass, StatusArg::Pass)
            | (Status::Fail, StatusArg::Fail)
            | (Status::Muted, StatusArg::Muted),
    )
}

async fn run_aws_scan(args: &cli::ScanArgs) -> anyhow::Result<Vec<CheckReport>> {
    println!("lancer-prowler scan — provider: aws");
    let provider = providers::aws::AwsProvider::new(args.region.clone())
        .await
        .context("Failed to initialize AWS provider")?;
    println!("  Account ID : {}", provider.account_id);
    println!("  Identity   : {}", provider.identity_arn);
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
    Ok(run_scan(&provider).await)
}

fn run_azure_scan(args: &cli::ScanArgs) -> anyhow::Result<Vec<CheckReport>> {
    println!("lancer-prowler scan — provider: azure");
    let subscription_id = std::env::var("AZURE_SUBSCRIPTION_ID")
        .unwrap_or_else(|_| "unknown-subscription".to_string());
    println!("  Subscription : {}", subscription_id);
    let _ = args; // tenant / client args reserved for real impl
    let storage_svc = AzureStorageService::new_stub(subscription_id.clone());
    let keyvault_svc = KeyVaultService::new_stub(subscription_id.clone());
    let compute_svc = AzureComputeService::new_stub(subscription_id.clone());

    let mut findings: Vec<CheckReport> = vec![];
    for c in all_azure_storage_checks() {
        findings.extend(c.execute(&storage_svc));
    }
    for c in all_azure_keyvault_checks() {
        findings.extend(c.execute(&keyvault_svc));
    }
    for c in all_azure_compute_checks() {
        findings.extend(c.execute(&compute_svc));
    }
    Ok(findings)
}

fn run_gcp_scan(args: &cli::ScanArgs) -> anyhow::Result<Vec<CheckReport>> {
    println!("lancer-prowler scan — provider: gcp");
    let project_id = std::env::var("GOOGLE_CLOUD_PROJECT")
        .or_else(|_| std::env::var("GCP_PROJECT_ID"))
        .unwrap_or_else(|_| "unknown-project".to_string());
    let _ = args;
    let iam_svc = GcpIamService::new_stub(project_id.clone());
    let storage_svc = GcpStorageService::new_stub(project_id.clone());
    let compute_svc = GcpComputeService::new_stub(project_id.clone());

    let mut findings: Vec<CheckReport> = vec![];
    for c in all_gcp_iam_checks() {
        findings.extend(c.execute(&iam_svc));
    }
    for c in all_gcp_storage_checks() {
        findings.extend(c.execute(&storage_svc));
    }
    for c in all_gcp_compute_checks() {
        findings.extend(c.execute(&compute_svc));
    }
    Ok(findings)
}

fn run_kubernetes_scan(args: &cli::ScanArgs) -> anyhow::Result<Vec<CheckReport>> {
    println!("lancer-prowler scan — provider: kubernetes");
    let cluster_name = std::env::var("KUBE_CLUSTER_NAME")
        .unwrap_or_else(|_| "default-cluster".to_string());
    let _ = args;
    let rbac_svc = RbacService::new_stub(cluster_name.clone());
    let workloads_svc = WorkloadsService::new_stub(cluster_name.clone());
    let network_svc = NetworkService::new_stub(cluster_name.clone());

    let mut findings: Vec<CheckReport> = vec![];
    for c in all_k8s_rbac_checks() {
        findings.extend(c.execute(&rbac_svc));
    }
    for c in all_k8s_workload_checks() {
        findings.extend(c.execute(&workloads_svc));
    }
    for c in all_k8s_network_checks() {
        findings.extend(c.execute(&network_svc));
    }
    Ok(findings)
}

fn run_ingest(_ctx: &ScanContext, args: cli::IngestArgs) -> anyhow::Result<()> {
    let fmt = args.format.as_ref().and_then(|f| match f {
        OutputFormatArg::Csv => Some(ingest::IngestFormat::Csv),
        OutputFormatArg::JsonOcsf => Some(ingest::IngestFormat::JsonOcsf),
        OutputFormatArg::JsonAsff => Some(ingest::IngestFormat::JsonAsff),
        OutputFormatArg::Sarif => Some(ingest::IngestFormat::Sarif),
        _ => None,
    });
    let findings = ingest::ingest_file(&args.path, fmt)?;
    println!("Ingested {} findings from {}", findings.len(), args.path);

    let formats: Vec<OutputFormat> = if args.output_formats.is_empty() {
        vec![OutputFormat::Console]
    } else {
        args.output_formats.iter().map(arg_to_format).collect()
    };
    write_findings_multi(&findings, &formats, args.output_filename.as_deref(), None)
}

fn all_known_checks() -> Vec<models::CheckMetadata> {
    let mut metas: Vec<models::CheckMetadata> = vec![];
    // AWS — pull from each check's metadata()
    for c in all_iam_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_s3_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_ec2_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_cloudtrail_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_kms_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_awsconfig_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_vpc_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_rds_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_lambda_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_guardduty_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_securityhub_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_secretsmanager_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_elbv2_checks() {
        metas.push(c.metadata().clone());
    }
    // Azure
    for c in all_azure_storage_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_azure_keyvault_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_azure_compute_checks() {
        metas.push(c.metadata().clone());
    }
    // GCP
    for c in all_gcp_iam_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_gcp_storage_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_gcp_compute_checks() {
        metas.push(c.metadata().clone());
    }
    // Kubernetes
    for c in all_k8s_rbac_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_k8s_workload_checks() {
        metas.push(c.metadata().clone());
    }
    for c in all_k8s_network_checks() {
        metas.push(c.metadata().clone());
    }
    // Stubs
    metas.extend(providers::m365::sample_checks());
    metas.extend(providers::github::sample_checks());
    metas.extend(providers::oci::sample_checks());
    metas.extend(providers::alibaba::sample_checks());
    metas.extend(providers::cloudflare::sample_checks());
    metas.extend(providers::iac::sample_checks());
    metas.extend(providers::container_image::sample_checks());
    metas
}

fn list_checks(args: cli::ListChecksArgs, as_json: bool) {
    let metas = all_known_checks();
    let mut filtered = metas;
    if let Some(p) = args.provider.as_ref() {
        let needle = p.to_string();
        filtered.retain(|m| m.provider == needle);
    }
    if let Some(s) = args.service.as_ref() {
        filtered.retain(|m| &m.service == s);
    }
    if let Some(sev) = args.severity.as_ref() {
        let sev_rank = sev.rank();
        filtered.retain(|m| severity_rank(&m.severity) == sev_rank);
    }
    if let Some(comp) = args.compliance.as_ref() {
        filtered.retain(|m| m.compliance.iter().any(|c| &c.framework == comp));
    }
    if as_json {
        let json = serde_json::to_string_pretty(&filtered).unwrap_or_default();
        println!("{json}");
    } else {
        println!("Available checks ({} total):", filtered.len());
        for m in &filtered {
            println!(
                "  [{:14}][{:<13}] {} — {}",
                m.provider, m.service, m.id, m.severity
            );
        }
    }
}

fn list_services(args: cli::ListServicesArgs) {
    use std::collections::BTreeMap;
    let by_provider: BTreeMap<&str, Vec<&str>> = [
        ("aws", vec![
            "iam", "s3", "ec2", "cloudtrail", "kms", "config", "vpc", "rds",
            "lambda", "guardduty", "securityhub", "secretsmanager", "elbv2",
        ]),
        ("azure", vec!["storage", "keyvault", "compute"]),
        ("gcp", vec!["iam", "storage", "compute"]),
        ("kubernetes", vec!["rbac", "workloads", "network"]),
        ("m365", providers::m365::SERVICES.to_vec()),
        ("github", providers::github::SERVICES.to_vec()),
        ("oci", providers::oci::SERVICES.to_vec()),
        ("alibaba", providers::alibaba::SERVICES.to_vec()),
        ("cloudflare", providers::cloudflare::SERVICES.to_vec()),
        ("iac", providers::iac::FILE_TYPES.to_vec()),
        ("container-image", vec!["vulnerability", "secrets", "config", "malware"]),
    ]
    .into_iter()
    .collect();

    let needle = args.provider.as_ref().map(|p| p.to_string());
    for (prov, services) in &by_provider {
        if let Some(n) = needle.as_ref() {
            if n != prov {
                continue;
            }
        }
        println!("[{prov}]");
        for s in services {
            println!("  {s}");
        }
    }
}

fn list_compliance(args: cli::ListComplianceArgs) {
    let compliance_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("compliance");
    let mut entries: Vec<(String, String)> = vec![];
    if let Ok(rd) = std::fs::read_dir(&compliance_dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") {
                continue;
            }
            let content = std::fs::read_to_string(entry.path()).unwrap_or_default();
            let provider = serde_json::from_str::<serde_json::Value>(&content)
                .ok()
                .and_then(|v| v.get("Provider").cloned())
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "unknown".to_string());
            entries.push((name, provider));
        }
    }
    entries.sort();
    let needle = args.provider.as_ref().map(|p| p.to_string());
    println!("Available compliance frameworks ({} bundled):", entries.len());
    for (name, prov) in &entries {
        if let Some(n) = needle.as_ref() {
            if n != prov {
                continue;
            }
        }
        println!("  [{prov:<14}] {name}");
    }
}

fn list_compliance_requirements(args: cli::ListComplianceRequirementsArgs) -> anyhow::Result<()> {
    let compliance_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("compliance");
    let name = if args.framework.ends_with(".json") {
        args.framework.clone()
    } else {
        format!("{}.json", args.framework)
    };
    let path = compliance_dir.join(&name);
    if !path.exists() {
        anyhow::bail!("Compliance framework not found: {name}. Try `list-compliance`.");
    }
    let content = std::fs::read_to_string(&path)?;
    let v: serde_json::Value = serde_json::from_str(&content)?;
    let framework = v["Framework"].as_str().unwrap_or("?");
    let version = v["Version"].as_str().unwrap_or("?");
    let provider = v["Provider"].as_str().unwrap_or("?");
    println!("Framework : {framework}");
    println!("Version   : {version}");
    println!("Provider  : {provider}");
    println!("Requirements:");
    if let Some(reqs) = v["Requirements"].as_array() {
        for r in reqs {
            let id = r["Id"].as_str().unwrap_or("?");
            let desc = r["Description"].as_str().unwrap_or("?");
            let checks = r["Checks"].as_array().cloned().unwrap_or_default();
            println!("  - {id}: {desc}");
            for c in checks {
                if let Some(s) = c.as_str() {
                    println!("      * {s}");
                }
            }
        }
    }
    Ok(())
}

fn list_categories() {
    let cats = [
        "encryption",
        "logging",
        "trust-boundaries",
        "internet-exposure",
        "iam-least-privilege",
        "secrets-management",
        "backups-and-dr",
        "threat-detection",
        "rbac",
        "supply-chain",
    ];
    println!("Available categories ({}):", cats.len());
    for c in cats {
        println!("  {c}");
    }
}

fn list_fixer() {
    // Upstream prowler `--list-fixer` enumerates checks that have remediation
    // code (the `--fix` subset). lancer-prowler is read-only, so the list is
    // surfaced as informational and the actions are refused at runtime.
    let fixable_ids = [
        "iam_password_policy_minimum_length_14",
        "iam_password_policy_uppercase",
        "iam_password_policy_lowercase",
        "iam_password_policy_symbol",
        "iam_password_policy_number",
        "iam_password_policy_reuse_24",
        "iam_password_policy_expires_passwords_within_90_days_or_less",
        "iam_no_root_access_key",
        "iam_avoid_root_usage",
        "s3_bucket_default_encryption",
        "s3_bucket_secure_transport_policy",
        "ec2_ebs_default_encryption",
        "rds_instance_storage_encrypted",
        "kms_cmk_rotation_enabled",
        "cloudtrail_multi_region_enabled",
        "cloudtrail_log_file_validation_enabled",
        "guardduty_is_enabled",
        "securityhub_enabled",
    ];
    println!(
        "Fixable upstream checks ({}) — lancer-prowler is read-only so --fix is REFUSED at runtime, but parity requires this list:",
        fixable_ids.len()
    );
    for id in fixable_ids {
        println!("  {id}");
    }
}

/// Build the complete list of CloudTrail check instances.
fn all_cloudtrail_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(CloudtrailMultiRegionEnabled),
        Box::new(CloudtrailLogsS3BucketIsNotPubliclyAccessible),
        Box::new(CloudtrailLogFileValidationEnabled),
        Box::new(CloudtrailKmsEncryptionEnabled),
        Box::new(CloudtrailS3DataeventsReadEnabled),
        Box::new(CloudtrailS3DataeventsWriteEnabled),
        Box::new(CloudtrailCloudwatchLoggingEnabled),
        Box::new(CloudtrailThreatDetectionPrivilegeEscalation),
        Box::new(CloudtrailThreatDetectionEnumeration),
    ]
}

/// Build the complete list of KMS check instances.
fn all_kms_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(KmsCmkRotationEnabled),
        Box::new(KmsCmkNotPendingDeletion),
        Box::new(KmsKeyNotDisabled),
    ]
}

/// Build the complete list of AWS Config check instances.
fn all_awsconfig_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(ConfigRecorderAllRegionsEnabled),
        Box::new(ConfigRecorderUsingAllSupportedResourceTypes),
        Box::new(ConfigDeliveryChannelExists),
    ]
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

/// Build the complete list of VPC check instances.
fn all_vpc_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(VpcFlowLogsEnabled),
        Box::new(VpcSubnetNoPublicIpByDefault),
        Box::new(VpcDifferentRegions),
        Box::new(VpcEndpointConnectionsTrustBoundaries),
        Box::new(VpcPeeringRoutingTablesWithLeastPrivilege),
    ]
}

/// Build the complete list of RDS check instances.
fn all_rds_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(RdsInstanceEncrypted),
        Box::new(RdsInstancePublicAccess),
        Box::new(RdsInstanceDefaultAdmin),
        Box::new(RdsInstanceBackupEnabled),
        Box::new(RdsInstanceMultiAz),
        Box::new(RdsInstanceMinorVersionUpgradeEnabled),
        Box::new(RdsInstanceStorageEncrypted),
        Box::new(RdsSnapshotsPublicAccess),
        Box::new(RdsSnapshotsEncrypted),
    ]
}

/// Build the complete list of Lambda check instances.
fn all_lambda_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(LambdaFunctionUrlPublic),
        Box::new(LambdaFunctionNotPubliclyAccessible),
        Box::new(LambdaFunctionEnvironmentVariablesEncrypted),
        Box::new(LambdaFunctionInVpc),
    ]
}

/// Build the complete list of GuardDuty check instances.
fn all_guardduty_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(GuardDutyIsEnabled),
        Box::new(GuardDutyFindingPublishingFrequencySixHoursOrLess),
    ]
}

/// Build the complete list of Security Hub check instances.
fn all_securityhub_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(SecurityHubEnabled),
        Box::new(SecurityHubAutoEnableControls),
    ]
}

/// Build the complete list of Secrets Manager check instances.
fn all_secretsmanager_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(SecretsManagerSecretRotationEnabled),
        Box::new(SecretsManagerSecretEncryptedWithCmk),
        Box::new(SecretsManagerSecretUnused45Days),
    ]
}

/// Build the complete list of Azure Storage check instances.
fn all_azure_storage_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(StorageAccountSecureTransferRequired),
        Box::new(StorageAccountMinimumTlsVersion12),
        Box::new(StorageAccountPublicAccessLevelIsPrivate),
        Box::new(StorageAccountDefaultNetworkAccessRuleDeny),
        Box::new(StorageAccountCustomerManagedKey),
        Box::new(StorageAccountInfrastructureEncryptionEnabled),
        Box::new(StorageAccountBlobSoftDeleteEnabled),
        Box::new(StorageAccountContainerSoftDeleteEnabled),
        Box::new(StorageAccountVersioningEnabled),
        Box::new(StorageAccountSharedKeyAccessDisabled),
    ]
}

/// Build the complete list of Azure KeyVault check instances.
fn all_azure_keyvault_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(KeyVaultSoftDeleteEnabled),
        Box::new(KeyVaultPurgeProtectionEnabled),
        Box::new(KeyVaultPublicNetworkAccessDisabled),
        Box::new(KeyVaultRbacAuthorizationEnabled),
        Box::new(KeyVaultDefaultNetworkAccessRuleDeny),
        Box::new(KeyVaultPremiumSku),
        Box::new(KeyVaultRecoverable),
        Box::new(KeyVaultLoggingEnabled),
        Box::new(KeyVaultPrivateEndpoint),
        Box::new(KeyVaultKeyExpirationSet),
    ]
}

/// Build the complete list of Azure Compute check instances.
fn all_azure_compute_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(ComputeVmOsDiskEncryptionEnabled),
        Box::new(ComputeVmDataDisksEncrypted),
        Box::new(ComputeVmManagedIdentityEnabled),
        Box::new(ComputeVmBootDiagnosticsEnabled),
        Box::new(ComputeVmOsAutomaticPatching),
        Box::new(ComputeVmAvailabilityZoneEnabled),
        Box::new(ComputeVmDisasterRecovery),
        Box::new(ComputeVmEndpointProtection),
        Box::new(ComputeVmNetworkSecurityGroup),
        Box::new(ComputeVmPublicIpAddress),
    ]
}

/// Build the complete list of GCP IAM check instances.
fn all_gcp_iam_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(IamNoServiceAccountWithAdminPrivileges),
        Box::new(IamServiceAccountKeyNotUserManaged),
        Box::new(IamAvoidPrimitiveRoles),
        Box::new(IamProjectHasOwner),
        Box::new(IamNoPublicAccess),
        Box::new(IamSaNoAdminPrivileges),
        Box::new(IamServiceAccountKeyRotation90Days),
        Box::new(IamWorkloadIdentityFederationEnabled),
    ]
}

/// Build the complete list of GCP Storage check instances.
fn all_gcp_storage_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(StorageBucketUniformBucketLevelAccess),
        Box::new(StorageBucketPublicAccessPrevention),
        Box::new(StorageBucketVersioningEnabled),
        Box::new(StorageBucketLoggingEnabled),
        Box::new(StorageBucketKmsEncryption),
        Box::new(StorageBucketRetentionPolicy),
        Box::new(StorageBucketNotPubliclyAccessible),
        Box::new(StorageBucketLabelEnvironment),
    ]
}

/// Build the complete list of GCP Compute check instances.
fn all_gcp_compute_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(ComputeInstanceIpForwardingDisabled),
        Box::new(ComputeInstanceSerialPortDisabled),
        Box::new(ComputeInstanceOsloginEnabled),
        Box::new(ComputeInstanceShieldedVmEnabled),
        Box::new(ComputeInstanceNoPublicIp),
        Box::new(ComputeInstanceDefaultServiceAccount),
        Box::new(ComputeInstanceDefaultServiceAccountFullAccess),
        Box::new(ComputeFirewallRuleNoIngress0000022),
        Box::new(ComputeFirewallRuleNoIngress000003389),
    ]
}

/// Build the complete list of ELBv2 check instances.
fn all_elbv2_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(Elbv2InternetFacing),
        Box::new(Elbv2AccessLogsEnabled),
        Box::new(Elbv2DeletionProtectionEnabled),
        Box::new(Elbv2InsecureListenerProtocols),
        Box::new(Elbv2ListenerUsesSecureSslPolicy),
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

/// Build the complete list of Kubernetes RBAC check instances.
fn all_k8s_rbac_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(RbacClusterAdminBindings),
        Box::new(RbacWildcardVerbs),
        Box::new(RbacBindClusterAdminRole),
        Box::new(RbacNoAnonymousAccess),
        Box::new(RbacServiceAccountLeastPrivilege),
        Box::new(RbacNoClusterAdminDefault),
    ]
}

/// Build the complete list of Kubernetes Workloads check instances.
fn all_k8s_workload_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(WorkloadsNoPrivilegedContainers),
        Box::new(WorkloadsNoPrivilegeEscalation),
        Box::new(WorkloadsRunAsNonRoot),
        Box::new(WorkloadsReadOnlyRootFilesystem),
        Box::new(WorkloadsNoHostNetwork),
        Box::new(WorkloadsNoHostPidNamespace),
        Box::new(WorkloadsResourceLimitsSet),
        Box::new(WorkloadsNoRootCapabilities),
        Box::new(WorkloadsAutomountServiceAccountToken),
    ]
}

/// Build the complete list of Kubernetes Network check instances.
fn all_k8s_network_checks() -> Vec<Box<dyn check::Check>> {
    vec![
        Box::new(NetworkNamespaceHasNetworkPolicy),
        Box::new(NetworkDefaultDenyPolicy),
        Box::new(NetworkNoExposedDashboard),
        Box::new(NetworkPodsIngressTrafficRestricted),
        Box::new(NetworkPodsEgressTrafficRestricted),
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

    // ── CloudTrail ────────────────────────────────────────────────────────────
    println!("  [scan] Fetching CloudTrail state…");
    let cloudtrail_service = match CloudtrailService::new(
        &provider.config,
        provider.account_id.clone(),
        provider.regions(),
    )
    .await
    {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching CloudTrail state: {:#}", e);
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (no CloudTrail/KMS/Config) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] CloudTrail state fetched — {} trail(s)",
        cloudtrail_service.trails.len(),
    );

    let cloudtrail_checks = all_cloudtrail_checks();
    println!("  [scan] Running {} CloudTrail checks…", cloudtrail_checks.len());
    for c in &cloudtrail_checks {
        findings.extend(c.execute(&cloudtrail_service));
    }

    // ── KMS ───────────────────────────────────────────────────────────────────
    println!("  [scan] Fetching KMS state…");
    let kms_service = match KmsService::new(
        &provider.config,
        provider.account_id.clone(),
        provider.regions(),
    )
    .await
    {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching KMS state: {:#}", e);
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (no KMS/Config) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] KMS state fetched — {} key(s)",
        kms_service.keys.len(),
    );

    let kms_checks = all_kms_checks();
    println!("  [scan] Running {} KMS checks…", kms_checks.len());
    for c in &kms_checks {
        findings.extend(c.execute(&kms_service));
    }

    // ── AWS Config ────────────────────────────────────────────────────────────
    println!("  [scan] Fetching AWS Config state…");
    let awsconfig_service = match AwsConfigService::new(
        &provider.config,
        provider.account_id.clone(),
        provider.regions(),
    )
    .await
    {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching AWS Config state: {:#}", e);
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (no Config) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] AWS Config state fetched — {} recorder(s)",
        awsconfig_service.recorders.len(),
    );

    let awsconfig_checks = all_awsconfig_checks();
    println!("  [scan] Running {} AWS Config checks…", awsconfig_checks.len());
    for c in &awsconfig_checks {
        findings.extend(c.execute(&awsconfig_service));
    }

    // ── VPC ───────────────────────────────────────────────────────────────────
    println!("  [scan] Fetching VPC state…");
    let vpc_service = match VpcService::new(
        &provider.config,
        provider.account_id.clone(),
        provider.regions(),
    )
    .await
    {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching VPC state: {:#}", e);
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (no VPC/RDS/Lambda) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] VPC state fetched — {} VPC(s), {} subnet(s), {} peering connection(s) (stub mode)",
        vpc_service.vpcs.len(),
        vpc_service.subnets.len(),
        vpc_service.peering_connections.len(),
    );

    let vpc_checks = all_vpc_checks();
    println!("  [scan] Running {} VPC checks…", vpc_checks.len());
    for c in &vpc_checks {
        findings.extend(c.execute(&vpc_service));
    }

    // ── RDS ───────────────────────────────────────────────────────────────────
    println!("  [scan] Fetching RDS state…");
    let rds_service = match RdsService::new(
        &provider.config,
        provider.account_id.clone(),
        provider.regions(),
    )
    .await
    {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching RDS state: {:#}", e);
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (no RDS/Lambda) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] RDS state fetched — {} instance(s), {} snapshot(s)",
        rds_service.instances.len(),
        rds_service.snapshots.len(),
    );

    let rds_checks = all_rds_checks();
    println!("  [scan] Running {} RDS checks…", rds_checks.len());
    for c in &rds_checks {
        findings.extend(c.execute(&rds_service));
    }

    // ── Lambda ────────────────────────────────────────────────────────────────
    println!("  [scan] Fetching Lambda state…");
    let lambda_service = match LambdaService::new(
        &provider.config,
        provider.account_id.clone(),
        provider.regions(),
    )
    .await
    {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching Lambda state: {:#}", e);
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (no Lambda) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] Lambda state fetched — {} function(s)",
        lambda_service.functions.len(),
    );

    let lambda_checks = all_lambda_checks();
    println!("  [scan] Running {} Lambda checks…", lambda_checks.len());
    for c in &lambda_checks {
        findings.extend(c.execute(&lambda_service));
    }

    // ── GuardDuty ─────────────────────────────────────────────────────────────
    println!("  [scan] Fetching GuardDuty state…");
    let guardduty_service = match GuardDutyService::new(
        &provider.config,
        provider.account_id.clone(),
        provider.regions(),
    )
    .await
    {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching GuardDuty state: {:#}", e);
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (no GuardDuty/SecHub/Secrets/ELBv2) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] GuardDuty state fetched — {} detector(s)",
        guardduty_service.detectors.len(),
    );

    let guardduty_checks = all_guardduty_checks();
    println!("  [scan] Running {} GuardDuty checks…", guardduty_checks.len());
    for c in &guardduty_checks {
        findings.extend(c.execute(&guardduty_service));
    }

    // ── Security Hub ──────────────────────────────────────────────────────────
    println!("  [scan] Fetching Security Hub state…");
    let securityhub_service = match SecurityHubService::new(
        &provider.config,
        provider.account_id.clone(),
        provider.regions(),
    )
    .await
    {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching Security Hub state: {:#}", e);
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (no SecHub/Secrets/ELBv2) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] Security Hub state fetched — {} hub(s)",
        securityhub_service.hubs.len(),
    );

    let securityhub_checks = all_securityhub_checks();
    println!("  [scan] Running {} Security Hub checks…", securityhub_checks.len());
    for c in &securityhub_checks {
        findings.extend(c.execute(&securityhub_service));
    }

    // ── Secrets Manager ───────────────────────────────────────────────────────
    println!("  [scan] Fetching Secrets Manager state…");
    let secretsmanager_service = match SecretsManagerService::new(
        &provider.config,
        provider.account_id.clone(),
        provider.regions(),
    )
    .await
    {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching Secrets Manager state: {:#}", e);
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (no Secrets/ELBv2) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] Secrets Manager state fetched — {} secret(s)",
        secretsmanager_service.secrets.len(),
    );

    let secretsmanager_checks = all_secretsmanager_checks();
    println!("  [scan] Running {} Secrets Manager checks…", secretsmanager_checks.len());
    for c in &secretsmanager_checks {
        findings.extend(c.execute(&secretsmanager_service));
    }

    // ── ELBv2 ─────────────────────────────────────────────────────────────────
    println!("  [scan] Fetching ELBv2 state…");
    let elbv2_service = match Elbv2Service::new(
        &provider.config,
        provider.account_id.clone(),
        provider.regions(),
    )
    .await
    {
        Ok(svc) => svc,
        Err(e) => {
            eprintln!("  [scan] ERROR fetching ELBv2 state: {:#}", e);
            let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
            let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
            println!(
                "  [scan] Complete (no ELBv2) — {} findings ({} PASS, {} FAIL)",
                findings.len(), pass, fail
            );
            return findings;
        }
    };
    println!(
        "  [scan] ELBv2 state fetched — {} load balancer(s)",
        elbv2_service.load_balancers.len(),
    );

    let elbv2_checks = all_elbv2_checks();
    println!("  [scan] Running {} ELBv2 checks…", elbv2_checks.len());
    for c in &elbv2_checks {
        findings.extend(c.execute(&elbv2_service));
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
