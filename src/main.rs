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

                ProviderArg::Azure => {
                    println!("lancer-prowler scan — provider: azure");

                    let azure_provider = providers::azure::AzureProvider::new_stub(
                        std::env::var("AZURE_SUBSCRIPTION_ID")
                            .unwrap_or_else(|_| "unknown-subscription".to_string()),
                    );
                    let subscription_id = azure_provider.subscription_id.clone();

                    println!("  Subscription : {}", subscription_id);

                    let storage_svc =
                        AzureStorageService::new_stub(subscription_id.clone());
                    let keyvault_svc =
                        KeyVaultService::new_stub(subscription_id.clone());
                    let compute_svc =
                        AzureComputeService::new_stub(subscription_id.clone());

                    let mut findings: Vec<models::CheckReport> = vec![];

                    let storage_checks = all_azure_storage_checks();
                    println!("  [scan] Running {} Azure Storage checks…", storage_checks.len());
                    for check in &storage_checks {
                        findings.extend(check.execute(&storage_svc));
                    }

                    let keyvault_checks = all_azure_keyvault_checks();
                    println!("  [scan] Running {} Azure KeyVault checks…", keyvault_checks.len());
                    for check in &keyvault_checks {
                        findings.extend(check.execute(&keyvault_svc));
                    }

                    let compute_checks = all_azure_compute_checks();
                    println!("  [scan] Running {} Azure Compute checks…", compute_checks.len());
                    for check in &compute_checks {
                        findings.extend(check.execute(&compute_svc));
                    }

                    let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
                    let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
                    println!(
                        "  [scan] Complete — {} findings ({} PASS, {} FAIL)",
                        findings.len(), pass, fail
                    );

                    write_findings(&findings, format, args.output_path.as_deref())
                        .context("Failed to write findings")?;
                }

                ProviderArg::Gcp => {
                    println!("lancer-prowler scan — provider: gcp");

                    let project_id = std::env::var("GOOGLE_CLOUD_PROJECT")
                        .or_else(|_| std::env::var("GCP_PROJECT_ID"))
                        .unwrap_or_else(|_| "unknown-project".to_string());
                    let gcp_provider =
                        providers::gcp::GcpProvider::new_stub(project_id.clone());

                    println!("  Project : {}", gcp_provider.project_id);

                    let iam_svc = GcpIamService::new_stub(project_id.clone());
                    let storage_svc = GcpStorageService::new_stub(project_id.clone());
                    let compute_svc = GcpComputeService::new_stub(project_id.clone());

                    let mut findings: Vec<models::CheckReport> = vec![];

                    let gcp_iam_checks = all_gcp_iam_checks();
                    println!("  [scan] Running {} GCP IAM checks…", gcp_iam_checks.len());
                    for check in &gcp_iam_checks {
                        findings.extend(check.execute(&iam_svc));
                    }

                    let gcp_storage_checks = all_gcp_storage_checks();
                    println!("  [scan] Running {} GCP Storage checks…", gcp_storage_checks.len());
                    for check in &gcp_storage_checks {
                        findings.extend(check.execute(&storage_svc));
                    }

                    let gcp_compute_checks = all_gcp_compute_checks();
                    println!("  [scan] Running {} GCP Compute checks…", gcp_compute_checks.len());
                    for check in &gcp_compute_checks {
                        findings.extend(check.execute(&compute_svc));
                    }

                    let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
                    let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
                    println!(
                        "  [scan] Complete — {} findings ({} PASS, {} FAIL)",
                        findings.len(), pass, fail
                    );

                    write_findings(&findings, format, args.output_path.as_deref())
                        .context("Failed to write findings")?;
                }

                ProviderArg::Kubernetes => {
                    println!("lancer-prowler scan — provider: kubernetes");

                    let cluster_name = std::env::var("KUBE_CLUSTER_NAME")
                        .unwrap_or_else(|_| "default-cluster".to_string());

                    let _k8s_provider =
                        providers::kubernetes::KubernetesProvider::new_stub(cluster_name.clone());

                    println!("  Cluster : {}", cluster_name);

                    let rbac_svc = RbacService::new_stub(cluster_name.clone());
                    let workloads_svc = WorkloadsService::new_stub(cluster_name.clone());
                    let network_svc = NetworkService::new_stub(cluster_name.clone());

                    let mut findings: Vec<models::CheckReport> = vec![];

                    let k8s_rbac_checks = all_k8s_rbac_checks();
                    println!("  [scan] Running {} Kubernetes RBAC checks…", k8s_rbac_checks.len());
                    for check in &k8s_rbac_checks {
                        findings.extend(check.execute(&rbac_svc));
                    }

                    let k8s_workload_checks = all_k8s_workload_checks();
                    println!("  [scan] Running {} Kubernetes Workload checks…", k8s_workload_checks.len());
                    for check in &k8s_workload_checks {
                        findings.extend(check.execute(&workloads_svc));
                    }

                    let k8s_network_checks = all_k8s_network_checks();
                    println!("  [scan] Running {} Kubernetes Network checks…", k8s_network_checks.len());
                    for check in &k8s_network_checks {
                        findings.extend(check.execute(&network_svc));
                    }

                    let pass = findings.iter().filter(|r| r.status == models::Status::Pass).count();
                    let fail = findings.iter().filter(|r| r.status == models::Status::Fail).count();
                    println!(
                        "  [scan] Complete — {} findings ({} PASS, {} FAIL)",
                        findings.len(), pass, fail
                    );

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
                         only 'aws' and 'azure' are supported."
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
