pub mod ec2_ami_public;
pub mod ec2_ebs_default_encryption;
pub mod ec2_ebs_public_snapshot;
pub mod ec2_ebs_snapshot_encrypted;
pub mod ec2_ebs_volume_encryption;
pub mod ec2_elastic_ip_unassigned;
pub mod ec2_instance_imdsv2_enabled;
pub mod ec2_instance_internet_facing_with_instance_profile;
pub mod ec2_instance_managed_by_ssm;
pub mod ec2_instance_paravirtual_type;
pub mod ec2_instance_public_ip;
pub mod ec2_instance_secrets_user_data;
pub mod ec2_securitygroup_allow_ingress_from_internet_to_any_port;
pub mod ec2_securitygroup_allow_ingress_from_internet_to_port_22;
pub mod ec2_securitygroup_allow_ingress_from_internet_to_port_3389;
pub mod ec2_securitygroup_allow_wide_open_public_ipv4;
pub mod ec2_securitygroup_default_restrict_traffic;
pub mod ec2_securitygroup_not_used;

use crate::models::{CheckReport, ComplianceRef, Severity, Status};
use chrono::Utc;

/// Build a CheckReport for an EC2 check.
#[allow(clippy::too_many_arguments)]
pub fn make_report(
    check_id: &str,
    check_name: &str,
    severity: Severity,
    status: Status,
    resource_id: &str,
    resource_arn: &str,
    region: &str,
    account_id: &str,
    status_extended: &str,
    compliance: Vec<ComplianceRef>,
) -> CheckReport {
    CheckReport {
        check_id: check_id.to_string(),
        check_name: check_name.to_string(),
        status,
        status_extended: status_extended.to_string(),
        severity,
        resource_id: resource_id.to_string(),
        resource_arn: resource_arn.to_string(),
        region: region.to_string(),
        provider: "aws".to_string(),
        service: "ec2".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}
