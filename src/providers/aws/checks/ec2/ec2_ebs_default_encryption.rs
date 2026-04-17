use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2EbsDefaultEncryption;

impl Check for Ec2EbsDefaultEncryption {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_ebs_default_encryption".to_string(),
            name: "Ensure EBS volume default encryption is enabled".to_string(),
            description:
                "AWS accounts should have EBS default encryption enabled so that all new \
                 volumes are encrypted at rest automatically."
                    .to_string(),
            severity: Severity::Medium,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.2.1".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-28".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<Ec2Service>() {
            Some(s) => s,
            None => return vec![],
        };

        // Account-level check — one finding per region scope
        let (status, msg) = if svc.ebs_default_encryption_enabled {
            (
                Status::Pass,
                "EBS default encryption is enabled for this account".to_string(),
            )
        } else {
            (
                Status::Fail,
                "EBS default encryption is NOT enabled for this account".to_string(),
            )
        };

        vec![make_report(
            "ec2_ebs_default_encryption",
            "Ensure EBS volume default encryption is enabled",
            Severity::Medium,
            status,
            &svc.account_id,
            &format!("arn:aws:ec2:::account/{}", svc.account_id),
            "global",
            &svc.account_id,
            &msg,
            self.metadata().compliance.clone(),
        )]
    }
}
