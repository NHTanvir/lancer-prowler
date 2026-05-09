use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::kms::make_report;
use crate::providers::aws::services::kms::KmsService;

pub struct KmsCmkRotationEnabled;

impl Check for KmsCmkRotationEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "kms_cmk_rotation_enabled".to_string(),
            name: "Ensure KMS customer-managed keys have automatic rotation enabled".to_string(),
            description: "Rotating encryption keys reduces the risk of key compromise. \
                KMS customer-managed keys should have annual automatic rotation enabled."
                .to_string(),
            severity: Severity::Medium,
            service: "kms".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.8".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-12".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<KmsService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for key in &svc.keys {
            // Only check CUSTOMER-managed keys that are currently Enabled
            if key.key_manager != "CUSTOMER" || !key.enabled {
                continue;
            }

            let (status, msg) = if key.key_rotation_enabled {
                (
                    Status::Pass,
                    format!("KMS CMK {} has automatic key rotation enabled", key.key_id),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "KMS CMK {} does not have automatic key rotation enabled",
                        key.key_id
                    ),
                )
            };

            reports.push(make_report(
                "kms_cmk_rotation_enabled",
                "Ensure KMS customer-managed keys have automatic rotation enabled",
                Severity::Medium,
                status,
                &key.key_id,
                &key.arn,
                &key.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
