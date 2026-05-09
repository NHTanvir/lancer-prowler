use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::kms::make_report;
use crate::providers::aws::services::kms::KmsService;

pub struct KmsKeyNotDisabled;

impl Check for KmsKeyNotDisabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "kms_key_not_disabled".to_string(),
            name: "Ensure KMS customer-managed keys are not disabled".to_string(),
            description: "Disabled KMS customer-managed keys prevent decryption of data \
                encrypted with those keys. Review disabled keys to ensure they are intentional."
                .to_string(),
            severity: Severity::Low,
            service: "kms".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
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
            // Only report on CUSTOMER-managed keys
            if key.key_manager != "CUSTOMER" {
                continue;
            }

            let (status, msg) = if key.key_state == "Disabled" {
                (
                    Status::Fail,
                    format!("KMS customer-managed key {} is disabled", key.key_id),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "KMS customer-managed key {} is not disabled (state: {})",
                        key.key_id, key.key_state
                    ),
                )
            };

            reports.push(make_report(
                "kms_key_not_disabled",
                "Ensure KMS customer-managed keys are not disabled",
                Severity::Low,
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
