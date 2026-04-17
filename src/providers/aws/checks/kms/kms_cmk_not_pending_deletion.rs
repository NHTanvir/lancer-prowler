use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::kms::make_report;
use crate::providers::aws::services::kms::KmsService;

pub struct KmsCmkNotPendingDeletion;

impl Check for KmsCmkNotPendingDeletion {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "kms_cmk_not_pending_deletion".to_string(),
            name: "Ensure KMS keys are not scheduled for deletion".to_string(),
            description: "KMS keys pending deletion cannot be used for encryption/decryption. \
                Accidental scheduling can lead to permanent data loss if dependent resources exist."
                .to_string(),
            severity: Severity::Medium,
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
            let (status, msg) = if key.key_state == "PendingDeletion" {
                let deletion_info = key
                    .deletion_date
                    .as_deref()
                    .unwrap_or("unknown date");
                (
                    Status::Fail,
                    format!(
                        "KMS key {} is pending deletion (scheduled for {})",
                        key.key_id, deletion_info
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!("KMS key {} is not pending deletion (state: {})", key.key_id, key.key_state),
                )
            };

            reports.push(make_report(
                "kms_cmk_not_pending_deletion",
                "Ensure KMS keys are not scheduled for deletion",
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
