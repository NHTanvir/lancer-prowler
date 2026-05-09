use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::rds::make_report;
use crate::providers::aws::services::rds::RdsService;

/// Explicit storage-encryption check (kept for parity with Prowler's check list).
/// Functionally identical to rds_instance_encrypted but uses a separate check ID
/// so it appears as a distinct finding in output.
pub struct RdsInstanceStorageEncrypted;

impl Check for RdsInstanceStorageEncrypted {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rds_instance_storage_encrypted".to_string(),
            name: "Ensure RDS DB instance storage is encrypted".to_string(),
            description: "RDS storage encryption protects data at rest. \
                This check explicitly verifies the StorageEncrypted flag for each instance."
                .to_string(),
            severity: Severity::High,
            service: "rds".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-28".to_string(),
                },
                ComplianceRef {
                    framework: "PCI_DSS_3.2.1".to_string(),
                    control_id: "3.4".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<RdsService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for instance in &svc.instances {
            let (status, msg) = if instance.storage_encrypted {
                (
                    Status::Pass,
                    format!(
                        "RDS instance {} storage is encrypted",
                        instance.db_instance_id
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "RDS instance {} storage is not encrypted",
                        instance.db_instance_id
                    ),
                )
            };

            reports.push(make_report(
                "rds_instance_storage_encrypted",
                "Ensure RDS DB instance storage is encrypted",
                Severity::High,
                status,
                &instance.db_instance_id,
                &instance.arn,
                &instance.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
