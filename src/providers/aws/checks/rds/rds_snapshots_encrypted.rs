use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::rds::make_report;
use crate::providers::aws::services::rds::RdsService;

pub struct RdsSnapshotsEncrypted;

impl Check for RdsSnapshotsEncrypted {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rds_snapshots_encrypted".to_string(),
            name: "Ensure RDS snapshots are encrypted".to_string(),
            description: "Encrypting RDS snapshots ensures that backup data at rest is \
                protected from unauthorized access even if the snapshot is inadvertently shared."
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

        for snapshot in &svc.snapshots {
            let (status, msg) = if snapshot.encrypted {
                (
                    Status::Pass,
                    format!("RDS snapshot {} is encrypted", snapshot.snapshot_id),
                )
            } else {
                (
                    Status::Fail,
                    format!("RDS snapshot {} is not encrypted", snapshot.snapshot_id),
                )
            };

            reports.push(make_report(
                "rds_snapshots_encrypted",
                "Ensure RDS snapshots are encrypted",
                Severity::High,
                status,
                &snapshot.snapshot_id,
                &snapshot.arn,
                &snapshot.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
