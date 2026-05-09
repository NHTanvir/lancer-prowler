use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::rds::make_report;
use crate::providers::aws::services::rds::RdsService;

pub struct RdsSnapshotsPublicAccess;

impl Check for RdsSnapshotsPublicAccess {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rds_snapshots_public_access".to_string(),
            name: "Ensure RDS snapshots are not publicly accessible".to_string(),
            description: "Publicly shared RDS snapshots expose potentially sensitive data to \
                any AWS account. Snapshots should only be shared with specific, trusted accounts."
                .to_string(),
            severity: Severity::Critical,
            service: "rds".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.3.7".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-3".to_string(),
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
            let (status, msg) = if snapshot.is_public {
                (
                    Status::Fail,
                    format!(
                        "RDS snapshot {} is publicly accessible",
                        snapshot.snapshot_id
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "RDS snapshot {} is not publicly accessible",
                        snapshot.snapshot_id
                    ),
                )
            };

            reports.push(make_report(
                "rds_snapshots_public_access",
                "Ensure RDS snapshots are not publicly accessible",
                Severity::Critical,
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
