use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2EbsSnapshotEncrypted;

impl Check for Ec2EbsSnapshotEncrypted {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_ebs_snapshot_encrypted".to_string(),
            name: "Ensure EBS snapshots are encrypted".to_string(),
            description:
                "EBS snapshots should be encrypted to prevent exposure of sensitive data \
                 if they are shared or accessed."
                    .to_string(),
            severity: Severity::Medium,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
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

        svc.ebs_snapshots
            .iter()
            .map(|snap| {
                let (status, msg) = if snap.encrypted {
                    (
                        Status::Pass,
                        format!("EBS snapshot {} is encrypted", snap.snapshot_id),
                    )
                } else {
                    (
                        Status::Fail,
                        format!("EBS snapshot {} is NOT encrypted", snap.snapshot_id),
                    )
                };

                make_report(
                    "ec2_ebs_snapshot_encrypted",
                    "Ensure EBS snapshots are encrypted",
                    Severity::Medium,
                    status,
                    &snap.snapshot_id,
                    &format!(
                        "arn:aws:ec2:{}:{}:snapshot/{}",
                        snap.region, svc.account_id, snap.snapshot_id
                    ),
                    &snap.region,
                    &svc.account_id,
                    &msg,
                    self.metadata().compliance.clone(),
                )
            })
            .collect()
    }
}
