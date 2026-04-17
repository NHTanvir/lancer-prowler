use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::ec2::make_report;
use crate::providers::aws::services::ec2::Ec2Service;
use std::sync::OnceLock;

pub struct Ec2EbsPublicSnapshot;

impl Check for Ec2EbsPublicSnapshot {
    fn metadata(&self) -> &CheckMetadata {
        static META: OnceLock<CheckMetadata> = OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "ec2_ebs_public_snapshot".to_string(),
            name: "Ensure EBS snapshots are not publicly accessible".to_string(),
            description:
                "EBS snapshots should not be made public as they may contain sensitive data \
                 that could be accessed by any AWS account."
                    .to_string(),
            severity: Severity::Critical,
            service: "ec2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.2.2".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-3".to_string(),
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
                let (status, msg) = if snap.is_public {
                    (
                        Status::Fail,
                        format!(
                            "EBS snapshot {} is publicly accessible",
                            snap.snapshot_id
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!("EBS snapshot {} is not public", snap.snapshot_id),
                    )
                };

                make_report(
                    "ec2_ebs_public_snapshot",
                    "Ensure EBS snapshots are not publicly accessible",
                    Severity::Critical,
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
