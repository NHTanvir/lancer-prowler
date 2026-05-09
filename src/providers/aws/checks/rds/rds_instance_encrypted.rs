use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::rds::make_report;
use crate::providers::aws::services::rds::RdsService;

pub struct RdsInstanceEncrypted;

impl Check for RdsInstanceEncrypted {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rds_instance_encrypted".to_string(),
            name: "Ensure RDS DB instances are encrypted at rest".to_string(),
            description: "RDS DB instances should have storage encryption enabled to protect \
                data at rest from unauthorized access."
                .to_string(),
            severity: Severity::High,
            service: "rds".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.3.1".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-28".to_string(),
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
                        "RDS instance {} has storage encryption enabled",
                        instance.db_instance_id
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "RDS instance {} does not have storage encryption enabled",
                        instance.db_instance_id
                    ),
                )
            };

            reports.push(make_report(
                "rds_instance_encrypted",
                "Ensure RDS DB instances are encrypted at rest",
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
