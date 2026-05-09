use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::rds::make_report;
use crate::providers::aws::services::rds::RdsService;

pub struct RdsInstanceBackupEnabled;

impl Check for RdsInstanceBackupEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rds_instance_backup_enabled".to_string(),
            name: "Ensure RDS instances have automated backups enabled".to_string(),
            description: "A backup retention period greater than 0 enables automated daily \
                backups. Without backups, data recovery from accidental deletion or corruption \
                is impossible."
                .to_string(),
            severity: Severity::Medium,
            service: "rds".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.3.4".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "CP-9".to_string(),
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
            let (status, msg) = if instance.backup_retention_period == 0 {
                (
                    Status::Fail,
                    format!(
                        "RDS instance {} has automated backups disabled (retention period = 0)",
                        instance.db_instance_id
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "RDS instance {} has automated backups enabled (retention period = {} days)",
                        instance.db_instance_id, instance.backup_retention_period
                    ),
                )
            };

            reports.push(make_report(
                "rds_instance_backup_enabled",
                "Ensure RDS instances have automated backups enabled",
                Severity::Medium,
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
