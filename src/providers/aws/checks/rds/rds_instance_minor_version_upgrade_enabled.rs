use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::rds::make_report;
use crate::providers::aws::services::rds::RdsService;

pub struct RdsInstanceMinorVersionUpgradeEnabled;

impl Check for RdsInstanceMinorVersionUpgradeEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rds_instance_minor_version_upgrade_enabled".to_string(),
            name: "Ensure RDS instances have auto minor version upgrade enabled".to_string(),
            description: "Enabling automatic minor version upgrades ensures that DB instances \
                receive security patches and bug fixes as soon as they become available."
                .to_string(),
            severity: Severity::Low,
            service: "rds".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.3.6".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SI-2".to_string(),
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
            let (status, msg) = if instance.auto_minor_version_upgrade {
                (
                    Status::Pass,
                    format!(
                        "RDS instance {} has auto minor version upgrade enabled",
                        instance.db_instance_id
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "RDS instance {} does not have auto minor version upgrade enabled",
                        instance.db_instance_id
                    ),
                )
            };

            reports.push(make_report(
                "rds_instance_minor_version_upgrade_enabled",
                "Ensure RDS instances have auto minor version upgrade enabled",
                Severity::Low,
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
