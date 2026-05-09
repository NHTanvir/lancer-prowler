use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::rds::make_report;
use crate::providers::aws::services::rds::RdsService;

/// Well-known default admin usernames that should be avoided.
const DEFAULT_USERNAMES: &[&str] = &[
    "admin",
    "root",
    "postgres",
    "sa",
    "administrator",
    "mysql",
    "oracle",
    "user",
];

pub struct RdsInstanceDefaultAdmin;

impl Check for RdsInstanceDefaultAdmin {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rds_instance_default_admin".to_string(),
            name: "Ensure RDS instances do not use default master usernames".to_string(),
            description: "Default admin usernames are well-known and increase the risk of \
                brute-force or credential-stuffing attacks. Use a custom master username."
                .to_string(),
            severity: Severity::Medium,
            service: "rds".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.3.3".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "IA-5".to_string(),
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
            let username_lower = instance.master_username.to_lowercase();
            let is_default = DEFAULT_USERNAMES.contains(&username_lower.as_str());

            let (status, msg) = if is_default {
                (
                    Status::Fail,
                    format!(
                        "RDS instance {} uses a default master username '{}'",
                        instance.db_instance_id, instance.master_username
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "RDS instance {} uses a non-default master username",
                        instance.db_instance_id
                    ),
                )
            };

            reports.push(make_report(
                "rds_instance_default_admin",
                "Ensure RDS instances do not use default master usernames",
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
