use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::rds::make_report;
use crate::providers::aws::services::rds::RdsService;

pub struct RdsInstancePublicAccess;

impl Check for RdsInstancePublicAccess {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rds_instance_public_access".to_string(),
            name: "Ensure RDS instances are not publicly accessible".to_string(),
            description: "RDS instances with PubliclyAccessible set to true can be reached \
                directly from the internet, bypassing network controls."
                .to_string(),
            severity: Severity::Critical,
            service: "rds".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.3.2".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-7".to_string(),
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
            let (status, msg) = if instance.publicly_accessible {
                (
                    Status::Fail,
                    format!(
                        "RDS instance {} is publicly accessible",
                        instance.db_instance_id
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "RDS instance {} is not publicly accessible",
                        instance.db_instance_id
                    ),
                )
            };

            reports.push(make_report(
                "rds_instance_public_access",
                "Ensure RDS instances are not publicly accessible",
                Severity::Critical,
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
