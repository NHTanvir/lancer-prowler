use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::rds::make_report;
use crate::providers::aws::services::rds::RdsService;

pub struct RdsInstanceMultiAz;

impl Check for RdsInstanceMultiAz {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "rds_instance_multi_az".to_string(),
            name: "Ensure RDS instances have Multi-AZ enabled".to_string(),
            description: "Multi-AZ deployments provide high availability and automatic failover \
                in the event of an Availability Zone outage or database maintenance."
                .to_string(),
            severity: Severity::Medium,
            service: "rds".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "2.3.5".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "CP-10".to_string(),
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
            let (status, msg) = if instance.multi_az {
                (
                    Status::Pass,
                    format!(
                        "RDS instance {} has Multi-AZ enabled",
                        instance.db_instance_id
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "RDS instance {} does not have Multi-AZ enabled",
                        instance.db_instance_id
                    ),
                )
            };

            reports.push(make_report(
                "rds_instance_multi_az",
                "Ensure RDS instances have Multi-AZ enabled",
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
