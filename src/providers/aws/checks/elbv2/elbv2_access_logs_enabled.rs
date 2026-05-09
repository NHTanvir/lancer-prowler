use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::elbv2::make_report;
use crate::providers::aws::services::elbv2::Elbv2Service;

pub struct Elbv2AccessLogsEnabled;

impl Check for Elbv2AccessLogsEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "elbv2_access_logs_enabled".to_string(),
            name: "Ensure ELBv2 load balancers have access logs enabled".to_string(),
            description: "Access logs capture detailed information about requests sent to \
                your load balancer. Enabling access logs helps with security auditing, \
                troubleshooting, and compliance."
                .to_string(),
            severity: Severity::Medium,
            service: "elbv2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_1.4".to_string(),
                    control_id: "3.1".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AU-12".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<Elbv2Service>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for lb in &svc.load_balancers {
            let (status, msg) = if !lb.access_logs_enabled {
                (
                    Status::Fail,
                    format!("Load balancer {} does not have access logs enabled", lb.name),
                )
            } else {
                (
                    Status::Pass,
                    format!("Load balancer {} has access logs enabled", lb.name),
                )
            };

            reports.push(make_report(
                "elbv2_access_logs_enabled",
                "Ensure ELBv2 load balancers have access logs enabled",
                Severity::Medium,
                status,
                &lb.name,
                &lb.arn,
                &lb.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
