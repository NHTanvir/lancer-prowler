use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::elbv2::make_report;
use crate::providers::aws::services::elbv2::Elbv2Service;

pub struct Elbv2InternetFacing;

impl Check for Elbv2InternetFacing {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "elbv2_internet_facing".to_string(),
            name: "Identify internet-facing load balancers".to_string(),
            description: "Internet-facing load balancers are accessible from the public internet. \
                This check reports on their presence for awareness and review."
                .to_string(),
            severity: Severity::Medium,
            service: "elbv2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "SC-7".to_string(),
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
            let (status, msg) = if lb.scheme == "internet-facing" {
                (
                    Status::Fail,
                    format!(
                        "Load balancer {} is internet-facing and publicly accessible",
                        lb.name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Load balancer {} is internal (not internet-facing)",
                        lb.name
                    ),
                )
            };

            reports.push(make_report(
                "elbv2_internet_facing",
                "Identify internet-facing load balancers",
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
