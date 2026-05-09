use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::elbv2::make_report;
use crate::providers::aws::services::elbv2::Elbv2Service;

pub struct Elbv2DeletionProtectionEnabled;

impl Check for Elbv2DeletionProtectionEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "elbv2_deletion_protection_enabled".to_string(),
            name: "Ensure ELBv2 load balancers have deletion protection enabled".to_string(),
            description: "Deletion protection prevents a load balancer from being accidentally \
                deleted. Enabling this feature protects against unintended disruption \
                of your application."
                .to_string(),
            severity: Severity::Low,
            service: "elbv2".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "CP-10".to_string(),
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
            let (status, msg) = if !lb.deletion_protection {
                (
                    Status::Fail,
                    format!(
                        "Load balancer {} does not have deletion protection enabled",
                        lb.name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Load balancer {} has deletion protection enabled",
                        lb.name
                    ),
                )
            };

            reports.push(make_report(
                "elbv2_deletion_protection_enabled",
                "Ensure ELBv2 load balancers have deletion protection enabled",
                Severity::Low,
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
