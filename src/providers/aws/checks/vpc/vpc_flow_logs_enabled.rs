use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::vpc::make_report;
use crate::providers::aws::services::vpc::VpcService;

pub struct VpcFlowLogsEnabled;

impl Check for VpcFlowLogsEnabled {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "vpc_flow_logs_enabled".to_string(),
            name: "Ensure VPC flow logging is enabled in all VPCs".to_string(),
            description: "VPC Flow Logs capture network traffic information and help detect \
                anomalous traffic or potential security incidents."
                .to_string(),
            severity: Severity::Medium,
            service: "vpc".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "3.9".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AU-12".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<VpcService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for vpc in &svc.vpcs {
            let (status, msg) = if vpc.flow_logs_enabled {
                (
                    Status::Pass,
                    format!("VPC {} has flow logging enabled", vpc.vpc_id),
                )
            } else {
                (
                    Status::Fail,
                    format!("VPC {} does not have flow logging enabled", vpc.vpc_id),
                )
            };

            reports.push(make_report(
                "vpc_flow_logs_enabled",
                "Ensure VPC flow logging is enabled in all VPCs",
                Severity::Medium,
                status,
                &vpc.vpc_id,
                &format!("arn:aws:ec2:{}:{}:vpc/{}", vpc.region, account_id, vpc.vpc_id),
                &vpc.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
