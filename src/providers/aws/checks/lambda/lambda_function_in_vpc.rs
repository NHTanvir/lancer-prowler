use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::lambda::make_report;
use crate::providers::aws::services::lambda::LambdaService;

pub struct LambdaFunctionInVpc;

impl Check for LambdaFunctionInVpc {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "lambda_function_in_vpc".to_string(),
            name: "Ensure Lambda functions are deployed inside a VPC".to_string(),
            description: "Lambda functions not attached to a VPC run in a shared AWS-managed \
                network. Placing functions in a VPC enforces network segmentation and allows \
                fine-grained security group controls."
                .to_string(),
            severity: Severity::Low,
            service: "lambda".to_string(),
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
        let svc = match context.downcast_ref::<LambdaService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();

        for function in &svc.functions {
            let (status, msg) = if function.vpc_config.is_some() {
                (
                    Status::Pass,
                    format!(
                        "Lambda function {} is deployed inside a VPC",
                        function.function_name
                    ),
                )
            } else {
                (
                    Status::Fail,
                    format!(
                        "Lambda function {} is not deployed inside a VPC",
                        function.function_name
                    ),
                )
            };

            reports.push(make_report(
                "lambda_function_in_vpc",
                "Ensure Lambda functions are deployed inside a VPC",
                Severity::Low,
                status,
                &function.function_name,
                &function.arn,
                &function.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
