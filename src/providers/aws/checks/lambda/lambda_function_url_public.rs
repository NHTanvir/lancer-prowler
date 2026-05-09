use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::lambda::make_report;
use crate::providers::aws::services::lambda::LambdaService;

pub struct LambdaFunctionUrlPublic;

impl Check for LambdaFunctionUrlPublic {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "lambda_function_url_public".to_string(),
            name: "Ensure Lambda function URLs require authentication".to_string(),
            description: "Lambda function URLs with auth_type NONE are publicly accessible \
                without any AWS IAM authentication, allowing anyone to invoke the function."
                .to_string(),
            severity: Severity::Critical,
            service: "lambda".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-3".to_string(),
                },
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.20".to_string(),
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
            if let Some(url_config) = &function.function_url_config {
                let (status, msg) = if url_config.auth_type == "NONE" {
                    (
                        Status::Fail,
                        format!(
                            "Lambda function {} has a public URL with no authentication (auth_type=NONE)",
                            function.function_name
                        ),
                    )
                } else {
                    (
                        Status::Pass,
                        format!(
                            "Lambda function {} URL requires {} authentication",
                            function.function_name, url_config.auth_type
                        ),
                    )
                };

                reports.push(make_report(
                    "lambda_function_url_public",
                    "Ensure Lambda function URLs require authentication",
                    Severity::Critical,
                    status,
                    &function.function_name,
                    &function.arn,
                    &function.region,
                    account_id,
                    &msg,
                    self.metadata().compliance.clone(),
                ));
            }
        }

        reports
    }
}
