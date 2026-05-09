use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::lambda::make_report;
use crate::providers::aws::services::lambda::LambdaService;

pub struct LambdaFunctionNotPubliclyAccessible;

impl Check for LambdaFunctionNotPubliclyAccessible {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "lambda_function_not_publicly_accessible".to_string(),
            name: "Ensure Lambda functions are not publicly accessible via resource policy"
                .to_string(),
            description: "A Lambda resource policy that grants Principal \"*\" allows any \
                AWS principal — including unauthenticated identities — to invoke the function."
                .to_string(),
            severity: Severity::Critical,
            service: "lambda".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.20".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-3".to_string(),
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
            let (status, msg) = if function.policy_allows_public {
                (
                    Status::Fail,
                    format!(
                        "Lambda function {} resource policy allows public access (Principal: \"*\")",
                        function.function_name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Lambda function {} resource policy does not allow public access",
                        function.function_name
                    ),
                )
            };

            reports.push(make_report(
                "lambda_function_not_publicly_accessible",
                "Ensure Lambda functions are not publicly accessible via resource policy",
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

        reports
    }
}
