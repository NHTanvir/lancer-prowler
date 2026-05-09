use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::lambda::make_report;
use crate::providers::aws::services::lambda::LambdaService;

pub struct LambdaFunctionEnvironmentVariablesEncrypted;

impl Check for LambdaFunctionEnvironmentVariablesEncrypted {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "lambda_function_environment_variables_encrypted".to_string(),
            name: "Ensure Lambda environment variables do not contain plaintext secrets"
                .to_string(),
            description: "Environment variable names containing words like SECRET, PASSWORD, \
                KEY, TOKEN, or CREDENTIAL suggest that sensitive values may be stored in \
                plaintext. Use AWS Secrets Manager or SSM Parameter Store instead."
                .to_string(),
            severity: Severity::Medium,
            service: "lambda".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.21".to_string(),
                },
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "IA-5".to_string(),
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
            let (status, msg) = if function.env_has_secrets {
                (
                    Status::Fail,
                    format!(
                        "Lambda function {} environment variables appear to contain secret-like \
                         names (e.g. SECRET, PASSWORD, KEY, TOKEN)",
                        function.function_name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Lambda function {} environment variables do not contain obvious secret names",
                        function.function_name
                    ),
                )
            };

            reports.push(make_report(
                "lambda_function_environment_variables_encrypted",
                "Ensure Lambda environment variables do not contain plaintext secrets",
                Severity::Medium,
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
