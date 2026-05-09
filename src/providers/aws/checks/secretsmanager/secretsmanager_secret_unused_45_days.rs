use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::secretsmanager::make_report;
use crate::providers::aws::services::secretsmanager::SecretsManagerService;
use chrono::{DateTime, Utc};

pub struct SecretsManagerSecretUnused45Days;

impl Check for SecretsManagerSecretUnused45Days {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "secretsmanager_secret_unused_45_days".to_string(),
            name: "Ensure Secrets Manager secrets have been accessed within 45 days".to_string(),
            description: "Secrets that have not been accessed for more than 45 days may be \
                stale or orphaned. Unused secrets should be reviewed and potentially deleted \
                to reduce the attack surface."
                .to_string(),
            severity: Severity::Low,
            service: "secretsmanager".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "NIST_800_53_Rev5".to_string(),
                    control_id: "AC-2".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let svc = match context.downcast_ref::<SecretsManagerService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &svc.account_id;
        let mut reports = Vec::new();
        let now = Utc::now();

        for secret in &svc.secrets {
            // If last_accessed_date is None, treat as PASS (never accessed == unknown, not stale)
            let (status, msg) = match &secret.last_accessed_date {
                None => (
                    Status::Pass,
                    format!(
                        "Secret {} has no last accessed date recorded",
                        secret.name
                    ),
                ),
                Some(date_str) => {
                    // Parse the date string; AWS returns timestamps like "2024-01-15T00:00:00Z"
                    match date_str.parse::<DateTime<Utc>>() {
                        Ok(last_accessed) => {
                            let days_since = (now - last_accessed).num_days();
                            if days_since > 45 {
                                (
                                    Status::Fail,
                                    format!(
                                        "Secret {} has not been accessed in {} days (threshold: 45)",
                                        secret.name, days_since
                                    ),
                                )
                            } else {
                                (
                                    Status::Pass,
                                    format!(
                                        "Secret {} was last accessed {} day(s) ago",
                                        secret.name, days_since
                                    ),
                                )
                            }
                        }
                        Err(_) => (
                            Status::Pass,
                            format!(
                                "Secret {} last accessed date could not be parsed: {}",
                                secret.name, date_str
                            ),
                        ),
                    }
                }
            };

            reports.push(make_report(
                "secretsmanager_secret_unused_45_days",
                "Ensure Secrets Manager secrets have been accessed within 45 days",
                Severity::Low,
                status,
                &secret.name,
                &secret.arn,
                &secret.region,
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}
