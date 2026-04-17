use crate::check::Check;
use crate::models::{CheckMetadata, CheckReport, ComplianceRef, Severity, Status};
use crate::providers::aws::checks::iam::make_report;
use crate::providers::aws::services::iam::IamService;

const READONLY_POLICY_ARN: &str = "arn:aws:iam::aws:policy/ReadOnlyAccess";

pub struct IamRoleCrossAccountReadonlyAccessPolicy;

impl Check for IamRoleCrossAccountReadonlyAccessPolicy {
    fn metadata(&self) -> &CheckMetadata {
        static META: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        META.get_or_init(|| CheckMetadata {
            id: "iam_role_cross_account_readonlyaccess_policy".to_string(),
            name: "Ensure IAM roles with cross-account trust do not have ReadOnlyAccess".to_string(),
            description: "IAM roles with cross-account trust policies that also have ReadOnlyAccess \
                attached allow external accounts to read all resources. This should be reviewed \
                carefully to ensure it is intentional."
                .to_string(),
            severity: Severity::Medium,
            service: "iam".to_string(),
            provider: "aws".to_string(),
            compliance: vec![
                ComplianceRef {
                    framework: "CIS_3.0".to_string(),
                    control_id: "1.20".to_string(),
                },
            ],
        })
    }

    fn execute(&self, context: &dyn std::any::Any) -> Vec<CheckReport> {
        let iam = match context.downcast_ref::<IamService>() {
            Some(s) => s,
            None => return vec![],
        };

        let account_id = &iam.account_id;
        let mut reports = Vec::new();

        for role in &iam.roles {
            let has_readonly = role
                .attached_policies
                .iter()
                .any(|p| p == READONLY_POLICY_ARN);

            if !has_readonly {
                continue;
            }

            // Check if trust policy allows a cross-account principal
            // A cross-account trust contains an AWS account ID (12-digit) that is not ours
            let has_cross_account = is_cross_account_trust(&role.assume_role_policy, account_id);

            let (status, msg) = if has_cross_account {
                (
                    Status::Fail,
                    format!(
                        "Role {} has cross-account trust policy AND ReadOnlyAccess attached — \
                        verify this external access is intentional",
                        role.role_name
                    ),
                )
            } else {
                (
                    Status::Pass,
                    format!(
                        "Role {} has ReadOnlyAccess but no cross-account trust",
                        role.role_name
                    ),
                )
            };

            reports.push(make_report(
                "iam_role_cross_account_readonlyaccess_policy",
                "Ensure IAM roles with cross-account trust do not have ReadOnlyAccess",
                Severity::Medium,
                status,
                &role.role_name,
                &role.arn,
                "us-east-1",
                account_id,
                &msg,
                self.metadata().compliance.clone(),
            ));
        }

        reports
    }
}

/// Heuristic: check if the assume_role_policy document references an AWS account
/// principal that is different from our own account_id.
fn is_cross_account_trust(policy_doc: &str, own_account_id: &str) -> bool {
    if policy_doc.is_empty() {
        return false;
    }
    let v: serde_json::Value = match serde_json::from_str(policy_doc) {
        Ok(v) => v,
        Err(_) => {
            // Fall back to string heuristic on URL-encoded or malformed JSON
            return policy_doc.contains("arn:aws:iam::")
                && !policy_doc.contains(&format!("arn:aws:iam::{}:", own_account_id));
        }
    };
    let statements = match v.get("Statement").and_then(|s| s.as_array()) {
        Some(arr) => arr,
        None => return false,
    };
    for stmt in statements {
        let principal = match stmt.get("Principal") {
            Some(p) => p,
            None => continue,
        };
        let principal_strs = collect_principal_strings(principal);
        for ps in &principal_strs {
            // AWS account ARN pattern: arn:aws:iam::<account-id>:root or :role/...
            if ps.starts_with("arn:aws:iam::") && !ps.contains(&format!(":{}:", own_account_id)) {
                return true;
            }
            // Bare account ID (12 digits)
            if ps.len() == 12 && ps.chars().all(|c| c.is_ascii_digit()) && ps != own_account_id {
                return true;
            }
        }
    }
    false
}

fn collect_principal_strings(principal: &serde_json::Value) -> Vec<String> {
    match principal {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        serde_json::Value::Object(map) => {
            let mut out = Vec::new();
            for (_, val) in map {
                match val {
                    serde_json::Value::String(s) => out.push(s.clone()),
                    serde_json::Value::Array(arr) => {
                        for v in arr {
                            if let Some(s) = v.as_str() {
                                out.push(s.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            out
        }
        _ => vec![],
    }
}
