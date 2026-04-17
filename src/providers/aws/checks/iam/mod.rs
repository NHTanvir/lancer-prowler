pub mod iam_avoid_root_usage;
pub mod iam_aws_attached_policy_no_administrative_privileges;
pub mod iam_check_saml_providers_sts;
pub mod iam_customer_attached_policy_no_administrative_privileges;
pub mod iam_inline_policy_no_administrative_privileges;
pub mod iam_no_root_access_key;
pub mod iam_password_policy_expires_passwords_within_90_days_or_less;
pub mod iam_password_policy_lowercase;
pub mod iam_password_policy_minimum_length_14;
pub mod iam_password_policy_number;
pub mod iam_password_policy_reuse_24;
pub mod iam_password_policy_symbol;
pub mod iam_password_policy_uppercase;
pub mod iam_policy_allows_privilege_escalation;
pub mod iam_policy_attached_only_to_group_or_roles;
pub mod iam_policy_no_full_access_to_cloudtrail;
pub mod iam_policy_no_full_access_to_kms;
pub mod iam_role_cross_account_readonlyaccess_policy;
pub mod iam_root_hardware_mfa_enabled;
pub mod iam_root_mfa_enabled;
pub mod iam_rotate_access_key_90_days;
pub mod iam_support_role_created;
pub mod iam_user_mfa_enabled_console_access;
pub mod iam_user_no_setup_initial_access_key;
pub mod iam_user_two_active_access_key;

use crate::models::{CheckReport, ComplianceRef, Severity, Status};
use chrono::{DateTime, Utc};

/// Build a CheckReport with all fields populated and a UTC timestamp.
pub fn make_report(
    check_id: &str,
    check_name: &str,
    severity: Severity,
    status: Status,
    resource_id: &str,
    resource_arn: &str,
    region: &str,
    account_id: &str,
    status_extended: &str,
    compliance: Vec<ComplianceRef>,
) -> CheckReport {
    CheckReport {
        check_id: check_id.to_string(),
        check_name: check_name.to_string(),
        status,
        status_extended: status_extended.to_string(),
        severity,
        resource_id: resource_id.to_string(),
        resource_arn: resource_arn.to_string(),
        region: region.to_string(),
        provider: "aws".to_string(),
        service: "iam".to_string(),
        account_id: account_id.to_string(),
        compliance,
        timestamp: Utc::now().to_rfc3339(),
    }
}

/// Parse a date string and return true if the date is within the last `days` days.
/// Returns false (safe fallback) if parsing fails.
pub fn within_last_days(date_str: &str, days: i64) -> bool {
    if date_str.is_empty() || date_str == "N/A" || date_str == "no_information" {
        return false;
    }
    if let Ok(dt) = date_str.parse::<DateTime<Utc>>() {
        let now = Utc::now();
        let diff = now.signed_duration_since(dt);
        return diff.num_days() <= days;
    }
    // Try parsing just a date without time
    if let Ok(dt) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
        let naive_dt = dt.and_hms_opt(0, 0, 0).unwrap_or_default();
        let dt_utc = DateTime::<Utc>::from_naive_utc_and_offset(naive_dt, Utc);
        let now = Utc::now();
        let diff = now.signed_duration_since(dt_utc);
        return diff.num_days() <= days;
    }
    false
}

/// Parse a date string and return true if the date is older than `days` days ago.
/// Returns false (safe fallback) if parsing fails or value is N/A.
pub fn older_than_days(date_str: &str, days: i64) -> bool {
    if date_str.is_empty() || date_str == "N/A" || date_str == "no_information"
        || date_str == "not_supported"
    {
        return false;
    }
    if let Ok(dt) = date_str.parse::<DateTime<Utc>>() {
        let now = Utc::now();
        let diff = now.signed_duration_since(dt);
        return diff.num_days() > days;
    }
    if let Ok(dt) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
        let naive_dt = dt.and_hms_opt(0, 0, 0).unwrap_or_default();
        let dt_utc = DateTime::<Utc>::from_naive_utc_and_offset(naive_dt, Utc);
        let now = Utc::now();
        let diff = now.signed_duration_since(dt_utc);
        return diff.num_days() > days;
    }
    false
}

/// Check whether a policy document JSON contains a statement granting
/// full administrative access (Effect:Allow, Action:*, Resource:*).
pub fn policy_has_admin_access(doc: &str) -> bool {
    if doc.is_empty() {
        return false;
    }
    let v: serde_json::Value = match serde_json::from_str(doc) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let statements = match v.get("Statement").and_then(|s| s.as_array()) {
        Some(arr) => arr,
        None => return false,
    };
    for stmt in statements {
        if stmt.get("Effect").and_then(|e| e.as_str()) != Some("Allow") {
            continue;
        }
        let action_is_star = match stmt.get("Action") {
            Some(serde_json::Value::String(s)) => s == "*",
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .any(|a| a.as_str() == Some("*")),
            _ => false,
        };
        if !action_is_star {
            continue;
        }
        let resource_is_star = match stmt.get("Resource") {
            Some(serde_json::Value::String(s)) => s == "*",
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .any(|r| r.as_str() == Some("*")),
            _ => false,
        };
        if resource_is_star {
            return true;
        }
    }
    false
}

/// Check whether a policy document grants a specific action pattern
/// with Effect:Allow and Resource:*.
pub fn policy_grants_action_on_star(doc: &str, action_prefix: &str) -> bool {
    if doc.is_empty() {
        return false;
    }
    let v: serde_json::Value = match serde_json::from_str(doc) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let statements = match v.get("Statement").and_then(|s| s.as_array()) {
        Some(arr) => arr,
        None => return false,
    };
    for stmt in statements {
        if stmt.get("Effect").and_then(|e| e.as_str()) != Some("Allow") {
            continue;
        }
        let action_matches = match stmt.get("Action") {
            Some(serde_json::Value::String(s)) => {
                s == "*"
                    || s.to_lowercase().starts_with(&action_prefix.to_lowercase())
            }
            Some(serde_json::Value::Array(arr)) => arr.iter().any(|a| {
                if let Some(s) = a.as_str() {
                    s == "*" || s.to_lowercase().starts_with(&action_prefix.to_lowercase())
                } else {
                    false
                }
            }),
            _ => false,
        };
        if !action_matches {
            continue;
        }
        let resource_is_star = match stmt.get("Resource") {
            Some(serde_json::Value::String(s)) => s == "*",
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .any(|r| r.as_str() == Some("*")),
            _ => false,
        };
        if resource_is_star {
            return true;
        }
    }
    false
}

/// Check whether a policy document contains any of the given actions with Effect:Allow Resource:*.
pub fn policy_grants_any_action_on_star(doc: &str, actions: &[&str]) -> bool {
    if doc.is_empty() {
        return false;
    }
    let v: serde_json::Value = match serde_json::from_str(doc) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let statements = match v.get("Statement").and_then(|s| s.as_array()) {
        Some(arr) => arr,
        None => return false,
    };
    for stmt in statements {
        if stmt.get("Effect").and_then(|e| e.as_str()) != Some("Allow") {
            continue;
        }
        let resource_is_star = match stmt.get("Resource") {
            Some(serde_json::Value::String(s)) => s == "*",
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .any(|r| r.as_str() == Some("*")),
            _ => false,
        };
        if !resource_is_star {
            continue;
        }
        let action_matches = match stmt.get("Action") {
            Some(serde_json::Value::String(s)) => {
                let sl = s.to_lowercase();
                sl == "*" || actions.iter().any(|a| sl == a.to_lowercase())
            }
            Some(serde_json::Value::Array(arr)) => arr.iter().any(|a| {
                if let Some(s) = a.as_str() {
                    let sl = s.to_lowercase();
                    sl == "*" || actions.iter().any(|act| sl == act.to_lowercase())
                } else {
                    false
                }
            }),
            _ => false,
        };
        if action_matches {
            return true;
        }
    }
    false
}
