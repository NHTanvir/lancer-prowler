//! IAM service — bulk-fetches all IAM state once per scan.
//! The data structures and fetch helpers are consumed by Week-3 checks.

use anyhow::Context;
use aws_sdk_iam::error::ProvideErrorMetadata;
use aws_sdk_iam::Client as IamClient;
use aws_types::region::Region;
use std::sync::Arc;

// ── Data structures ──────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct IamAccessKey {
    pub access_key_id: String,
    pub status: String, // "Active" | "Inactive"
    pub create_date: Option<String>,
    pub last_used_date: Option<String>,
}

#[allow(dead_code)]
pub struct IamUser {
    pub user_id: String,
    pub user_name: String,
    pub arn: String,
    pub password_last_used: Option<String>,
    pub access_keys: Vec<IamAccessKey>,
    pub mfa_devices: Vec<String>,
    pub attached_policies: Vec<String>,
    pub inline_policies: Vec<String>,
}

#[allow(dead_code)]
pub struct IamPasswordPolicy {
    pub minimum_password_length: Option<i32>,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_symbols: bool,
    pub require_numbers: bool,
    pub max_password_age: Option<i32>, // days; None = no expiry
    pub password_reuse_prevention: Option<i32>,
    pub allow_users_to_change_password: bool,
    pub expire_passwords: bool,
}

#[allow(dead_code)]
pub struct IamRole {
    pub role_id: String,
    pub role_name: String,
    pub arn: String,
    pub assume_role_policy: String,
    pub attached_policies: Vec<String>,
    pub inline_policies: Vec<String>,
}

#[allow(dead_code)]
pub struct IamGroup {
    pub group_id: String,
    pub group_name: String,
    pub arn: String,
    pub attached_policies: Vec<String>,
    pub inline_policies: Vec<String>,
}

#[allow(dead_code)]
pub struct IamPolicy {
    pub policy_id: String,
    pub policy_name: String,
    pub arn: String,
    pub is_aws_managed: bool,
    pub document: String, // JSON policy document
    pub attachment_count: i32,
}

#[allow(dead_code)]
pub struct CredentialReportEntry {
    pub user: String,
    pub arn: String,
    pub user_creation_time: String,
    pub password_enabled: String,
    pub password_last_used: String,
    pub password_last_changed: String,
    pub password_next_rotation: String,
    pub mfa_active: bool,
    pub access_key_1_active: bool,
    pub access_key_1_last_rotated: String,
    pub access_key_1_last_used_date: String,
    pub access_key_2_active: bool,
    pub access_key_2_last_rotated: String,
    pub access_key_2_last_used_date: String,
}

#[allow(dead_code)]
pub struct IamService {
    pub users: Vec<IamUser>,
    pub roles: Vec<IamRole>,
    pub groups: Vec<IamGroup>,
    pub policies: Vec<IamPolicy>,
    pub password_policy: Option<IamPasswordPolicy>,
    pub account_id: String,
    pub credential_report: Vec<CredentialReportEntry>,
}

// ── IamService::new ───────────────────────────────────────────────────────────

#[allow(dead_code)]
impl IamService {
    pub async fn new(
        config: &aws_config::SdkConfig,
        account_id: String,
    ) -> anyhow::Result<Self> {
        // IAM is a global service — force us-east-1
        let iam_cfg = config
            .to_builder()
            .region(Region::new("us-east-1"))
            .build();
        let client = Arc::new(IamClient::new(&iam_cfg));

        // Parallel bulk-fetch
        let (users_result, roles_result, groups_result, policies_result, pwd_policy_result) =
            tokio::try_join!(
                fetch_users(Arc::clone(&client)),
                fetch_roles(Arc::clone(&client)),
                fetch_groups(Arc::clone(&client)),
                fetch_customer_policies(Arc::clone(&client)),
                fetch_password_policy(Arc::clone(&client)),
            )?;

        // Credential report requires sequential generate → poll → get
        let credential_report = match fetch_credential_report(&client).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to fetch credential report: {:#}", e);
                vec![]
            }
        };

        Ok(Self {
            users: users_result,
            roles: roles_result,
            groups: groups_result,
            policies: policies_result,
            password_policy: pwd_policy_result,
            account_id,
            credential_report,
        })
    }
}

// ── Helper: fetch users (with access keys + MFA per user) ────────────────────

#[allow(dead_code)]
async fn fetch_users(client: Arc<IamClient>) -> anyhow::Result<Vec<IamUser>> {
    let mut users: Vec<IamUser> = Vec::new();

    let mut paginator = client.list_users().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = page.context("Failed to list IAM users")?;
        for u in page.users() {
            let user_name = u.user_name().to_string();
            let user_id = u.user_id().to_string();
            let arn = u.arn().to_string();
            let password_last_used = u
                .password_last_used()
                .map(|dt| dt.to_string());

            // Fetch access keys, MFA devices, and policies in parallel
            let (access_keys, mfa_devices, attached_policies, inline_policies) = tokio::join!(
                async { fetch_access_keys_for_user(Arc::clone(&client), &user_name).await.unwrap_or_else(|e| { tracing::warn!("access keys fetch failed for {}: {:#}", user_name, e); vec![] }) },
                async { fetch_mfa_devices_for_user(Arc::clone(&client), &user_name).await.unwrap_or_else(|e| { tracing::warn!("MFA devices fetch failed for {}: {:#}", user_name, e); vec![] }) },
                async { fetch_user_attached_policies(Arc::clone(&client), &user_name).await.unwrap_or_else(|e| { tracing::warn!("attached policies fetch failed for {}: {:#}", user_name, e); vec![] }) },
                async { fetch_user_inline_policies(Arc::clone(&client), &user_name).await.unwrap_or_else(|e| { tracing::warn!("inline policies fetch failed for {}: {:#}", user_name, e); vec![] }) },
            );

            users.push(IamUser {
                user_id,
                user_name,
                arn,
                password_last_used,
                access_keys,
                mfa_devices,
                attached_policies,
                inline_policies,
            });
        }
    }

    Ok(users)
}

#[allow(dead_code)]
async fn fetch_access_keys_for_user(
    client: Arc<IamClient>,
    user_name: &str,
) -> anyhow::Result<Vec<IamAccessKey>> {
    let mut keys: Vec<IamAccessKey> = Vec::new();

    let mut paginator = client
        .list_access_keys()
        .user_name(user_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to list access keys for user {user_name}: {e}");
                break;
            }
        };

        for key_meta in page.access_key_metadata() {
            let access_key_id = key_meta.access_key_id().unwrap_or_default().to_string();
            let status = key_meta.status().map(|s| s.as_str().to_string()).unwrap_or_default();
            let create_date = key_meta.create_date().map(|d| d.to_string());

            // Fetch last-used date
            let last_used_date = match client
                .get_access_key_last_used()
                .access_key_id(&access_key_id)
                .send()
                .await
            {
                Ok(resp) => resp
                    .access_key_last_used()
                    .and_then(|lu| lu.last_used_date())
                    .map(|d| d.to_string()),
                Err(_) => None,
            };

            keys.push(IamAccessKey {
                access_key_id,
                status,
                create_date,
                last_used_date,
            });
        }
    }

    Ok(keys)
}

#[allow(dead_code)]
async fn fetch_mfa_devices_for_user(
    client: Arc<IamClient>,
    user_name: &str,
) -> anyhow::Result<Vec<String>> {
    let mut serials: Vec<String> = Vec::new();

    let mut paginator = client
        .list_mfa_devices()
        .user_name(user_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to list MFA devices for user {user_name}: {e}");
                break;
            }
        };
        for device in page.mfa_devices() {
            serials.push(device.serial_number().to_string());
        }
    }

    Ok(serials)
}

#[allow(dead_code)]
async fn fetch_user_attached_policies(
    client: Arc<IamClient>,
    user_name: &str,
) -> anyhow::Result<Vec<String>> {
    let mut policy_arns: Vec<String> = Vec::new();

    let mut paginator = client
        .list_attached_user_policies()
        .user_name(user_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to list attached policies for user {user_name}: {e}");
                break;
            }
        };
        for policy in page.attached_policies() {
            if let Some(arn) = policy.policy_arn() {
                policy_arns.push(arn.to_string());
            }
        }
    }

    Ok(policy_arns)
}

#[allow(dead_code)]
async fn fetch_user_inline_policies(
    client: Arc<IamClient>,
    user_name: &str,
) -> anyhow::Result<Vec<String>> {
    let mut policy_names: Vec<String> = Vec::new();

    let mut paginator = client
        .list_user_policies()
        .user_name(user_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to list inline policies for user {user_name}: {e}");
                break;
            }
        };
        for name in page.policy_names() {
            policy_names.push(name.to_string());
        }
    }

    Ok(policy_names)
}

// ── Helper: fetch roles ───────────────────────────────────────────────────────

#[allow(dead_code)]
async fn fetch_roles(client: Arc<IamClient>) -> anyhow::Result<Vec<IamRole>> {
    let mut roles: Vec<IamRole> = Vec::new();

    let mut paginator = client.list_roles().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = page.context("Failed to list IAM roles")?;
        for r in page.roles() {
            let role_name = r.role_name().to_string();

            let (attached_policies, inline_policies) = tokio::join!(
                async { fetch_role_attached_policies(Arc::clone(&client), &role_name).await.unwrap_or_else(|e| { tracing::warn!("attached policies fetch failed for role {}: {:#}", role_name, e); vec![] }) },
                async { fetch_role_inline_policies(Arc::clone(&client), &role_name).await.unwrap_or_else(|e| { tracing::warn!("inline policies fetch failed for role {}: {:#}", role_name, e); vec![] }) },
            );

            roles.push(IamRole {
                role_id: r.role_id().to_string(),
                role_name,
                arn: r.arn().to_string(),
                assume_role_policy: r
                    .assume_role_policy_document()
                    .unwrap_or("")
                    .to_string(),
                attached_policies,
                inline_policies,
            });
        }
    }

    Ok(roles)
}

#[allow(dead_code)]
async fn fetch_role_attached_policies(
    client: Arc<IamClient>,
    role_name: &str,
) -> anyhow::Result<Vec<String>> {
    let mut policy_arns: Vec<String> = Vec::new();

    let mut paginator = client
        .list_attached_role_policies()
        .role_name(role_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to list attached policies for role {role_name}: {e}");
                break;
            }
        };
        for policy in page.attached_policies() {
            if let Some(arn) = policy.policy_arn() {
                policy_arns.push(arn.to_string());
            }
        }
    }

    Ok(policy_arns)
}

#[allow(dead_code)]
async fn fetch_role_inline_policies(
    client: Arc<IamClient>,
    role_name: &str,
) -> anyhow::Result<Vec<String>> {
    let mut policy_names: Vec<String> = Vec::new();

    let mut paginator = client
        .list_role_policies()
        .role_name(role_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to list inline policies for role {role_name}: {e}");
                break;
            }
        };
        for name in page.policy_names() {
            policy_names.push(name.to_string());
        }
    }

    Ok(policy_names)
}

// ── Helper: fetch groups ──────────────────────────────────────────────────────

#[allow(dead_code)]
async fn fetch_groups(client: Arc<IamClient>) -> anyhow::Result<Vec<IamGroup>> {
    let mut groups: Vec<IamGroup> = Vec::new();

    let mut paginator = client.list_groups().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = page.context("Failed to list IAM groups")?;
        for g in page.groups() {
            let group_name = g.group_name().to_string();

            let (attached_policies, inline_policies) = tokio::join!(
                async { fetch_group_attached_policies(Arc::clone(&client), &group_name).await.unwrap_or_else(|e| { tracing::warn!("attached policies fetch failed for group {}: {:#}", group_name, e); vec![] }) },
                async { fetch_group_inline_policies(Arc::clone(&client), &group_name).await.unwrap_or_else(|e| { tracing::warn!("inline policies fetch failed for group {}: {:#}", group_name, e); vec![] }) },
            );

            groups.push(IamGroup {
                group_id: g.group_id().to_string(),
                group_name,
                arn: g.arn().to_string(),
                attached_policies,
                inline_policies,
            });
        }
    }

    Ok(groups)
}

#[allow(dead_code)]
async fn fetch_group_attached_policies(
    client: Arc<IamClient>,
    group_name: &str,
) -> anyhow::Result<Vec<String>> {
    let mut policy_arns: Vec<String> = Vec::new();

    let mut paginator = client
        .list_attached_group_policies()
        .group_name(group_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to list attached policies for group {group_name}: {e}");
                break;
            }
        };
        for policy in page.attached_policies() {
            if let Some(arn) = policy.policy_arn() {
                policy_arns.push(arn.to_string());
            }
        }
    }

    Ok(policy_arns)
}

#[allow(dead_code)]
async fn fetch_group_inline_policies(
    client: Arc<IamClient>,
    group_name: &str,
) -> anyhow::Result<Vec<String>> {
    let mut policy_names: Vec<String> = Vec::new();

    let mut paginator = client
        .list_group_policies()
        .group_name(group_name)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to list inline policies for group {group_name}: {e}");
                break;
            }
        };
        for name in page.policy_names() {
            policy_names.push(name.to_string());
        }
    }

    Ok(policy_names)
}

// ── Helper: fetch customer-managed policies ───────────────────────────────────

#[allow(dead_code)]
async fn fetch_customer_policies(client: Arc<IamClient>) -> anyhow::Result<Vec<IamPolicy>> {
    let mut policies: Vec<IamPolicy> = Vec::new();

    let mut paginator = client
        .list_policies()
        .scope(aws_sdk_iam::types::PolicyScopeType::Local)
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let page = page.context("Failed to list IAM policies")?;
        for p in page.policies() {
            let arn = p.arn().unwrap_or("").to_string();
            let policy_name = p.policy_name().unwrap_or("").to_string();
            let policy_id = p.policy_id().unwrap_or("").to_string();
            let attachment_count = p.attachment_count().unwrap_or(0);
            let is_aws_managed = arn.starts_with("arn:aws:iam::aws:");

            // Fetch the default policy version document
            let document = if let Some(default_version_id) = p.default_version_id() {
                match client
                    .get_policy_version()
                    .policy_arn(&arn)
                    .version_id(default_version_id)
                    .send()
                    .await
                {
                    Ok(resp) => resp
                        .policy_version()
                        .and_then(|pv| pv.document())
                        .map(|d| {
                            // URL-decode the document (AWS returns URL-encoded JSON)
                            url_decode(d)
                        })
                        .unwrap_or_default(),
                    Err(e) => {
                        tracing::warn!("Failed to get policy version for {arn}: {e}");
                        String::new()
                    }
                }
            } else {
                String::new()
            };

            policies.push(IamPolicy {
                policy_id,
                policy_name,
                arn,
                is_aws_managed,
                document,
                attachment_count,
            });
        }
    }

    Ok(policies)
}

/// URL percent-decode for policy documents returned by IAM.
/// Builds a byte Vec first, then converts to String, avoiding unsound byte-as-char casts.
#[allow(dead_code)]
fn url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(s) = std::str::from_utf8(&bytes[i+1..i+3]) {
                if let Ok(b) = u8::from_str_radix(s, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── Helper: password policy ───────────────────────────────────────────────────

#[allow(dead_code)]
async fn fetch_password_policy(
    client: Arc<IamClient>,
) -> anyhow::Result<Option<IamPasswordPolicy>> {
    match client.get_account_password_policy().send().await {
        Ok(resp) => {
            if let Some(pp) = resp.password_policy() {
                Ok(Some(IamPasswordPolicy {
                    minimum_password_length: pp.minimum_password_length(),
                    require_uppercase: pp.require_uppercase_characters(),
                    require_lowercase: pp.require_lowercase_characters(),
                    require_symbols: pp.require_symbols(),
                    require_numbers: pp.require_numbers(),
                    max_password_age: pp.max_password_age(),
                    password_reuse_prevention: pp.password_reuse_prevention(),
                    allow_users_to_change_password: pp.allow_users_to_change_password(),
                    expire_passwords: pp.expire_passwords(),
                }))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            let code = e.code();
            if code == Some("NoSuchEntity") {
                Ok(None)
            } else if code == Some("AccessDenied") {
                tracing::warn!("Access denied for get_account_password_policy");
                Ok(None)
            } else {
                Err(e).context("Failed to get password policy")
            }
        }
    }
}

// ── Helper: credential report ─────────────────────────────────────────────────

#[allow(dead_code)]
async fn fetch_credential_report(
    client: &Arc<IamClient>,
) -> anyhow::Result<Vec<CredentialReportEntry>> {
    // Step 1: Trigger report generation (may already be complete)
    match client.generate_credential_report().send().await {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to generate credential report: {e}");
            return Ok(vec![]);
        }
    }

    // Step 2: Poll until the report is ready (up to ~30s)
    let report_content = {
        let mut attempts = 0u32;
        loop {
            match client.get_credential_report().send().await {
                Ok(resp) => break resp,
                Err(e) if e.code() == Some("ReportNotPresent")
                    || e.code() == Some("ReportInProgress") =>
                {
                    attempts += 1;
                    if attempts > 15 {
                        tracing::warn!("Credential report not ready after 15 attempts");
                        return Ok(vec![]);
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                Err(e) => {
                    tracing::warn!("Failed to get credential report: {e}");
                    return Ok(vec![]);
                }
            }
        }
    };

    // Step 3: Parse the CSV content
    let content_bytes = report_content
        .content()
        .map(|b| b.as_ref().to_vec())
        .unwrap_or_default();
    let content_str = String::from_utf8_lossy(&content_bytes);

    let mut rdr = csv::Reader::from_reader(content_str.as_bytes());
    let mut entries: Vec<CredentialReportEntry> = Vec::new();

    for result in rdr.records() {
        let record = match result {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to parse credential report row: {e}");
                continue;
            }
        };

        // CSV columns (in order):
        // user, arn, user_creation_time, password_enabled, password_last_used,
        // password_last_changed, password_next_rotation, mfa_active,
        // access_key_1_active, access_key_1_last_rotated, access_key_1_last_used_date,
        // access_key_1_last_used_region, access_key_1_last_used_service,
        // access_key_2_active, access_key_2_last_rotated, access_key_2_last_used_date,
        // access_key_2_last_used_region, access_key_2_last_used_service,
        // cert_1_active, cert_1_last_rotated, cert_2_active, cert_2_last_rotated
        if record.len() < 22 {
            tracing::warn!("Credential report row has {} columns, expected >= 22, skipping", record.len());
            continue;
        }
        let get = |idx: usize| record.get(idx).unwrap_or("").to_string();
        let bool_field = |idx: usize| record.get(idx).unwrap_or("false") == "true";

        entries.push(CredentialReportEntry {
            user: get(0),
            arn: get(1),
            user_creation_time: get(2),
            password_enabled: get(3),
            password_last_used: get(4),
            password_last_changed: get(5),
            password_next_rotation: get(6),
            mfa_active: bool_field(7),
            access_key_1_active: bool_field(8),
            access_key_1_last_rotated: get(9),
            access_key_1_last_used_date: get(10),
            access_key_2_active: bool_field(13),
            access_key_2_last_rotated: get(14),
            access_key_2_last_used_date: get(15),
        });
    }

    Ok(entries)
}
