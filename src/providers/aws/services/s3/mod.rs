//! S3 service — bulk-fetches all S3 bucket state once per scan.
//! ListBuckets is global; per-bucket APIs use the bucket's home region.

use aws_sdk_s3::Client as S3Client;
use aws_types::region::Region;
use std::collections::HashMap;
use tokio::task::JoinSet;
use tracing::warn;

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct PublicAccessBlock {
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
}

#[allow(dead_code)]
pub struct BucketEncryption {
    pub enabled: bool,
    /// None = SSE-S3 (AES256); Some(key_id) = SSE-KMS
    pub kms_master_key_id: Option<String>,
}

#[allow(dead_code)]
pub struct S3Bucket {
    pub name: String,
    pub region: String,
    pub creation_date: Option<String>,
    pub public_access_block: Option<PublicAccessBlock>,
    /// "private" | "public-read" | "public-read-write" | "authenticated-read" | "unknown"
    pub acl: String,
    pub encryption: Option<BucketEncryption>,
    pub versioning_enabled: bool,
    pub versioning_mfa_delete: bool,
    pub logging_enabled: bool,
    /// true if bucket policy has Deny + aws:SecureTransport:false
    pub secure_transport_policy: bool,
    pub object_lock_enabled: bool,
    /// Raw JSON policy document; None if no policy attached
    pub policy: Option<String>,
    /// true if policy allows public access (Principal: * with Effect: Allow)
    pub policy_is_public: bool,
}

#[allow(dead_code)]
pub struct S3AccountLevelPublicAccess {
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
}

#[allow(dead_code)]
pub struct S3Service {
    pub buckets: Vec<S3Bucket>,
    /// TODO: populate via aws-sdk-s3control once that crate is added
    pub account_level_public_access: Option<S3AccountLevelPublicAccess>,
    pub account_id: String,
}

// ── S3Service::new ────────────────────────────────────────────────────────────

impl S3Service {
    pub async fn new(
        config: &aws_config::SdkConfig,
        account_id: String,
    ) -> anyhow::Result<Self> {
        // S3 ListBuckets is a global call; use us-east-1 client
        let global_cfg = config
            .to_builder()
            .region(Region::new("us-east-1"))
            .build();
        let global_client = S3Client::new(&global_cfg);

        // 1. List all buckets
        let list_resp = match global_client.list_buckets().send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to list S3 buckets: {:#}", e);
                return Ok(Self {
                    buckets: vec![],
                    account_level_public_access: None,
                    account_id,
                });
            }
        };

        // Collect (name, creation_date, region) for every bucket
        let raw_buckets: Vec<(String, Option<String>)> = list_resp
            .buckets()
            .iter()
            .map(|b| {
                let name = b.name().unwrap_or("").to_string();
                let creation_date = b.creation_date().map(|d| d.to_string());
                (name, creation_date)
            })
            .collect();

        // 2. Resolve each bucket's region
        // We need the global client for get_bucket_location calls
        let mut bucket_regions: HashMap<String, String> = HashMap::new();
        for (name, _) in &raw_buckets {
            let region = get_bucket_region(&global_client, name).await;
            bucket_regions.insert(name.clone(), region);
        }

        // 3. Fetch per-bucket details with bounded concurrency (max 10 at once)
        let config_clone = config.clone();
        let mut join_set: JoinSet<S3Bucket> = JoinSet::new();
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(10));

        for (name, creation_date) in raw_buckets {
            let region = bucket_regions
                .get(&name)
                .cloned()
                .unwrap_or_else(|| "us-east-1".to_string());
            let cfg = config_clone.clone();
            let sem = semaphore.clone();

            join_set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok();
                fetch_bucket_details(name, creation_date, region, &cfg).await
            });
        }

        let mut buckets: Vec<S3Bucket> = Vec::new();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(bucket) => buckets.push(bucket),
                Err(e) => warn!("S3 bucket fetch task panicked: {e}"),
            }
        }

        // TODO: fetch account-level public access block via aws-sdk-s3control
        Ok(Self {
            buckets,
            account_level_public_access: None,
            account_id,
        })
    }
}

// ── Helper: resolve bucket region ─────────────────────────────────────────────

async fn get_bucket_region(client: &S3Client, bucket_name: &str) -> String {
    match client
        .get_bucket_location()
        .bucket(bucket_name)
        .send()
        .await
    {
        Ok(resp) => {
            let loc = resp
                .location_constraint()
                .map(|c| c.as_str().to_string())
                .unwrap_or_default();
            // Empty string / "us-east-1" both mean us-east-1
            if loc.is_empty() {
                "us-east-1".to_string()
            } else {
                loc
            }
        }
        Err(e) => {
            warn!("get_bucket_location failed for {bucket_name}: {e}");
            "us-east-1".to_string()
        }
    }
}

// ── Helper: fetch all per-bucket details ──────────────────────────────────────

async fn fetch_bucket_details(
    name: String,
    creation_date: Option<String>,
    region: String,
    config: &aws_config::SdkConfig,
) -> S3Bucket {
    let bucket_cfg = config
        .to_builder()
        .region(Region::new(region.clone()))
        .build();
    let client = S3Client::new(&bucket_cfg);

    // Fire all independent per-bucket calls in parallel
    let (pab_res, acl_res, enc_res, ver_res, log_res, pol_res, lock_res) = tokio::join!(
        get_public_access_block(&client, &name),
        get_acl_string(&client, &name),
        get_encryption(&client, &name),
        get_versioning(&client, &name),
        get_logging(&client, &name),
        get_policy(&client, &name),
        get_object_lock(&client, &name),
    );

    let public_access_block = pab_res;
    let acl = acl_res;
    let encryption = enc_res;
    let (versioning_enabled, versioning_mfa_delete) = ver_res;
    let logging_enabled = log_res;
    let policy = pol_res;
    let object_lock_enabled = lock_res;

    let secure_transport_policy = policy
        .as_deref()
        .map(check_secure_transport_policy)
        .unwrap_or(false);
    let policy_is_public = policy
        .as_deref()
        .map(check_policy_is_public)
        .unwrap_or(false);

    S3Bucket {
        name,
        region,
        creation_date,
        public_access_block,
        acl,
        encryption,
        versioning_enabled,
        versioning_mfa_delete,
        logging_enabled,
        secure_transport_policy,
        object_lock_enabled,
        policy,
        policy_is_public,
    }
}

// ── Per-bucket API helpers ────────────────────────────────────────────────────

async fn get_public_access_block(
    client: &S3Client,
    bucket: &str,
) -> Option<PublicAccessBlock> {
    match client
        .get_public_access_block()
        .bucket(bucket)
        .send()
        .await
    {
        Ok(resp) => resp.public_access_block_configuration().map(|c| {
            PublicAccessBlock {
                block_public_acls: c.block_public_acls().unwrap_or(false),
                ignore_public_acls: c.ignore_public_acls().unwrap_or(false),
                block_public_policy: c.block_public_policy().unwrap_or(false),
                restrict_public_buckets: c.restrict_public_buckets().unwrap_or(false),
            }
        }),
        Err(e) => {
            let code = e
                .as_service_error()
                .and_then(|se| se.meta().code());
            if code == Some("NoSuchPublicAccessBlockConfiguration")
                || code == Some("AccessDenied")
                || code == Some("NoSuchBucket")
            {
                // No PAB configured — treat as None (all blocks false)
            } else {
                warn!("get_public_access_block failed for {bucket}: {e}");
            }
            None
        }
    }
}

async fn get_acl_string(client: &S3Client, bucket: &str) -> String {
    match client.get_bucket_acl().bucket(bucket).send().await {
        Ok(resp) => {
            // Check grants for public access
            for grant in resp.grants() {
                if let Some(grantee) = grant.grantee() {
                    // URI-based public grants
                    if let Some(uri) = grantee.uri() {
                        if uri.contains("AllUsers") {
                            let perm = grant
                                .permission()
                                .map(|p| p.as_str())
                                .unwrap_or("");
                            if perm == "WRITE" || perm == "FULL_CONTROL" {
                                return "public-read-write".to_string();
                            }
                            return "public-read".to_string();
                        }
                        if uri.contains("AuthenticatedUsers") {
                            return "authenticated-read".to_string();
                        }
                    }
                }
            }
            "private".to_string()
        }
        Err(e) => {
            let code = e
                .as_service_error()
                .and_then(|se| se.meta().code());
            if code == Some("AccessDenied") || code == Some("NoSuchBucket") {
                warn!("get_bucket_acl denied/missing for {bucket}: {e}");
            } else {
                warn!("get_bucket_acl failed for {bucket}: {e}");
            }
            "unknown".to_string()
        }
    }
}

async fn get_encryption(client: &S3Client, bucket: &str) -> Option<BucketEncryption> {
    match client
        .get_bucket_encryption()
        .bucket(bucket)
        .send()
        .await
    {
        Ok(resp) => {
            let rules = resp
                .server_side_encryption_configuration()
                .map(|c| c.rules())
                .unwrap_or(&[]);
            if rules.is_empty() {
                return None;
            }
            // Look for the first SSE rule
            for rule in rules {
                if let Some(def) = rule.apply_server_side_encryption_by_default() {
                    let kms_key = def.kms_master_key_id().map(|k| k.to_string());
                    return Some(BucketEncryption {
                        enabled: true,
                        kms_master_key_id: kms_key,
                    });
                }
            }
            Some(BucketEncryption {
                enabled: true,
                kms_master_key_id: None,
            })
        }
        Err(e) => {
            let code = e
                .as_service_error()
                .and_then(|se| se.meta().code());
            if code == Some("ServerSideEncryptionConfigurationNotFoundError")
                || code == Some("AccessDenied")
                || code == Some("NoSuchBucket")
            {
                // no encryption configured
            } else {
                warn!("get_bucket_encryption failed for {bucket}: {e}");
            }
            None
        }
    }
}

/// Returns (versioning_enabled, mfa_delete_enabled)
async fn get_versioning(client: &S3Client, bucket: &str) -> (bool, bool) {
    match client
        .get_bucket_versioning()
        .bucket(bucket)
        .send()
        .await
    {
        Ok(resp) => {
            let versioning_enabled = resp
                .status()
                .map(|s| s.as_str() == "Enabled")
                .unwrap_or(false);
            let mfa_delete = resp
                .mfa_delete()
                .map(|m| m.as_str() == "Enabled")
                .unwrap_or(false);
            (versioning_enabled, mfa_delete)
        }
        Err(e) => {
            warn!("get_bucket_versioning failed for {bucket}: {e}");
            (false, false)
        }
    }
}

async fn get_logging(client: &S3Client, bucket: &str) -> bool {
    match client
        .get_bucket_logging()
        .bucket(bucket)
        .send()
        .await
    {
        Ok(resp) => resp.logging_enabled().is_some(),
        Err(e) => {
            warn!("get_bucket_logging failed for {bucket}: {e}");
            false
        }
    }
}

async fn get_policy(client: &S3Client, bucket: &str) -> Option<String> {
    match client.get_bucket_policy().bucket(bucket).send().await {
        Ok(resp) => resp.policy().map(|p| p.to_string()),
        Err(e) => {
            let code = e
                .as_service_error()
                .and_then(|se| se.meta().code());
            if code == Some("NoSuchBucketPolicy")
                || code == Some("AccessDenied")
                || code == Some("NoSuchBucket")
            {
                // no policy or denied — return None
            } else {
                warn!("get_bucket_policy failed for {bucket}: {e}");
            }
            None
        }
    }
}

async fn get_object_lock(client: &S3Client, bucket: &str) -> bool {
    match client
        .get_object_lock_configuration()
        .bucket(bucket)
        .send()
        .await
    {
        Ok(resp) => resp
            .object_lock_configuration()
            .and_then(|c| c.object_lock_enabled())
            .map(|e| e.as_str() == "Enabled")
            .unwrap_or(false),
        Err(e) => {
            let code = e
                .as_service_error()
                .and_then(|se| se.meta().code());
            if code == Some("ObjectLockConfigurationNotFoundError")
                || code == Some("AccessDenied")
                || code == Some("NoSuchBucket")
            {
                // object lock not configured
            } else {
                warn!("get_object_lock_configuration failed for {bucket}: {e}");
            }
            false
        }
    }
}

// ── Policy analysis helpers ───────────────────────────────────────────────────

/// Returns true if the policy has a Deny statement with
/// Condition aws:SecureTransport = false, which enforces HTTPS.
fn check_secure_transport_policy(policy_json: &str) -> bool {
    let v: serde_json::Value = match serde_json::from_str(policy_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let statements = match v.get("Statement").and_then(|s| s.as_array()) {
        Some(arr) => arr,
        None => return false,
    };
    for stmt in statements {
        if stmt.get("Effect").and_then(|e| e.as_str()) != Some("Deny") {
            continue;
        }
        // Check for aws:SecureTransport condition with value false
        if let Some(condition) = stmt.get("Condition") {
            // Condition can be Bool or StringEquals, etc.
            for (op_key, op_val) in condition
                .as_object()
                .into_iter()
                .flat_map(|m| m.iter())
            {
                let op = op_key.to_lowercase();
                if op == "bool" || op == "stringequals" {
                    if let Some(cond_map) = op_val.as_object() {
                        for (cond_key, cond_val) in cond_map {
                            if cond_key.to_lowercase() == "aws:securetransport" {
                                // Value should be "false" (string) or false (bool)
                                let is_false = cond_val.as_bool() == Some(false)
                                    || cond_val.as_str() == Some("false");
                                if is_false {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Returns true if any statement has Effect:Allow with Principal:* or Principal:{"AWS":"*"}
/// without restrictive conditions (simple check: just look for wildcard principal + Allow).
fn check_policy_is_public(policy_json: &str) -> bool {
    let v: serde_json::Value = match serde_json::from_str(policy_json) {
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
        let principal = match stmt.get("Principal") {
            Some(p) => p,
            None => continue,
        };
        let is_wildcard = match principal {
            serde_json::Value::String(s) => s == "*",
            serde_json::Value::Object(m) => {
                m.get("AWS")
                    .map(|aws_val| match aws_val {
                        serde_json::Value::String(s) => s == "*",
                        serde_json::Value::Array(arr) => {
                            arr.iter().any(|a| a.as_str() == Some("*"))
                        }
                        _ => false,
                    })
                    .unwrap_or(false)
            }
            _ => false,
        };
        if is_wildcard {
            return true;
        }
    }
    false
}
