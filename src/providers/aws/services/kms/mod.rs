//! KMS service — bulk-fetches KMS key metadata across all regions.

use aws_sdk_kms::Client as KmsClient;
use aws_types::region::Region;
use tokio::task::JoinSet;
use tracing::warn;

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct KmsKey {
    pub key_id: String,
    pub arn: String,
    pub region: String,
    pub enabled: bool,
    /// "Enabled", "Disabled", "PendingDeletion", "PendingImport", "Unavailable"
    pub key_state: String,
    /// "AWS" or "CUSTOMER"
    pub key_manager: String,
    pub key_rotation_enabled: bool,
    pub description: String,
    pub deletion_date: Option<String>,
}

#[allow(dead_code)]
pub struct KmsService {
    pub keys: Vec<KmsKey>,
    pub account_id: String,
}

// ── KmsService::new ───────────────────────────────────────────────────────────

impl KmsService {
    pub async fn new(
        config: &aws_config::SdkConfig,
        account_id: String,
        regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        let config_clone = config.clone();
        let mut join_set: JoinSet<Vec<KmsKey>> = JoinSet::new();

        for region in regions {
            let cfg = config_clone.clone();
            join_set.spawn(async move {
                fetch_keys_for_region(&cfg, &region).await
            });
        }

        let mut all_keys: Vec<KmsKey> = Vec::new();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(keys) => all_keys.extend(keys),
                Err(e) => warn!("KMS region fetch task panicked: {e}"),
            }
        }

        Ok(Self {
            keys: all_keys,
            account_id,
        })
    }
}

// ── Region-level fetcher ──────────────────────────────────────────────────────

async fn fetch_keys_for_region(config: &aws_config::SdkConfig, region: &str) -> Vec<KmsKey> {
    let regional_cfg = config
        .to_builder()
        .region(Region::new(region.to_string()))
        .build();
    let client = KmsClient::new(&regional_cfg);

    // Paginate through all keys in the region
    let mut key_ids: Vec<String> = Vec::new();
    let mut next_marker: Option<String> = None;

    loop {
        let mut req = client.list_keys();
        if let Some(ref marker) = next_marker {
            req = req.marker(marker);
        }

        match req.send().await {
            Ok(resp) => {
                for key_list_entry in resp.keys() {
                    if let Some(kid) = key_list_entry.key_id() {
                        key_ids.push(kid.to_string());
                    }
                }
                if resp.truncated() {
                    next_marker = resp.next_marker().map(|s| s.to_string());
                } else {
                    break;
                }
            }
            Err(e) => {
                warn!("list_keys failed for region {region}: {e}");
                break;
            }
        }
    }

    // Fetch details for each key
    let mut keys = Vec::new();
    for key_id in key_ids {
        if let Some(key) = fetch_key_details(&client, &key_id, region).await {
            keys.push(key);
        }
    }

    keys
}

// ── Per-key helpers ───────────────────────────────────────────────────────────

async fn fetch_key_details(client: &KmsClient, key_id: &str, region: &str) -> Option<KmsKey> {
    let describe_resp = match client.describe_key().key_id(key_id).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!("describe_key failed for {key_id}: {e}");
            return None;
        }
    };

    let metadata = describe_resp.key_metadata()?;
    let arn = metadata.arn().unwrap_or("").to_string();
    let key_state = metadata
        .key_state()
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let enabled = key_state == "Enabled";
    let key_manager = metadata
        .key_manager()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "CUSTOMER".to_string());
    let description = metadata.description().unwrap_or("").to_string();
    let deletion_date = metadata
        .deletion_date()
        .map(|d| d.to_string());

    // Get rotation status — skip for AWS-managed keys (they don't support this call)
    let key_rotation_enabled = if key_manager == "AWS" {
        false
    } else {
        get_key_rotation_status(client, key_id).await
    };

    Some(KmsKey {
        key_id: key_id.to_string(),
        arn,
        region: region.to_string(),
        enabled,
        key_state,
        key_manager,
        key_rotation_enabled,
        description,
        deletion_date,
    })
}

async fn get_key_rotation_status(client: &KmsClient, key_id: &str) -> bool {
    match client
        .get_key_rotation_status()
        .key_id(key_id)
        .send()
        .await
    {
        Ok(resp) => resp.key_rotation_enabled(),
        Err(e) => {
            // UnsupportedOperationException for asymmetric keys, etc.
            let code = e
                .as_service_error()
                .and_then(|se| se.meta().code());
            if code != Some("UnsupportedOperationException")
                && code != Some("AccessDeniedException")
            {
                warn!("get_key_rotation_status failed for {key_id}: {e}");
            }
            false
        }
    }
}
