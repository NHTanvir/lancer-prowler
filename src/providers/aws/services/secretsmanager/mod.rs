//! Secrets Manager service — bulk-fetches secret metadata across all regions.

use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_types::region::Region;
use tokio::task::JoinSet;
use tracing::warn;

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct Secret {
    pub name: String,
    pub arn: String,
    pub region: String,
    pub rotation_enabled: bool,
    pub rotation_lambda_arn: Option<String>,
    pub last_rotated_date: Option<String>,
    pub last_accessed_date: Option<String>,
    pub kms_key_id: Option<String>,
}

#[allow(dead_code)]
pub struct SecretsManagerService {
    pub secrets: Vec<Secret>,
    pub account_id: String,
}

// ── SecretsManagerService::new ────────────────────────────────────────────────

impl SecretsManagerService {
    pub async fn new(
        config: &aws_config::SdkConfig,
        account_id: String,
        regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        let config_clone = config.clone();
        let mut join_set: JoinSet<Vec<Secret>> = JoinSet::new();

        for region in regions {
            let cfg = config_clone.clone();
            join_set.spawn(async move {
                fetch_secrets_for_region(&cfg, &region).await
            });
        }

        let mut all_secrets: Vec<Secret> = Vec::new();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(secrets) => all_secrets.extend(secrets),
                Err(e) => warn!("SecretsManager region fetch task panicked: {e}"),
            }
        }

        Ok(Self {
            secrets: all_secrets,
            account_id,
        })
    }
}

// ── Region-level fetcher ──────────────────────────────────────────────────────

async fn fetch_secrets_for_region(
    config: &aws_config::SdkConfig,
    region: &str,
) -> Vec<Secret> {
    let regional_cfg = config
        .to_builder()
        .region(Region::new(region.to_string()))
        .build();
    let client = SecretsManagerClient::new(&regional_cfg);

    let mut secrets = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client.list_secrets();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }

        match req.send().await {
            Ok(resp) => {
                for s in resp.secret_list() {
                    let name = s.name().unwrap_or("").to_string();
                    let arn = s.arn().unwrap_or("").to_string();
                    let rotation_enabled = s.rotation_enabled().unwrap_or(false);
                    let rotation_lambda_arn = s.rotation_lambda_arn().map(|a| a.to_string());
                    let last_rotated_date = s
                        .last_rotated_date()
                        .map(|d| d.to_string());
                    let last_accessed_date = s
                        .last_accessed_date()
                        .map(|d| d.to_string());
                    let kms_key_id = s.kms_key_id().map(|k| k.to_string());

                    secrets.push(Secret {
                        name,
                        arn,
                        region: region.to_string(),
                        rotation_enabled,
                        rotation_lambda_arn,
                        last_rotated_date,
                        last_accessed_date,
                        kms_key_id,
                    });
                }

                if resp.next_token().is_some() {
                    next_token = resp.next_token().map(|s| s.to_string());
                } else {
                    break;
                }
            }
            Err(e) => {
                warn!("list_secrets failed for region {region}: {e}");
                break;
            }
        }
    }

    secrets
}
