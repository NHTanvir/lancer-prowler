//! Security Hub service — bulk-fetches hub metadata across all regions.

use aws_sdk_securityhub::Client as SecurityHubClient;
use aws_types::region::Region;
use tokio::task::JoinSet;
use tracing::warn;

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct SecurityHubHub {
    pub hub_arn: String,
    pub region: String,
    pub subscribed_at: String,
    pub auto_enable_controls: bool,
}

#[allow(dead_code)]
pub struct SecurityHubService {
    pub hubs: Vec<SecurityHubHub>,
    pub account_id: String,
}

// ── SecurityHubService::new ───────────────────────────────────────────────────

impl SecurityHubService {
    pub async fn new(
        config: &aws_config::SdkConfig,
        account_id: String,
        regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        let config_clone = config.clone();
        let mut join_set: JoinSet<Option<SecurityHubHub>> = JoinSet::new();

        for region in regions {
            let cfg = config_clone.clone();
            join_set.spawn(async move {
                fetch_hub_for_region(&cfg, &region).await
            });
        }

        let mut all_hubs: Vec<SecurityHubHub> = Vec::new();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Some(hub)) => all_hubs.push(hub),
                Ok(None) => {}
                Err(e) => warn!("SecurityHub region fetch task panicked: {e}"),
            }
        }

        Ok(Self {
            hubs: all_hubs,
            account_id,
        })
    }
}

// ── Region-level fetcher ──────────────────────────────────────────────────────

async fn fetch_hub_for_region(
    config: &aws_config::SdkConfig,
    region: &str,
) -> Option<SecurityHubHub> {
    let regional_cfg = config
        .to_builder()
        .region(Region::new(region.to_string()))
        .build();
    let client = SecurityHubClient::new(&regional_cfg);

    match client.describe_hub().send().await {
        Ok(resp) => {
            let hub_arn = resp.hub_arn().unwrap_or("").to_string();
            let subscribed_at = resp.subscribed_at().unwrap_or("").to_string();
            let auto_enable_controls = resp.auto_enable_controls().unwrap_or(false);

            Some(SecurityHubHub {
                hub_arn,
                region: region.to_string(),
                subscribed_at,
                auto_enable_controls,
            })
        }
        Err(e) => {
            // It's normal for SecurityHub to not be enabled in a region
            let code = e
                .as_service_error()
                .and_then(|se| se.meta().code());
            if code != Some("InvalidAccessException") && code != Some("ResourceNotFoundException") {
                warn!("describe_hub failed for region {region}: {e}");
            }
            None
        }
    }
}
