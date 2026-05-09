//! AWS Config service — fetches recorder and delivery channel status per region.
//!
//! Module named `awsconfig` to avoid collision with the `aws_config` crate.

use aws_sdk_config::Client as ConfigClient;
use aws_types::region::Region;
use tokio::task::JoinSet;
use tracing::warn;

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct ConfigRecorder {
    pub name: String,
    pub region: String,
    pub recording: bool,
    pub all_supported: bool,
    pub include_global_resource_types: bool,
    pub delivery_channel_exists: bool,
}

#[allow(dead_code)]
pub struct AwsConfigService {
    pub recorders: Vec<ConfigRecorder>,
    pub account_id: String,
}

// ── AwsConfigService::new ─────────────────────────────────────────────────────

impl AwsConfigService {
    pub async fn new(
        config: &aws_config::SdkConfig,
        account_id: String,
        regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        let config_clone = config.clone();
        let mut join_set: JoinSet<Vec<ConfigRecorder>> = JoinSet::new();

        for region in regions {
            let cfg = config_clone.clone();
            join_set.spawn(async move {
                fetch_recorders_for_region(&cfg, &region).await
            });
        }

        let mut all_recorders: Vec<ConfigRecorder> = Vec::new();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(recorders) => all_recorders.extend(recorders),
                Err(e) => warn!("AWS Config region fetch task panicked: {e}"),
            }
        }

        Ok(Self {
            recorders: all_recorders,
            account_id,
        })
    }
}

// ── Region-level fetcher ──────────────────────────────────────────────────────

async fn fetch_recorders_for_region(
    config: &aws_config::SdkConfig,
    region: &str,
) -> Vec<ConfigRecorder> {
    let regional_cfg = config
        .to_builder()
        .region(Region::new(region.to_string()))
        .build();
    let client = ConfigClient::new(&regional_cfg);

    // Fetch recorders, their status, and delivery channels in parallel
    let (recorders_resp, status_resp, delivery_resp) = tokio::join!(
        client.describe_configuration_recorders().send(),
        client.describe_configuration_recorder_status().send(),
        client.describe_delivery_channels().send(),
    );

    let recorders = match recorders_resp {
        Ok(r) => r,
        Err(e) => {
            warn!("describe_configuration_recorders failed for {region}: {e}");
            return vec![];
        }
    };

    // Build a map of recorder name -> is_recording from status response
    let mut recording_map: std::collections::HashMap<String, bool> =
        std::collections::HashMap::new();
    if let Ok(status) = status_resp {
        for s in status.configuration_recorders_status() {
            let name = s.name().unwrap_or("").to_string();
            let is_recording = s.recording();
            recording_map.insert(name, is_recording);
        }
    }

    // Check if at least one delivery channel exists in this region
    let delivery_channel_exists = match delivery_resp {
        Ok(d) => !d.delivery_channels().is_empty(),
        Err(_) => false,
    };

    let mut result = Vec::new();
    for recorder in recorders.configuration_recorders() {
        let name = recorder.name().unwrap_or("default").to_string();
        let recording = *recording_map.get(&name).unwrap_or(&false);
        let spec = recorder.recording_group();
        let all_supported = spec
            .map(|s| s.all_supported())
            .unwrap_or(false);
        let include_global_resource_types = spec
            .map(|s| s.include_global_resource_types())
            .unwrap_or(false);

        result.push(ConfigRecorder {
            name,
            region: region.to_string(),
            recording,
            all_supported,
            include_global_resource_types,
            delivery_channel_exists,
        });
    }

    result
}
