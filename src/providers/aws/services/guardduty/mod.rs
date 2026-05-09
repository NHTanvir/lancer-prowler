//! GuardDuty service — bulk-fetches detector metadata across all regions.

use aws_sdk_guardduty::Client as GuardDutyClient;
use aws_types::region::Region;
use tokio::task::JoinSet;
use tracing::warn;

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct GuardDutyDetector {
    pub detector_id: String,
    pub region: String,
    pub status: String,      // "ENABLED" | "DISABLED"
    pub finding_publishing_frequency: String,
    pub updated_at: String,
}

#[allow(dead_code)]
pub struct GuardDutyService {
    pub detectors: Vec<GuardDutyDetector>,
    pub account_id: String,
    /// All regions that were scanned (used to detect regions with no detectors).
    pub scanned_regions: Vec<String>,
}

// ── GuardDutyService::new ─────────────────────────────────────────────────────

impl GuardDutyService {
    pub async fn new(
        config: &aws_config::SdkConfig,
        account_id: String,
        regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        let config_clone = config.clone();
        let scanned_regions = regions.clone();
        let mut join_set: JoinSet<Vec<GuardDutyDetector>> = JoinSet::new();

        for region in regions {
            let cfg = config_clone.clone();
            join_set.spawn(async move {
                fetch_detectors_for_region(&cfg, &region).await
            });
        }

        let mut all_detectors: Vec<GuardDutyDetector> = Vec::new();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(detectors) => all_detectors.extend(detectors),
                Err(e) => warn!("GuardDuty region fetch task panicked: {e}"),
            }
        }

        Ok(Self {
            detectors: all_detectors,
            account_id,
            scanned_regions,
        })
    }
}

// ── Region-level fetcher ──────────────────────────────────────────────────────

async fn fetch_detectors_for_region(
    config: &aws_config::SdkConfig,
    region: &str,
) -> Vec<GuardDutyDetector> {
    let regional_cfg = config
        .to_builder()
        .region(Region::new(region.to_string()))
        .build();
    let client = GuardDutyClient::new(&regional_cfg);

    // List all detector IDs in this region
    let mut detector_ids: Vec<String> = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client.list_detectors();
        if let Some(ref t) = next_token {
            req = req.next_token(t);
        }

        match req.send().await {
            Ok(resp) => {
                for id in resp.detector_ids() {
                    detector_ids.push(id.to_string());
                }
                if resp.next_token().is_some() {
                    next_token = resp.next_token().map(|s| s.to_string());
                } else {
                    break;
                }
            }
            Err(e) => {
                warn!("list_detectors failed for region {region}: {e}");
                break;
            }
        }
    }

    // Fetch details for each detector
    let mut detectors = Vec::new();
    for detector_id in &detector_ids {
        match client.get_detector().detector_id(detector_id).send().await {
            Ok(resp) => {
                let status = resp
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_else(|| "DISABLED".to_string());
                let finding_publishing_frequency = resp
                    .finding_publishing_frequency()
                    .map(|f| f.as_str().to_string())
                    .unwrap_or_else(|| "SIX_HOURS".to_string());
                let updated_at = resp.updated_at().unwrap_or("").to_string();

                detectors.push(GuardDutyDetector {
                    detector_id: detector_id.to_string(),
                    region: region.to_string(),
                    status,
                    finding_publishing_frequency,
                    updated_at,
                });
            }
            Err(e) => {
                warn!("get_detector failed for {detector_id} in region {region}: {e}");
            }
        }
    }

    detectors
}
