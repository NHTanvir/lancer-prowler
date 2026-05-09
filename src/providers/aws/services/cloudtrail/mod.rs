//! CloudTrail service — bulk-fetches trail configuration across all regions.

use aws_sdk_cloudtrail::Client as CloudtrailClient;
use aws_types::region::Region;
use tokio::task::JoinSet;
use tracing::warn;

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct Trail {
    pub name: String,
    pub arn: String,
    pub home_region: String,
    pub is_multi_region: bool,
    pub log_file_validation_enabled: bool,
    pub kms_key_id: Option<String>,
    pub s3_bucket_name: String,
    /// Cross-reference with S3 data not done at this layer; always false.
    pub s3_bucket_is_public: bool,
    pub cloudwatch_logs_log_group_arn: Option<String>,
    pub has_insight_selectors: bool,
    pub data_events_s3_read: bool,
    pub data_events_s3_write: bool,
    pub is_logging: bool,
}

#[allow(dead_code)]
pub struct CloudtrailService {
    pub trails: Vec<Trail>,
    pub account_id: String,
}

// ── CloudtrailService::new ────────────────────────────────────────────────────

impl CloudtrailService {
    pub async fn new(
        config: &aws_config::SdkConfig,
        account_id: String,
        regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        // Always include us-east-1 for global trail discovery
        let mut all_regions = regions.clone();
        if !all_regions.iter().any(|r| r == "us-east-1") {
            all_regions.push("us-east-1".to_string());
        }

        let config_clone = config.clone();
        let mut join_set: JoinSet<Vec<Trail>> = JoinSet::new();

        for region in all_regions {
            let cfg = config_clone.clone();
            join_set.spawn(async move {
                fetch_trails_for_region(&cfg, &region).await
            });
        }

        let mut all_trails: Vec<Trail> = Vec::new();
        let mut seen_arns: std::collections::HashSet<String> = std::collections::HashSet::new();

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(trails) => {
                    for trail in trails {
                        // Deduplicate multi-region trails by ARN
                        if seen_arns.insert(trail.arn.clone()) {
                            all_trails.push(trail);
                        }
                    }
                }
                Err(e) => warn!("CloudTrail region fetch task panicked: {e}"),
            }
        }

        Ok(Self {
            trails: all_trails,
            account_id,
        })
    }
}

// ── Region-level fetcher ──────────────────────────────────────────────────────

async fn fetch_trails_for_region(config: &aws_config::SdkConfig, region: &str) -> Vec<Trail> {
    let regional_cfg = config
        .to_builder()
        .region(Region::new(region.to_string()))
        .build();
    let client = CloudtrailClient::new(&regional_cfg);

    // describe_trails with include_shadow_trails=false returns only trails whose
    // home region is this region (avoids duplicates from multi-region shadows).
    let describe_resp = match client
        .describe_trails()
        .include_shadow_trails(false)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("describe_trails failed for region {region}: {e}");
            return vec![];
        }
    };

    let trail_list = describe_resp.trail_list();
    let mut trails = Vec::new();

    for trail_info in trail_list {
        let name = trail_info.name().unwrap_or("").to_string();
        let arn = trail_info.trail_arn().unwrap_or("").to_string();
        let home_region = trail_info.home_region().unwrap_or(region).to_string();
        let is_multi_region = trail_info.is_multi_region_trail().unwrap_or(false);
        let log_file_validation_enabled = trail_info
            .log_file_validation_enabled()
            .unwrap_or(false);
        let kms_key_id = trail_info.kms_key_id().map(|s| s.to_string());
        let s3_bucket_name = trail_info.s3_bucket_name().unwrap_or("").to_string();
        let cloudwatch_logs_log_group_arn = trail_info
            .cloud_watch_logs_log_group_arn()
            .map(|s| s.to_string());

        // Get trail logging status
        let is_logging = get_trail_status(&client, &arn).await;

        // Get event selectors for data event coverage
        let (data_events_s3_read, data_events_s3_write) =
            get_data_event_selectors(&client, &arn).await;

        trails.push(Trail {
            name,
            arn,
            home_region,
            is_multi_region,
            log_file_validation_enabled,
            kms_key_id,
            s3_bucket_name,
            s3_bucket_is_public: false,
            cloudwatch_logs_log_group_arn,
            has_insight_selectors: false,
            data_events_s3_read,
            data_events_s3_write,
            is_logging,
        });
    }

    trails
}

// ── Per-trail helpers ─────────────────────────────────────────────────────────

async fn get_trail_status(client: &CloudtrailClient, trail_arn: &str) -> bool {
    match client
        .get_trail_status()
        .name(trail_arn)
        .send()
        .await
    {
        Ok(resp) => resp.is_logging().unwrap_or(false),
        Err(e) => {
            warn!("get_trail_status failed for {trail_arn}: {e}");
            false
        }
    }
}

/// Returns (s3_read_enabled, s3_write_enabled)
async fn get_data_event_selectors(
    client: &CloudtrailClient,
    trail_arn: &str,
) -> (bool, bool) {
    match client
        .get_event_selectors()
        .trail_name(trail_arn)
        .send()
        .await
    {
        Ok(resp) => {
            let mut s3_read = false;
            let mut s3_write = false;

            // Classic event selectors
            for selector in resp.event_selectors() {
                for ds in selector.data_resources() {
                    let type_val = ds.r#type().unwrap_or("");
                    if type_val == "AWS::S3::Object" {
                        let read_write = selector
                            .read_write_type()
                            .map(|t| t.as_str())
                            .unwrap_or("");
                        if read_write == "ReadOnly" || read_write == "All" {
                            s3_read = true;
                        }
                        if read_write == "WriteOnly" || read_write == "All" {
                            s3_write = true;
                        }
                    }
                }
            }

            // Advanced event selectors
            for advanced in resp.advanced_event_selectors() {
                let mut is_s3 = false;
                let mut has_read = false;
                let mut has_write = false;

                for field_selector in advanced.field_selectors() {
                    let field = field_selector.field();
                    let values: Vec<&str> = field_selector
                        .equals()
                        .iter()
                        .map(|s| s.as_str())
                        .collect();

                    if field == "resources.type" {
                        if values.contains(&"AWS::S3::Object") {
                            is_s3 = true;
                        }
                    }
                    if field == "readOnly" {
                        if values.contains(&"false") {
                            has_write = true;
                        }
                        if values.contains(&"true") {
                            has_read = true;
                        }
                        // If readOnly is not filtered, both read and write are included
                    }
                }

                if is_s3 {
                    // If no readOnly filter exists, it covers both
                    if !has_read && !has_write {
                        s3_read = true;
                        s3_write = true;
                    } else {
                        if has_read {
                            s3_read = true;
                        }
                        if has_write {
                            s3_write = true;
                        }
                    }
                }
            }

            (s3_read, s3_write)
        }
        Err(e) => {
            warn!("get_event_selectors failed for {trail_arn}: {e}");
            (false, false)
        }
    }
}
