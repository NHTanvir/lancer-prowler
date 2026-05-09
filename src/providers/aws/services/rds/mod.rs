//! RDS service — bulk-fetches DB instance and snapshot metadata across all regions.

use aws_sdk_rds::Client as RdsClient;
use aws_types::region::Region;
use tokio::task::JoinSet;
use tracing::warn;

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct RdsInstance {
    pub db_instance_id: String,
    pub arn: String,
    pub region: String,
    pub engine: String,
    pub engine_version: String,
    pub storage_encrypted: bool,
    pub publicly_accessible: bool,
    pub multi_az: bool,
    /// Days of automated backup retention; 0 means backups are disabled.
    pub backup_retention_period: i32,
    pub auto_minor_version_upgrade: bool,
    pub master_username: String,
    pub db_instance_class: String,
    pub deletion_protection: bool,
    pub enhanced_monitoring_enabled: bool,
    pub performance_insights_enabled: bool,
}

#[allow(dead_code)]
pub struct RdsSnapshot {
    pub snapshot_id: String,
    pub arn: String,
    pub region: String,
    pub db_instance_id: String,
    pub encrypted: bool,
    pub is_public: bool,
    /// "manual" or "automated"
    pub snapshot_type: String,
}

#[allow(dead_code)]
pub struct RdsService {
    pub instances: Vec<RdsInstance>,
    pub snapshots: Vec<RdsSnapshot>,
    pub account_id: String,
}

// ── RdsService::new ───────────────────────────────────────────────────────────

impl RdsService {
    pub async fn new(
        config: &aws_config::SdkConfig,
        account_id: String,
        regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        let config_clone = config.clone();
        let mut join_set: JoinSet<(Vec<RdsInstance>, Vec<RdsSnapshot>)> = JoinSet::new();

        for region in regions {
            let cfg = config_clone.clone();
            join_set.spawn(async move {
                fetch_rds_for_region(&cfg, &region).await
            });
        }

        let mut all_instances: Vec<RdsInstance> = Vec::new();
        let mut all_snapshots: Vec<RdsSnapshot> = Vec::new();

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok((instances, snapshots)) => {
                    all_instances.extend(instances);
                    all_snapshots.extend(snapshots);
                }
                Err(e) => warn!("RDS region fetch task panicked: {e}"),
            }
        }

        Ok(Self {
            instances: all_instances,
            snapshots: all_snapshots,
            account_id,
        })
    }
}

// ── Region-level fetcher ──────────────────────────────────────────────────────

async fn fetch_rds_for_region(
    config: &aws_config::SdkConfig,
    region: &str,
) -> (Vec<RdsInstance>, Vec<RdsSnapshot>) {
    let regional_cfg = config
        .to_builder()
        .region(Region::new(region.to_string()))
        .build();
    let client = RdsClient::new(&regional_cfg);

    let (instances, snapshots) = tokio::join!(
        fetch_instances(&client, region),
        fetch_snapshots(&client, region),
    );

    (instances, snapshots)
}

// ── Instance fetcher ──────────────────────────────────────────────────────────

async fn fetch_instances(client: &RdsClient, region: &str) -> Vec<RdsInstance> {
    let mut instances = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut req = client.describe_db_instances();
        if let Some(ref m) = marker {
            req = req.marker(m);
        }

        match req.send().await {
            Ok(resp) => {
                for db in resp.db_instances() {
                    let db_instance_id = db.db_instance_identifier().unwrap_or("").to_string();
                    let arn = db.db_instance_arn().unwrap_or("").to_string();
                    let engine = db.engine().unwrap_or("").to_string();
                    let engine_version = db.engine_version().unwrap_or("").to_string();
                    let storage_encrypted = db.storage_encrypted().unwrap_or(false);
                    let publicly_accessible = db.publicly_accessible().unwrap_or(false);
                    let multi_az = db.multi_az().unwrap_or(false);
                    let backup_retention_period = db.backup_retention_period().unwrap_or(0);
                    let auto_minor_version_upgrade = db.auto_minor_version_upgrade().unwrap_or(false);
                    let master_username = db.master_username().unwrap_or("").to_string();
                    let db_instance_class = db.db_instance_class().unwrap_or("").to_string();
                    let deletion_protection = db.deletion_protection().unwrap_or(false);
                    let enhanced_monitoring_enabled =
                        db.enhanced_monitoring_resource_arn().is_some();
                    let performance_insights_enabled =
                        db.performance_insights_enabled().unwrap_or(false);

                    instances.push(RdsInstance {
                        db_instance_id,
                        arn,
                        region: region.to_string(),
                        engine,
                        engine_version,
                        storage_encrypted,
                        publicly_accessible,
                        multi_az,
                        backup_retention_period,
                        auto_minor_version_upgrade,
                        master_username,
                        db_instance_class,
                        deletion_protection,
                        enhanced_monitoring_enabled,
                        performance_insights_enabled,
                    });
                }

                if resp.marker().is_some() {
                    marker = resp.marker().map(|s| s.to_string());
                } else {
                    break;
                }
            }
            Err(e) => {
                warn!("describe_db_instances failed for region {region}: {e}");
                break;
            }
        }
    }

    instances
}

// ── Snapshot fetcher ──────────────────────────────────────────────────────────

async fn fetch_snapshots(client: &RdsClient, region: &str) -> Vec<RdsSnapshot> {
    let mut snapshots = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut req = client
            .describe_db_snapshots()
            .snapshot_type("manual");
        if let Some(ref m) = marker {
            req = req.marker(m);
        }

        match req.send().await {
            Ok(resp) => {
                for snap in resp.db_snapshots() {
                    let snapshot_id = snap.db_snapshot_identifier().unwrap_or("").to_string();
                    let arn = snap.db_snapshot_arn().unwrap_or("").to_string();
                    let db_instance_id = snap.db_instance_identifier().unwrap_or("").to_string();
                    let encrypted = snap.encrypted().unwrap_or(false);
                    let snapshot_type = snap.snapshot_type().unwrap_or("manual").to_string();

                    // Check whether this snapshot is publicly accessible
                    let is_public =
                        check_snapshot_public(client, &snapshot_id).await;

                    snapshots.push(RdsSnapshot {
                        snapshot_id,
                        arn,
                        region: region.to_string(),
                        db_instance_id,
                        encrypted,
                        is_public,
                        snapshot_type,
                    });
                }

                if resp.marker().is_some() {
                    marker = resp.marker().map(|s| s.to_string());
                } else {
                    break;
                }
            }
            Err(e) => {
                warn!("describe_db_snapshots failed for region {region}: {e}");
                break;
            }
        }
    }

    snapshots
}

// ── Snapshot public-access helper ─────────────────────────────────────────────

/// Returns true if the `restore` attribute contains the literal value `"all"`,
/// which means the snapshot is publicly accessible.
async fn check_snapshot_public(client: &RdsClient, snapshot_id: &str) -> bool {
    match client
        .describe_db_snapshot_attributes()
        .db_snapshot_identifier(snapshot_id)
        .send()
        .await
    {
        Ok(resp) => {
            if let Some(result) = resp.db_snapshot_attributes_result() {
                for attr in result.db_snapshot_attributes() {
                    if attr.attribute_name().unwrap_or("") == "restore" {
                        return attr
                            .attribute_values()
                            .iter()
                            .any(|v| v == "all");
                    }
                }
            }
            false
        }
        Err(e) => {
            warn!("describe_db_snapshot_attributes failed for {snapshot_id}: {e}");
            false
        }
    }
}
