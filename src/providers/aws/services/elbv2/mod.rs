//! ELBv2 service — bulk-fetches load balancer metadata across all regions.

use aws_sdk_elasticloadbalancingv2::Client as Elbv2Client;
use aws_types::region::Region;
use tokio::task::JoinSet;
use tracing::warn;

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct Listener {
    pub arn: String,
    pub port: i32,
    pub protocol: String,
    pub ssl_policy: Option<String>,
}

#[allow(dead_code)]
pub struct LoadBalancer {
    pub arn: String,
    pub name: String,
    pub region: String,
    pub scheme: String,     // "internet-facing" | "internal"
    pub lb_type: String,    // "application" | "network" | "gateway"
    pub state: String,
    pub deletion_protection: bool,
    pub access_logs_enabled: bool,
    pub drop_invalid_header_fields: bool,  // ALB only
    pub listeners: Vec<Listener>,
}

#[allow(dead_code)]
pub struct Elbv2Service {
    pub load_balancers: Vec<LoadBalancer>,
    pub account_id: String,
}

// ── Elbv2Service::new ─────────────────────────────────────────────────────────

impl Elbv2Service {
    pub async fn new(
        config: &aws_config::SdkConfig,
        account_id: String,
        regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        let config_clone = config.clone();
        let mut join_set: JoinSet<Vec<LoadBalancer>> = JoinSet::new();

        for region in regions {
            let cfg = config_clone.clone();
            join_set.spawn(async move {
                fetch_lbs_for_region(&cfg, &region).await
            });
        }

        let mut all_lbs: Vec<LoadBalancer> = Vec::new();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(lbs) => all_lbs.extend(lbs),
                Err(e) => warn!("ELBv2 region fetch task panicked: {e}"),
            }
        }

        Ok(Self {
            load_balancers: all_lbs,
            account_id,
        })
    }
}

// ── Region-level fetcher ──────────────────────────────────────────────────────

async fn fetch_lbs_for_region(
    config: &aws_config::SdkConfig,
    region: &str,
) -> Vec<LoadBalancer> {
    let regional_cfg = config
        .to_builder()
        .region(Region::new(region.to_string()))
        .build();
    let client = Elbv2Client::new(&regional_cfg);

    // Paginate through all load balancers
    let mut lb_arns: Vec<(String, String, String, String, String)> = Vec::new();
    // (arn, name, scheme, lb_type, state)
    let mut marker: Option<String> = None;

    loop {
        let mut req = client.describe_load_balancers();
        if let Some(ref m) = marker {
            req = req.marker(m);
        }

        match req.send().await {
            Ok(resp) => {
                for lb in resp.load_balancers() {
                    let arn = lb.load_balancer_arn().unwrap_or("").to_string();
                    let name = lb.load_balancer_name().unwrap_or("").to_string();
                    let scheme = lb
                        .scheme()
                        .map(|s| s.as_str().to_string())
                        .unwrap_or_else(|| "internal".to_string());
                    let lb_type = lb
                        .r#type()
                        .map(|t| t.as_str().to_string())
                        .unwrap_or_else(|| "application".to_string());
                    let state = lb
                        .state()
                        .and_then(|s| s.code())
                        .map(|c| c.as_str().to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    lb_arns.push((arn, name, scheme, lb_type, state));
                }
                if resp.next_marker().is_some() {
                    marker = resp.next_marker().map(|s| s.to_string());
                } else {
                    break;
                }
            }
            Err(e) => {
                warn!("describe_load_balancers failed for region {region}: {e}");
                break;
            }
        }
    }

    // Fetch details for each LB
    let mut load_balancers = Vec::new();
    for (arn, name, scheme, lb_type, state) in &lb_arns {
        if let Some(lb) = fetch_lb_details(&client, arn, name, region, scheme, lb_type, state).await {
            load_balancers.push(lb);
        }
    }

    load_balancers
}

// ── Per-LB detail fetcher ─────────────────────────────────────────────────────

async fn fetch_lb_details(
    client: &Elbv2Client,
    arn: &str,
    name: &str,
    region: &str,
    scheme: &str,
    lb_type: &str,
    state: &str,
) -> Option<LoadBalancer> {
    let (attrs_resp, listeners_resp) = tokio::join!(
        client
            .describe_load_balancer_attributes()
            .load_balancer_arn(arn)
            .send(),
        client
            .describe_listeners()
            .load_balancer_arn(arn)
            .send(),
    );

    let mut deletion_protection = false;
    let mut access_logs_enabled = false;
    let mut drop_invalid_header_fields = false;

    match attrs_resp {
        Ok(resp) => {
            for attr in resp.attributes() {
                match attr.key().unwrap_or("") {
                    "deletion_protection.enabled" => {
                        deletion_protection = attr.value().unwrap_or("false") == "true";
                    }
                    "access_logs.s3.enabled" => {
                        access_logs_enabled = attr.value().unwrap_or("false") == "true";
                    }
                    "routing.http.drop_invalid_header_fields.enabled" => {
                        drop_invalid_header_fields = attr.value().unwrap_or("false") == "true";
                    }
                    _ => {}
                }
            }
        }
        Err(e) => {
            warn!("describe_load_balancer_attributes failed for {arn}: {e}");
        }
    }

    let mut listeners = Vec::new();
    match listeners_resp {
        Ok(resp) => {
            for l in resp.listeners() {
                let listener_arn = l.listener_arn().unwrap_or("").to_string();
                let port = l.port().unwrap_or(0);
                let protocol = l
                    .protocol()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| "TCP".to_string());
                let ssl_policy = l.ssl_policy().map(|s| s.to_string());

                listeners.push(Listener {
                    arn: listener_arn,
                    port,
                    protocol,
                    ssl_policy,
                });
            }
        }
        Err(e) => {
            warn!("describe_listeners failed for {arn}: {e}");
        }
    }

    Some(LoadBalancer {
        arn: arn.to_string(),
        name: name.to_string(),
        region: region.to_string(),
        scheme: scheme.to_string(),
        lb_type: lb_type.to_string(),
        state: state.to_string(),
        deletion_protection,
        access_logs_enabled,
        drop_invalid_header_fields,
        listeners,
    })
}
