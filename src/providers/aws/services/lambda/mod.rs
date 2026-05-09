//! Lambda service — bulk-fetches function metadata across all regions.

use aws_sdk_lambda::Client as LambdaClient;
use aws_types::region::Region;
use std::collections::HashMap;
use tokio::task::JoinSet;
use tracing::warn;

// ── Data structures ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct LambdaVpcConfig {
    pub vpc_id: String,
    pub subnet_ids: Vec<String>,
    pub security_group_ids: Vec<String>,
}

#[allow(dead_code)]
pub struct FunctionUrlConfig {
    pub function_url: String,
    /// "AWS_IAM" or "NONE"
    pub auth_type: String,
    pub cors_allowed_origins: Vec<String>,
}

#[allow(dead_code)]
pub struct LambdaFunction {
    pub function_name: String,
    pub arn: String,
    pub region: String,
    pub runtime: String,
    pub role: String,
    pub handler: String,
    pub code_size: i64,
    pub last_modified: String,
    pub environment_variables: HashMap<String, String>,
    /// Heuristic: any env var name (uppercased) contains "KEY", "SECRET",
    /// "PASSWORD", "TOKEN", "CREDENTIAL", or "ACCESS_KEY".
    pub env_has_secrets: bool,
    pub vpc_config: Option<LambdaVpcConfig>,
    pub function_url_config: Option<FunctionUrlConfig>,
    /// Raw JSON of the resource-based policy (if any).
    pub resource_policy: Option<String>,
    /// Computed: true if the resource policy contains `"Principal": "*"`.
    pub policy_allows_public: bool,
}

#[allow(dead_code)]
pub struct LambdaService {
    pub functions: Vec<LambdaFunction>,
    pub account_id: String,
}

// ── LambdaService::new ────────────────────────────────────────────────────────

impl LambdaService {
    pub async fn new(
        config: &aws_config::SdkConfig,
        account_id: String,
        regions: Vec<String>,
    ) -> anyhow::Result<Self> {
        let config_clone = config.clone();
        let mut join_set: JoinSet<Vec<LambdaFunction>> = JoinSet::new();

        for region in regions {
            let cfg = config_clone.clone();
            join_set.spawn(async move {
                fetch_functions_for_region(&cfg, &region).await
            });
        }

        let mut all_functions: Vec<LambdaFunction> = Vec::new();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(fns) => all_functions.extend(fns),
                Err(e) => warn!("Lambda region fetch task panicked: {e}"),
            }
        }

        Ok(Self {
            functions: all_functions,
            account_id,
        })
    }
}

// ── Region-level fetcher ──────────────────────────────────────────────────────

async fn fetch_functions_for_region(
    config: &aws_config::SdkConfig,
    region: &str,
) -> Vec<LambdaFunction> {
    let regional_cfg = config
        .to_builder()
        .region(Region::new(region.to_string()))
        .build();
    let client = LambdaClient::new(&regional_cfg);

    // Paginate through all functions
    let mut function_names: Vec<(String, String)> = Vec::new(); // (name, arn)
    let mut marker: Option<String> = None;

    loop {
        let mut req = client.list_functions();
        if let Some(ref m) = marker {
            req = req.marker(m);
        }

        match req.send().await {
            Ok(resp) => {
                for f in resp.functions() {
                    let name = f.function_name().unwrap_or("").to_string();
                    let arn = f.function_arn().unwrap_or("").to_string();
                    function_names.push((name, arn));
                }
                if resp.next_marker().is_some() {
                    marker = resp.next_marker().map(|s| s.to_string());
                } else {
                    break;
                }
            }
            Err(e) => {
                warn!("list_functions failed for region {region}: {e}");
                break;
            }
        }
    }

    // For each function, fetch full config + URL config + policy in parallel
    let mut functions = Vec::new();
    for (name, _arn) in &function_names {
        if let Some(f) = fetch_function_details(&client, name, region).await {
            functions.push(f);
        }
    }

    functions
}

// ── Per-function detail fetcher ───────────────────────────────────────────────

async fn fetch_function_details(
    client: &LambdaClient,
    function_name: &str,
    region: &str,
) -> Option<LambdaFunction> {
    let (config_resp, url_resp, policy_resp) = tokio::join!(
        client.get_function_configuration().function_name(function_name).send(),
        client.list_function_url_configs().function_name(function_name).send(),
        client.get_policy().function_name(function_name).send(),
    );

    let cfg = match config_resp {
        Ok(r) => r,
        Err(e) => {
            warn!("get_function_configuration failed for {function_name}: {e}");
            return None;
        }
    };

    let function_name_str = cfg.function_name().unwrap_or("").to_string();
    let arn = cfg.function_arn().unwrap_or("").to_string();
    let runtime = cfg
        .runtime()
        .map(|r| r.as_str().to_string())
        .unwrap_or_default();
    let role = cfg.role().unwrap_or("").to_string();
    let handler = cfg.handler().unwrap_or("").to_string();
    let code_size = cfg.code_size();
    let last_modified = cfg.last_modified().unwrap_or("").to_string();

    // Environment variables
    let mut environment_variables: HashMap<String, String> = HashMap::new();
    if let Some(env) = cfg.environment() {
        for (k, v) in env.variables() {
            environment_variables.insert(k.to_string(), v.to_string());
        }
    }

    // Detect secret-like variable names
    let secret_keywords = ["SECRET", "PASSWORD", "KEY", "TOKEN", "CREDENTIAL", "ACCESS_KEY"];
    let env_has_secrets = environment_variables.keys().any(|k| {
        let upper = k.to_uppercase();
        secret_keywords.iter().any(|kw| upper.contains(kw))
    });

    // VPC config
    let vpc_config = cfg.vpc_config().and_then(|v| {
        let vpc_id = v.vpc_id().unwrap_or("").to_string();
        if vpc_id.is_empty() {
            None
        } else {
            Some(LambdaVpcConfig {
                vpc_id,
                subnet_ids: v.subnet_ids().iter().map(|s| s.to_string()).collect(),
                security_group_ids: v
                    .security_group_ids()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            })
        }
    });

    // Function URL config (first entry from the list, if any)
    let function_url_config = match url_resp {
        Ok(resp) => {
            resp.function_url_configs().first().map(|u| {
                let cors_allowed_origins = u
                    .cors()
                    .map(|c| c.allow_origins().iter().map(|s| s.to_string()).collect())
                    .unwrap_or_default();
                FunctionUrlConfig {
                    function_url: u.function_url().to_string(),
                    auth_type: u.auth_type().as_str().to_string(),
                    cors_allowed_origins,
                }
            })
        }
        Err(e) => {
            warn!("list_function_url_configs failed for {function_name}: {e}");
            None
        }
    };

    // Resource policy
    let resource_policy = match policy_resp {
        Ok(resp) => resp.policy().map(|p| p.to_string()),
        Err(e) => {
            // ResourceNotFoundException is normal when no policy exists
            let code = e
                .as_service_error()
                .and_then(|se| se.meta().code());
            if code != Some("ResourceNotFoundException") {
                warn!("get_policy failed for {function_name}: {e}");
            }
            None
        }
    };

    // Compute policy_allows_public: check for `"Principal":"*"` or `"Principal":{"AWS":"*"}`
    let policy_allows_public = resource_policy
        .as_deref()
        .map(|p| policy_has_public_principal(p))
        .unwrap_or(false);

    Some(LambdaFunction {
        function_name: function_name_str,
        arn,
        region: region.to_string(),
        runtime,
        role,
        handler,
        code_size,
        last_modified,
        environment_variables,
        env_has_secrets,
        vpc_config,
        function_url_config,
        resource_policy,
        policy_allows_public,
    })
}

// ── Policy analysis ───────────────────────────────────────────────────────────

/// Returns true if the resource policy JSON grants access to Principal "*".
fn policy_has_public_principal(policy_json: &str) -> bool {
    // Quick string-based check for common patterns:
    //   "Principal":"*"
    //   "Principal": "*"
    //   "Principal":{"AWS":"*"}
    //   "Principal": { "AWS": "*" }
    if policy_json.contains("\"Principal\":\"*\"")
        || policy_json.contains("\"Principal\": \"*\"")
    {
        return true;
    }
    // Try parsing for the nested {"AWS":"*"} case
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(policy_json) {
        return principal_is_wildcard(&val);
    }
    false
}

fn principal_is_wildcard(val: &serde_json::Value) -> bool {
    match val {
        serde_json::Value::Object(map) => {
            // Check Statement array
            if let Some(stmts) = map.get("Statement") {
                if let serde_json::Value::Array(arr) = stmts {
                    for stmt in arr {
                        if let Some(principal) = stmt.get("Principal") {
                            if principal_value_is_wildcard(principal) {
                                return true;
                            }
                        }
                    }
                }
            }
            false
        }
        _ => false,
    }
}

fn principal_value_is_wildcard(principal: &serde_json::Value) -> bool {
    match principal {
        serde_json::Value::String(s) => s == "*",
        serde_json::Value::Object(map) => {
            // {"AWS": "*"} or {"Service": "*"}
            map.values().any(|v| {
                matches!(v, serde_json::Value::String(s) if s == "*")
                    || matches!(v, serde_json::Value::Array(arr)
                        if arr.iter().any(|e| matches!(e, serde_json::Value::String(s) if s == "*")))
            })
        }
        _ => false,
    }
}
