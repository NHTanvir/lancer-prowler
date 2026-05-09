pub struct Pod {
    pub name: String,
    pub namespace: String,
    pub node_name: Option<String>,
    pub service_account_name: String,
    pub host_network: bool,
    pub host_pid: bool,
    pub host_ipc: bool,
    pub containers: Vec<Container>,
    pub automount_service_account_token: Option<bool>,
}

pub struct Container {
    pub name: String,
    pub image: String,
    pub privileged: bool,
    pub allow_privilege_escalation: Option<bool>,
    pub run_as_root: Option<bool>,
    pub run_as_non_root: Option<bool>,
    pub read_only_root_filesystem: Option<bool>,
    pub capabilities_add: Vec<String>,
    pub capabilities_drop: Vec<String>,
    pub resource_limits_set: bool,
    pub resource_requests_set: bool,
}

pub struct WorkloadsService {
    pub pods: Vec<Pod>,
    pub cluster_name: String,
}

impl WorkloadsService {
    pub fn new_stub(cluster_name: String) -> Self {
        tracing::info!("Kubernetes Workloads service: stub mode");
        Self { pods: vec![], cluster_name }
    }
}
