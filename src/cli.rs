//! CLI surface — designed for 100% feature parity with upstream `prowler --help`.
//!
//! Parity contract: every upstream flag is present here, even if the underlying
//! behavior is stubbed. Flags that lancer-prowler cannot honor (e.g. `--fix` for
//! auto-remediation, which is a read-only clone) are accepted by the parser and
//! refuse with a clear error at runtime — never silently dropped.

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "lancer-prowler",
    version,
    about = "Cloud Security Posture Management — Rust clone of Prowler",
    long_about = "lancer-prowler is a Rust reimplementation of Prowler with 100% \
                  upstream CLI parity plus a native GUI. Launch with no args to \
                  open the GUI, or use --cli (alone or before a subcommand) to fall \
                  through to the CLI surface.",
)]
pub struct Cli {
    /// Force CLI mode (default is GUI when no subcommand is given).
    #[arg(long, global = true)]
    pub cli: bool,

    /// Disable banner output (parity with upstream `--no-banner`).
    #[arg(long, global = true)]
    pub no_banner: bool,

    /// Exit code 3 is normally returned when failures were found; with this flag,
    /// always exit 0 unless a real error occurred.
    #[arg(long, global = true)]
    pub ignore_exit_code_3: bool,

    /// Quiet — suppress non-essential output (parity with upstream `--quiet`).
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Verbose — extra logging (parity with upstream `--verbose`).
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// Log level (trace | debug | info | warn | error). Parity with `--log-level`.
    #[arg(long, global = true, default_value = "warn")]
    pub log_level: String,

    /// Log to a file (parity with upstream `--log-file`).
    #[arg(long, global = true)]
    pub log_file: Option<String>,

    /// Configuration file (TOML/YAML) (parity with `--config-file`).
    #[arg(long, global = true)]
    pub config_file: Option<String>,

    /// Self-test — run the parity matrix and exit.
    #[arg(long, global = true)]
    pub self_test: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run security checks against a cloud provider.
    Scan(ScanArgs),

    /// List checks (upstream `--list-checks`).
    ListChecks(ListChecksArgs),

    /// List checks as machine-readable JSON (upstream `--list-checks-json`).
    ListChecksJson(ListChecksArgs),

    /// List supported services (upstream `--list-services`).
    ListServices(ListServicesArgs),

    /// List supported compliance frameworks (upstream `--list-compliance`).
    ListCompliance(ListComplianceArgs),

    /// List requirements within a compliance framework
    /// (upstream `--list-compliance-requirements`).
    ListComplianceRequirements(ListComplianceRequirementsArgs),

    /// List check categories (upstream `--list-categories`).
    ListCategories,

    /// List fixers (upstream `--list-fixer`). Returns the curated list of checks
    /// with an upstream `--fix` remediation. Read-only clone: `--fix` is refused
    /// at runtime, but the list is still surfaced for parity.
    ListFixer,

    /// Ingest a prior scan output (CSV / JSON-OCSF / SARIF) and merge into the
    /// pipeline (upstream `--ingest`).
    Ingest(IngestArgs),

    /// Print version.
    Version,
}

#[derive(Parser, Debug)]
#[command(about = "Run security checks against a cloud provider")]
pub struct ScanArgs {
    /// Provider to scan.
    #[arg(long, default_value = "aws")]
    pub provider: ProviderArg,

    /// Regions to scan (repeatable). Default: all.
    #[arg(long)]
    pub region: Vec<String>,

    /// Services to scan (repeatable). Default: all.
    #[arg(long, alias = "services")]
    pub service: Vec<String>,

    /// Exclude these services from the scan (repeatable).
    #[arg(long, alias = "excluded-services")]
    pub exclude_service: Vec<String>,

    /// Specific check IDs to run (repeatable).
    #[arg(long, alias = "checks")]
    pub check: Vec<String>,

    /// Read check IDs from a file (one per line) — upstream `--checks-file`.
    #[arg(long)]
    pub checks_file: Option<String>,

    /// Load extra check definitions from this folder — upstream `--checks-folder`.
    #[arg(long)]
    pub checks_folder: Option<String>,

    /// Exclude these check IDs (repeatable) — upstream `--exclude-checks`.
    #[arg(long)]
    pub exclude_checks: Vec<String>,

    /// Filter by category (repeatable) — upstream `--category`.
    #[arg(long)]
    pub category: Vec<String>,

    /// Filter by minimum severity (alias `--severity` from upstream).
    #[arg(long = "severity", alias = "severity-filter")]
    pub severity: Option<SeverityArg>,

    /// Filter by status (alias `--status` from upstream).
    #[arg(long = "status", alias = "status-filter")]
    pub status: Option<StatusArg>,

    /// Filter by compliance framework (repeatable) — upstream `--compliance`.
    #[arg(long)]
    pub compliance: Vec<String>,

    /// Output formats (repeatable) — upstream `--output-formats`.
    /// Recognised: console | csv | json-ocsf | json-asff | html | sarif | markdown.
    #[arg(long = "output-formats", alias = "output-format", value_delimiter = ',')]
    pub output_formats: Vec<OutputFormatArg>,

    /// Single output filename base (upstream `--output-filename`).
    #[arg(long, alias = "output-path")]
    pub output_filename: Option<String>,

    /// Output directory (upstream `--output-directory`).
    #[arg(long)]
    pub output_directory: Option<String>,

    /// Use Unix epoch seconds (rather than ISO 8601) for `--output-filename`
    /// timestamp suffix — upstream `--unix-timestamp`.
    #[arg(long)]
    pub unix_timestamp: bool,

    /// Disable colored terminal output.
    #[arg(long, default_value_t = false)]
    pub no_color: bool,

    /// Show interactive TUI dashboard after scan.
    #[arg(long)]
    pub tui: bool,

    /// Upload findings to AWS Security Hub.
    #[arg(long)]
    pub upload_security_hub: bool,

    /// AWS region for Security Hub upload.
    #[arg(long, default_value = "us-east-1")]
    pub security_hub_region: String,

    /// Send a Slack summary after the scan (requires SLACK_WEBHOOK_URL env or
    /// `--slack-webhook`).
    #[arg(long)]
    pub slack: bool,

    /// Override the SLACK_WEBHOOK_URL env var for this run.
    #[arg(long)]
    pub slack_webhook: Option<String>,

    /// Mutelist file (YAML) — upstream `--mutelist-file`.
    #[arg(long, alias = "allowlist-file")]
    pub mutelist_file: Option<String>,

    /// Parallel cross-check execution pool (upstream `--parallel-executions`).
    #[arg(long, default_value_t = 1)]
    pub parallel_executions: usize,

    /// Scan unused services (upstream `--scan-unused-services`).
    #[arg(long)]
    pub scan_unused_services: bool,

    /// Auto-remediate ("fixer" mode). Read-only clone: parser accepts, runtime
    /// refuses with a clear error per the parity contract.
    #[arg(long, alias = "fixer")]
    pub fix: bool,

    /// Fixer configuration file (parity stub).
    #[arg(long)]
    pub fixer_config: Option<String>,

    // ── Azure ────────────────────────────────────────────────────────────────
    #[arg(long, help = "Azure region (repeatable)")]
    pub azure_region: Vec<String>,
    #[arg(long, help = "Azure tenant ID")]
    pub tenant_id: Option<String>,
    #[arg(long, help = "Azure client ID")]
    pub client_id: Option<String>,
    #[arg(long, help = "Azure client secret")]
    pub client_secret: Option<String>,
    #[arg(long, help = "Azure auth: browser flow")]
    pub browser_auth: bool,
    #[arg(long, help = "Azure auth: service-principal env vars")]
    pub sp_env_auth: bool,
    #[arg(long, help = "Azure auth: az CLI cached creds")]
    pub cli_auth: bool,
    #[arg(long, help = "Azure auth: managed identity")]
    pub managed_identity_auth: bool,

    // ── GCP ──────────────────────────────────────────────────────────────────
    #[arg(long, help = "GCP credentials JSON file")]
    pub credentials_file: Option<String>,
    #[arg(long, help = "GCP service account to impersonate")]
    pub impersonate_service_account: Option<String>,
    #[arg(long, help = "GCP organization ID")]
    pub organization_id: Option<String>,
    #[arg(long, help = "Exclude this GCP project (repeatable)")]
    pub excluded_project_id: Vec<String>,

    // ── Kubernetes ───────────────────────────────────────────────────────────
    #[arg(long, help = "Kubeconfig file")]
    pub kubeconfig_file: Option<String>,
    #[arg(long, help = "Kubeconfig context")]
    pub context: Option<String>,
    #[arg(long, help = "Kubernetes namespace (repeatable)")]
    pub namespace: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct ListChecksArgs {
    /// Filter by provider.
    #[arg(long)]
    pub provider: Option<ProviderArg>,

    /// Filter by service.
    #[arg(long)]
    pub service: Option<String>,

    /// Filter by severity.
    #[arg(long)]
    pub severity: Option<SeverityArg>,

    /// Filter by compliance framework.
    #[arg(long)]
    pub compliance: Option<String>,
}

#[derive(Parser, Debug)]
pub struct ListServicesArgs {
    /// Filter by provider.
    #[arg(long)]
    pub provider: Option<ProviderArg>,
}

#[derive(Parser, Debug)]
pub struct ListComplianceArgs {
    /// Filter by provider.
    #[arg(long)]
    pub provider: Option<ProviderArg>,
}

#[derive(Parser, Debug)]
pub struct ListComplianceRequirementsArgs {
    /// Framework name (e.g. `cis_3.0_aws`).
    pub framework: String,
}

#[derive(Parser, Debug)]
pub struct IngestArgs {
    /// Path to the prior scan output.
    pub path: String,

    /// Format of the input file (auto-detect by extension if omitted).
    #[arg(long)]
    pub format: Option<OutputFormatArg>,

    /// Where to write the merged result set.
    #[arg(long)]
    pub output_filename: Option<String>,

    #[arg(long = "output-formats", value_delimiter = ',')]
    pub output_formats: Vec<OutputFormatArg>,
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum ProviderArg {
    Aws,
    Azure,
    Gcp,
    Kubernetes,
    M365,
    Github,
    Oci,
    Alibaba,
    Cloudflare,
    Iac,
    ContainerImage,
}

impl std::fmt::Display for ProviderArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ProviderArg::Aws => "aws",
            ProviderArg::Azure => "azure",
            ProviderArg::Gcp => "gcp",
            ProviderArg::Kubernetes => "kubernetes",
            ProviderArg::M365 => "m365",
            ProviderArg::Github => "github",
            ProviderArg::Oci => "oci",
            ProviderArg::Alibaba => "alibaba",
            ProviderArg::Cloudflare => "cloudflare",
            ProviderArg::Iac => "iac",
            ProviderArg::ContainerImage => "container-image",
        };
        write!(f, "{s}")
    }
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum OutputFormatArg {
    Console,
    Csv,
    #[value(name = "json-ocsf")]
    JsonOcsf,
    #[value(name = "json-asff")]
    JsonAsff,
    Html,
    Sarif,
    Markdown,
}

impl std::fmt::Display for OutputFormatArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OutputFormatArg::Console => "console",
            OutputFormatArg::Csv => "csv",
            OutputFormatArg::JsonOcsf => "json-ocsf",
            OutputFormatArg::JsonAsff => "json-asff",
            OutputFormatArg::Html => "html",
            OutputFormatArg::Sarif => "sarif",
            OutputFormatArg::Markdown => "markdown",
        };
        write!(f, "{s}")
    }
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl SeverityArg {
    pub fn rank(&self) -> u8 {
        match self {
            SeverityArg::Critical => 5,
            SeverityArg::High => 4,
            SeverityArg::Medium => 3,
            SeverityArg::Low => 2,
            SeverityArg::Informational => 1,
        }
    }
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum StatusArg {
    Pass,
    Fail,
    Muted,
}
