use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "lancer-prowler",
    version,
    about = "Cloud Security Posture Management — Rust clone of Prowler"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Scan(ScanArgs),
    ListChecks(ListChecksArgs),
    ListServices(ListServicesArgs),
    Version,
}

#[derive(Parser, Debug)]
#[command(about = "Run security checks against a cloud provider")]
pub struct ScanArgs {
    #[arg(long, default_value = "aws", help = "Cloud provider to scan")]
    pub provider: ProviderArg,

    #[arg(long, help = "Region(s) to scan (repeatable; default: all)")]
    pub region: Vec<String>,

    #[arg(long, help = "Service(s) to scan (repeatable; default: all)")]
    pub service: Vec<String>,

    #[arg(long, help = "Specific check ID(s) to run (repeatable; default: all)")]
    pub check: Vec<String>,

    #[arg(long, default_value = "console", help = "Output format")]
    pub output_format: OutputFormatArg,

    #[arg(long, help = "Path for output file (used with csv/json-ocsf/html)")]
    pub output_path: Option<String>,

    #[arg(long, help = "Minimum severity to report")]
    pub severity_filter: Option<SeverityArg>,

    #[arg(long, help = "Filter by status")]
    pub status_filter: Option<StatusArg>,

    #[arg(long, default_value_t = false, help = "Disable colored terminal output")]
    pub no_color: bool,

    #[arg(long, help = "Show interactive TUI dashboard after scan")]
    pub tui: bool,

    #[arg(long, help = "Upload findings to AWS Security Hub")]
    pub upload_security_hub: bool,

    #[arg(long, help = "AWS region for Security Hub upload", default_value = "us-east-1")]
    pub security_hub_region: String,
}

#[derive(Parser, Debug)]
#[command(about = "List all available checks")]
pub struct ListChecksArgs {
    #[arg(long, help = "Filter by provider")]
    pub provider: Option<ProviderArg>,

    #[arg(long, help = "Filter by service")]
    pub service: Option<String>,
}

#[derive(Parser, Debug)]
#[command(about = "List all available services")]
pub struct ListServicesArgs {
    #[arg(long, help = "Filter by provider")]
    pub provider: Option<ProviderArg>,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum ProviderArg {
    Aws,
    Azure,
    Gcp,
    Kubernetes,
}

impl std::fmt::Display for ProviderArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderArg::Aws => write!(f, "aws"),
            ProviderArg::Azure => write!(f, "azure"),
            ProviderArg::Gcp => write!(f, "gcp"),
            ProviderArg::Kubernetes => write!(f, "kubernetes"),
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormatArg {
    Console,
    Csv,
    #[value(name = "json-ocsf")]
    JsonOcsf,
    Html,
}

impl std::fmt::Display for OutputFormatArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormatArg::Console => write!(f, "console"),
            OutputFormatArg::Csv => write!(f, "csv"),
            OutputFormatArg::JsonOcsf => write!(f, "json-ocsf"),
            OutputFormatArg::Html => write!(f, "html"),
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
pub enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum StatusArg {
    Pass,
    Fail,
}
