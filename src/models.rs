use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Informational => write!(f, "INFORMATIONAL"),
        }
    }
}

impl Severity {
    pub fn ocsf_id(&self) -> u8 {
        match self {
            Severity::Informational => 1,
            Severity::Low => 2,
            Severity::Medium => 3,
            Severity::High => 4,
            Severity::Critical => 5,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Muted,
    Unknown,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Pass => write!(f, "PASS"),
            Status::Fail => write!(f, "FAIL"),
            Status::Muted => write!(f, "MUTED"),
            Status::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl Status {
    pub fn ocsf_id(&self) -> u8 {
        match self {
            Status::Pass => 1,
            Status::Fail => 2,
            Status::Muted => 3,
            Status::Unknown => 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceRef {
    pub framework: String,
    pub control_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub service: String,
    pub provider: String,
    pub compliance: Vec<ComplianceRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckReport {
    pub check_id: String,
    pub check_name: String,
    pub status: Status,
    pub status_extended: String,
    pub severity: Severity,
    pub resource_id: String,
    pub resource_arn: String,
    pub region: String,
    pub provider: String,
    pub service: String,
    pub account_id: String,
    pub compliance: Vec<ComplianceRef>,
    pub timestamp: String,
}
