use crate::models::{CheckReport, Severity, Status};

/// Upload findings to AWS Security Hub in ASFF format.
/// Requires aws-sdk-securityhub already in Cargo.toml.
pub async fn upload_findings_to_security_hub(
    config: &aws_config::SdkConfig,
    findings: &[CheckReport],
    account_id: &str,
    region: &str,
) -> anyhow::Result<()> {
    use aws_sdk_securityhub::types::{
        AwsSecurityFinding, Compliance, Resource, Severity as HubSeverity,
        SeverityLabel, Workflow, WorkflowStatus, RecordState,
    };
    use aws_types::region::Region;
    use chrono::Utc;

    if findings.is_empty() {
        return Ok(());
    }

    let hub_cfg = config
        .to_builder()
        .region(Region::new(region.to_string()))
        .build();
    let client = aws_sdk_securityhub::Client::new(&hub_cfg);

    let now = Utc::now().to_rfc3339();

    // Security Hub accepts up to 100 findings per batch
    for chunk in findings.chunks(100) {
        let asff_findings: Vec<AwsSecurityFinding> = chunk
            .iter()
            .map(|f| {
                let severity_label = match f.severity {
                    Severity::Critical => SeverityLabel::Critical,
                    Severity::High => SeverityLabel::High,
                    Severity::Medium => SeverityLabel::Medium,
                    Severity::Low => SeverityLabel::Low,
                    Severity::Informational => SeverityLabel::Informational,
                };
                let workflow_status = match f.status {
                    Status::Pass => WorkflowStatus::Resolved,
                    Status::Fail => WorkflowStatus::New,
                    _ => WorkflowStatus::New,
                };
                let finding_id = format!(
                    "arn:aws:securityhub:{}:{}:product/{}/default/{}",
                    region, account_id, account_id, &f.check_id
                );

                let compliance_status = if matches!(f.status, Status::Pass) {
                    aws_sdk_securityhub::types::ComplianceStatus::Passed
                } else {
                    aws_sdk_securityhub::types::ComplianceStatus::Failed
                };

                let resource = Resource::builder()
                    .id(&f.resource_arn)
                    .r#type(&f.service)
                    .region(&f.region)
                    .build();

                AwsSecurityFinding::builder()
                    .schema_version("2018-10-08")
                    .id(&finding_id)
                    .product_arn(format!(
                        "arn:aws:securityhub:{}:{}:product/{}/default",
                        region, account_id, account_id
                    ))
                    .generator_id(format!("lancer-prowler/{}", &f.check_id))
                    .aws_account_id(account_id)
                    .types(
                        "Software and Configuration Checks/Industry and Regulatory Standards",
                    )
                    .first_observed_at(&now)
                    .last_observed_at(&now)
                    .updated_at(&now)
                    .created_at(&now)
                    .severity(HubSeverity::builder().label(severity_label).build())
                    .title(&f.check_name)
                    .description(&f.status_extended)
                    .resources(resource)
                    .compliance(
                        Compliance::builder()
                            .status(compliance_status)
                            .build(),
                    )
                    .workflow(Workflow::builder().status(workflow_status).build())
                    .record_state(RecordState::Active)
                    .build()
            })
            .collect();

        match client
            .batch_import_findings()
            .set_findings(Some(asff_findings))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.failed_count().unwrap_or(0) > 0 {
                    tracing::warn!(
                        "Security Hub: {} findings failed to import out of {}",
                        resp.failed_count().unwrap_or(0),
                        chunk.len()
                    );
                }
            }
            Err(e) => {
                tracing::error!("Security Hub batch import failed: {:#}", e);
            }
        }
    }

    Ok(())
}
