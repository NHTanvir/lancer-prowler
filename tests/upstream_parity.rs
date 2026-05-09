//! Upstream parity tests — pin upstream prowler's flag combinations and the
//! canned output structures we emit. CI runs these to catch silent drift.

use std::process::Command;

const CARGO_BIN: &str = env!("CARGO_BIN_EXE_lancer-prowler");

#[test]
fn version_works() {
    let out = Command::new(CARGO_BIN)
        .arg("--cli")
        .arg("--no-banner")
        .arg("version")
        .output()
        .expect("failed to run lancer-prowler");
    assert!(out.status.success(), "version exit: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("lancer-prowler"));
}

#[test]
fn list_services_includes_new_providers() {
    let out = Command::new(CARGO_BIN)
        .arg("--cli")
        .arg("--no-banner")
        .arg("list-services")
        .output()
        .expect("failed to run list-services");
    assert!(out.status.success(), "list-services exit: {:?}", out.status);
    let s = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "aws",
        "azure",
        "gcp",
        "kubernetes",
        "m365",
        "github",
        "oci",
        "alibaba",
        "cloudflare",
        "iac",
        "container-image",
    ] {
        assert!(
            s.to_lowercase().contains(needle),
            "list-services output missing {needle}: {s}"
        );
    }
}

#[test]
fn list_compliance_finds_the_bundled_frameworks() {
    let out = Command::new(CARGO_BIN)
        .arg("--cli")
        .arg("--no-banner")
        .arg("list-compliance")
        .output()
        .expect("failed to run list-compliance");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    for f in [
        "cis_3.0_aws.json",
        "cis_microsoft_365_foundations_v4.0.0.json",
        "cis_github_benchmark_v1.0.0.json",
        "cis_azure_v3.0.0.json",
        "cis_gcp_v3.0.0.json",
        "cis_kubernetes_v1.9.0.json",
        "nis2_aws.json",
        "gdpr_aws.json",
    ] {
        assert!(s.contains(f), "list-compliance missing {f}: {s}");
    }
}

#[test]
fn list_checks_emits_checks() {
    let out = Command::new(CARGO_BIN)
        .arg("--cli")
        .arg("--no-banner")
        .arg("list-checks")
        .output()
        .expect("failed to run list-checks");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    // Sample upstream check IDs that must always be in the catalog.
    for needle in [
        "iam_root_mfa_enabled",
        "s3_bucket_public_access",
        "cloudtrail_multi_region_enabled",
        "kms_cmk_rotation_enabled",
        "rds_instance_encrypted",
    ] {
        assert!(s.contains(needle), "list-checks missing {needle}: {s}");
    }
}

#[test]
fn list_checks_json_is_valid_json() {
    let out = Command::new(CARGO_BIN)
        .arg("--cli")
        .arg("--no-banner")
        .arg("list-checks-json")
        .output()
        .expect("failed to run list-checks-json");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(&s).unwrap_or_else(|e| panic!("invalid JSON: {e}\n{s}"));
    let arr = v.as_array().expect("expected JSON array");
    assert!(!arr.is_empty(), "list-checks-json returned an empty list");
}

#[test]
fn fix_flag_is_refused_per_parity_contract() {
    let out = Command::new(CARGO_BIN)
        .arg("--cli")
        .arg("--no-banner")
        .arg("--ignore-exit-code-3")
        .arg("scan")
        .arg("--provider")
        .arg("m365")
        .arg("--fix")
        .output()
        .expect("failed to run scan --fix");
    // Should fail with a read-only message, NOT silently succeed.
    assert!(!out.status.success(), "scan --fix should refuse");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        combined.to_lowercase().contains("read-only") || combined.to_lowercase().contains("parity"),
        "scan --fix should mention the read-only / parity reason, got: {combined}"
    );
}

#[test]
fn list_fixer_surfaces_fixable_checks() {
    let out = Command::new(CARGO_BIN)
        .arg("--cli")
        .arg("--no-banner")
        .arg("list-fixer")
        .output()
        .expect("failed to run list-fixer");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("iam_password_policy_minimum_length_14"));
    assert!(s.to_lowercase().contains("read-only"));
}

#[test]
fn self_test_runs_to_completion() {
    let out = Command::new(CARGO_BIN)
        .arg("--cli")
        .arg("--no-banner")
        .arg("--self-test")
        .output()
        .expect("failed to run --self-test");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("Upstream Parity Self-Test"),
        "self-test output missing header: {s}"
    );
    assert!(s.contains("PASS"), "self-test never reported PASS: {s}");
}

#[test]
fn ingest_round_trip_csv_to_ocsf() {
    let tmp = std::env::temp_dir();
    let in_path = tmp.join("lancer-parity-ingest.csv");
    let out_path = tmp.join("lancer-parity-ingest.ocsf");

    // Tiny synthetic CSV.
    std::fs::write(
        &in_path,
        "check_id,check_name,status,severity,resource_id,resource_arn,region,provider,service,account_id,timestamp\nt1,Test,FAIL,HIGH,res-1,arn:aws:test:::res,us-east-1,aws,test,000000000000,2026-05-30T00:00:00Z\n"
    )
    .unwrap();

    let _ = std::fs::remove_file(&out_path);

    let out = Command::new(CARGO_BIN)
        .arg("--cli")
        .arg("--no-banner")
        .arg("ingest")
        .arg(in_path.to_str().unwrap())
        .arg("--format")
        .arg("csv")
        .arg("--output-formats")
        .arg("json-ocsf")
        .arg("--output-filename")
        .arg(out_path.to_str().unwrap())
        .output()
        .expect("failed to run ingest");
    assert!(
        out.status.success(),
        "ingest exit: {:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
}
