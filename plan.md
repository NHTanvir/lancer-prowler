# RESEARCH DOSSIER: Prowler

> Part of the Lancer ecosystem. A Rust clone of Prowler — multi-cloud security posture management. Build with Claude Code.
> Upstream: github.com/prowler-cloud/prowler (Python, v5 has UI; CLI scope is what we clone). 600+ AWS / 167 Azure / 102 GCP / 83 K8s checks.

## Feature Parity Mandate

**`lancer-prowler` MUST ship with 100% feature parity to the upstream `prowler` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `prowler --help` (and the long-form man page / docs) must work in `lancer-prowler --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-prowler` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-prowler --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

Prowler is a multi-cloud security posture management (CSPM) tool written in Python. It performs read-only audit checks against AWS, Azure, GCP, Kubernetes, M365, GitHub, OCI, Alibaba Cloud, and Cloudflare. As of 2026, it ships **600+ AWS checks** across **84 services**, **167 Azure checks** (22 services), **102 GCP checks** (18 services), and **83 Kubernetes checks** (7 services). Each check returns a `Check_Report` with status (PASS/FAIL/MUTED), severity, and compliance-framework mappings. Output formats: CSV, JSON-OCSF, JSON-ASFF (for AWS Security Hub), HTML dashboard, native Security Hub upload. The deliverable is **finding evidence with framework attribution** — not just "what's wrong" but "which CIS / NIST / PCI-DSS control just failed."

## Internal architecture (with file refs)

Repo entry points:
- `prowler-cli.py` — top-level CLI launcher (just bootstraps `prowler.__main__`)
- `prowler/__main__.py` — orchestrator
- `prowler/lib/check/check.py` — check discovery/execution engine
- `prowler/lib/check/models.py` — `Check`, `Check_Report_AWS`, `CheckMetadata`, severity enum
- `prowler/lib/check/compliance.py` — compliance framework loader

Provider layout:
```
prowler/providers/
  aws/
    aws_provider.py            # AwsProvider: session, identity, audit metadata
    services/
      iam/
        iam_service.py         # IAMClient wraps boto3, bulk-fetches state once
        iam_password_policy_minimum_length_14/
          __init__.py
          iam_password_policy_minimum_length_14.py        # check class
          iam_password_policy_minimum_length_14.metadata.json  # static metadata
      ec2/
      s3/
      ...
  azure/services/...
  gcp/services/...
  kubernetes/services/...
```

**Critical design rule:** each `<service>/<service>_service.py` is instantiated **once** per scan and bulk-fetches all relevant API state into in-memory objects (lists, dicts). Individual check classes then iterate that in-memory state without making API calls. This is Prowler's answer to N+1 API calls.

**Check base class** (`prowler/lib/check/models.py`):
```python
class Check(ABC, ABCMeta):
    @abstractmethod
    def execute(self) -> list[Check_Report]: ...
    def metadata(self) -> CheckMetadata: ...  # loaded from sibling .metadata.json
```

**Check discovery** (`prowler/lib/check/check.py`): `import_check()` dynamically constructs `prowler.providers.{provider}.services.{service}.{check_name}.{check_name}` and uses `getattr(module, check_name)` to grab the class. `execute_checks()` iterates a sorted check list and calls `.execute()` on each instance, with progress shown by `alive_bar`.

**Parallelism (or lack of it):** Prowler executes checks **sequentially** in a single thread. Concurrency exists only at the *service-fetch* layer where each `*_service.py` uses `ThreadPoolExecutor` for per-region/per-resource boto3 calls. There is no multiprocessing of checks themselves. **For a Rust clone this is the single biggest performance win**: tokio + `tokio::task::JoinSet` over checks within a service, and `JoinSet` over services within a provider.

**State management:** `AwsProvider` holds boto3 `Session`, identity (`get_caller_identity`), audit resources, regions list, output options. A check accesses provider state through `iam_client` singletons imported from `iam_client.py` — a module-level instance pattern. Replicate this in Rust with `Arc<ServiceState>` injected into a `Context` object passed to every check.

## Compliance framework mapping

Framework JSONs live in `prowler/compliance/<provider>/`:

AWS frameworks shipped (verified from repo):
- `cis_1.4_aws.json`, `cis_1.5_aws.json`, `cis_2.0_aws.json`, `cis_3.0_aws.json`, `cis_4.0_aws.json`, `cis_5.0_aws.json`, `cis_6.0_aws.json`
- `nist_800_53_revision_4_aws.json`, `nist_800_53_revision_5_aws.json`
- `nist_800_171_revision_2_aws.json`
- `nist_csf_1.1_aws.json`, `nist_csf_2.0_aws.json`
- `pci_3.2.1_aws.json`, `pci_4.0_aws.json`
- `iso27001_2013_aws.json`, `iso27001_2022_aws.json`
- `soc2_aws.json`, `hipaa_aws.json`
- `fedramp_low_revision_4_aws.json`, `fedramp_moderate_revision_4_aws.json`, `fedramp_ksi_low_2.0x_aws.json`
- `gdpr_aws.json`
- `ens_rd2022_aws.json` (Spanish ENS)
- `nis2_aws.json`, `secnumcloud_3.2_aws.json`, `kisa_isms_p_2023_aws.json`
- `aws_foundational_security_best_practices_aws.json`
- `aws_well_architected_framework_security_pillar_aws.json`
- `aws_well_architected_framework_reliability_pillar_aws.json`
- `mitre_attack_aws.json`, `csa_ccm_4.0_aws.json`, `prowler_threatscore_aws.json`

Each is a list of requirements; each requirement has `Id`, `Description`, `Attributes` (free-form metadata per framework), and `Checks: [check_id, ...]`. Loading is via `prowler/lib/check/compliance.py: load_compliance_framework()` → JSON parse → `ComplianceFramework` dataclass. At report time, a check ID is reverse-looked-up against every loaded framework to attribute findings.

## Complete catalog (top 100 AWS checks)

**IAM (highest finding density)** — `iam_root_hardware_mfa_enabled`, `iam_root_mfa_enabled`, `iam_no_root_access_key`, `iam_password_policy_minimum_length_14`, `iam_password_policy_uppercase`, `iam_password_policy_lowercase`, `iam_password_policy_symbol`, `iam_password_policy_number`, `iam_password_policy_reuse_24`, `iam_password_policy_expires_passwords_within_90_days_or_less`, `iam_user_mfa_enabled_console_access`, `iam_user_no_setup_initial_access_key`, `iam_user_two_active_access_key`, `iam_rotate_access_key_90_days`, `iam_inline_policy_no_administrative_privileges`, `iam_customer_attached_policy_no_administrative_privileges`, `iam_aws_attached_policy_no_administrative_privileges`, `iam_policy_attached_only_to_group_or_roles`, `iam_policy_no_full_access_to_cloudtrail`, `iam_policy_no_full_access_to_kms`, `iam_avoid_root_usage`, `iam_check_saml_providers_sts`, `iam_support_role_created`, `iam_role_cross_account_readonlyaccess_policy`, `iam_policy_allows_privilege_escalation`.

**S3** — `s3_bucket_public_access`, `s3_bucket_acl_prohibited`, `s3_account_level_public_access_blocks`, `s3_bucket_level_public_access_block`, `s3_bucket_default_encryption`, `s3_bucket_kms_encryption`, `s3_bucket_secure_transport_policy`, `s3_bucket_server_access_logging_enabled`, `s3_bucket_no_mfa_delete`, `s3_bucket_object_versioning`, `s3_bucket_object_lock`, `s3_bucket_cross_account_access`.

**EC2** — `ec2_securitygroup_allow_ingress_from_internet_to_any_port`, `..._to_port_22`, `..._to_port_3389`, `ec2_securitygroup_default_restrict_traffic`, `ec2_securitygroup_not_used`, `ec2_securitygroup_allow_wide_open_public_ipv4`, `ec2_ebs_default_encryption`, `ec2_ebs_volume_encryption`, `ec2_ebs_snapshot_encrypted`, `ec2_ebs_public_snapshot`, `ec2_instance_imdsv2_enabled`, `ec2_instance_public_ip`, `ec2_instance_secrets_user_data`, `ec2_instance_paravirtual_type`, `ec2_instance_managed_by_ssm`, `ec2_instance_internet_facing_with_instance_profile`, `ec2_ami_public`, `ec2_elastic_ip_unassigned`.

**CloudTrail** — `cloudtrail_multi_region_enabled`, `cloudtrail_logs_s3_bucket_is_not_publicly_accessible`, `cloudtrail_log_file_validation_enabled`, `cloudtrail_kms_encryption_enabled`, `cloudtrail_s3_dataevents_read_enabled`, `cloudtrail_s3_dataevents_write_enabled`, `cloudtrail_cloudwatch_logging_enabled`, `cloudtrail_threat_detection_privilege_escalation`, `cloudtrail_threat_detection_enumeration`.

**VPC** — `vpc_flow_logs_enabled`, `vpc_endpoint_connections_trust_boundaries`, `vpc_subnet_no_public_ip_by_default`, `vpc_different_regions`, `vpc_peering_routing_tables_with_least_privilege`.

**RDS** — `rds_instance_encrypted`, `rds_instance_public_access`, `rds_instance_default_admin`, `rds_instance_backup_enabled`, `rds_instance_multi_az`, `rds_instance_minor_version_upgrade_enabled`, `rds_instance_storage_encrypted`, `rds_snapshots_public_access`, `rds_snapshots_encrypted`.

**KMS / Lambda / CloudFront / EFS / Secrets / GuardDuty / Security Hub / Config / ELB** — see prowler-cloud/prowler `prowler/providers/aws/services/`.

## Engineering hard parts

**Bulk-fetch pattern (avoiding N+1):** every Rust `*_service.rs` must wrap an `aws_sdk_*` client and on `new()` issue all list/describe calls in parallel with `tokio::join!` or `JoinSet`. Store results in `Arc<RwLock<ServiceState>>`. Checks then borrow `&ServiceState` synchronously.

**Cross-region:** AWS gives us a regional endpoint per region. Build per-region `aws_sdk_ec2::Client` instances cached in a `HashMap<Region, Client>`. Use `Arc<Client>` to share across tasks. Iterate user-supplied region list (default: `Ec2Client::new(...).describe_regions()`).

**Global services (IAM, S3-ListBuckets, CloudFront, Route53, Organizations, WAF Global, Shield):** issue calls in `us-east-1` and tag findings region `global`. **S3 is a trap**: `ListBuckets` is global but `GetBucketLocation`/`GetBucketPolicy` must be issued against the bucket's *home region* and the bucket-region SDK client must be region-specific or you get HTTP 301 redirects.

**Azure differences from AWS:**
- Authentication via Azure Identity (`azure_identity` crate) with `DefaultAzureCredential` chain (env → managed identity → CLI → interactive).
- Resource model is `/subscriptions/{id}/resourceGroups/{rg}/providers/...` not regional buckets.
- Pagination uses `nextLink` URLs, not tokens.
- Many services live behind ARM (`management.azure.com`) but data-plane operations (e.g., KeyVault) use a different host.

**GCP differences:**
- Auth via service-account JSON or ADC (Application Default Credentials).
- Projects are the unit (not accounts). Multi-project enumeration via Resource Manager.
- Many APIs need to be **enabled** per-project — handle `googleapi: Error 403: ... has not been used` gracefully.

## Rust library mapping (with versions, as of 2026)

```toml
[dependencies]
# AWS — one crate per service used
aws-config = "1.8"
aws-sdk-iam = "1.109"
aws-sdk-s3 = "1.133"
aws-sdk-ec2 = "1.150"
aws-sdk-cloudtrail = "1.90"
aws-sdk-cloudwatch = "1.90"
aws-sdk-kms = "1.85"
aws-sdk-lambda = "1.100"
aws-sdk-rds = "1.110"
aws-sdk-cloudfront = "1.85"
aws-sdk-config = "1.85"
aws-sdk-guardduty = "1.85"
aws-sdk-securityhub = "1.85"
aws-sdk-secretsmanager = "1.85"
aws-sdk-ssm = "1.85"
aws-sdk-organizations = "1.85"
aws-sdk-elasticloadbalancingv2 = "1.85"
aws-sdk-route53 = "1.85"

# Azure
azure_core = "0.21"
azure_identity = "0.21"
azure_mgmt_storage = "0.21"
azure_mgmt_compute = "0.21"
azure_mgmt_keyvault = "0.21"

# GCP
google-cloud-iam = "0.5"
google-cloud-storage = "0.20"
google-cloud-compute = "0.5"
google-cloud-auth = "0.16"

# Kubernetes
kube = { version = "3.1", features = ["runtime", "derive"] }
k8s-openapi = { version = "0.27", features = ["latest"] }

# Output
serde = { version = "1", features = ["derive"] }
serde_json = "1"
csv = "1.3"
tera = "1.20"
comfy-table = "7.2"
ratatui = "0.30"
indicatif = "0.17"

# Runtime
tokio = { version = "1.40", features = ["full"] }
anyhow = "1.0"
thiserror = "1.0"
tracing = "0.1"
tracing-subscriber = "0.3"
```

## SDK-specific gotchas

- `aws-config` default chain (in order): env vars → SSO → web identity → ECS task role → IMDS → profile from `~/.aws/credentials`. Build once: `let config = aws_config::defaults(BehaviorVersion::v2025_01_17()).load().await;`. Reuse for every service client to avoid redundant token refreshes.
- **Paginators:** `client.list_users().into_paginator().send()` returns a stream; use `.items().send()` to flatten and `try_collect::<Vec<_>>()` to materialize. Always handle `SdkError::ServiceError` separately from `SdkError::TimeoutError` — service-level `AccessDenied` is informational (skip check), network errors should retry.
- **Global services:** force `us-east-1`: `let cfg = config.clone().to_builder().region(Region::new("us-east-1")).build();`.
- **S3 bucket region resolution:** `head_bucket()` returns `x-amz-bucket-region`; or use `get_bucket_location()`. Cache per-bucket region.
- **ECR auth:** `get_authorization_token()` returns base64 `username:password` — split on `:`.
- **Lambda Function URLs:** `list_function_url_configs()` per function.

## Validation environment

- **LocalStack Pro** (community S3/IAM/EC2/Lambda are decent, but compliance-grade fidelity is in Pro). Free tier suffices for ~70% of checks.
- **Sandbox AWS account** with [aws-nuke](https://github.com/rebuy-de/aws-nuke) for resets. Seed with intentionally insecure Terraform from `cloudgoat`.
- **Azure**: free trial subscription + bicep deploy of vulnerable resources.
- **GCP**: free credits + Terraform `goat` lab.
- **Kubernetes**: `kind create cluster` + Helm chart of intentionally vulnerable workloads (`kube-goat`).

## 2024-2026 state

- v5 (2025) added the UI/API split (Django REST + Next.js) — your CLI clone doesn't need this but the OCSF JSON output is now the canonical format. Adopt it.
- `prowler_threatscore_aws.json` (new in 2025): a curated threat-modelled framework — implement this as a first-class output.
- M365, GitHub, Cloudflare providers added in 2025. Skip for v1 of clone.

### 2026-05-30 research note (vs upstream v5.28.1)

**Verified upstream provider catalog (as of 5.28.1, May 2026):**
- AWS: 600 checks / 84 services
- Azure: 167 checks / 22 services
- GCP: 102 checks / 18 services
- Kubernetes: 83 checks / 7 services
- **M365: 102 checks / 10 services** (was bootstrapped in 5.3; major expansion through 5.x — Teams, Defender, Purview, Exchange, AdminCenter, Entra ID, SharePoint, OneDrive)
- **GitHub: 24 checks / 3 services** (repository / workflow / org settings; `zizmor`-backed workflow scanning)
- **OCI: 51 checks / 14 services** (Oracle Cloud Infrastructure)
- **Alibaba Cloud: 63 checks / 9 services**
- **Cloudflare: 29 checks / 3 services**
- **MongoDB Atlas, Google Workspace, OpenStack, Vercel, Okta, NHN, Scaleway, StackIT, VMware/Broadcom VCF, IaC (Terraform/CloudFormation/Dockerfile/K8s manifests), container-image scanning** — all live in 5.x; treat as v2 scope but the trait surface must accommodate them now.

**Compliance frameworks — gaps to add to the loader (verified 44+ frameworks shipped):**
- **M365**: CIS Microsoft 365 Foundations Benchmark v4.0.0
- **Azure**: CIS Azure 2.x/3.x, NIST 800-53 r5, ISO 27001:2022, PCI 4.0
- **GCP**: CIS GCP 2.x/3.0, NIST 800-53 r5, ISO 27001:2022
- **Kubernetes**: CIS Kubernetes Benchmark, NSA-CISA Hardening Guidance, MITRE-ATT&CK Containers
- **GitHub**: CIS GitHub Benchmark
- **AWS additions since dossier**: ASD Essential Eight Maturity Model, BSI C5, FFIEC, RBI, GxP, KSA-CCC, expanded CIS up to v6.0
- **All providers**: NIS2 (EU), GDPR mapping, custom-framework loader (user YAML/JSON) — supported upstream, must be supported here.

**Output formats — additions vs dossier:**
- **SARIF** (already in parity contract; restate: required for GitHub Code Scanning integration when scanning IaC).
- **PDF compliance reports** (failed-findings focus, per-framework executive summary) — new in 5.x; render via `printpdf` or headless Chromium fallback.
- **Slack notification** integration (post finding summary).
- **AWS Security Hub** native upload (ASFF format) — already mentioned but restate: requires `batch_import_findings` with throttle/back-off.
- **JSON-OCSF v1.1+** canonical (the upstream emits 1.1, watch for 1.2 drift).
- **Imported-scan ingestion** — Prowler Cloud accepts third-party scan output; mirror this as a `--ingest` flag for our CSV/JSON.

**Allowlist / mutelist (must implement):**
- Upstream `--mutelist-file <path>` (YAML). Schema: `Mutelist.Accounts.<account>.Checks.<check_id>.Regions: [...]; Resources: [...]; Tags: [...]; Description: ...`. Mutes are NOT silent — they emit status `MUTED` (counted separately from PASS/FAIL).
- Default mutelist at `prowler/config/aws_mutelist.yaml`. Ship our own at `lancer-prowler/config/<provider>_mutelist.yaml`.
- Regex match on resource ARN; wildcard on account; tag-key/tag-value match.

**Parallelism — actual upstream flags to mirror:**
- `--parallel-executions <N>` (5.x): cross-check parallel pool — upstream now does support inter-check parallelism (revise the dossier claim that it's purely sequential — that was true in 3.x/4.x, no longer true in 5.x).
- `--scan-unused-services` toggle.
- Per-provider region/subscription/project fan-out flags: `--region`, `--subscription-id`, `--project-id`, `--namespace`.

**Threat-detection mode (new):**
- `cloudtrail_threat_detection_*` family (privilege escalation, enumeration, defense-evasion). Read-time pattern matching against CloudTrail event JSON. Requires `lookup_events` paginator.
- Behavioral signal scoring fed into `prowler_threatscore_<provider>.json` framework — exists for AWS, Azure, GCP, K8s, M365 in 5.x.

**Prowler Cloud SaaS (out-of-scope for CLI parity but informs OCSF schema):**
- Attack-path visualization (React Flow + Neo4j backend) — out of scope, but the underlying graph is built from `relationships[]` arrays in OCSF records; emit those fields so downstream tools can graph.
- ThreatScore dashboard with redesigned pillar visualization — emit the score in OCSF + a `--threatscore` CLI flag.
- Alerts system with custom rules and email delivery — out of scope.
- "View in Console" deep-links — emit `console_url` per finding (AWS console URL builder per resource type).
- Claude Code plugin for remediation workflows — out of scope, but `remediation.code.aws_cli` / `remediation.code.terraform` fields in OCSF must be populated.

**CLI flags to verify against upstream `prowler --help` (add to parity matrix):**
- `--checks`, `--checks-file`, `--checks-folder`, `--exclude-checks`, `--severity`, `--service`, `--exclude-service`, `--compliance`, `--category`, `--status`
- `--list-checks`, `--list-checks-json`, `--list-services`, `--list-compliance`, `--list-compliance-requirements`, `--list-categories`, `--list-fixer`
- `--output-formats`, `--output-filename`, `--output-directory`, `--unix-timestamp`
- `--quiet`, `--log-level`, `--log-file`, `--verbose`
- `--config-file`, `--fixer-config`
- `--no-banner`, `--slack`, `--ignore-exit-code-3`
- `--azure-region`, `--tenant-id`, `--client-id`, `--client-secret`, `--browser-auth`, `--sp-env-auth`, `--cli-auth`, `--managed-identity-auth`
- `--credentials-file` (GCP), `--impersonate-service-account`, `--organization-id`, `--excluded-project-id`
- `--kubeconfig-file`, `--context`, `--namespace`
- `--fix` / `--fixer` (auto-remediation mode — new in 5.x; mark **out of scope for read-only clone** but parser must accept and refuse with clear error)

## Real-world authorized usage

Bugcrowd / HackerOne cloud programs almost always require **ReadOnlyAccess + SecurityAudit** managed policies on a provided IAM user/role. Prowler is **fully read-only** for AWS; the only "write" operations are `iam:GenerateCredentialReport` (which is benign). Run it from a workstation with the program's credentials, scope by `--region` and `--service`, export `--output-formats csv json-ocsf html`. Audit log footprint: CloudTrail records every API call — programs expect this. Always set a custom user-agent for attribution.

## AI augmentation ideas

- **Risk ranking:** LLM scores each finding against business context the hunter provides ("this is a payment processor"). Map to CVSS and bug-bounty payout tiers.
- **Exploit chain suggestion:** feed Prowler findings → Pacu module map. If `iam_policy_allows_privilege_escalation` PASSes negatively (i.e., is exploitable), suggest the matching Pacu privesc module.
- **Compliance gap narrative:** generate a per-framework executive summary by joining failed checks with their compliance attributions.
- **False positive triage:** classify each FAIL as `true_positive`/`needs_review`/`probable_fp` using LLM + the `status_extended` text.

## Implementation phases (12 weeks)

| Week | Deliverable |
|------|-------------|
| 1 | Repo skeleton: `lancer-prowler` crate, `Provider`/`Service`/`Check` traits, OCSF output schema, CLI parser (clap) |
| 2 | `aws-config` integration, region discovery, global-service handling, IAM service bulk-fetch |
| 3 | IAM checks (25 checks above). Compliance JSON loader. CIS 3.0 mapping. |
| 4 | S3 service + 12 S3 checks. Bucket region resolution. Public-access logic. |
| 5 | EC2 service + 18 EC2/SG/EBS checks. Per-region client cache. |
| 6 | CloudTrail + KMS + Config services + their checks. |
| 7 | VPC, RDS, Lambda services + checks. |
| 8 | Remaining AWS services to hit 200 checks. CSV/JSON-OCSF/HTML (tera template) output. |
| 9 | Azure provider skeleton (auth, subscription enumeration) + 30 Azure checks (Storage, KeyVault, VMs). |
| 10 | GCP provider skeleton + 25 GCP checks (IAM, Storage, Compute). |
| 11 | Kubernetes provider (`kube` crate) + 20 K8s checks. |
| 12 | TUI dashboard (ratatui), Security Hub upload, benchmark vs upstream Prowler (target: >5x faster on 600-check AWS scan). |

---

## GUI (Lancer-standard pattern)

`lancer-prowler` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-prowler-cli` companion binary), but the **plain `lancer-prowler` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-prowler/`, `%APPDATA%\lancer-prowler\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-prowler-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-prowler.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-prowler.exe` (double-click opens the GUI window).
- Linux: `build/lancer-prowler` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-prowler` (bundled into `lancer-prowler.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-prowler/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-prowler.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-prowler-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-prowler
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-prowler.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-prowler-windows-x86_64\bin\lancer-prowler.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-prowler`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
