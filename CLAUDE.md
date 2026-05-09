# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`lancer-prowler` is a Rust reimplementation of upstream [`prowler`](https://github.com/prowler-cloud/prowler) — multi-cloud security posture management. Part of the Lancer bug-bounty toolkit ecosystem. Read-only audit checks against AWS, Azure, GCP, Kubernetes, M365, GitHub, OCI, Alibaba, Cloudflare, plus IaC and container-image scanning.

The local `plan.md` is the canonical research dossier and feature-parity contract. It is gitignored — never push it. If the user updates `plan.md`, treat it as the spec to drive implementation against.

## Commands

```bash
cargo check                  # PRIMARY verification — fast, validates source
cargo check --tests          # validate test code as well
cargo test                   # run unit + integration tests (incl. tests/upstream_parity.rs)
cargo test <name>            # run a single test by name
cargo build                  # debug build (slow; see "Windows MSVC" note below)
build.bat / build-windows.bat / build-linux.sh   # produces the packaged binary
```

Do **not** run `cargo build --release` for routine verification — it is very slow on this repo and the AWS SDK crates have a pre-existing Windows MSVC stack-overflow during compilation (documented at the top of `Cargo.toml`). Use `cargo check` to validate that code compiles.

GUI is gated behind a cargo feature: `cargo check --features gui`. Default builds ship a TUI fallback (`src/gui/mod.rs`).

## Architecture

### Two surfaces, one core

`lancer-prowler` ships as **GUI by default**. Invoke with no subcommand → opens the eframe/egui window (or the TUI fallback when the `gui` feature is off). Pass `--cli` to fall through to the CLI surface. CLI flags are defined in `src/cli.rs` and chosen to mirror upstream `prowler --help` 1:1 — the parity contract is enforced by `lancer-prowler --self-test` (`src/self_test.rs`) and `tests/upstream_parity.rs`.

### Provider / Service / Check trait layout

Every cloud provider follows the same three-layer pattern, mirroring upstream prowler's Python module layout:

```
src/providers/<provider>/
  mod.rs                          # Provider impl (auth, identity, regions)
  services/<service>/mod.rs       # *Service struct: bulk-fetches state in `new()`, stores
                                  # results in plain fields. ONE instantiation per scan.
  checks/<service>/<check_id>.rs  # one struct per check, impl Check.
                                  #   metadata() returns a OnceLock<CheckMetadata>
                                  #   execute(context: &dyn Any) downcasts to the service
                                  #   and produces Vec<CheckReport>.
```

**Critical design rule:** each `<service>` is instantiated once per scan and bulk-fetches all relevant API state into in-memory fields. Individual checks borrow `&Service` and never make API calls themselves. This is the answer to N+1 API calls. When adding new AWS checks, follow this pattern — extend the service to hold the needed state and have the check iterate it synchronously.

`Check::execute` takes `&dyn Any` and downcasts to the appropriate service type — this lets the same trait object hold heterogeneous checks across providers/services. The aggregator `fn all_known_checks()` in `src/main.rs` lists every check; new checks must be added there and to the relevant `all_<service>_checks()` function so they're picked up.

### Output pipeline

`CheckReport` (`src/models.rs`) is the canonical finding type. The output module (`src/output/mod.rs`) emits to: `console`, `csv`, `json-ocsf`, `json-asff` (file form), `html`, `sarif` (GitHub Code Scanning), and `markdown`. `--output-formats a,b,c` writes all of them at once via `write_findings_multi`.

`src/security_hub.rs` is the *upload* path (separate from `output/asff.rs` which only writes the file form). The S3/IAM AWS SDK crates are wired live; other services have stubbed fetchers (see "Windows MSVC" note).

### Mutelist & filters

Findings flow through `filter_findings` (severity / status / service / check filters) and then through `Mutelist::apply` if `--mutelist-file` is set. Muted findings flip to `Status::Muted` — they are NEVER silently dropped, per upstream prowler's semantics. Default mutelist lives at `config/aws_mutelist.yaml`.

### Compliance frameworks

`compliance/*.json` files use the upstream schema (`Framework / Version / Provider / Requirements[].{Id, Description, Checks[], Attributes}`). Loaded lazily by the `list-compliance*` commands and used by the `--compliance` filter. Adding a framework = drop a new JSON file in that directory; nothing else to register.

### Lancer ecosystem integration

`src/lancer_server.rs` starts a small HTTP server on `127.0.0.1:<auto-port>` and writes the port to `%TEMP%/lancer-prowler.port` so the main Lancer GUI can discover us. Endpoints: `GET /v1/state`, `POST /v1/import`, `GET /v1/export?format=...`. This is identical across all Lancer-clone tools.

### What's stubbed and why

Documented in `Cargo.toml`. Summary:

- **aws-sdk-ec2 / aws-sdk-vpc / aws-sdk-cloudtrail / aws-sdk-kms / aws-sdk-config / aws-sdk-lambda / aws-sdk-guardduty / aws-sdk-elasticloadbalancingv2** — pinned to specific older versions in `Cargo.toml` because the latest minors crash rustc with `STATUS_STACK_BUFFER_OVERRUN` on Windows MSVC. EC2 (and the VPC subset of EC2) is stubbed entirely; the others compile live.
- **Azure / GCP / Kubernetes** — official Rust SDKs are either unstable or unavailable; provider modules return synthetic data. Real implementation would talk to the REST APIs via `reqwest`.
- **M365 / GitHub / OCI / Alibaba / Cloudflare / IaC / container-image** — full provider stubs; sample checks + sample metadata so the catalog and `--list-services` output is honest about what would be there.

When extending a stubbed service to live data, mirror the IAM/S3 services in `src/providers/aws/services/`: the `Service` struct bulk-fetches in `new()`, and the checks downcast and iterate.

### `--fix` is intentionally refused

Upstream prowler has an auto-remediation `--fixer` mode. `lancer-prowler` is read-only by design. The CLI parser accepts `--fix` (parity), but `run_scan_command` refuses at runtime with a clear error citing the parity contract. Do not silently fix this — the read-only stance is load-bearing.

## Things to avoid

- Don't add a check without registering it in the relevant `all_<service>_checks()` function in `src/main.rs` and (if it has a new check ID worth surfacing) in `fn all_known_checks()`.
- Don't bypass the service-layer state cache by calling the AWS SDK directly from a check — checks should only borrow `&Service`.
- Don't add behavior behind a CLI flag that is not in upstream prowler unless you also add it to the "our flags" list in `src/self_test.rs` so the parity matrix stays honest.
- Don't push `plan.md` — it is the local-only blueprint (in `.gitignore`).
