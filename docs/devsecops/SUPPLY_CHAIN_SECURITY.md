# DevSecOps & Supply Chain Security (Phase 9)

## 1. GitHub Actions Immutable SHA Pinning

All third-party actions across `.github/workflows/ci.yml`, `.github/workflows/release.yml`, and `.github/workflows/cloud-lab-prowler.yml` are pinned to full 40-character commit SHAs:

| Action | Pinned Commit SHA | Version |
|---|---|---|
| `actions/checkout` | `11bd71901bbe5b1630ceea73d27597364c9af683` | `v4.2.2` |
| `actions/setup-python` | `a26af69be951a213d495a4c3e4e4022e16d87065` | `v5.6.0` |
| `actions/setup-node` | `49933ea5288caeca8642d1e84afbd3f7d6820020` | `v4.4.0` |
| `gitleaks/gitleaks-action` | `ff98106e4c7b2bc287b24eaf42907196329070c7` | `v2.3.9` |
| `open-policy-agent/setup-opa` | `b2b258e089860efaadaaf71bf6e3aecb4a3eeff1` | `v2.4.0` |
| `hashicorp/setup-terraform` | `b9cd54a3c349d3f38e8881555d616ced269862dd` | `v3.1.2` |
| `bridgecrewio/checkov-action` | `83b08f51b20950f791f5caadcc92e336b371eb12` | `v12.3143.0` |
| `docker/login-action` | `74a5d142397b4f367a81961eba4e8cd7edddf772` | `v3.4.0` |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | `v4.6.2` |

---

## 2. Blocking Security Gates in CI

1. **Semgrep CLI (Blocking)**: Replaced the archived `semgrep/semgrep-action@v1` with direct `semgrep==1.99.0` CLI scanning (`--config p/python --config p/typescript --config p/owasp-top-ten --error`).
2. **Checkov IaC & Dockerfile Scan (Blocking)**: Configured `soft_fail: false` in `.github/workflows/ci.yml`. Sandbox-specific Terraform lab trade-offs (`infrastructure/terraform/aws/main.tf` and `infrastructure/terraform/azure/main.tf`) carry explicit, auditable `#checkov:skip=` justifications.
3. **Trivy Container Vulnerability Gate (Blocking)**: Scans built container images with `--ignore-unfixed --severity CRITICAL,HIGH` and fails CI on any fixable `HIGH` or `CRITICAL` CVE.
4. **Release Pipeline Hardening (`.github/workflows/release.yml`)**:
   - Validates `inputs.release_version` against strict SemVer regex `^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$`.
   - Removed unused top-level `id-token: write` permission.
   - Generates CycloneDX SBOMs (`api-sbom.cdx.json`, `worker-sbom.cdx.json`, `web-sbom.cdx.json`) and executes blocking Trivy scans across all three production container images (`api`, `worker`, `web`).
