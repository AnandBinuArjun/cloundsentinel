# Compliance Framework Mappings

**Status**: Implemented v1.0.0 (`Milestone 6`)

## Files
- `frameworks.json` — Version-controlled reference mappings for:
  - **CIS AWS Foundations Benchmark** (`v3.0.0`)
  - **CIS Microsoft Azure Foundations Benchmark** (`v2.1.0`)
  - **NIST Cybersecurity Framework (CSF)** (`v2.0`)
  - **ISO/IEC 27001:2022 Annex A** (`2022`)
- `loader.py` — Loads the catalog and computes live technical coverage via `compute_compliance_posture()` from persisted `AssessmentResult` rows.

> **Governance Notice**: Every control explicitly documents `coverage_status`, `rationale`, and `limitations`. Unassessed or errored technical checks are never reported as `PASS`, and technical checks alone never establish full organizational compliance.
