# Cloud Threat Detection Engine

**Status**: Implemented v1.0.0 (`Milestone 5`)

## Files
- `engine.py` — Normalizes raw AWS CloudTrail (`normalize_aws_cloudtrail_event`) and Azure Activity Log (`normalize_azure_activity_event`) events, evaluates 9 deterministic detection rules (`DET-AWS-001..005`, `DET-AZ-001..004`) mapped to MITRE ATT&CK tactics/techniques, and correlates related actor activity within a configurable 30-minute window.
- `fixtures.py` — Replayable synthetic AWS CloudTrail and Azure Activity Log event fixtures (`data_source="synthetic_fixture"`) used in automated tests and local demos.

> **Honesty Boundary**: This engine uses deterministic, reproducible rule matching and time-window actor correlation — it does not advertise unimplemented ML/anomaly detection.
