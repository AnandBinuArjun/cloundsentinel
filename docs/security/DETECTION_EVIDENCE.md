# Detection Pipeline & Evidence Integrity (Phase 7)

## 1. Threat Model & Trust Boundaries

`POST /api/v1/detections/ingest` accepts normalized or raw AWS CloudTrail and Azure Activity Log batches from authenticated callers with `Permission.DETECTIONS_WRITE`. Without strict validation, a caller could:
1. Inject events referencing an arbitrary `account_ref` not registered to their tenant.
2. Spoof `data_source="live"` on events belonging to a `synthetic_fixture` demo connection.
3. Replay identical events to flood detection queues.
4. Submit malformed events missing timestamps.

---

## 2. Implemented Controls

1. **Mandatory Event Timestamp & Event ID Validation**:
   - `normalize_aws_cloudtrail_event()` requires a valid ISO-8601 `eventTime` and non-empty `eventID` (when provided).
   - `normalize_azure_activity_event()` requires a valid ISO-8601 `eventTimestamp` and non-empty `eventDataId` (when provided).
   - Missing or malformed timestamps return `HTTP 422 Unprocessable Entity` instead of fabricating `datetime.now(UTC)`.
2. **Tenant CloudConnection Scope Verification**:
   - `ingest_detection_events()` verifies that every normalized event's `account_ref` matches a registered `CloudConnection` (`tenant_id == auth.tenant_id` and `provider == payload.provider`). Unregistered account references are rejected with `HTTP 403 Forbidden`.
3. **Provenance Integrity Enforcement**:
   - If the matched `CloudConnection.data_source == "synthetic_fixture"`, the persisted `DetectionEvent.data_source` is forced to `"synthetic_fixture"` even if the request payload specified `data_source="live"`.
4. **Idempotent Event Deduplication**:
   - `DetectionEvent` stores `provider_event_id` indexed by `ix_detection_events_dedup` (`tenant_id`, `provider`, `provider_event_id`, `rule_id`).
   - Re-ingesting the same `(provider_event_id, rule_id)` within the same batch or across requests skips duplicate creation and reports `duplicates_skipped` in the response and audit log.
5. **Sensitive Payload Redaction**:
   - All persisted `evidence_payload` dictionaries pass through `redact_data()` before database insertion.
