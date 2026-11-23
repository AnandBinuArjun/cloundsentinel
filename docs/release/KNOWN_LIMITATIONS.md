# Known Limitations & Operational Boundaries (Phase 12)

In accordance with the **Proof Before Action** engineering principle, the following boundaries and limitations are explicitly documented:

1. **Live Cloud Lab Validation (`NOT_RUN` in CI)**:
   - Automated CI and local test suites validate AWS and Azure connectors using deterministic synthetic fixtures (`data_source="synthetic_fixture"`) and mocked SDK/HTTP error injection (`boto3` `ClientError`, `httpx.MockTransport` HTTP `403`/`429`/cyclic pagination).
   - Live AWS STS `AssumeRole` and Azure Workload Identity assessments against real cloud accounts require owner-provisioned sandbox credentials and manual execution of `pytest -m cloud_lab`.
2. **Live Cloud Remediation Executors Disabled by Default**:
   - `CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED` defaults to `false`.
   - The remediation engine implements the complete state machine, separation-of-duties approval workflow, dry-run simulation, and provider executor / reassessment verification contract (`ProviderExecutor` + `PostureVerifier`), but intentionally ships without destructive default cloud mutation executors enabled.
3. **In-Memory Auth Revocation & PKCE Store in Single-Node Mode**:
   - `OIDCVerifier` stores pending PKCE `state`/`nonce` challenges and revoked JWT `jti` digests in process memory by default. Multi-replica production deployments should back token revocation and rate-limit counters with the configured Redis instance (`REDIS_URL`).
4. **Compliance Posture Scope**:
   - Compliance mappings (`CIS AWS Foundations`, `CIS Azure Foundations`, `NIST CSF 2.0`, `ISO/IEC 27001:2022`) evaluate automated technical cloud configuration checks only and do not constitute formal audit certification.
