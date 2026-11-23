# Database Fixture Seeds

**Status**: Implemented v1.0.0 (`Milestone 9`)

- `seed_demo_fixtures.py` — Populates a local non-production tenant with explicitly tagged `data_source="synthetic_fixture"` AWS & Azure connectors, executes deterministic assessments, ingests synthetic CloudTrail & Azure Activity Log fixtures, and prints short-lived local dev JWT tokens (`Tenant Admin` and `Security Analyst`).
- **Safety Guard**: Refuses to execute if `CLOUDSENTINEL_ENV == "production"`. Synthetic fixtures are visibly badged across the console and never presented as live cloud evidence.
