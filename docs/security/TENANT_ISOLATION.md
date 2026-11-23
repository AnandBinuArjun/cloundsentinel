# CloudSentinel — Multi-Tenant PostgreSQL Isolation & RLS Specification

**Phase**: Phase 2 (`P0`)  
**Implementation**:
- [database/migrations/versions/0003_security_hardening_schema.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/database/migrations/versions/0003_security_hardening_schema.py)
- [packages/db/session.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/packages/db/session.py)
- [packages/auth/dependencies.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/packages/auth/dependencies.py)

---

## 1. Defense-in-Depth Architecture

CloudSentinel enforces tenant isolation across three independent layers:

1. **Application Query Filtering**: Every SQLAlchemy `SELECT`, `UPDATE`, and `DELETE` includes an explicit `.where(Model.tenant_id == auth.tenant_id)` predicate derived strictly from the server-verified `AuthContext`.
2. **PostgreSQL Row-Level Security (`ENABLE` + `FORCE ROW LEVEL SECURITY`)**:
   - Enabled and forced on all 14 tenant-scoped tables (`memberships`, `cloud_connections`, `cloud_accounts`, `assets`, `assessment_profiles`, `assessment_runs`, `assessment_results`, `findings`, `finding_history`, `evidence`, `detection_events`, `remediation_requests`, `remediation_approvals`, `audit_events`).
   - Enforces both `USING` (for `SELECT`, `UPDATE`, `DELETE`) and `WITH CHECK` (for `INSERT`, `UPDATE`) against `NULLIF(current_setting('app.current_tenant_id', true), '')::uuid`.
   - Fails closed: when `app.current_tenant_id` is empty or unset, `NULLIF(..., '')::uuid` evaluates to `NULL`, matching zero rows and rejecting any `INSERT` or `UPDATE`.
3. **Privilege Separation (`cloudsentinel_app` vs. Migration Owner)**:
   - Migration `0003_security_hardening_schema` creates the non-owner runtime role `cloudsentinel_app` (`NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`).
   - Because `FORCE ROW LEVEL SECURITY` is enabled on every tenant-scoped table, even table-owner connections in CI/dev are subject to RLS policies unless explicitly granted `BYPASSRLS`.

---

## 2. Session Lifecycle & Bootstrap Authentication Ordering

1. **Connection Checkout Cleanup**: `get_db_session()` calls `reset_postgres_tenant_context(session)` (`SELECT set_config('app.current_tenant_id', '', false)`) both when a session is yielded and inside the `finally:` block before returning the connection to the SQLAlchemy pool, preventing pooled-connection context leakage.
2. **Pre-Membership Context Binding**: In `get_auth_context()`, after cryptographic JWT verification extracts `claims.tenant_id`, `await set_postgres_tenant_context(session, claims.tenant_id)` is executed **before** querying `memberships`, allowing the RLS policy on `memberships` to authorize only membership rows belonging to `claims.tenant_id`.
3. **Worker Context Verification**: Background Celery tasks bind `set_postgres_tenant_context(session, tenant_uuid)` and call `verify_postgres_tenant_context(session, tenant_uuid)` before querying `cloud_connections` or persisting assessment results.
