# API Scalability, Rate Limiting & Payload Hardening (Phase 8)

## 1. Overview

`apps/api/core/middleware.py` enforces pure-ASGI request hardening across all CloudSentinel API workers:

1. **`RequestIdMiddleware`**: Validates incoming `X-Request-ID` headers against `^[A-Za-z0-9._-]{1,64}$` or generates a fresh UUIDv4, binding it to structured JSON logs and response headers.
2. **`SecurityHeadersMiddleware`**: Attaches `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, and `Cache-Control: no-store`.
3. **`RequestSizeLimitMiddleware`**: Rejects HTTP requests whose `Content-Length` or streamed body exceeds `CLOUDSENTINEL_MAX_REQUEST_BODY_BYTES` (default `1,048,576` bytes / `1 MB`) with `HTTP 413 Payload Too Large`.
4. **`RateLimitMiddleware`**:
   - **Trusted-Proxy Client IP Extraction**: Only honors `X-Forwarded-For` when the immediate socket peer IP is in `CLOUDSENTINEL_TRUSTED_PROXY_HOSTS` (default `127.0.0.1,::1`). Direct untrusted clients cannot spoof `X-Forwarded-For` to bypass rate limits.
   - **Route-Class Rate Limits**:
     - `auth` (`/api/v1/auth/*`): capped at `min(limit, 30)` RPM.
     - `remediation_write` (`POST/PATCH/DELETE /api/v1/remediations/*`): capped at `min(limit, 30)` RPM.
     - `assessment_trigger` (`POST /api/v1/assessments`): capped at `min(limit, 30)` RPM.
     - `detection_ingest` (`POST /api/v1/detections/ingest`): capped at `min(limit, 60)` RPM.
     - `default`: `CLOUDSENTINEL_RATE_LIMIT_RPM` (default `120` RPM).
   - **Distributed Redis + Bounded LRU Memory Fallback**: Supports shared Redis atomic window counters (`INCR` + `EXPIRE`) across multi-worker deployments and falls back to a bounded `OrderedDict` LRU (`max_memory_keys=10,000`) when Redis is unconfigured or unreachable.
