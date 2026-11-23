"""Real async connectivity probes for PostgreSQL and Redis."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

import asyncpg
import redis.asyncio as aioredis

from packages.common.config import Settings
from packages.contracts.system import DependencyCheck

ProbeFunc = Callable[[], Awaitable[DependencyCheck]]


def _normalize_postgres_dsn(database_url: str) -> str:
    """Convert SQLAlchemy asyncpg URL to native asyncpg DSN."""
    if database_url.startswith("postgresql+asyncpg://"):
        return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    return database_url


async def probe_postgres(database_url: str, timeout_seconds: float) -> DependencyCheck:
    """Verify PostgreSQL connectivity via a bounded SELECT 1 query."""
    start = time.perf_counter()
    dsn = _normalize_postgres_dsn(database_url)
    conn: Any = None
    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(dsn=dsn, timeout=timeout_seconds),
            timeout=timeout_seconds,
        )
        await asyncio.wait_for(conn.fetchval("SELECT 1"), timeout=timeout_seconds)
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return DependencyCheck(status="up", latency_ms=elapsed_ms, detail=None)
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return DependencyCheck(
            status="down",
            latency_ms=elapsed_ms,
            detail=f"PostgreSQL probe failed ({type(exc).__name__})",
        )
    finally:
        if conn is not None:
            await conn.close()


async def probe_redis(redis_url: str, timeout_seconds: float) -> DependencyCheck:
    """Verify Redis connectivity via a bounded PING command."""
    start = time.perf_counter()
    client: Any = aioredis.from_url(  # type: ignore[no-untyped-call]
        redis_url,
        socket_connect_timeout=timeout_seconds,
        socket_timeout=timeout_seconds,
    )
    try:
        pong = await asyncio.wait_for(client.ping(), timeout=timeout_seconds)
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
        if pong:
            return DependencyCheck(status="up", latency_ms=elapsed_ms, detail=None)
        return DependencyCheck(
            status="down",
            latency_ms=elapsed_ms,
            detail="Redis probe returned unexpected response",
        )
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
        return DependencyCheck(
            status="down",
            latency_ms=elapsed_ms,
            detail=f"Redis probe failed ({type(exc).__name__})",
        )
    finally:
        await client.aclose()


def build_default_probes(settings: Settings) -> dict[str, ProbeFunc]:
    """Construct the default backing service probes for GET /ready."""

    async def _check_postgres() -> DependencyCheck:
        return await probe_postgres(settings.database_url, settings.readiness_timeout_seconds)

    async def _check_redis() -> DependencyCheck:
        return await probe_redis(settings.redis_url, settings.readiness_timeout_seconds)

    return {
        "postgres": _check_postgres,
        "redis": _check_redis,
    }
