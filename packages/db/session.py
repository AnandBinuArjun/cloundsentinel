"""Async SQLAlchemy 2 engine, session management, and PostgreSQL RLS tenant context."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from packages.db.base import Base


def create_db_engine(database_url: str) -> AsyncEngine:
    """Create an async SQLAlchemy engine supporting PostgreSQL (asyncpg) and SQLite (tests)."""
    return create_async_engine(database_url, pool_pre_ping=True, future=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory bound to the given engine."""
    return async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def create_all_tables(engine: AsyncEngine) -> None:
    """Create schema metadata (for local tests and ephemeral SQLite harnesses)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def set_postgres_tenant_context(session: AsyncSession, tenant_id: uuid.UUID) -> None:
    """Bind PostgreSQL session-local `app.current_tenant_id` for Row-Level Security defense-in-depth."""
    bind = session.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        await session.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": str(tenant_id)},
        )


async def get_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a scoped AsyncSession per request."""
    session_factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with session_factory() as session:
        yield session
