# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Backend — Async Database Engine & Session Management.

Key design decisions:
- Uses asyncpg for high-performance async PostgreSQL access.
- Every request gets its own session with `app.current_tenant` set for RLS.
- The session factory is a dependency injected into routers via FastAPI Depends().
"""

import re
import ssl
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all Phantex models."""

    pass

# ── Asyncpg-Compat Wrapper ───────────────────────────────────────────────────

_POS_PARAM_RE = re.compile(r"\$(\d+)")

class RawSessionWrapper:
    """Wrap SQLAlchemy AsyncSession to provide asyncpg-style fetch/fetchrow/execute.

    Routers written with raw asyncpg in mind (``$1``-style positional params,
    ``db.fetch()``, ``db.fetchrow()``) can use this wrapper transparently.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # -- parameter conversion --------------------------------------------------

    @staticmethod
    def _convert(sql: str, args: tuple) -> tuple[str, dict]:
        """Convert ``$1, $2, …`` positional params to ``:p1, :p2, …`` named params."""
        params: dict = {}
        for i, arg in enumerate(args, 1):
            params[f"p{i}"] = arg
        # Use regex to replace $N tokens (word-boundary aware to avoid $1 matching $10)
        converted = _POS_PARAM_RE.sub(lambda m: f":p{m.group(1)}", sql)
        return converted, params

    # -- asyncpg-like API ------------------------------------------------------

    async def fetch(self, sql: str, *args):
        """Return a list of row mappings (like asyncpg.Connection.fetch)."""
        sql, params = self._convert(sql, args)
        result = await self._session.execute(text(sql), params)
        return result.mappings().all()

    async def fetchrow(self, sql: str, *args):
        """Return a single row mapping or None (like asyncpg.Connection.fetchrow)."""
        sql, params = self._convert(sql, args)
        result = await self._session.execute(text(sql), params)
        return result.mappings().first()

    async def fetchval(self, sql: str, *args):
        """Return the first column of the first row (like asyncpg.Connection.fetchval)."""
        sql, params = self._convert(sql, args)
        result = await self._session.execute(text(sql), params)
        row = result.first()
        return row[0] if row else None

    async def execute(self, sql: str, *args) -> str:
        """Execute and return a status string (like asyncpg.Connection.execute)."""
        sql, params = self._convert(sql, args)
        result = await self._session.execute(text(sql), params)
        verb = sql.strip().split()[0].upper()
        return f"{verb} {result.rowcount}"

    async def set_tenant(self, tenant_id: str) -> None:
        """Set RLS tenant context on the underlying session."""
        import uuid as _uuid

        validated = str(_uuid.UUID(str(tenant_id)))
        # Defense-in-depth: reject anything that isn't a canonical UUID hex form
        assert re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', validated), \
            f"Invalid tenant_id format after UUID parse: {validated!r}"
        await self._session.execute(text(f"SET LOCAL app.current_tenant = '{validated}'"))

    # -- pass-through for code that uses the session directly -------------------

    def get(self, key: str, default=None):
        """Allow ``row.get()`` on the wrapper itself (shouldn't happen, but safe)."""
        return getattr(self, key, default)

# ── SSL Context Helper ───────────────────────────────────────────────────────

def _build_ssl_context(settings) -> ssl.SSLContext | str | None:
    """Build an SSL context for asyncpg based on db_ssl_mode.

    asyncpg supports passing ssl="prefer" (string) which attempts SSL
    but falls back to plaintext — matching libpq's "prefer" semantics.
    A full SSLContext forces SSL and fails if the server rejects it.
    """
    mode = settings.db_ssl_mode
    if mode == "disable":
        return None

    # "prefer" and "allow" should attempt SSL but fall back gracefully.
    # asyncpg handles this when ssl is the string "prefer".
    if mode in ("prefer", "allow"):
        return "prefer"

    ctx = ssl.create_default_context()

    if settings.db_ssl_ca_file:
        ctx.load_verify_locations(settings.db_ssl_ca_file)

    if settings.db_ssl_cert_file and settings.db_ssl_key_file:
        ctx.load_cert_chain(settings.db_ssl_cert_file, settings.db_ssl_key_file)

    if mode == "require":
        # require: encrypted but no server cert verification
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif mode == "verify-ca":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
    elif mode == "verify-full":
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

    return ctx

# ── Engine & Session Factory ──────────────────────────────────────────────────

_settings = get_settings()
_ssl_ctx = _build_ssl_context(_settings)
_connect_args: dict = {}
if _ssl_ctx is not None:
    _connect_args["ssl"] = _ssl_ctx

engine = create_async_engine(
    _settings.database_url,
    echo=_settings.db_echo_sql,
    pool_size=_settings.db_pool_size,
    max_overflow=_settings.db_pool_max_overflow,
    pool_pre_ping=True,  # Detect stale connections
    connect_args=_connect_args,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ── Admin Engine (for auth — bypasses RLS) ────────────────────────────────────
# Login and token refresh need to read users across tenants (before we know
# which tenant the user belongs to). The admin role bypasses RLS by default.
# This pool is ONLY used by the auth service — never exposed to routers.
# Credentials are configurable via PHANTEX_DB_ADMIN_USER / PHANTEX_DB_ADMIN_PASSWORD.

admin_engine = create_async_engine(
    _settings.admin_database_url,
    echo=_settings.db_echo_sql,
    pool_size=3,  # Small pool — only for auth
    max_overflow=5,
    pool_pre_ping=True,
    connect_args=_connect_args,
)

admin_session_factory = async_sessionmaker(
    admin_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ── Dependency: Session with Tenant Context ───────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield an async DB session (phantex_app role, RLS-enabled).
    Used as a FastAPI dependency for standard endpoints.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def get_raw_db() -> AsyncGenerator[RawSessionWrapper, None]:
    """
    Yield an asyncpg-compatible wrapper around an AsyncSession.

    Use this for routers written with raw ``db.fetch()`` / ``db.fetchrow()``
    / ``$1``-style positional parameters instead of SQLAlchemy ORM.

    Callers should call ``await db.set_tenant(tenant_id)`` immediately after
    obtaining the session so that RLS policies are satisfied.
    """
    async with async_session_factory() as session:
        try:
            yield RawSessionWrapper(session)
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def get_admin_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield an async DB session using the admin role (bypasses RLS).
    ONLY for auth operations (login, refresh) that need cross-tenant access.
    """
    async with admin_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def set_tenant_context(session: AsyncSession, tenant_id: str) -> None:
    """
    Set the PostgreSQL session variable for Row-Level Security.

    This is called by the tenant middleware on every authenticated request.
    PostgreSQL RLS policies check `current_setting('app.current_tenant', true)`
    to filter rows automatically.

    NOTE: Validate as UUID first to reject non-UUID input, then pass via
    text() bindparams for safe parameterized query execution.
    """
    import uuid as _uuid

    # Validate as UUID to prevent SQL injection — will raise ValueError if invalid
    validated = str(_uuid.UUID(str(tenant_id)))
    # Defense-in-depth: reject anything that isn't a canonical UUID hex form
    assert re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', validated), \
        f"Invalid tenant_id format after UUID parse: {validated!r}"
    # NOTE: SET doesn't support parameterized values ($1) in PostgreSQL.
    # UUID validation above guarantees the value is safe for interpolation.
    await session.execute(text(f"SET LOCAL app.current_tenant = '{validated}'"))

@asynccontextmanager
async def get_tenant_session(tenant_id: str) -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager that yields a session with tenant RLS pre-configured.
    Useful in background tasks or service-to-service calls.
    """
    async with async_session_factory() as session:
        await set_tenant_context(session, tenant_id)
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def check_db_health() -> bool:
    """Quick health check — can we reach the database?"""
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
            return True
    except Exception:
        return False
