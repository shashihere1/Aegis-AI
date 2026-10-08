import re
from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from aegis.control.tables import Base


class Database:
    def __init__(self, url: str, schema: str = ""):
        kwargs = {}
        if schema:
            if not url.startswith("postgresql") or not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", schema):
                raise ValueError("An isolated schema requires PostgreSQL and a safe namespace identifier")
            kwargs["connect_args"] = {"server_settings": {"search_path": schema}}
        if url.startswith("sqlite") and ":memory:" in url:
            # One shared connection so every session sees the same in-memory database.
            kwargs = {"poolclass": StaticPool, "connect_args": {"check_same_thread": False}}
        self.engine: AsyncEngine = create_async_engine(url, **kwargs)
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

    async def create_all(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            if self.engine.dialect.name == "postgresql":
                # The ledger is append-only even if application code accidentally attempts a mutation.
                await conn.execute(
                    text("""
                    CREATE OR REPLACE FUNCTION aegis_ledger_immutable() RETURNS trigger AS $$
                    BEGIN RAISE EXCEPTION 'Aegis ledger is append-only'; END;
                    $$ LANGUAGE plpgsql
                """)
                )
                await conn.execute(text("DROP TRIGGER IF EXISTS aegis_ledger_immutable ON ledger_entries"))
                await conn.execute(
                    text("""
                    CREATE TRIGGER aegis_ledger_immutable BEFORE UPDATE OR DELETE ON ledger_entries
                    FOR EACH ROW EXECUTE FUNCTION aegis_ledger_immutable()
                """)
                )
                await conn.execute(text("DROP TRIGGER IF EXISTS aegis_case_immutable ON case_events"))
                await conn.execute(
                    text("""
                    CREATE TRIGGER aegis_case_immutable BEFORE UPDATE OR DELETE ON case_events
                    FOR EACH ROW EXECUTE FUNCTION aegis_ledger_immutable()
                """)
                )

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.sessionmaker() as session:
            yield session
