import re
from collections.abc import AsyncIterator

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from aegis.control import bank_tables  # noqa: F401 -- register additive sandbox/archive tables
from aegis.control.tables import Base


class Database:
    def __init__(self, url: str, schema: str = ""):
        self.schema = schema
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
            await self._upgrade_decision_policy_version(conn)
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
                await conn.execute(text("DROP TRIGGER IF EXISTS aegis_checkpoint_immutable ON ledger_checkpoints"))
                await conn.execute(
                    text("""
                    CREATE TRIGGER aegis_checkpoint_immutable BEFORE UPDATE OR DELETE ON ledger_checkpoints
                    FOR EACH ROW EXECUTE FUNCTION aegis_ledger_immutable()
                """)
                )
                await conn.execute(
                    text("""
                    CREATE OR REPLACE FUNCTION aegis_report_immutable() RETURNS trigger AS $$
                    BEGIN
                      IF TG_OP = 'DELETE' THEN
                        RAISE EXCEPTION 'Aegis evidence reports are immutable';
                      END IF;
                      IF NEW.id IS DISTINCT FROM OLD.id OR NEW.job_key IS DISTINCT FROM OLD.job_key
                        OR NEW.schedule_id IS DISTINCT FROM OLD.schedule_id
                        OR NEW.generated_by IS DISTINCT FROM OLD.generated_by
                        OR NEW.generated_at IS DISTINCT FROM OLD.generated_at
                        OR NEW.status IS DISTINCT FROM OLD.status
                        OR NEW.scope::jsonb IS DISTINCT FROM OLD.scope::jsonb
                        OR NEW.summary::jsonb IS DISTINCT FROM OLD.summary::jsonb
                        OR NEW.sha256 IS DISTINCT FROM OLD.sha256
                        OR NEW.key_fingerprint IS DISTINCT FROM OLD.key_fingerprint
                        OR NEW.artifact IS DISTINCT FROM OLD.artifact
                        OR NEW.error_code IS DISTINCT FROM OLD.error_code
                      THEN RAISE EXCEPTION 'Aegis evidence report content is immutable'; END IF;
                      IF OLD.reviewed_at IS NOT NULL AND (
                        NEW.reviewed_at IS DISTINCT FROM OLD.reviewed_at
                        OR NEW.reviewed_by IS DISTINCT FROM OLD.reviewed_by
                        OR NEW.review_note IS DISTINCT FROM OLD.review_note
                      ) THEN RAISE EXCEPTION 'Aegis evidence report review is immutable'; END IF;
                      RETURN NEW;
                    END;
                    $$ LANGUAGE plpgsql
                """)
                )
                await conn.execute(text("DROP TRIGGER IF EXISTS aegis_report_immutable ON evidence_reports"))
                await conn.execute(
                    text("""
                    CREATE TRIGGER aegis_report_immutable BEFORE UPDATE OR DELETE ON evidence_reports
                    FOR EACH ROW EXECUTE FUNCTION aegis_report_immutable()
                """)
                )

    @staticmethod
    async def _upgrade_decision_policy_version(conn) -> None:
        """Non-destructive, idempotent upgrade; create_all alone does not widen existing columns."""
        if conn.dialect.name != "postgresql":
            return
        columns = await conn.run_sync(lambda sync_conn: inspect(sync_conn).get_columns("decisions"))
        column = next(c for c in columns if c["name"] == "policy_version")
        length = getattr(column["type"], "length", None)
        if length is not None and length < 64:
            await conn.execute(text("ALTER TABLE decisions ALTER COLUMN policy_version TYPE VARCHAR(64)"))

    async def upgrade_schema(self) -> None:
        """Apply the targeted compatibility upgrade without starting services or touching their state."""
        async with self.engine.begin() as conn:
            # Do not queue a long exclusive-lock wait behind requests in an already-running console.
            if conn.dialect.name == "postgresql":
                await conn.execute(text("SET LOCAL lock_timeout = '3s'"))
            await self._upgrade_decision_policy_version(conn)

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.sessionmaker() as session:
            yield session
