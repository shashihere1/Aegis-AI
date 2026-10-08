"""Real OTel spans, W3C propagation and a local database exporter (no cloud collector)."""

import asyncio
import logging

from fastapi import APIRouter, Depends, Query
from opentelemetry import propagate, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from sqlalchemy import select

from aegis.control.auth import OPERATORS, require_roles
from aegis.control.context import ctx, session
from aegis.control.tables import DecisionRecord, TraceSpan

logger = logging.getLogger(__name__)

ALLOWED_SPAN_ATTRIBUTES = {
    "http.request.method",
    "http.route",
    "http.response.status_code",
    "mcp.method.name",
    "gen_ai.agent.id",
    "gen_ai.operation.name",
    "gen_ai.tool.name",
    "gen_ai.request.model",
    "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens",
    "aegis.mandate.id",
    "aegis.user.id",
    "aegis.decision",
    "aegis.policy.version",
    "aegis.policy.rules",
}


def tracing_headers(headers: dict | None = None, context=None) -> dict:
    result = dict(headers or {})
    carrier = {}
    propagate.inject(carrier, context=context)
    # Baggage can contain arbitrary user-defined data. Forward correlation fields only.
    result.update({key: value for key, value in carrier.items() if key in {"traceparent", "tracestate"}})
    return result


class LocalExporter(SpanExporter):
    def __init__(self):
        self.pending: list[dict] = []
        self.dropped = 0

    def export(self, spans):
        for span in spans:
            if len(self.pending) >= 10_000:
                self.dropped += 1
                continue
            attributes = {k: v for k, v in (span.attributes or {}).items() if k in ALLOWED_SPAN_ATTRIBUTES}
            self.pending.append(
                {
                    "span_id": format(span.context.span_id, "016x"),
                    "trace_id": format(span.context.trace_id, "032x"),
                    "parent_id": format(span.parent.span_id, "016x") if span.parent else None,
                    "name": span.name[:200],
                    "service": span.resource.attributes.get("service.name", "aegis"),
                    "start_ns": span.start_time,
                    "end_ns": span.end_time,
                    "status": span.status.status_code.name,
                    "attributes": attributes,
                }
            )
        return SpanExportResult.SUCCESS

    def shutdown(self):
        pass

    def requeue(self, rows):
        pending = rows + self.pending
        self.dropped += max(0, len(pending) - 10_000)
        self.pending = pending[:10_000]


class Telemetry:
    def __init__(self, db):
        self.db = db
        self.exporter = LocalExporter()
        self.providers = {}
        self.flush_lock = asyncio.Lock()
        self.writer = None
        self.failed_flushes = 0

    def tracer(self, service: str):
        if service not in self.providers:
            provider = TracerProvider(resource=Resource.create({"service.name": service}), shutdown_on_exit=False)
            provider.add_span_processor(SimpleSpanProcessor(self.exporter))
            self.providers[service] = provider
        return self.providers[service].get_tracer(service)

    async def flush(self):
        async with self.flush_lock:
            rows, self.exporter.pending = self.exporter.pending, []
            if not rows:
                return
            try:
                async with self.db.sessionmaker() as s:
                    s.add_all([TraceSpan(**row) for row in rows])
                    await s.commit()
            except asyncio.CancelledError:
                self.exporter.requeue(rows)
                raise
            except Exception:
                self.exporter.requeue(rows)
                self.failed_flushes += 1
                logger.warning("Local trace export failed; spans remain queued. No audit evidence was removed.")

    async def start(self):
        if self.db.engine.dialect.name == "sqlite":
            # Explicit ephemeral tests share one SQLite connection. A background transaction
            # would interleave with domain writes; export on trace reads and shutdown instead.
            return

        async def writer():
            while True:
                await asyncio.sleep(0.25)
                await self.flush()

        self.writer = asyncio.create_task(writer())

    async def stop(self):
        if self.writer:
            self.writer.cancel()
            await asyncio.gather(self.writer, return_exceptions=True)
        await self.flush()
        for provider in self.providers.values():
            provider.shutdown()


class TraceMiddleware:
    def __init__(self, app, telemetry: Telemetry, service: str):
        self.app, self.telemetry = app, telemetry
        self.tracer = telemetry.tracer(service)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path.startswith(("/v1/traces", "/ui", "/docs", "/openapi")):
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        context = propagate.extract(headers)
        # Deliberately no headers, bodies, prompts, SQL, tokens or exception strings in the exporter.
        with self.tracer.start_as_current_span(
            f"{scope['method']} {path}", context=context, record_exception=False
        ) as span:
            span.set_attributes({"http.request.method": scope["method"], "http.route": path})

            async def traced_send(message):
                if message["type"] == "http.response.start":
                    span.set_attribute("http.response.status_code", message["status"])
                    if message["status"] >= 500:
                        span.set_status(trace.StatusCode.ERROR)
                    message.setdefault("headers", []).append(
                        (b"x-aegis-trace-id", format(span.get_span_context().trace_id, "032x").encode())
                    )
                await send(message)

            try:
                await self.app(scope, receive, traced_send)
            except Exception:
                span.set_status(trace.StatusCode.ERROR)
                raise


def router() -> APIRouter:
    r = APIRouter(prefix="/v1/traces", tags=["OpenTelemetry"], dependencies=[Depends(require_roles(*OPERATORS))])

    @r.get("")
    async def spans(
        root_id: str | None = None,
        trace_id: str | None = None,
        limit: int = Query(default=500, ge=1, le=2000),
        c=Depends(ctx),
        s=Depends(session),
    ):
        await c.telemetry.flush()
        query = select(TraceSpan)
        if root_id:
            ids = select(DecisionRecord.trace_id).where(
                DecisionRecord.root_id == root_id, DecisionRecord.trace_id.is_not(None)
            )
            query = query.where(TraceSpan.trace_id.in_(ids))
        if trace_id:
            query = query.where(TraceSpan.trace_id == trace_id)
        rows = (await s.scalars(query.order_by(TraceSpan.start_ns.desc()).limit(limit))).all()
        return {
            "spans": [
                {
                    "span_id": v.span_id,
                    "trace_id": v.trace_id,
                    "parent_id": v.parent_id,
                    "name": v.name,
                    "service": v.service,
                    "start_ns": str(v.start_ns),
                    "duration_ms": round((v.end_ns - v.start_ns) / 1_000_000, 3),
                    "status": v.status,
                    "attributes": v.attributes,
                }
                for v in reversed(rows)
            ],
            "queued": len(c.telemetry.exporter.pending),
            "dropped": c.telemetry.exporter.dropped,
            "failed_flushes": c.telemetry.failed_flushes,
        }

    return r
