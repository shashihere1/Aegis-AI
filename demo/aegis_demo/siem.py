"""Independent local mock SIEM: authenticated HTTP ingest and a persistent receipt viewer.

Provision once with --init, then launch in its own terminal. Never launches Azure requests.
This is a demo receiving application, not Microsoft Sentinel or Splunk.
"""

import argparse
import asyncio
import json
import os
import secrets
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from aegis.common.hashing import sha256_hex
from aegis.common.settings import REPO_ROOT, Settings
from aegis.control.siem import connector_token


def provision(directory: Path, port: int = 8011):
    directory.mkdir(parents=True, exist_ok=True)
    token_file = directory / "token"
    # Explicit init only; exclusive creation never overwrites a working credential.
    try:
        fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(secrets.token_urlsafe(48))
    if os.name == "posix":
        directory.chmod(0o700)
    connection = directory / "connection.json"
    if not connection.exists():
        with connection.open("x", encoding="utf-8") as out:
            json.dump(
                {
                    "siem_enabled": True,
                    "siem_url": f"http://127.0.0.1:{port}/events",
                    "siem_token_path": str(token_file.resolve()),
                },
                out,
            )
    else:
        previous = json.loads(connection.read_text(encoding="utf-8"))
        if previous.get("siem_url") != f"http://127.0.0.1:{port}/events":
            raise ValueError("Existing SIEM configuration uses another port; it was not overwritten.")
    # On Windows this directory inherits protected .local ACLs from local-postgres.ps1.
    return connection


def create_app(token: str, database: Path) -> FastAPI:
    if len(token) < 32:
        raise ValueError("Provision an ingestion token of at least 32 characters.")
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS received_events (event_id TEXT PRIMARY KEY, payload_hash TEXT NOT NULL, "
            "payload TEXT NOT NULL, received_at TEXT NOT NULL)"
        )
    app = FastAPI(title="Aegis local mock SIEM")

    @app.post("/events")
    async def ingest(request: Request):
        authorization = request.headers.get("authorization", "")
        if not secrets.compare_digest(authorization.encode(), f"Bearer {token}".encode()):
            raise HTTPException(401, "Invalid SIEM ingestion credential.")
        # Bound streamed input, not just a client-supplied Content-Length.
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 32768:
                raise HTTPException(413, "Event too large.")
        try:
            event = json.loads(raw)
        except ValueError:
            raise HTTPException(422, "Invalid event JSON.") from None
        if (
            not isinstance(event, dict)
            or event.get("schema") != "aegis.alert.v1"
            or not isinstance(event.get("event_id"), str)
            or not event["event_id"].startswith("alr_")
            or len(event["event_id"]) > 40
            or not isinstance(event.get("finding"), dict)
        ):
            raise HTTPException(422, "Unsupported alert envelope.")
        if request.headers.get("idempotency-key") != event["event_id"]:
            raise HTTPException(422, "Idempotency key must match the event ID.")
        digest = sha256_hex(event)
        received = datetime.now(UTC).isoformat()

        def store():
            with sqlite3.connect(database, timeout=5) as db:
                db.execute(
                    "INSERT OR IGNORE INTO received_events VALUES (?, ?, ?, ?)",
                    (event["event_id"], digest, json.dumps(event), received),
                )
                return db.execute(
                    "SELECT payload_hash, received_at FROM received_events WHERE event_id = ?", (event["event_id"],)
                ).fetchone()

        stored_hash, stored_at = await asyncio.to_thread(store)
        if stored_hash != digest:
            raise HTTPException(409, "An event ID cannot be reused with different content.")
        return {"accepted": True, "event_id": event["event_id"], "payload_hash": digest, "received_at": stored_at}

    @app.get("/events")
    async def received_events():
        # Loopback-only demo viewer. Only minimized event envelopes are stored/exposed here.
        def read():
            with sqlite3.connect(database) as db:
                return [
                    {"event": json.loads(payload), "received_at": at}
                    for payload, at in db.execute(
                        "SELECT payload, received_at FROM received_events ORDER BY received_at DESC LIMIT 100"
                    )
                ]

        return {"items": await asyncio.to_thread(read), "mock": True}

    @app.get("/", response_class=HTMLResponse)
    async def viewer():
        return """<!doctype html><html><head><meta charset="utf-8"><title>Aegis mock SIEM</title>
        <style>body{background:#0c1117;color:#dce3ea;font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px}
        h1{color:#20cf83}article{border:1px solid #303946;border-radius:12px;margin:16px 0;padding:18px}
        pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#aebdcd}small{color:#99a8b6}</style></head><body>
        <h1>Central alert inbox · Mock SIEM</h1><p>Independent receiving application. Real HTTP deliveries;
        not Sentinel, Splunk or a production SOC platform. Local synthetic demonstration only.</p>
        <small>Only minimized security identifiers/rules are received. No prompts, bank details or credentials.</small>
        <div id="events">Loading received events…</div><script>
        async function refresh(){try{const r=await fetch('/events');if(!r.ok)throw Error('Receiver unavailable');
        const data=await r.json();const root=document.getElementById('events');root.replaceChildren();
        if(!data.items.length)root.textContent='No received alerts yet. Trigger an Aegis security test.';
        for(const item of data.items){const a=document.createElement('article');const h=document.createElement('h3');
        h.textContent=item.event.finding.rule_id+' · '+item.event.finding.title;const p=document.createElement('pre');
        p.textContent=JSON.stringify(item,null,2);a.append(h,p);root.append(a)}}catch(e){
        document.getElementById('events').textContent='Could not load received events.'}}
        refresh();setInterval(refresh,1000);</script></body></html>"""

    return app


def main():
    parser = argparse.ArgumentParser(description="Provision/serve the loopback-only mock SIEM")
    parser.add_argument(
        "--init", action="store_true", help="Provision protected local configuration; no server restart"
    )
    parser.add_argument("--port", type=int, default=8011)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Use a port between 1024 and 65535.")
    directory = REPO_ROOT / ".local" / "siem"
    if args.init:
        provision(directory, args.port)
        print("Mock SIEM provisioned in Git-ignored .local/siem; no credential was printed.")
        print("New Aegis processes read this configuration. The running console was not changed.")
        return
    settings = Settings.from_env()
    token = connector_token(settings)
    app = create_app(token, directory / "received.sqlite3")
    print(f"Mock SIEM: http://127.0.0.1:{args.port}/ · separate receiver, no Azure calls")
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
