# Third-party components and licences

Versions as installed on 2026-10-05 (see `requirements.lock`). All are open source; none is grey-listed.

| Component | Version | Licence | Used for |
|---|---|---|---|
| FastAPI | 0.142.2 | MIT | Control plane, Gateway and demo agent APIs |
| Starlette | 1.7.0 | BSD-3-Clause | ASGI routing (via FastAPI) |
| Uvicorn | 0.54.0 | BSD-3-Clause | ASGI server |
| Pydantic | 2.13.5 | MIT | Schemas and settings |
| HTTPX | 0.28.1 | BSD-3-Clause | Service-to-service HTTP |
| python-multipart | 0.0.32 | Apache-2.0 | Form parsing for the OAuth token endpoints |
| PyJWT | 2.15.1 | MIT | JWT signing and verification |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | ES256 keys |
| SQLAlchemy | 2.1.3 | MIT | Persistence |
| aiosqlite | 0.22.1 | MIT | Local database driver |
| MCP Python SDK (`mcp`) | 1.30.0 | MIT | Mock-bank MCP servers |
| AnyIO | 4.15.1 | MIT | Async runtime (via Starlette/MCP) |
| OpenTelemetry API / SDK | 1.45.0 | Apache-2.0 | Tracing |
| pytest | 9.1.1 | MIT | Tests (dev only) |
| pytest-asyncio | 1.4.0 | Apache-2.0 | Async tests (dev only) |
| Ruff | 0.16.10 | MIT | Linting (dev only) |

**Console (`web/`, npm through the Infy Artifactory mirror):**

| Component | Version | Licence | Used for |
|---|---|---|---|
| React / React DOM | 19.3.0 | MIT | UI |
| React Router | 7.18.4 | MIT | Routing |
| TanStack Query | 5.104.1 | MIT | Data fetching and live polling |
| React Flow (`@xyflow/react`) | 12.12.0 | MIT | Lineage graph |
| Lucide icons | 1.52.0 | ISC | Icons |
| Tailwind CSS (+ Vite plugin) | 4.3.3 | MIT | Styling |
| Vite (+ React plugin) | 7.3.7 | MIT | Build (dev only) |
| TypeScript | 5.8.3 | Apache-2.0 | Type checking (dev only) |

Optional, not installed by default: `asyncpg` (Apache-2.0, PostgreSQL), `redis` (MIT, Valkey client),
Open Policy Agent (Apache-2.0, policy sidecar).

Policy reason codes, taxonomy and demo data are original to this project. Demo personas and customers are
fictional; BSNs and IBANs are generated and valid only in format.
