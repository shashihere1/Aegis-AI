"""MCP server and tool registry: import, pinning, poisoning scan, classification, approval (plan §8.6)."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common.hashing import tool_definition_hash
from aegis.common.ids import new_id
from aegis.common.models import McpServerCreate, ToolClassification
from aegis.control import ledger
from aegis.control.auth import OPERATORS, require_roles
from aegis.control.context import ControlContext, session
from aegis.control.identity.idp import Persona
from aegis.control.tables import Alert, McpServer, Tool
from aegis.guard.detectors import scan_tool_description

MCP_HEADERS = {"accept": "application/json, text/event-stream", "content-type": "application/json"}


def tool_dict(t: Tool) -> dict:
    return {
        "id": t.id, "server_id": t.server_id, "name": t.name, "description": t.description,
        "input_schema": t.input_schema, "annotations": t.annotations, "definition_hash": t.definition_hash,
        "approved_hash": t.approved_hash, "classification": t.classification,
        "poisoning_findings": t.poisoning_findings, "status": t.status,
    }


def default_classification(annotations: dict) -> dict:
    """MCP annotations are hints from the server and are only used as defaults (servers can lie)."""
    read_only = annotations.get("readOnlyHint", False)
    destructive = annotations.get("destructiveHint", True)
    side_effect = "read" if read_only else "destructive" if destructive else "write"
    egress = "external" if annotations.get("openWorldHint", False) else "none"
    return ToolClassification(side_effect=side_effect, egress=egress).model_dump()


async def list_upstream_tools(c: ControlContext, url: str) -> list[dict]:
    response = await c.http.post(url, headers=MCP_HEADERS,
                                 json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    response.raise_for_status()
    return response.json()["result"]["tools"]


async def quarantine_tool(s: AsyncSession, tool: Tool, reason: str, actor: str, upstream: dict | None = None) -> None:
    if tool.status == "quarantined":
        return
    tool.status = "quarantined"
    s.add(Alert(id=new_id("alr"), rule_id="DET-03", severity="high", title=f"Tool {tool.id} quarantined: {reason}",
                evidence={"tool": tool.id, "approved_hash": tool.approved_hash, "upstream": upstream or {}}))
    await ledger.append(s, "tool.quarantined", actor, tool.id, {"reason": reason})


def router() -> APIRouter:
    r = APIRouter(prefix="/v1", tags=["mcp-registry"])

    @r.post("/mcp/servers", status_code=201)
    async def register_server(body: McpServerCreate, s: AsyncSession = Depends(session),
                              user: Persona = Depends(require_roles("agent-developer", "admin"))):
        if await s.get(McpServer, body.id):
            raise HTTPException(409, "server already registered")
        s.add(McpServer(**body.model_dump()))
        await ledger.append(s, "mcp.server.registered", f"user:{user.username}", body.id, body.model_dump())
        await s.commit()
        return body

    @r.get("/mcp/servers", dependencies=[Depends(require_roles(*OPERATORS))])
    async def list_servers(s: AsyncSession = Depends(session)):
        return [{"id": m.id, "url": m.url, "owner": m.owner, "vendor": m.vendor, "status": m.status}
                for m in (await s.execute(select(McpServer))).scalars()]

    @r.post("/mcp/servers/{server_id}/import")
    async def import_tools(server_id: str, request: Request, s: AsyncSession = Depends(session),
                           user: Persona = Depends(require_roles("agent-developer", "admin"))):
        """Fetch tools/list, pin each definition, scan for poisoning, quarantine changed definitions."""
        server = await s.get(McpServer, server_id)
        if server is None:
            raise HTTPException(404, "unknown server")
        c: ControlContext = request.app.state.ctx
        result = {"new": [], "unchanged": [], "drifted": []}
        for upstream in await list_upstream_tools(c, server.url):
            tool_id = f"{server_id}.{upstream['name']}"
            digest = tool_definition_hash(upstream)
            tool = await s.get(Tool, tool_id)
            if tool is None:
                scan = scan_tool_description(f"{upstream.get('description', '')}\n{upstream.get('inputSchema', {})}")
                s.add(Tool(
                    id=tool_id, server_id=server_id, name=upstream["name"],
                    description=upstream.get("description") or "", input_schema=upstream.get("inputSchema") or {},
                    annotations=upstream.get("annotations") or {}, definition_hash=digest,
                    classification=default_classification(upstream.get("annotations") or {}),
                    poisoning_findings=scan.findings if scan.injection else [],
                ))
                result["new"].append(tool_id)
            elif digest != tool.definition_hash:
                tool.definition_hash = digest
                tool.description = upstream.get("description") or ""
                tool.input_schema = upstream.get("inputSchema") or {}
                if tool.approved_hash and digest != tool.approved_hash:
                    await quarantine_tool(s, tool, "definition changed after approval (possible rug pull)",
                                          f"user:{user.username}", upstream)
                result["drifted"].append(tool_id)
            else:
                result["unchanged"].append(tool_id)
        await ledger.append(s, "mcp.tools.imported", f"user:{user.username}", server_id, result)
        await s.commit()
        return result

    @r.get("/tools", dependencies=[Depends(require_roles(*OPERATORS))])
    async def list_tools(server: str | None = None, s: AsyncSession = Depends(session)):
        query = select(Tool).where(Tool.server_id == server) if server else select(Tool)
        return [tool_dict(t) for t in (await s.execute(query.order_by(Tool.id))).scalars()]

    @r.put("/tools/{tool_id}/classification")
    async def classify(tool_id: str, body: ToolClassification, s: AsyncSession = Depends(session),
                       user: Persona = Depends(require_roles("agent-developer", "admin"))):
        tool = await s.get(Tool, tool_id)
        if tool is None:
            raise HTTPException(404, "unknown tool")
        tool.classification = body.model_dump()
        await ledger.append(s, "tool.classified", f"user:{user.username}", tool_id, tool.classification)
        await s.commit()
        return tool_dict(tool)

    @r.post("/tools/{tool_id}/approve")
    async def approve(tool_id: str, override: bool = False, s: AsyncSession = Depends(session),
                      user: Persona = Depends(require_roles("security-approver"))):
        tool = await s.get(Tool, tool_id)
        if tool is None:
            raise HTTPException(404, "unknown tool")
        if tool.poisoning_findings and not override:
            raise HTTPException(409, {"message": "tool description looks poisoned; security override required",
                                      "findings": tool.poisoning_findings})
        tool.status, tool.approved_hash = "approved", tool.definition_hash
        await ledger.append(s, "tool.approved", f"user:{user.username}", tool_id,
                            {"hash": tool.approved_hash, "override": override})
        await s.commit()
        return tool_dict(tool)

    @r.post("/tools/{tool_id}/quarantine")
    async def quarantine(tool_id: str, s: AsyncSession = Depends(session),
                         user: Persona = Depends(require_roles("security-approver", "soc-analyst"))):
        tool = await s.get(Tool, tool_id)
        if tool is None:
            raise HTTPException(404, "unknown tool")
        await quarantine_tool(s, tool, "manual quarantine", f"user:{user.username}")
        await s.commit()
        return tool_dict(tool)

    return r
