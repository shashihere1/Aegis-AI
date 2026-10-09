"""Real MCP transport over a persistent synthetic bank, accessible only through Aegis."""

import hmac
from contextvars import ContextVar

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse

from aegis_demo.bank import Execution

READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
_execution: ContextVar[Execution | None] = ContextVar("bank_execution", default=None)


def actor() -> Execution:
    result = _execution.get()
    if result is None:
        raise ValueError("A gateway-authorized task is required, not a direct MCP call.")
    return result


class BankBoundary:
    def __init__(self, app, key: str):
        self.app, self.key = app, key

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = Request(scope).headers
        if not hmac.compare_digest(headers.get("x-aegis-bank-key", "").encode(), self.key.encode()):
            return await JSONResponse({"detail": "Use the Aegis Gateway with an authorized Mandate."}, 403)(
                scope, receive, send
            )
        values = [headers.get(f"x-aegis-bank-{name}", "") for name in ("subject", "root", "mandate", "agent")]
        execution = Execution(*values) if all(values) and all(len(v) <= 120 for v in values) else None
        token = _execution.set(execution)
        try:
            await self.app(scope, receive, send)
        finally:
            _execution.reset(token)


def apps(bank, key: str) -> dict:
    servers = {
        name: FastMCP(name, stateless_http=True, json_response=True)
        for name in ("core-banking", "payments", "kyc", "docs", "crm")
    }

    @servers["core-banking"].tool(
        description="Return the current balance and IBAN of a customer's main account.", annotations=READ
    )
    async def get_balance(customer_id: str) -> dict:
        return await bank.balance(customer_id, actor())

    @servers["payments"].tool(
        description=(
            "Transfer EUR between existing synthetic sandbox accounts transactionally. No real SEPA settlement."
        ),
        annotations=WRITE,
    )
    async def initiate_transfer(
        customer_id: str, amount: float, creditor_iban: str, new_beneficiary: bool, reference: str = ""
    ) -> dict:
        return await bank.transfer(customer_id, amount, creditor_iban, new_beneficiary, reference, actor())

    @servers["payments"].tool(description="Return the status of a payment.", annotations=READ)
    async def get_payment_status(payment_id: str) -> dict:
        return await bank.payment_status(payment_id, actor())

    @servers["kyc"].tool(
        description=(
            "Check ownership, type and expiry of a stored synthetic identity document. "
            "Not genuine identity verification."
        ),
        annotations=WRITE,
    )
    async def verify_document(customer_id: str, document_id: str) -> dict:
        return await bank.verify(customer_id, document_id, actor())

    @servers["kyc"].tool(
        description="Return the recorded synthetic document-check status of a customer.", annotations=READ
    )
    async def get_kyc_status(customer_id: str) -> dict:
        return await bank.kyc_status(customer_id, actor())

    @servers["docs"].tool(description="Read a document uploaded by a customer.", annotations=READ)
    async def read_document(document_id: str) -> str:
        return await bank.document(document_id, actor())

    @servers["crm"].tool(description="Return a customer's profile.", annotations=READ)
    async def get_customer(customer_id: str) -> dict:
        return await bank.profile(customer_id, actor())

    @servers["crm"].tool(description="Update a customer's postal address.", annotations=WRITE)
    async def update_address(customer_id: str, new_address: str) -> dict:
        return await bank.update_address(customer_id, new_address, actor())

    result = {}
    for name, mcp in servers.items():
        app = mcp.streamable_http_app()
        app.add_middleware(BankBoundary, key=key)
        result[name] = app
    return result
