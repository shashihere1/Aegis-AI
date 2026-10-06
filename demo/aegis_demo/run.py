"""Narrated demo of the governed-transaction core (plan §13.4). Run: python -m aegis_demo.run"""

import asyncio
import logging
import time

from aegis.sdk import AegisDenied
from aegis_demo import mcp_servers
from aegis_demo.data import LANDLORD_IBAN
from aegis_demo.world import BASE, FAKE_LLM_URL, running_world

JAN = "jan.devries"


def scene(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def say(text: str) -> None:
    print(f"  {text}")


async def mandate_status(w, mandate_id: str) -> str:
    rows = (await w.api("mark.jansen", "GET", "/v1/mandates?status=completed")).json()
    return "completed" if any(m["id"] == mandate_id for m in rows) else "active"


async def main() -> None:
    logging.disable(logging.WARNING)
    async with running_world(seed=1244, llm_upstream_url=FAKE_LLM_URL) as w:
        ids = w.agent_ids

        scene("S0  Registry at enterprise scale")
        started = time.perf_counter()
        stats = (await w.api("mark.jansen", "GET", "/v1/agents/stats")).json()
        page = (await w.api("mark.jansen", "GET", "/v1/agents?environment=PRD&cloud=azure&limit=5")).json()
        say(f"{stats['total']} agents, {page['total']} in PRD on Azure "
            f"(stats + filtered page in {(time.perf_counter() - started) * 1000:.0f} ms)")

        scene("S1  Onboarding with segregation of duties")
        for agent_id in ids.values():
            a = (await w.api("mark.jansen", "GET", f"/v1/agents/{agent_id}")).json()
            say(f"{a['name']:<28} {a['id']}  risk={a['risk_tier']:<6} {a['risk_breakdown']}  status={a['status']}")
        say("Registered by priya.raman, approved by sanne.bakker; identities provisioned with private_key_jwt keys.")

        scene("S2  Governed journey: mandate -> A2A delegation -> PII redaction")
        r = await w.ava.change_address(w.token(JAN), "C-1001", "D-77", "Keizersgracht 401, 1016 EK Amsterdam")
        claims = r["task"].claims
        say(f"Mandate {claims['aegis']['mandate_id']} for {claims['sub']}, TTL {claims['exp'] - claims['iat']} s")
        say(f"Intent categories: {claims['authorization_details'][0]['intent_categories']}")
        kyc = w.kyc_app.state.last_task.claims
        say(f"KYC delegated mandate: act chain {kyc['act']}, purpose narrowed to "
            f"{kyc['authorization_details'][0]['intent_categories']}")
        data = r["verification"]["artifacts"][0]["parts"][0]["data"]
        say(f"KYC result as seen by Ava: verified={data['verified']} bsn={data['bsn']} iban={data['iban']}")
        say(f"Task closed by Ava -> mandate status: {(await mandate_status(w, claims['aegis']['mandate_id']))}")
        summary = await w.sdks["ava"].start_task("Verify identity document for address change", w.token(JAN))
        reply = await summary.chat([{"role": "user", "content": "Confirm the address change in one sentence."}])
        await summary.complete()
        usage = (await w.api("mark.jansen", "GET", "/v1/usage")).json()[0]
        answer = reply["choices"][0]["message"]["content"]
        say(f"LLM call via gateway: {usage['input_tokens']}+{usage['output_tokens']} tokens, "
            f"EUR {usage['cost_eur']:.6f}, {usage['avg_latency_ms']} ms ('{answer}')")
        graph = (await w.api("mark.jansen", "GET", f"/v1/lineage/{r['task'].root_id}")).json()
        for e in graph["edges"]:
            say(f"lineage: {e['from']} -[{e['kind']}{'/' + e['decision'] if e.get('decision') else ''}]-> {e['to']}")

        scene("S3  High-value transfer: human approval bound to the exact action")
        flow = await w.ava.transfer(w.token(JAN), "C-1001", 25000, LANDLORD_IBAN, True)
        pending = flow["response"]["artifacts"][0]["parts"][0]["data"]
        say(f"Payments agent -> {flow['response']['status']['state']}: {pending['reasons'][0]['message']}")
        approval_id = pending["approval_id"]
        await w.api("sanne.bakker", "POST", f"/v1/approvals/{approval_id}/approve", json={"justification": "rent"})
        task, args = w.payments_app.state.pending[approval_id]
        try:
            await task.call_tool("payments", "initiate_transfer", {**args, "amount": 45000}, approval_id=approval_id)
        except AegisDenied as exc:
            say(f"Replay with EUR 45,000 using the same approval -> DENIED {exc.rules}")
        done = await w.ava.resume_transfer(flow["task"], approval_id)
        say(f"Approved by sanne.bakker -> {done['status']['state']}, payment {mcp_servers.TRANSFERS[-1]['payment_id']}")

        scene("S4  Attack: poisoned document -> containment -> cascade revocation")
        started = time.perf_counter()
        attack = await w.ava.process_uploaded_document(w.token(JAN), "C-1001", "D-99")
        for step in attack["steps"]:
            say(f"step {step['step']:<14} -> {'ok' if step['ok'] else 'DENIED ' + str(step['denied'])}")
        alerts = (await w.api("mark.jansen", "GET", "/v1/alerts")).json()
        for a in alerts:
            if a["rule_id"] in {"DET-01", "DET-02"}:
                say(f"alert {a['rule_id']} [{a['severity']}] {a['title']}")
        radius = next(a for a in alerts if a["rule_id"] == "DET-02")["actions_taken"][0]["blast_radius"]
        say(f"Playbook suspended Ava; cascade revoked {len(radius['mandates'])} mandates across "
            f"{radius['agents_affected']} in {(time.perf_counter() - started) * 1000:.0f} ms (whole scene)")
        try:
            await w.kyc_app.state.last_task.call_tool("kyc", "get_kyc_status", {"customer_id": "C-1001"})
        except AegisDenied as exc:
            say(f"KYC agent's delegated mandate now fails: {exc}")
        say(f"Emails actually sent: {len(mcp_servers.SENT_EMAILS)}")

        scene("S5  Shadow agent discovery")
        await w.http.post(f"{BASE}/gw/mcp/crm", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "get_customer", "arguments": {"customer_id": "C-1001"}}},
            headers={"x-api-key": "static-key", "user-agent": "marketing-lead-scraper/0.3"})
        w.ctx.idp.register_unmanaged_client("marketing-lead-scraper", "Marketing lead scraper")
        await w.api("mark.jansen", "POST", "/v1/discovery/scan")
        for f in (await w.api("mark.jansen", "GET", "/v1/discovery/findings")).json():
            say(f"finding {f['fingerprint']} via {f['sources']} ({f['hits']} hit)")

        scene("S8  Evidence")
        ledger = (await w.api("eva.visser", "GET", "/v1/ledger/verify")).json()
        decisions = (await w.api("eva.visser", "GET", "/v1/decisions?limit=500")).json()
        say(f"Ledger: {ledger['entries']} hash-chained entries, integrity ok={ledger['ok']}")
        say(f"Decisions recorded: {len(decisions)} "
            f"({', '.join(sorted({d['decision'] for d in decisions}))}), policy {decisions[0]['policy_version']}")


if __name__ == "__main__":
    asyncio.run(main())
