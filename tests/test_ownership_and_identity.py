"""Control 12: agents can be managed only by their owner, and separation of duties compares people, not usernames."""

import asyncio
import copy
import json

import jwt
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from test_oidc import FakeProvider, settings, verifier

from aegis.common.crypto import SigningKey
from aegis.common.settings import Settings
from aegis.control.db import Database
from aegis.control.identity.idp import DevIdp, Persona
from aegis.control.identity.oidc import OidcConfig, OidcVerifier
from aegis.control.identity.people import PersonDirectory
from aegis.control.identity.users import UserAuthenticator
from aegis.control.tables import PersonLink
from aegis_demo.data import LANDLORD_IBAN

BODY = {"name": "Mortgage-Advice-Agent", "purpose": "Answer mortgage questions for customers.",
        "intent_categories": ["customer.inquiry.read"], "owner": "niels.vandijk", "sponsor": "retail.ops.head",
        "capabilities": ["core-banking.get_balance"]}


def add(world, username, roles, person_id=None):
    world.ctx.idp.add_persona(Persona(username, username.title(), roles, person_id=person_id))


# ---- agent ownership ----


async def test_an_owner_cannot_suspend_modify_or_retire_someone_elses_agent(world):
    add(world, "other.owner", ["agent-owner"])
    ava = world.agent_ids["ava"]  # owned by niels.vandijk
    for method, path, body in (("POST", "suspend", {}), ("PATCH", "", {"description": "x"}), ("POST", "retire", {}),
                               ("POST", "submit", {})):
        denied = await world.api("other.owner", method, f"/v1/agents/{ava}/{path}".rstrip("/"), json=body)
        assert denied.status_code == 403 and "OWN-001" in denied.text, (method, path, denied.text)
    agent = (await world.api("mark.jansen", "GET", f"/v1/agents/{ava}")).json()
    assert agent["status"] == "active" and agent["description"] != "x"


async def test_the_owner_can_suspend_and_modify_their_own_agent(world):
    ava = world.agent_ids["ava"]
    edited = await world.api("niels.vandijk", "PATCH", f"/v1/agents/{ava}", json={"description": "Owner edit"})
    assert edited.status_code == 200 and edited.json()["description"] == "Owner edit"
    suspended = await world.api("niels.vandijk", "POST", f"/v1/agents/{ava}/suspend", json={"reason": "owner stop"})
    assert suspended.status_code == 200 and suspended.json()["agent"]["status"] == "suspended"


async def test_incident_roles_can_still_suspend_any_agent(world):
    for index, username in enumerate(("mark.jansen", "sanne.bakker")):
        agent_id = world.agent_ids["kyc-agent" if index == 0 else "payments-agent"]
        response = await world.api(username, "POST", f"/v1/agents/{agent_id}/suspend", json={})
        assert response.status_code == 200, response.text


async def test_the_owners_second_account_counts_as_the_owner(world):
    add(world, "niels.vandijk.alt", ["agent-owner"], person_id="niels.vandijk")
    response = await world.api("niels.vandijk.alt", "POST", f"/v1/agents/{world.agent_ids['ava']}/suspend", json={})
    assert response.status_code == 200


async def test_the_registrant_can_edit_but_not_suspend_and_admin_can_manage_any_agent(world):
    ava = world.agent_ids["ava"]  # registered by priya.raman, owned by niels.vandijk
    assert (await world.api("priya.raman", "PATCH", f"/v1/agents/{ava}", json={"description": "dev edit"})
            ).status_code == 200
    assert (await world.api("priya.raman", "POST", f"/v1/agents/{ava}/suspend", json={})).status_code == 403
    assert (await world.api("admin", "PATCH", f"/v1/agents/{ava}", json={"description": "admin edit"})
            ).status_code == 200
    assert (await world.api("admin", "POST", f"/v1/agents/{ava}/retire", json={})).status_code == 200


async def test_only_the_owner_can_attest(world):
    add(world, "other.owner", ["agent-owner"])
    ava = world.agent_ids["ava"]
    assert (await world.api("other.owner", "POST", f"/v1/agents/{ava}/attest")).status_code == 403
    assert (await world.api("niels.vandijk", "POST", f"/v1/agents/{ava}/attest")).status_code == 200


# ---- separation of duties across one person's accounts ----


async def test_a_second_account_of_the_registrant_cannot_approve_their_agent(world):
    add(world, "priya.raman.approver", ["risk-approver"], person_id="Priya.Raman")  # same person, other account
    agent = (await world.api("priya.raman", "POST", "/v1/agents", json=BODY)).json()
    await world.api("priya.raman", "POST", f"/v1/agents/{agent['id']}/submit")
    own = await world.api("priya.raman.approver", "POST", f"/v1/agents/{agent['id']}/approve", json={})
    assert own.status_code == 403 and "SOD-001" in own.text
    approved = await world.api("sanne.bakker", "POST", f"/v1/agents/{agent['id']}/approve", json={})
    assert approved.status_code == 200


async def test_a_second_account_of_the_owner_cannot_approve_their_agent(world):
    add(world, "niels.vandijk.approver", ["risk-approver"], person_id="niels.vandijk")
    agent = (await world.api("priya.raman", "POST", "/v1/agents", json=BODY)).json()
    await world.api("priya.raman", "POST", f"/v1/agents/{agent['id']}/submit")
    own = await world.api("niels.vandijk.approver", "POST", f"/v1/agents/{agent['id']}/approve", json={})
    assert own.status_code == 403 and "SOD-001" in own.text


async def test_a_second_account_of_the_policy_author_cannot_approve_the_policy(world):
    add(world, "priya.raman.policy-approver", ["policy-approver"], person_id="priya.raman")
    active = (await world.api("priya.raman", "GET", "/v1/policies")).json()
    config = copy.deepcopy(active["data"])
    config["thresholds"]["payments"]["hitl_amount_eur"] = 2000
    draft = await world.api("priya.raman", "POST", "/v1/policies/versions", json={
        "name": "Same person", "configuration": config, "justification": "Review payment exposure"})
    assert draft.status_code == 201, draft.text
    vid = draft.json()["id"]
    await world.api("priya.raman", "POST", f"/v1/policies/{vid}/replay", json={})
    await world.api("priya.raman", "POST", f"/v1/policies/{vid}/submit")
    own = await world.api("priya.raman.policy-approver", "POST", f"/v1/policies/{vid}/approve",
                          json={"justification": "Self review through my other account"})
    assert own.status_code == 403 and "own policy" in own.text
    other = await world.api("fatima.elamrani", "POST", f"/v1/policies/{vid}/approve",
                            json={"justification": "Independent review"})
    assert other.status_code == 200


async def test_the_approver_of_an_action_cannot_be_the_initiators_other_account(world):
    add(world, "jan.devries.staff", ["risk-approver"], person_id="jan.devries")
    flow = await world.ava.transfer(world.token("jan.devries"), "C-1001", 25000, LANDLORD_IBAN, True)
    approval_id = flow["response"]["artifacts"][0]["parts"][0]["data"]["approval_id"]
    own = await world.api("jan.devries.staff", "POST", f"/v1/approvals/{approval_id}/approve", json={})
    assert own.status_code == 403 and "SOD-003" in own.text
    assert (await world.api("sanne.bakker", "POST", f"/v1/approvals/{approval_id}/approve", json={})
            ).status_code == 200


# ---- the person directory ----


def idp() -> DevIdp:
    return DevIdp("http://control.test/idp", SigningKey.load_or_generate("", "idp-1"))


async def database() -> Database:
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.create_all()
    return db


async def test_configured_links_win_over_the_claim_and_the_name():
    people = PersonDirectory({"Priya.Raman.Policy-Author": " Priya.Raman "}, idp())
    linked = Persona("priya.raman.policy-author", "P", ["policy-author"], person_id="someone.else")
    assert people.person_of(linked) == "priya.raman"
    assert people.person_of(Persona("priya.raman", "P", [])) == "priya.raman"
    assert people.person_of(Persona("Sanne.Bakker", "S", [])) == "sanne.bakker"
    assert people.has_link("PRIYA.RAMAN.POLICY-AUTHOR") and not people.has_link("sanne.bakker")


async def test_a_name_stored_on_a_record_resolves_to_its_person():
    db = await database()
    directory_idp = idp()
    directory_idp.add_persona(Persona("niels.vandijk.alt", "N", ["agent-owner"], person_id="Niels.VanDijk"))
    people = PersonDirectory({"x.alt": "x"}, directory_idp, db)
    me = Persona("niels.vandijk", "N", ["agent-owner"])
    async with db.sessionmaker() as s:
        assert await people.same_person(s, me, "niels.vandijk")
        assert await people.same_person(s, me, "NIELS.VANDIJK.ALT")  # a dev-IdP account carrying the person id
        assert await people.same_person(s, Persona("x", "X", []), "x.alt")  # a configured link
        assert not await people.same_person(s, me, "sanne.bakker")
        assert not await people.same_person(s, me, "") and not await people.same_person(s, me, None)
    await db.engine.dispose()


async def test_sign_in_records_the_person_so_other_requests_can_resolve_the_account():
    db = await database()
    people = PersonDirectory({}, None, db)
    await people.record(Persona("emp.alt", "E", ["auditor"], person_id="E-1001"))
    async with db.sessionmaker() as s:
        assert await people.same_person(s, Persona("emp", "E", ["agent-owner"], person_id="e-1001"), "emp.alt")
    # a changed mapping replaces the old one, and a repeat of the same mapping needs no write
    await people.record(Persona("emp.alt", "E", ["auditor"], person_id="E-2002"))
    async with db.sessionmaker() as s:
        assert not await people.same_person(s, Persona("emp", "E", [], person_id="e-1001"), "emp.alt")
        assert await people.same_person(s, Persona("emp", "E", [], person_id="e-2002"), "emp.alt")
    await db.engine.dispose()


async def test_simultaneous_first_sign_ins_of_one_account_write_one_row_quietly(caplog):
    db = await database()
    people = PersonDirectory({}, None, db)
    mark = Persona("mark.jansen", "Mark", ["soc-analyst"])
    await asyncio.gather(*(people.record(mark) for _ in range(8)))  # the console sends many requests at once
    async with db.sessionmaker() as s:
        rows = (await s.scalars(select(PersonLink))).all()
    assert [(r.username, r.person_id) for r in rows] == [("mark.jansen", "mark.jansen")]
    assert not caplog.records
    await db.engine.dispose()


async def test_a_second_worker_inserting_the_same_account_first_is_handled(caplog):
    db = await database()
    worker_a, worker_b = PersonDirectory({}, None, db), PersonDirectory({}, None, db)
    real_upsert, calls = worker_b._upsert, []

    async def raced(name, person):
        calls.append(name)
        if len(calls) == 1:  # worker A gets its row in between worker B's read and its insert
            await worker_a.record(Persona("mark.jansen", "Mark", [], person_id="m-1"))
            raise IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed: person_links.username"))
        await real_upsert(name, person)

    worker_b._upsert = raced
    await worker_b.record(Persona("mark.jansen", "Mark", [], person_id="m-2"))
    assert len(calls) == 2 and worker_b._recorded == {"mark.jansen": "m-2"}
    async with db.sessionmaker() as s:
        assert (await s.get(PersonLink, "mark.jansen")).person_id == "m-2"  # the retry updated the existing row
    assert not caplog.records
    await db.engine.dispose()


async def test_a_storage_failure_while_recording_is_not_fatal():
    db = Database("sqlite+aiosqlite:///:memory:")  # tables never created: every write fails
    people = PersonDirectory({}, None, db)
    await people.record(Persona("emp", "E", []))
    assert people._recorded == {}  # not remembered as done, so the next sign-in retries
    await db.engine.dispose()


# ---- the person claim ----


async def test_the_person_claim_links_accounts_and_is_required_when_configured():
    provider = FakeProvider()
    claimed = verifier(provider, oidc_person_claim="employee_id")
    one = await claimed.authenticate(provider.token(preferred_username="priya", employee_id="E-7"))
    two = await claimed.authenticate(provider.token(preferred_username="priya.policy", employee_id="E-7"))
    assert one.person_id == two.person_id == "E-7"
    assert (await claimed.authenticate(provider.token(employee_id=["E-7", "E-8"]))).person_id is None  # ambiguous
    assert (await verifier(provider).authenticate(provider.token(employee_id="E-7"))).person_id is None  # not set up

    nested = verifier(provider, oidc_person_claim="hr.employee_id")
    assert (await nested.authenticate(provider.token(hr={"employee_id": "E-9"}))).person_id == "E-9"

    cfg = settings(oidc_person_claim="employee_id", person_links={"linked.account": "priya"})
    users = UserAuthenticator(idp(), cfg, OidcVerifier(OidcConfig.from_settings(cfg), provider.client()))
    with pytest.raises(jwt.InvalidTokenError, match="cannot be linked to a person"):
        await users.authenticate(provider.token(preferred_username="unlinked.account"))
    signed_in = await users.authenticate(provider.token(preferred_username="unlinked.account", employee_id="E-7"))
    assert signed_in.person_id == "e-7"
    assert (await users.authenticate(provider.token(preferred_username="linked.account"))).person_id == "priya"
    # an account with no Aegis role is not staff, so it needs no link
    no_role = provider.token(preferred_username="guest", realm_access={"roles": ["offline_access"]})
    assert (await users.authenticate(no_role)).roles == []


def test_person_links_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("AEGIS_PERSON_LINKS", json.dumps({"a.alt": "a"}))
    monkeypatch.setenv("AEGIS_OIDC_PERSON_CLAIM", "employee_id")
    loaded = Settings.from_env()
    assert loaded.person_links == {"a.alt": "a"} and loaded.oidc_person_claim == "employee_id"
