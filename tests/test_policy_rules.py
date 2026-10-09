"""Rego as part of a governed policy version: stored with the version, checked, diffed, replayed, signed off twice,
activated, rolled back, and pushed to OPA. A file edit on disk never changes the running policy by itself."""

import copy
import json
import shutil

import httpx
import pytest
from fake_opa import FakeOpa
from policy_cases import DELETE, POLICY_DIR, case, python_inputs
from sqlalchemy import delete, select
from starlette.routing import Mount
from test_policy_engines_world import active_version, boot, studio

from aegis.control import policies
from aegis.control.identity.idp import Persona
from aegis.control.policies import ManagedEngine
from aegis.control.tables import LedgerEntry, PolicyBundle, PolicyVersion
from aegis.policy.engines import OpaEngine, forget_opa_verification, rego_available, rego_sources
from aegis.policy.rules_check import check_rules, repository_cases_file
from aegis_demo.data import LANDLORD_IBAN
from aegis_demo.world import BASE

pytestmark = pytest.mark.skipif(not rego_available(), reason="checking and running Rego needs regopy")
REGO_FILE = "tool_call.rego"
PRD_RULE = 'sprops.env == "PRD"'
DESTRUCTIVE = python_inputs(case(DELETE))[0]


@pytest.fixture(autouse=True)
def fresh_verification():
    forget_opa_verification()
    yield
    forget_opa_verification()


def copied_policy(tmp_path) -> str:
    """A private copy of config/policies (and its cases) that a test may edit on disk."""
    root = tmp_path / "config"
    shutil.copytree(POLICY_DIR, root / "policies")
    shutil.copytree(repository_cases_file(POLICY_DIR).parent, root / "policy_tests")
    return str(root / "policies")


@pytest.fixture
async def rego_world():
    world, shutdown = await boot(policy_engine="rego")
    yield world
    await shutdown()


@pytest.fixture
async def opa_world():
    fake = FakeOpa(POLICY_DIR)
    world, shutdown = await boot(
        policy_engine="opa", opa_url=f"{BASE}/fake-opa", extra_routes=[Mount("/fake-opa", fake.app)]
    )
    world.fake_opa = fake
    yield world
    await shutdown()


def add(world, username, roles):
    world.ctx.idp.add_persona(Persona(username, username.title(), roles))


async def running_rules(world) -> dict[str, str]:
    return (await world.api("mark.jansen", "GET", f"/v1/policies/{await active_version(world)}/rules")).json()


def relaxed_destructive(rules: dict) -> tuple[dict, list]:
    """Destructive actions need approval only in ACC instead of PRD: a deliberate rule change, with its case updated."""
    modules = {REGO_FILE: rules["modules"][REGO_FILE].replace(PRD_RULE, 'sprops.env == "ACC"')}
    cases = copy.deepcopy(rules["cases"])
    for item in cases:
        if item["name"] == "destructive_in_production":
            item.update(decision="allow", rules=[])
    return modules, cases


async def propose(
    world, *, modules=None, cases=None, import_repository=False, configuration=None, author="priya.raman"
):
    configuration = configuration or (await world.api(author, "GET", "/v1/policies")).json()["data"]
    body = {"name": "Rule change", "justification": "Reviewed rule change", "configuration": configuration}
    if modules is not None:
        body["rules"] = {"modules": modules, **({"cases": cases} if cases is not None else {})}
    if import_repository:
        body["import_repository"] = True
    return await world.api(author, "POST", "/v1/policies/versions", json=body)


async def replay_and_submit(world, vid, author="priya.raman"):
    replay = await world.api(author, "POST", f"/v1/policies/{vid}/replay", json={})
    assert replay.status_code == 200, replay.text
    submitted = await world.api(author, "POST", f"/v1/policies/{vid}/submit")
    assert submitted.status_code == 200, submitted.text
    return replay.json()


def review(world, who, vid, verb):
    return world.api(who, "POST", f"/v1/policies/{vid}/{verb}", json={"justification": f"{verb} after review"})


async def activate(world, vid, who="fatima.elamrani", verb="activate"):
    body = {"expected_active_version": await active_version(world), "justification": "Activate the reviewed version"}
    return await world.api(who, "POST", f"/v1/policies/{vid}/{verb}", json=body)


async def ledger(world, event_type):
    async with world.ctx.db.sessionmaker() as s:
        rows = await s.scalars(
            select(LedgerEntry).where(LedgerEntry.event_type == event_type).order_by(LedgerEntry.seq)
        )
        return rows.all()


async def decide(world, policy_input=DESTRUCTIVE):
    return (await ManagedEngine(world.ctx).evaluate(policy_input))["decision"]


# ---- the running policy is the approved Rego, not the file on disk --------------------------------------------------


async def test_editing_the_rego_file_does_not_change_the_running_policy(tmp_path):
    policy_dir = copied_policy(tmp_path)
    world, shutdown = await boot(policy_engine="rego", policy_dir=policy_dir)
    try:
        assert (await studio(world, "scenarios/address-change"))["status"] == "completed"
        rego = tmp_path / "config" / "policies" / REGO_FILE
        rego.write_text(
            rego.read_text("utf-8") + '\ndeny contains {"rule": "TST-001", "message": "no"} if true\n', "utf-8"
        )
        assert (await studio(world, "scenarios/address-change"))["status"] == "completed"  # still the approved Rego
        repository = (await world.api("mark.jansen", "GET", "/v1/policies/repository")).json()
        assert repository["differs"] is True
        assert repository["files"] == [{"file": REGO_FILE, "status": "changed", "added_lines": 2, "removed_lines": 0}]
        # Importing it is a proposal like any other, and this one breaks every allowing case.
        imported = await propose(world, import_repository=True)
        assert imported.status_code == 422
        checks = imported.json()["detail"]["checks"]
        assert checks["passed"] is False and "allow_with_redaction" in {f["name"] for f in checks["cases"]["failed"]}
        assert (await world.api("mark.jansen", "GET", "/v1/policies")).json()["files"][REGO_FILE] == rego_sources(
            POLICY_DIR
        )[REGO_FILE]
    finally:
        await shutdown()


async def test_the_proposed_rules_must_pass_the_automatic_checks(rego_world):
    rules = await running_rules(rego_world)
    source = rules["modules"][REGO_FILE]
    refusals = {
        "network call": (
            {REGO_FILE: source + '\nx := http.send({"method": "get", "url": "http://evil"})\n'},
            "http.send",
        ),
        "syntax error": ({REGO_FILE: source + "\nbroken := {\n"}, "does not compile"),
        "foreign package": ({REGO_FILE: source.replace("package aegis.tool_call", "package system.authz")}, "outside"),
        "test module": ({"x_test.rego": source}, "test modules"),
        "behaviour change without updated cases": (relaxed_destructive(rules)[0], "test cases fail"),
    }
    for label, (modules, fragment) in refusals.items():
        refused = await propose(rego_world, modules=modules)
        assert refused.status_code == 422, label
        assert fragment in json.dumps(refused.json()["detail"]["checks"]), label
    both = await propose(rego_world, modules={REGO_FILE: source}, import_repository=True)
    assert both.status_code == 422 and "not both" in both.text
    versions = (await rego_world.api("mark.jansen", "GET", "/v1/policies/versions")).json()["versions"]
    assert len(versions) == 1  # nothing that failed a check was saved


async def test_the_python_engine_refuses_rule_changes_but_keeps_configuration_changes(world):
    rules = await running_rules(world)
    modules, cases = relaxed_destructive(rules)
    refused = await propose(world, modules=modules, cases=cases)
    assert refused.status_code == 409 and "python engine" in refused.text
    configuration = (await world.api("priya.raman", "GET", "/v1/policies")).json()["data"]
    configuration["thresholds"]["payments"]["hitl_amount_eur"] = 2000
    kept = await propose(world, configuration=configuration)
    assert kept.status_code == 201 and kept.json()["rules"]["origin"] == "inherited"


# ---- a rule change: diff, replay, two independent sign-offs, activation and rollback ---------------------------------


async def test_a_rule_change_goes_through_diff_replay_two_sign_offs_activation_and_rollback(rego_world):
    world = rego_world
    original = await active_version(world)
    assert await decide(world) == "require_approval"  # destructive in PRD needs approval today
    modules, cases = relaxed_destructive(await running_rules(world))
    draft = await propose(world, modules=modules, cases=cases)
    assert draft.status_code == 201, draft.text
    version = draft.json()
    vid = version["id"]
    assert version["rules"]["origin"] == "edited" and version["rules"]["checks"]["passed"] is True
    assert version["rules"]["checks"]["cases"] == {"total": len(cases), "passed": len(cases), "failed": []}
    assert version["rules"]["security"]["required"] is True and version["rules"]["security"]["rules_changed"] is True

    diff = (await world.api("fatima.elamrani", "GET", f"/v1/policies/{vid}/diff")).json()
    assert diff["against"] == original and diff["configuration"] == [] and diff["cases"]["changed"] is True
    (changed,) = diff["rules"]
    assert changed["status"] == "changed" and changed["added_lines"] == changed["removed_lines"] == 1
    assert f"-\t{PRD_RULE}" in changed["diff"] and '+\tsprops.env == "ACC"' in changed["diff"]

    report = await replay_and_submit(world, vid)
    assert report["rules_changed"] is True and report["evaluated_with"] in ([], ["rego"])
    assert (await review(world, "fatima.elamrani", vid, "approve")).status_code == 200
    blocked = await activate(world, vid)
    assert blocked.status_code == 409 and "SEC-001" in blocked.text  # policy approval alone is not enough
    same = await review(world, "fatima.elamrani", vid, "security-approve")
    assert same.status_code == 403 and "two people" in same.text
    assert (await review(world, "priya.raman", vid, "security-approve")).status_code == 403  # no role, and the author
    signed = await review(world, "lars.devos", vid, "security-approve")
    assert signed.status_code == 200 and signed.json()["rules"]["security"]["approver"] == "lars.devos"
    assert (await review(world, "lars.devos", vid, "security-approve")).status_code == 409  # once is enough
    assert (await activate(world, vid)).status_code == 200

    assert await decide(world) == "allow"  # the approved Rego from the database decides now
    policy = (await world.api("mark.jansen", "GET", "/v1/policies")).json()
    assert policy["version"] == vid and 'sprops.env == "ACC"' in policy["files"][REGO_FILE]
    (activated,) = await ledger(world, "policy.activated")
    assert activated.payload["rules_diff"] == [
        {"file": REGO_FILE, "status": "changed", "added_lines": 1, "removed_lines": 1}
    ]
    assert activated.payload["bundle_hash"] == version["rules"]["bundle_hash"]
    assert (await ledger(world, "policy.security_approved"))[0].actor == "lars.devos"

    # Rolling back restores the previous rules immediately; it was fully approved when it ran.
    assert (await activate(world, original, verb="rollback")).status_code == 200
    assert await decide(world) == "require_approval"


async def test_the_author_cannot_sign_off_their_own_rule_change(rego_world):
    add(rego_world, "dual.author", ["policy-author", "security-approver"])
    modules, cases = relaxed_destructive(await running_rules(rego_world))
    vid = (await propose(rego_world, modules=modules, cases=cases, author="dual.author")).json()["id"]
    await replay_and_submit(rego_world, vid, author="dual.author")
    own = await review(rego_world, "dual.author", vid, "security-approve")
    assert own.status_code == 403 and "authors" in own.text


async def test_the_policy_approver_cannot_be_the_person_who_signed_off_security(rego_world):
    add(rego_world, "sec.and.policy", ["policy-approver", "security-approver"])
    modules, cases = relaxed_destructive(await running_rules(rego_world))
    vid = (await propose(rego_world, modules=modules, cases=cases)).json()["id"]
    await replay_and_submit(rego_world, vid)
    assert (await review(rego_world, "sec.and.policy", vid, "security-approve")).status_code == 200
    second = await review(rego_world, "sec.and.policy", vid, "approve")
    assert second.status_code == 403 and "two people" in second.text


# ---- configuration changes: a sign-off only when the replay shows something loosening -------------------------------


async def test_a_configuration_change_that_loosens_a_decision_needs_a_security_sign_off(world):
    flow = await world.ava.transfer(world.token("jan.devries"), "C-1001", 25000, LANDLORD_IBAN, True)
    assert flow["response"]["status"]["state"] == "auth-required"  # recorded: 25,000 needs approval today
    configuration = (await world.api("priya.raman", "GET", "/v1/policies")).json()["data"]
    configuration["thresholds"]["payments"]["hitl_amount_eur"] = 50000
    vid = (await propose(world, configuration=configuration)).json()["id"]
    report = await replay_and_submit(world, vid)
    assert report["more_permissive"] > 0 and report["rules_changed"] is False
    assert any(
        r["before"] == "require_approval" and r["after"] == "allow" and r["more_permissive"] for r in report["results"]
    )
    assert (await review(world, "fatima.elamrani", vid, "approve")).status_code == 200
    assert (await activate(world, vid)).status_code == 409
    assert (await review(world, "lars.devos", vid, "security-approve")).status_code == 200
    assert (await activate(world, vid)).status_code == 200


async def test_a_stricter_configuration_change_needs_no_security_sign_off(world):
    await studio(world, "scenarios/policy-transfer")
    configuration = (await world.api("priya.raman", "GET", "/v1/policies")).json()["data"]
    configuration["thresholds"]["payments"]["hitl_amount_eur"] = 2000
    vid = (await propose(world, configuration=configuration)).json()["id"]
    report = await replay_and_submit(world, vid)
    assert report["changed"] > 0 and report["more_permissive"] == 0
    unneeded = await review(world, "lars.devos", vid, "security-approve")
    assert unneeded.status_code == 409 and "no sign-off needed" in unneeded.text
    assert (await review(world, "fatima.elamrani", vid, "approve")).status_code == 200
    assert (await activate(world, vid)).status_code == 200


# ---- versions saved before rules were versioned ---------------------------------------------------------------------


async def test_versions_saved_before_rules_were_versioned_get_their_rules_recorded(world):
    active = await active_version(world)
    async with world.ctx.db.sessionmaker() as s:
        await s.execute(delete(PolicyBundle))
        s.add(
            PolicyVersion(
                id="pol_unknown_rules",
                name="Approved for other Rego",
                configuration={},
                content_hash="x",
                rules_hash="not-this-evaluator",
                author="someone",
                status="superseded",
            )
        )
        await s.commit()
    await policies.initialize(world.ctx)
    async with world.ctx.db.sessionmaker() as s:
        assert (await s.get(PolicyBundle, active)).origin == "backfilled"  # provably the repository Rego
        assert await s.get(PolicyBundle, "pol_unknown_rules") is None  # never guessed
    (entry,) = await ledger(world, "policy.rules_backfilled")
    assert entry.payload == {"versions": [active]}


# ---- OPA: Aegis pushes the approved Rego ----------------------------------------------------------------------------


async def test_activating_a_rule_change_pushes_it_to_opa(opa_world):
    world, fake = opa_world, opa_world.fake_opa
    modules, cases = relaxed_destructive(await running_rules(world))
    vid = (await propose(world, modules=modules, cases=cases)).json()["id"]
    await replay_and_submit(world, vid)
    assert (await review(world, "fatima.elamrani", vid, "approve")).status_code == 200
    assert (await review(world, "lars.devos", vid, "security-approve")).status_code == 200
    fake.writes.clear()
    assert (await activate(world, vid)).status_code == 200
    (write,) = fake.writes
    assert write[0] == "PUT" and write[1].endswith(REGO_FILE)  # replaced in place, under the id OPA already used
    assert next(m["raw"] for m in fake.modules if m["id"] == write[1]) == modules[REGO_FILE]
    assert await decide(world) == "allow"  # OPA itself now decides with the new rules
    (activated,) = await ledger(world, "policy.activated")
    assert activated.payload["opa"]["replaced"] == [REGO_FILE]


async def test_when_opa_refuses_the_new_rules_nothing_is_activated(opa_world):
    world, fake = opa_world, opa_world.fake_opa
    modules, cases = relaxed_destructive(await running_rules(world))
    vid = (await propose(world, modules=modules, cases=cases)).json()["id"]
    await replay_and_submit(world, vid)
    await review(world, "fatima.elamrani", vid, "approve")
    await review(world, "lars.devos", vid, "security-approve")
    original = await active_version(world)
    fake.read_only = True
    refused = await activate(world, vid)
    assert refused.status_code == 503 and "nothing was activated" in refused.text
    assert await active_version(world) == original
    fake.read_only = False
    assert (await studio(world, "scenarios/address-change"))["status"] == "completed"  # still the approved policy


async def test_an_empty_opa_gets_the_approved_rego_at_start_up():
    fake = FakeOpa(POLICY_DIR, empty=True)
    world, shutdown = await boot(
        policy_engine="opa", opa_url=f"{BASE}/fake-opa", extra_routes=[Mount("/fake-opa", fake.app)]
    )
    try:
        assert fake.writes == [("PUT", REGO_FILE)]
        assert (await studio(world, "scenarios/address-change"))["status"] == "completed"
        (entry,) = await ledger(world, "policy.opa_synced")
        assert entry.actor == "system:startup" and entry.payload["added"] == [REGO_FILE]
    finally:
        await shutdown()


async def test_an_opa_that_restarted_empty_gets_the_policy_back_but_a_changed_one_is_not_overwritten(opa_world):
    world, fake = opa_world, opa_world.fake_opa
    fake.modules, fake.runtime = [], None  # OPA restarted with nothing loaded
    forget_opa_verification()
    assert (await studio(world, "scenarios/address-change"))["status"] == "completed"  # healed by pushing it back
    assert ("PUT", REGO_FILE) in fake.writes

    fake.writes.clear()
    fake.modules[0] = {**fake.modules[0], "raw": fake.modules[0]["raw"] + "\n# changed outside Aegis\n"}
    forget_opa_verification()
    assert (await studio(world, "scenarios/address-change"))["status"] == "blocked"  # fails closed, nothing written
    assert fake.writes == []

    assert (
        await world.api("priya.raman", "POST", "/v1/policies/opa/sync", json={"justification": "x" * 5})
    ).status_code == 403
    pushed = await world.api(
        "fatima.elamrani", "POST", "/v1/policies/opa/sync", json={"justification": "Restore the approved policy"}
    )
    assert pushed.status_code == 200 and pushed.json()["replaced"] == [REGO_FILE]
    assert (await studio(world, "scenarios/address-change"))["status"] == "completed"
    (entry,) = await ledger(world, "policy.opa_synced")
    assert entry.actor == "fatima.elamrani"


async def test_the_opa_sync_endpoint_needs_the_opa_engine(world):
    refused = await world.api("fatima.elamrani", "POST", "/v1/policies/opa/sync", json={"justification": "Not OPA"})
    assert refused.status_code == 409


async def test_sync_removes_unknown_modules_and_writes_nothing_when_opa_already_matches():
    fake = FakeOpa(POLICY_DIR)
    fake.modules.append({"id": "/opa/extra.rego", "raw": "package aegis.tool_call\n"})
    engine = OpaEngine("http://opa.test", POLICY_DIR, httpx.AsyncClient(transport=httpx.ASGITransport(app=fake.app)))
    plan = await engine.sync_policy()
    assert plan == {"removed": ["/opa/extra.rego"], "replaced": [], "added": [], "unchanged": [REGO_FILE]}
    fake.writes.clear()
    forget_opa_verification()
    assert (await engine.sync_policy())["removed"] == [] and fake.writes == []


# ---- the checks themselves ----------------------------------------------------------------------------------------


def test_the_checks_pass_on_the_repository_policy_and_name_what_fails():
    modules = rego_sources(POLICY_DIR)
    cases = json.loads(repository_cases_file(POLICY_DIR).read_text("utf-8"))
    good = check_rules(POLICY_DIR, modules, cases)
    assert good["passed"] is True and good["cases"]["passed"] == good["cases"]["total"] == len(cases)
    edited = check_rules(POLICY_DIR, {REGO_FILE: modules[REGO_FILE].replace(PRD_RULE, 'sprops.env == "X"')}, cases)
    assert edited["passed"] is False and [f["name"] for f in edited["cases"]["failed"]] == ["destructive_in_production"]
    unknown = check_rules(
        POLICY_DIR, {REGO_FILE: modules[REGO_FILE].replace("count(deny) > 0", "nosuch(deny) > 0")}, cases
    )
    assert unknown["passed"] is False and "did not return a valid decision" in unknown["problems"][0]
    for builtin in ("time.now_ns()", 'rand.intn("x", 2)', "opa.runtime()", 'net.lookup_ip_addr("x")'):
        report = check_rules(POLICY_DIR, {REGO_FILE: modules[REGO_FILE] + f"\nx := {builtin}\n"}, cases)
        assert report["passed"] is False and builtin.split("(")[0] in report["problems"][0]
    assert "at least one test case" in check_rules(POLICY_DIR, modules, [])["problems"][0]
