"""The Gateway → control-plane trust boundary rests on an asymmetric signature, not a shared secret."""

from aegis.common.crypto import SigningKey
from aegis.common.service_identity import mint_service_token
from aegis_demo.world import BASE


async def _internal_get(world, headers):
    return await world.http.get(f"{BASE}/internal/agents/{world.agent_ids['ava']}", headers=headers)


async def test_valid_gateway_assertion_is_accepted(world):
    assert (await _internal_get(world, world.internal_headers())).status_code == 200


async def test_missing_or_static_secret_is_rejected(world):
    assert (await _internal_get(world, {})).status_code == 401
    assert (await _internal_get(world, {"x-aegis-internal": "dev-internal-token"})).status_code == 401


async def test_assertion_signed_by_another_key_is_rejected(world):
    forged = mint_service_token(SigningKey.load_or_generate("", "attacker"))
    assert (await _internal_get(world, {"x-aegis-internal": forged})).status_code == 401


async def test_control_plane_cannot_mint_gateway_tokens(world):
    # The control plane holds only a public key; the STS key it does own must not pass as the Gateway.
    forged = mint_service_token(world.ctx.sts_key)
    assert (await _internal_get(world, {"x-aegis-internal": forged})).status_code == 401
