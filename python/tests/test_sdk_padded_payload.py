"""The Python SDK seals the request (prompt, seed, input manifest, options) in the padded form, against a fake gateway:
its ciphertext is a power-of-two bucket whatever the prompt's length, and the enclave's opening path reads it back."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from kuno_protocol.attestation import enclave_id_for
from kuno_protocol.canonical import b64d, b64e
from kuno_protocol.crypto import RecipientSession, generate_hpke_keypair, generate_signing_key, public_key_bytes
from kuno_protocol.profiles import load_profiles
from kuno_protocol.schemas import job_aad
from kuno_protocol.sealed_payload import MAX_JSON_LEN, MIN_PADDED, PAYLOAD_V2, open_payload, payload_version
from kunoworld import KunoClient
from kunoworld.client import KunoError

PROFILE = load_profiles()["ltx-2.5-fast"]


@pytest.fixture
def world(monkeypatch):
    private, public = generate_hpke_keypair()
    signing = public_key_bytes(generate_signing_key())
    enclave = {"enclave_id": enclave_id_for(public, signing), "hpke_public_key": b64e(public), "signing_public_key": b64e(signing)}
    posted: list[str] = []

    def gateway(request: httpx.Request) -> httpx.Response:
        posted.append(f"{request.method} {request.url.path}")
        return httpx.Response(404, json={"detail": {"code": "not_found", "message": request.url.path}})

    client = KunoClient("kw_test", "https://gw.test", transport=httpx.MockTransport(gateway))
    monkeypatch.setattr(client, "route", lambda *_a, **_k: SimpleNamespace(profile_id=PROFILE.id, fallback_reason=None, enclaves=[enclave]))
    monkeypatch.setattr(client, "profile", lambda _profile_id: PROFILE)
    monkeypatch.setattr(client, "_pick_enclave", lambda *_args, **_kwargs: enclave)
    return SimpleNamespace(client=client, private=private, posted=posted)


def test_the_request_is_sealed_padded_and_the_enclave_opens_it(world):
    prepared = world.client.prepare("a paper boat on a pond", model=PROFILE.id, seed=5, options={"camera_motion": "static"})
    request = prepared.request
    aad = job_aad(request.job_id, request.enclave_id, request.params, request.input_blob_ids)
    ciphertext, enc = b64d(request.ciphertext), b64d(request.enc)
    assert len(ciphertext) == MIN_PADDED + 16
    assert payload_version(RecipientSession(world.private, enc).open(ciphertext, aad)) == PAYLOAD_V2
    payload = open_payload(RecipientSession(world.private, enc), ciphertext, aad)
    assert (payload.prompt, payload.seed, payload.options) == ("a paper boat on a pond", 5, {"camera_motion": "static"})


def test_the_ciphertext_size_does_not_follow_the_prompt_length(world):
    sizes = {len(b64d(world.client.prepare("a" * n, model=PROFILE.id).request.ciphertext)) for n in (1, 200, 3000)}
    assert sizes == {MIN_PADDED + 16}
    longer = world.client.prepare("a boat", model=PROFILE.id, options={"shots": ["x" * 100] * 50})
    assert len(b64d(longer.request.ciphertext)) == 2 * MIN_PADDED + 16


def test_a_request_too_large_to_pad_is_refused_before_anything_is_sent(world):
    with pytest.raises(KunoError) as refused:
        world.client.prepare("a boat", model=PROFILE.id, options={"notes": "x" * MAX_JSON_LEN})
    assert refused.value.code == "request_too_large"
    assert world.posted == []
