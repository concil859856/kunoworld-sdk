"""An SDK that pins the subnet owner's key uses the gateway's manifest only once the owner's signature on it verifies."""

from __future__ import annotations

import json

import httpx
import pytest

from kuno_protocol.attestation import GoldenManifest, sign_manifest
from kuno_protocol.canonical import b64e
from kuno_protocol.crypto import generate_signing_key, public_key_bytes
from kunoworld.client import KunoClient, KunoError


def client_for(document: dict, owner_public_key) -> KunoClient:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/manifest/signed"
        return httpx.Response(200, json=document)

    return KunoClient("kw_test", "https://gateway.test", owner_public_key=owner_public_key, transport=httpx.MockTransport(handler))


def test_a_manifest_signed_by_the_owner_is_used_without_a_warning(recwarn):
    owner = generate_signing_key()
    manifest = GoldenManifest(max_evidence_age_s=900)
    signed = json.loads(sign_manifest(owner, manifest).model_dump_json())
    assert client_for(signed, b64e(public_key_bytes(owner))).manifest().max_evidence_age_s == 900
    assert not [w for w in recwarn if "gateway-served" in str(w.message)]


@pytest.mark.parametrize("tamper", ["field", "signer"])
def test_a_manifest_the_owner_did_not_sign_is_refused(tamper):
    owner = generate_signing_key()
    signed = json.loads(sign_manifest(owner if tamper == "field" else generate_signing_key(), GoldenManifest()).model_dump_json())
    if tamper == "field":
        signed["manifest"]["max_evidence_age_s"] = 10**9  # a relay widening what it may serve
    with pytest.raises(KunoError) as err:
        client_for(signed, public_key_bytes(owner)).manifest()
    assert err.value.code == "integrity"
