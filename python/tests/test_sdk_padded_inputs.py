"""The Python SDK seals reference media in the padded blob format (version 2) before uploading it, against a fake
gateway: only ciphertext of a PADMÉ bucket's size leaves the machine, and the enclave's input key opens it."""

from __future__ import annotations

from types import SimpleNamespace

import httpx

from kuno_protocol.attestation import enclave_id_for
from kuno_protocol.blobs import V2, blob_version, decrypt_blob, sealed_size
from kuno_protocol.canonical import b64d, b64e
from kuno_protocol.crypto import RecipientSession, generate_hpke_keypair, generate_signing_key, public_key_bytes
from kuno_protocol.profiles import InputRole, load_profiles
from kuno_protocol.schemas import input_label
from kunoworld import KunoClient
from kunoworld.client import Input

PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 3


def test_private_inputs_are_uploaded_padded(monkeypatch):
    private, public = generate_hpke_keypair()
    signing = public_key_bytes(generate_signing_key())
    enclave = {"enclave_id": enclave_id_for(public, signing), "hpke_public_key": b64e(public), "signing_public_key": b64e(signing)}
    uploads: list[bytes] = []

    def gateway(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/v1/blobs":
            uploads.append(request.content)
            return httpx.Response(201, json={"blob_id": f"{len(uploads):032x}"})
        return httpx.Response(404, json={"detail": {"code": "not_found", "message": request.url.path}})

    client = KunoClient("kw_test", "https://gw.test", transport=httpx.MockTransport(gateway))
    profile = load_profiles()["ltx-2.5-fast"]
    monkeypatch.setattr(client, "route", lambda *_a, **_k: SimpleNamespace(profile_id=profile.id, fallback_reason=None, enclaves=[enclave]))
    monkeypatch.setattr(client, "profile", lambda _profile_id: profile)
    monkeypatch.setattr(client, "_pick_enclave", lambda _route: enclave)

    prepared = client.prepare("a paper boat on a pond", inputs=[Input(role=InputRole.FIRST_FRAME, data=PNG, mime="image/png")], model=profile.id)

    [sealed] = uploads
    assert prepared.input_blob_bytes == [sealed]
    assert blob_version(sealed) == V2
    assert len(sealed) == sealed_size(len(PNG)) and PNG not in sealed
    session = RecipientSession(private, b64d(prepared.request.enc))
    assert decrypt_blob(session.input_key, input_label(prepared.request.job_id, 0), sealed) == PNG
