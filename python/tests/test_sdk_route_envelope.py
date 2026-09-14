"""The Python SDK sends a request's size, frame rate and duration to /v1/route, and skips a listed worker whose serving
envelope can't fit the job once defaults are filled in."""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from kuno_protocol import devkit
from kuno_protocol.attestation import OpenTEE, build_evidence, enclave_id_for
from kuno_protocol.canonical import b64d, b64e
from kuno_protocol.crypto import generate_hpke_keypair, generate_signing_key, public_key_bytes
from kuno_protocol.envelope import full_table, to_json
from kuno_protocol.profiles import Mode, load_profiles
from kuno_protocol.schemas import GenerationParams, RouteResponse
from kunoworld import KunoClient, KunoError
from kunoworld import client as client_module

PROFILE = load_profiles()["ltx-2.5-fast"]


def small_card() -> dict:
    table = full_table(PROFILE)
    table["1080p"]["16:9"] = {24: 8.0, 25: 8.0, 48: 4.0, 50: 4.0}
    return {PROFILE.id: to_json(table)}


def fake_gateway(routes: dict):
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        answer = routes.get(f"{request.method} {request.url.path}")
        return answer(request) if answer else httpx.Response(404, json={"detail": {"code": "not_found", "message": request.url.path}})

    return calls, KunoClient("kw_test", "https://gw.test", transport=httpx.MockTransport(handler))


def route_json(enclaves=()) -> dict:
    return {"profile_id": PROFILE.id, "requested_profile_id": PROFILE.id, "fallback_reason": None, "enclaves": list(enclaves)}


def status_json(job_id: str, params: dict) -> dict:
    return {
        "job_id": job_id, "status": "queued", "stage": None, "progress": 0.0, "params": params, "enclave_id": "e1", "price_usd": 0.5,
        "created_at": 1.0, "updated_at": 1.0, "output_blob_id": None, "receipt": None, "error_code": None, "error": None,
        "privacy": "standard",
    }


def test_route_sends_the_fields_it_is_given_and_nothing_else():
    calls, client = fake_gateway({"GET /v1/route": lambda r: httpx.Response(200, json=route_json())})
    client.route(Mode.TEXT_TO_VIDEO, PROFILE.id)
    client.route(Mode.TEXT_TO_VIDEO, PROFILE.id, resolution="1080p", aspect_ratio="16:9", fps=24, duration_s=10)
    client.route(Mode.TEXT_TO_VIDEO, PROFILE.id, privacy="standard", duration_s=8)
    bare, full, partial = (dict(c.url.params) for c in calls)
    assert bare == {"mode": "text_to_video", "profile_id": PROFILE.id}
    assert full == {"mode": "text_to_video", "profile_id": PROFILE.id, "resolution": "1080p", "aspect_ratio": "16:9", "fps": "24", "duration_s": "10"}
    assert partial == {"mode": "text_to_video", "profile_id": PROFILE.id, "privacy": "standard", "duration_s": "8"}


def test_a_standard_job_routes_with_its_size_frame_rate_and_duration():
    def create(request):
        body = json.loads(request.content)
        return httpx.Response(201, json=status_json(body["job_id"], body["params"]))

    calls, client = fake_gateway({
        "GET /v1/route": lambda r: httpx.Response(200, json=route_json()),
        "GET /v1/models": lambda r: httpx.Response(200, json={"models": [PROFILE.model_dump(mode="json")]}),
        "POST /v1/standard/videos": create,
    })
    client.generate("a lighthouse at dusk", model=PROFILE.id, privacy="standard", resolution="1080p", aspect_ratio="16:9", fps=24, duration_s=8, wait=False)
    route = next(c for c in calls if c.url.path == "/v1/route")
    assert {k: route.url.params[k] for k in ("resolution", "aspect_ratio", "fps", "duration_s")} == {
        "resolution": "1080p", "aspect_ratio": "16:9", "fps": "24", "duration_s": "8"
    }


def enclave(envelope: dict | None) -> dict:
    _, hpke = generate_hpke_keypair()
    signing = public_key_bytes(generate_signing_key())
    evidence = build_evidence(OpenTEE(), b"\x01" * 32, hpke, signing, devkit.DEV_IMAGE_DIGEST, [PROFILE.id], {})
    return {
        "enclave_id": enclave_id_for(hpke, signing), "hpke_public_key": b64e(hpke), "signing_public_key": b64e(signing),
        "evidence": evidence.model_dump(mode="json"), "envelope": envelope,
    }


def test_only_an_enclave_whose_envelope_fits_the_filled_in_params_is_picked(monkeypatch):
    def verified(evidence, _manifest):  # the evidence checks have their own tests; here every listed worker attests
        return SimpleNamespace(ok=True, enclave_id=enclave_id_for(b64d(evidence.hpke_public_key), b64d(evidence.signing_public_key)))

    monkeypatch.setattr(client_module, "verify_evidence", verified)
    _, client = fake_gateway({})
    client._manifest = object()
    small, full = enclave(small_card()), enclave(None)

    def params(duration_s: float) -> GenerationParams:
        return GenerationParams(profile_id=PROFILE.id, mode=Mode.TEXT_TO_VIDEO, duration_s=duration_s, resolution="1080p", aspect_ratio="16:9", fps=24)

    both = RouteResponse.model_validate(route_json([small, full]))
    assert client._pick_enclave(KunoClient._fitting_route(both, params(8))) is both.enclaves[0]
    assert client._pick_enclave(KunoClient._fitting_route(both, params(10))) is both.enclaves[1]
    assert client._pick_enclave(both) is both.enclaves[0]  # unfiltered, as before
    with pytest.raises(KunoError) as refused:
        KunoClient._fitting_route(RouteResponse.model_validate(route_json([small])), params(10))
    assert (refused.value.status, refused.value.code) == (503, "no_capacity")
    assert KunoClient._fitting_route(RouteResponse.model_validate(route_json()), params(10)).enclaves == []  # nothing listed: as before
