"""Storyboards in the Python SDK (PROTOCOL.md, "Storyboards"): `generate(prompt=<scene>, shots=[Shot(...)])` infers mode
`storyboard`, computes the stitched `duration_s`, routes and fits on the longest shot, seals the shot prompts
(`SealedPayload.shots`) in Private mode and sends them as `shots` in Standard mode, refuses what can't be a storyboard
before anything is sent, and estimates the stitched price. Against fake gateways (httpx.MockTransport)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from kuno_protocol.attestation import enclave_id_for
from kuno_protocol.canonical import b64d, b64e
from kuno_protocol.crypto import RecipientSession, generate_hpke_keypair, generate_signing_key, public_key_bytes
from kuno_protocol.envelope import full_table, to_json
from kuno_protocol.profiles import Mode, load_profiles, storyboard_duration_s
from kuno_protocol.schemas import GenerationParams, RouteResponse, ShotPrompt, ShotSpec, job_aad
from kuno_protocol.sealed_payload import open_payload
from kunoworld import KunoClient, KunoError, Shot
from kunoworld.client import _fit_params

PROFILES = load_profiles()
FAST = PROFILES["ltx-2.5-fast"]
SCENE = "A small blue fishing boat in a quiet harbor at dawn."
SHOTS = [Shot("It leaves the harbor.", 5), Shot("Gulls follow it past the breakwater.", 8), Shot("Night falls.", 5, "cut")]
PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 32


def specs(*spec: tuple[float, str]) -> list[ShotSpec]:
    return [ShotSpec(duration_s=duration, join=join) for duration, join in spec]


def models_json() -> dict:
    return {"models": [profile.model_dump(mode="json") for profile in PROFILES.values()]}


def route_json(profile_id: str = FAST.id, enclaves=()) -> dict:
    return {"profile_id": profile_id, "requested_profile_id": profile_id, "fallback_reason": None, "enclaves": list(enclaves)}


class Gateway:
    """Answers "METHOD /path" from `routes` and records every request."""

    def __init__(self, routes: dict):
        self.routes, self.calls = routes, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        answer = self.routes.get(f"{request.method} {request.url.path}")
        return answer(request) if answer else httpx.Response(404, json={"detail": {"code": "not_found", "message": request.url.path}})

    def client(self) -> KunoClient:
        return KunoClient("kw_test", "https://gw.test", transport=httpx.MockTransport(self))

    def paths(self) -> list[str]:
        return [f"{r.method} {r.url.path}" for r in self.calls]


# ---------------------------------------------------------------- params


def test_a_storyboards_params_carry_its_shots_and_their_stitched_length():
    params = _fit_params(FAST, Mode.STORYBOARD, [], None, "720p", None, None, True, None, shots=SHOTS)
    expected = specs((5, "fresh"), (8, "continue"), (5, "cut"))
    assert (params.mode, params.shots, params.resolution, params.aspect_ratio, params.fps) == (Mode.STORYBOARD, expected, "720p", "16:9", 24)
    assert params.duration_s == storyboard_duration_s(FAST, expected, 24) and params.render_duration_s == 8
    # Defaults: the clip's length for each shot, `fresh` first and `continue` after.
    defaults = _fit_params(FAST, Mode.STORYBOARD, [], None, None, None, 48, True, None, shots=[Shot("a"), Shot("b"), Shot("c")])
    assert defaults.shots == specs((5, "fresh"), (5, "continue"), (5, "continue"))
    assert defaults.duration_s == storyboard_duration_s(FAST, defaults.shots, 48)
    # The clip path is untouched: no shot list, so its bytes (and AAD) are as before storyboards.
    clip = _fit_params(FAST, Mode.TEXT_TO_VIDEO, [], None, None, None, None, True, None)
    assert clip.shots is None and "shots" not in clip.model_dump(mode="json")


# ---------------------------------------------------------------- Private


@pytest.fixture
def private(monkeypatch):
    hpke_private, hpke_public = generate_hpke_keypair()
    signing = public_key_bytes(generate_signing_key())
    enclave = {"enclave_id": enclave_id_for(hpke_public, signing), "hpke_public_key": b64e(hpke_public), "signing_public_key": b64e(signing)}
    gateway = Gateway({"GET /v1/models": lambda r: httpx.Response(200, json=models_json())})
    client = gateway.client()
    routes: list[tuple[tuple, dict]] = []

    def route(*args, **kwargs):
        routes.append((args, kwargs))
        return SimpleNamespace(profile_id=FAST.id, fallback_reason=None, enclaves=[enclave])

    monkeypatch.setattr(client, "route", route)
    monkeypatch.setattr(client, "_pick_enclave", lambda *_args, **_kwargs: enclave)
    return SimpleNamespace(client=client, gateway=gateway, routes=routes, hpke_private=hpke_private)


def test_a_private_storyboard_routes_on_its_longest_shot_and_seals_the_shot_prompts_with_the_scene(private):
    prepared = private.client.prepare(SCENE, model=FAST.id, resolution="1080p", seed=9, shots=SHOTS)
    [(args, kwargs)] = private.routes
    assert args[0] is Mode.STORYBOARD and kwargs["duration_s"] == 8 and kwargs["resolution"] == "1080p"

    request = prepared.request
    assert request.params.mode is Mode.STORYBOARD and request.params.shots == specs((5, "fresh"), (8, "continue"), (5, "cut"))
    assert request.params.duration_s == storyboard_duration_s(FAST, request.params.shots, 24) and request.input_blob_ids == []
    aad = job_aad(request.job_id, request.enclave_id, request.params, request.input_blob_ids)
    payload = open_payload(RecipientSession(private.hpke_private, b64d(request.enc)), b64d(request.ciphertext), aad)
    assert (payload.prompt, payload.shots, payload.seed) == (SCENE, [ShotPrompt(prompt=s.prompt) for s in SHOTS], 9)
    assert private.gateway.paths() == ["GET /v1/models"]  # nothing uploaded: a storyboard has no inputs

    # The scene may be empty; generate infers the mode from the shots and submits.
    private.gateway.routes["POST /v1/videos"] = lambda r: httpx.Response(201, json={})
    job = private.client.generate("", model=FAST.id, shots=SHOTS, wait=False)
    posted = json.loads(private.gateway.calls[-1].content)
    assert (posted["params"]["mode"], len(posted["params"]["shots"]), job.profile_id) == ("storyboard", 3, FAST.id)


def test_an_enclave_is_picked_if_it_fits_the_longest_shot_though_not_the_stitched_video():
    table = full_table(FAST)
    table["1080p"]["16:9"] = {24: 8.0, 25: 8.0, 48: 4.0, 50: 4.0}
    small, full = {"enclave_id": "small", "envelope": {FAST.id: to_json(table)}}, {"enclave_id": "full", "envelope": None}
    route = RouteResponse.model_validate(route_json(enclaves=[small, full]))
    eight = _fit_params(FAST, Mode.STORYBOARD, [], None, "1080p", "16:9", 24, True, None, shots=[Shot("a", 8)] * 4)
    assert eight.duration_s > 30
    assert [e["enclave_id"] for e in KunoClient._fitting_route(route, eight).enclaves] == ["small", "full"]
    ten = _fit_params(FAST, Mode.STORYBOARD, [], None, "1080p", "16:9", 24, True, None, shots=[Shot("a", 8), Shot("b", 10)])
    assert [e["enclave_id"] for e in KunoClient._fitting_route(route, ten).enclaves] == ["full"]


# ---------------------------------------------------------------- Standard


def test_a_standard_storyboard_sends_the_shot_prompts_next_to_the_scene():
    created: dict = {}

    def create(request):
        created.update(json.loads(request.content))
        return httpx.Response(201, json={
            "job_id": created["job_id"], "status": "queued", "stage": None, "progress": 0.0, "params": created["params"],
            "enclave_id": "e1", "price_usd": 0.5, "created_at": 1.0, "updated_at": 1.0, "output_blob_id": None, "receipt": None,
            "error_code": None, "error": None, "privacy": "standard",
        })

    gateway = Gateway({
        "GET /v1/route": lambda r: httpx.Response(200, json=route_json()),
        "GET /v1/models": lambda r: httpx.Response(200, json=models_json()),
        "POST /v1/standard/videos": create,
    })
    job = gateway.client().generate(SCENE, model=FAST.id, shots=SHOTS, privacy="standard", resolution="720p", wait=False)
    route = next(c for c in gateway.calls if c.url.path == "/v1/route")
    assert (route.url.params["mode"], route.url.params["duration_s"], route.url.params["privacy"]) == ("storyboard", "8", "standard")
    params = GenerationParams.model_validate(created["params"])
    assert (created["prompt"], created["shots"], created["inputs"]) == (SCENE, [{"prompt": s.prompt} for s in SHOTS], [])
    assert params.mode is Mode.STORYBOARD and params.duration_s == storyboard_duration_s(FAST, params.shots, 24)
    assert job.profile_id == FAST.id and "POST /v1/standard/uploads" not in gateway.paths()

    # A clip's body is as it was: no `shots` key.
    created.clear()
    gateway.client().generate("a quiet beach", model=FAST.id, privacy="standard", wait=False)
    assert created["prompt"] == "a quiet beach" and "shots" not in created


# ---------------------------------------------------------------- refusals


@pytest.mark.parametrize(
    ("change", "code", "words"),
    [
        (dict(first_frame=PNG), "invalid_inputs", "Storyboards take no inputs"),
        (dict(duration_s=20), "invalid_params", "leave duration_s unset"),
        (dict(mode="text_to_video"), "invalid_shots", "Only storyboards take shots"),
        (dict(shots=[Shot("a"), Shot("  ")]), "invalid_shots", "Shot 2 needs a prompt"),
        (dict(shots=None, mode="storyboard"), "invalid_shots", "needs its shots"),
        (dict(shots=[Shot("a"), Shot("b", join="dissolve")]), "invalid_shots", '"fresh", "continue" or "cut"'),  # type: ignore[arg-type]
        (dict(shots=[Shot("a"), Shot("x" * FAST.limits.max_prompt_chars)]), "prompt_too_long", "Shot 2's prompt, with the scene before it"),
    ],
)
@pytest.mark.parametrize("privacy", ["private", "standard"])
def test_what_cant_be_a_storyboard_is_refused_before_anything_is_sent(change, code, words, privacy):
    gateway = Gateway({
        "GET /v1/route": lambda r: httpx.Response(200, json=route_json()),
        "GET /v1/models": lambda r: httpx.Response(200, json=models_json()),
    })
    arguments = {"model": FAST.id, "shots": SHOTS, "privacy": privacy, "wait": False, **change}
    with pytest.raises(KunoError) as refused:
        gateway.client().generate(SCENE, **arguments)
    assert refused.value.code == code and words in refused.value.message, refused.value.message
    assert all(path.startswith("GET ") for path in gateway.paths())


def test_a_storyboard_on_a_profile_without_one_is_refused_after_routing():
    pro = PROFILES["ltx-2.5-pro"]
    gateway = Gateway({
        "GET /v1/route": lambda r: httpx.Response(200, json=route_json(pro.id)),
        "GET /v1/models": lambda r: httpx.Response(200, json=models_json()),
    })
    with pytest.raises(KunoError) as refused:
        gateway.client().generate(SCENE, model=pro.id, shots=SHOTS, privacy="standard", wait=False)
    assert refused.value.code == "invalid_params" and "does not support storyboard" in refused.value.message
    assert gateway.paths() == ["GET /v1/route", "GET /v1/models"]


# ---------------------------------------------------------------- price


def test_the_price_estimate_is_the_stitched_seconds_at_the_models_rate():
    client = Gateway({"GET /v1/models": lambda r: httpx.Response(200, json=models_json())}).client()
    shots = [Shot("It leaves the harbor.", 5), Shot("Gulls follow it.", 5), Shot("Night falls.", 5, "cut")]
    stitched = storyboard_duration_s(FAST, specs((5, "fresh"), (5, "continue"), (5, "cut")), 24)
    assert stitched == pytest.approx(13.708, abs=1e-3)
    assert client.estimate_price(FAST.id, shots=shots, resolution="720p") == round(0.05 * stitched, 4) == 0.6854
    assert client.estimate_price(FAST.id, shots=shots, resolution="720p", privacy="standard") == round(0.04 * stitched, 4)
    # At 48 fps the shots' frames and the overlap trim differ, and the fps multiplier applies to the whole video.
    at_48 = storyboard_duration_s(FAST, specs((5, "fresh"), (5, "continue"), (5, "cut")), 48)
    assert client.estimate_price(FAST.id, shots=shots, resolution="1080p", fps=48) == round(0.08 * at_48 * 1.5, 4)
    assert client.estimate_price(FAST.id, duration_s=10, resolution="1080p") == 0.8
    with pytest.raises(KunoError) as refused:
        client.estimate_price("ltx-2.5-pro", shots=shots)
    assert refused.value.code == "invalid_params"
