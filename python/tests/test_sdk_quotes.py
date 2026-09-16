"""Quotes and the budget guard in the Python SDK: `quote()` sends a job's shape and never a prompt, and `max_price_usd` on
`generate`, `prepare` and `submit_standard` has the gateway quote the exact params about to be sent, refusing `over_budget`
before any input is uploaded, anything is sealed or a worker is picked. Against a fake gateway (kuno_fake_network.py)."""

from __future__ import annotations

import json
import math

import pytest

from kuno_fake_network import PROFILES, FakeNetwork, detail
from kuno_protocol.profiles import InputRole, Mode, storyboard_duration_s
from kuno_protocol.schemas import GenerationParams, ShotSpec
from kunoworld import ERROR_CODES, Input, KunoError, Quote, Shot

FAST = PROFILES["ltx-2.5-fast"]
PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 32
SCENE = "A lighthouse keeper's cottage on a cliff, storm light, 35 mm film."
SECRET = "the keeper whispers the combination 4-8-15"
SHOTS = [Shot(f"{SECRET}, shot one", 5), Shot("Waves hit the rocks below.", 5), Shot("Inside, the lamp is lit.", 4, "cut")]


@pytest.fixture
def network() -> FakeNetwork:
    return FakeNetwork()


def test_a_quote_sends_the_jobs_shape_and_reads_back_a_typed_quote(network):
    quote = network.client().quote("ltx-2.5-fast", shots=SHOTS, resolution="720p")
    [body] = network.quotes
    assert body == {"privacy": "private", "audio": True, "profile_id": FAST.id, "mode": "storyboard", "resolution": "720p",
                    "shots": [{"duration_s": 5, "join": None}, {"duration_s": 5, "join": None}, {"duration_s": 4, "join": "cut"}]}
    assert SECRET.encode() not in network.sent()

    assert isinstance(quote, Quote) and isinstance(quote.params, GenerationParams)
    specs = [ShotSpec(duration_s=5, join="fresh"), ShotSpec(duration_s=5, join="continue"), ShotSpec(duration_s=4, join="cut")]
    assert quote.params.shots == specs and quote.params.duration_s == storyboard_duration_s(FAST, specs, 24)
    assert quote.price_usd == FAST.price_usd(quote.params) and quote.breakdown.billable_seconds == quote.params.duration_s
    assert (quote.profile_id, quote.privacy, quote.placeholder, quote.balance_usd, quote.balance_covers) == (FAST.id, "private", True, 25.0, True)

    # ShotSpecs work too, and the mode follows the inputs a job will send, as generate infers it.
    network.client().quote(shots=specs, privacy="standard")
    assert network.quotes[-1]["shots"][2] == {"duration_s": 4.0, "join": "cut"} and "profile_id" not in network.quotes[-1]
    network.client().quote(FAST.id, input_roles=["first_frame", "last_frame"], duration_s=8)
    assert (network.quotes[-1]["mode"], network.quotes[-1]["input_roles"]) == ("first_last_frame", ["first_frame", "last_frame"])


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        (dict(shots=SHOTS, duration_s=10), "invalid_params"),
        (dict(shots=SHOTS, mode="text_to_video"), "invalid_shots"),
        (dict(mode="storyboard"), "invalid_shots"),
        (dict(shots=SHOTS, input_roles=["first_frame"]), "invalid_inputs"),
        (dict(shots=[Shot("", 5), Shot("", 5, "dissolve")]), "invalid_shots"),  # type: ignore[arg-type]
        (dict(privacy="public"), "invalid_privacy"),
    ],
)
def test_a_quote_that_cant_be_a_job_is_refused_before_sending(network, arguments, code):
    with pytest.raises(KunoError) as refused:
        network.client().quote(FAST.id, **arguments)
    assert refused.value.code == code and network.calls == []


def test_gateway_refusals_come_back_with_their_codes(network):
    network.refuse["POST /v1/quote"] = detail(451, "region_restricted", "MiniMax H3 is not licensed in your region")
    with pytest.raises(KunoError) as refused:
        network.client().quote("h3")
    assert (refused.value.status, refused.value.code) == (451, "region_restricted")


# ---------------------------------------------------------------- the budget guard


def test_over_budget_a_private_job_is_refused_before_an_input_is_uploaded_or_a_worker_picked(network, monkeypatch):
    client = network.client()
    picked = []
    monkeypatch.setattr(client, "_pick_enclave", lambda route: picked.append(route) or network.enclave)
    network.price_usd = 2.5
    with pytest.raises(KunoError) as refused:
        client.generate("A glass flower turns.", model=FAST.id, first_frame=PNG, max_price_usd=2.49, wait=False)
    error = refused.value
    assert error.code == "over_budget" and error.details == {"price_usd": 2.5, "max_price_usd": 2.49, "profile_id": FAST.id}
    assert "$2.5" in error.message and error.explanation == ERROR_CODES["over_budget"]
    assert picked == [] and "POST /v1/blobs" not in network.paths() and "POST /v1/videos" not in network.paths()

    # The quote was for exactly the params generate would have sealed: every field sent, on the routed profile.
    [body] = network.quotes
    assert body == {"profile_id": FAST.id, "mode": "image_to_video", "privacy": "private", "resolution": "720p",
                    "aspect_ratio": "16:9", "fps": 24, "audio": True, "input_roles": ["first_frame"], "duration_s": 5.0}


def test_within_budget_the_job_goes_ahead_and_carries_its_quote(network):
    client = network.client()
    prepared = client.prepare(SCENE, model=FAST.id, shots=SHOTS, resolution="1080p", max_price_usd=5)
    assert prepared.quote is not None and prepared.quote.params == prepared.request.params
    assert prepared.quote.price_usd == FAST.price_usd(prepared.request.params) <= 5
    assert network.quotes[-1]["shots"] == [s.model_dump(mode="json") for s in prepared.request.params.shots]
    job = client.submit(prepared)
    assert network.jobs[job.job_id].price == prepared.quote.price_usd
    assert SECRET.encode() not in network.sent()  # the shot prompts went sealed, and never into the quote

    # A price exactly at the limit is within it.
    network.price_usd = prepared.quote.price_usd
    assert client.prepare(SCENE, model=FAST.id, shots=SHOTS, resolution="1080p", max_price_usd=prepared.quote.price_usd).quote


def test_over_budget_a_standard_job_uploads_nothing(network):
    network.price_usd = 1.0
    client = network.client()
    with pytest.raises(KunoError) as refused:
        client.submit_standard("A quiet beach.", inputs=[Input.load(InputRole.FIRST_FRAME, PNG)], model=FAST.id, max_price_usd=0.5)
    assert refused.value.code == "over_budget"
    assert network.quotes[-1]["privacy"] == "standard"
    assert "POST /v1/standard/uploads" not in network.paths() and "POST /v1/standard/videos" not in network.paths()

    network.price_usd = None
    job = client.generate("A quiet beach.", model=FAST.id, privacy="standard", max_price_usd=0.5, wait=False)
    assert network.jobs[job.job_id].body["prompt"] == "A quiet beach."


def test_a_quote_for_other_params_than_the_job_is_refused(network, monkeypatch):
    real = network.quote

    def other_params(body):
        return real({**body, "duration_s": 9.0})

    monkeypatch.setattr(network, "quote", other_params)
    with pytest.raises(KunoError) as refused:
        network.client().generate("A fox.", model=FAST.id, duration_s=5, max_price_usd=10, wait=False)
    assert refused.value.code == "quote_mismatch" and "POST /v1/videos" not in network.paths()


@pytest.mark.parametrize("bad", [-1, math.nan, math.inf, "5", True])
def test_a_budget_must_be_a_real_amount(network, bad):
    with pytest.raises(KunoError) as refused:
        network.client().generate("A fox.", model=FAST.id, max_price_usd=bad, wait=False)
    assert refused.value.code == "invalid_budget" and network.calls == []


def test_without_a_budget_nothing_is_quoted(network):
    network.client().generate("A fox.", model=FAST.id, wait=False)
    assert network.quotes == [] and "POST /v1/videos" in network.paths()


def test_status_and_cancel_work_by_job_id_in_either_mode(network):
    client = network.client()
    job = client.generate("A fox.", model=FAST.id, privacy="standard", wait=False)
    assert client.status(job.job_id).status.value == "queued"
    assert client.cancel(job.job_id).status.value == "canceled"
    assert json.loads(network.calls[-1].content or b"{}") == {} and network.paths()[-1] == f"POST /v1/videos/{job.job_id}/cancel"
    assert Mode(client.status(job.job_id).params.mode) is Mode.TEXT_TO_VIDEO
