"""Plans (Director) in the Python SDK (PROTOCOL.md "Plans (Director)"): `plan()` routes to enclaves that advertise `plan/1`,
sends the longest shot their envelopes serve as `options.plan.max_shot_s`, seals the brief and style, opens the sealed plan
here (form 2 framing), checks it against the signed receipt and `kuno_protocol.plans.validate`; `revise_plan` rewrites
listed shots only; Standard plans go through `/v1/standard/plans`; a plan renders as its storyboard exactly with
`generate(plan=...)`; plan prices are flat. Against a fake gateway and enclave (kuno_fake_network.py)."""

from __future__ import annotations

import json

import pytest

from kuno_fake_network import PROFILES, FakeNetwork
from kuno_protocol.plans import PLAN_FEATURE, validate
from kuno_protocol.profiles import Mode
from kuno_protocol.schemas import JobCreate, ShotPrompt
from kunoworld import KunoError, Plan, PlanJob

FAST = PROFILES["ltx-2.5-fast"]
BRIEF = 'A 30-second ad for a small coffee roastery, warm and handmade. End on "Roasted this morning."'
STYLE = "35mm film, warm"


@pytest.fixture
def network(monkeypatch) -> FakeNetwork:
    monkeypatch.setattr("kunoworld.client.time.sleep", lambda _s: None)
    return FakeNetwork()


def created(network: FakeNetwork) -> list[JobCreate]:
    return [JobCreate.model_validate_json(r.content) for r in network.calls if f"{r.method} {r.url.path}" == "POST /v1/videos"]


def test_a_private_plan_is_sealed_to_a_plan_worker_opened_here_and_checked(network):
    client = network.client()
    seen = []
    plan = client.plan(BRIEF, target_s=30, resolution="720p", style=STYLE, seed=7, on_progress=seen.append)

    # Routed for mode plan without a duration (a plan renders nothing), and sealed: the gateway never saw the brief.
    route = next(r for r in network.calls if r.url.path == "/v1/route")
    assert route.url.params.get("mode") == "plan" and "duration_s" not in route.url.params
    [job] = created(network)
    assert job.params.mode is Mode.PLAN and job.params.duration_s == 30 and job.params.shots is None and job.input_blob_ids == []
    assert b"roastery" not in network.sent() and STYLE.encode() not in network.sent()
    payload = network.jobs[job.job_id].payload
    options = payload.options["plan"]
    # No envelope on the worker: the longest shot is the profile's own at 24 fps.
    assert (payload.prompt, payload.seed, options["style"], options["max_shot_s"]) == (BRIEF, 7, STYLE, 20.0)
    assert [s.stage for s in seen] == [None, "planning", "checking", "done"]

    assert isinstance(plan, Plan) and plan.model_dump() == network.jobs[job.job_id].plan.model_dump()
    assert (plan.job_id, plan.privacy, plan.receipt.body.plan.shots) == (job.job_id, "private", len(plan.shots))
    assert abs(plan.duration_s - 30) <= 0.5 and plan.target_s == 30
    validate(plan, FAST)
    assert json.loads(plan.to_json())["title"] == plan.title and Plan.model_validate_json(plan.to_json()).model_dump() == plan.model_dump()


def test_a_plan_renders_as_its_storyboard_exactly(network):
    client = network.client()
    plan = client.plan(BRIEF, target_s=20, aspect_ratio="9:16")
    shots = plan.to_shots()
    assert [(s.prompt, s.duration_s, s.join) for s in shots] == [(p.prompt, p.duration_s, p.join) for p in plan.shots]

    video = client.generate(plan=plan, max_price_usd=10)
    [_, render] = created(network)
    assert render.params == plan.storyboard_params() and render.params.duration_s == plan.duration_s
    payload = network.jobs[render.job_id].payload
    assert payload.prompt == plan.scene and payload.shots == [ShotPrompt(prompt=s.prompt) for s in plan.shots]
    assert video.receipt.body.video.duration_s == plan.duration_s

    # Its price is the storyboard's, locally and from the gateway, and the frame can't be changed next to a plan.
    assert client.estimate_price(plan=plan) == FAST.price_usd(plan.storyboard_params())
    assert client.quote(plan=plan).params == plan.storyboard_params()
    for wrong in (dict(model="ltx-2.5-pro"), dict(fps=48), dict(prompt="another scene"), dict(duration_s=10)):
        with pytest.raises(KunoError) as refused:
            client.generate(plan=plan, **wrong)
        assert refused.value.code == "invalid_params"


def test_the_longest_shot_comes_from_the_plan_workers_envelopes(network):
    network.enclave["envelope"] = {FAST.id: {"720p": {"16:9": {"24": 11.0}}, "1080p": {"16:9": {"24": 4.0}}}}
    plan = network.client().plan(BRIEF, target_s=45, resolution="720p")
    [job] = created(network)
    assert network.jobs[job.job_id].payload.options["plan"]["max_shot_s"] == 11.0
    assert max(shot.duration_s for shot in plan.shots) <= 11

    # A size no plan worker serves is refused before anything is sent.
    network.enclave["envelope"] = {FAST.id: {"720p": {"16:9": {"24": 11.0}}}}
    with pytest.raises(KunoError) as refused:
        network.client().plan(BRIEF, target_s=30, resolution="1080p")
    assert refused.value.code == "plans_unavailable" and len(created(network)) == 1


def test_without_a_plan_worker_nothing_is_sent_and_the_reason_is_plain(network):
    network.enclave.pop("features")
    with pytest.raises(KunoError) as refused:
        network.client().plan(BRIEF, target_s=30, max_price_usd=1)
    assert refused.value.code == "plans_unavailable" and "doesn't say which workers write plans" in refused.value.message

    network.enclave["features"] = ["something/2"]
    with pytest.raises(KunoError) as refused:
        network.client().plan(BRIEF, target_s=30)
    assert refused.value.code == "plans_unavailable" and "No confidential worker that writes plans" in refused.value.message
    assert created(network) == [] and network.quotes == []
    assert refused.value.explanation and PLAN_FEATURE in refused.value.explanation


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        (dict(brief="   "), "brief_required"),
        (dict(brief="x" * 4001), "prompt_too_long"),
        (dict(style="y" * 501), "prompt_too_long"),
        (dict(target_s=3), "invalid_params"),
        (dict(target_s=121), "invalid_params"),
        (dict(model="ltx-2.5-pro"), "invalid_params"),
        (dict(privacy="public"), "invalid_privacy"),
        (dict(max_price_usd=-1), "invalid_budget"),
    ],
)
def test_plans_that_cant_be_made_are_refused_before_sending(network, arguments, code):
    kwargs = {"brief": BRIEF, "target_s": 30, **arguments}
    with pytest.raises(KunoError) as refused:
        network.client().plan(kwargs.pop("brief"), **kwargs)
    assert refused.value.code == code and created(network) == []


def test_a_plan_over_budget_costs_nothing_and_plan_prices_are_flat(network):
    client = network.client()
    with pytest.raises(KunoError) as refused:
        client.plan(BRIEF, target_s=30, max_price_usd=0.05)
    assert refused.value.code == "over_budget" and created(network) == []

    for target in (10, 90):
        private = client.quote(FAST.id, mode="plan", duration_s=target)
        assert (private.price_usd, private.params.mode, private.breakdown.plan_usd, private.breakdown.usd_per_second) == (0.1, Mode.PLAN, 0.1, None)
    assert client.quote(FAST.id, mode="plan", duration_s=30, privacy="standard").price_usd == 0.08
    assert client.estimate_price(FAST.id, mode="plan", duration_s=60) == 0.1
    assert client.estimate_price(FAST.id, mode="plan", duration_s=60, privacy="standard") == 0.08
    assert client.plan(BRIEF, target_s=30, max_price_usd=0.1).job_id


def test_a_plan_job_can_be_left_and_resumed_and_its_failures_keep_their_code(network):
    client = network.client()
    job = client.plan(BRIEF, target_s=30, wait=False)
    assert isinstance(job, PlanJob) and job.max_shot_s == 20.0
    saved = json.loads(json.dumps(job.export()))
    assert saved["kind"] == "plan" and saved["output_key"]
    plan = PlanJob.restore(network.client(), saved).wait()
    assert plan.job_id == job.job_id

    network.plan_failure = "plan_failed"
    with pytest.raises(KunoError) as failed:
        client.plan(BRIEF, target_s=30)
    assert failed.value.code == "plan_failed" and "refunded" in failed.value.explanation


def test_a_tampered_plan_is_refused(network):
    client = network.client()
    job = client.plan(BRIEF, target_s=30, wait=False)
    for _ in range(3):
        job.status()
    status = job.status()
    sealed = network.blobs[status.output_blob_id]
    network.blobs[status.output_blob_id] = sealed[:-1] + bytes([sealed[-1] ^ 1])
    with pytest.raises(KunoError) as refused:
        job.result(status)
    assert refused.value.code == "integrity"

    network.blobs[status.output_blob_id] = sealed
    other = PlanJob(client, job.job_id, job.profile_id, output_key=b"\x01" * 32, signing_public_key=job.signing_public_key)
    with pytest.raises(KunoError) as refused:
        other.result(status)
    assert refused.value.code == "decrypt_failed"
    assert job.result(status).job_id == job.job_id


def test_revising_listed_shots_keeps_everything_else(network):
    client = network.client()
    plan = client.plan(BRIEF, target_s=30)
    # An edit by hand: the stitched length is recomputed before the plan is sent.
    plan.shots[0].duration_s = plan.shots[0].duration_s - 1
    revised = client.revise_plan(plan, "darker, at night", shots=[2])
    [_, job] = created(network)
    options = network.jobs[job.job_id].payload.options["plan"]
    assert options["revise"]["shots"] == [2] and options["revise"]["instruction"] == "darker, at night"
    assert job.params.duration_s == plan.target_s and network.jobs[job.job_id].payload.prompt == ""
    assert "darker, at night" in revised.shots[1].prompt
    assert (revised.title, revised.scene, revised.notes) == (plan.title, plan.scene, plan.notes)
    assert [s for i, s in enumerate(revised.shots) if i != 1] == [s for i, s in enumerate(plan.shots) if i != 1]
    assert revised.privacy == "private" and revised.job_id == job.job_id

    # From JSON too; a shot number the plan doesn't have, or a broken plan, is refused before sending.
    assert client.revise_plan(revised.to_json(), "brighter").job_id
    with pytest.raises(KunoError) as refused:
        client.revise_plan(revised, "x", shots=[9])
    assert refused.value.code == "invalid_plan"
    broken = revised.model_copy(deep=True)
    broken.shots[0].join = "cut"
    with pytest.raises(KunoError) as refused:
        client.revise_plan(broken, "x")
    assert refused.value.code == "invalid_plan"
    with pytest.raises(KunoError) as refused:
        client.revise_plan({"title": "no"}, "x")
    assert refused.value.code == "invalid_plan"
    assert len(created(network)) == 3


def test_a_standard_plan_goes_through_the_standard_routes(network):
    client = network.client()
    plan = client.plan(BRIEF, target_s=25, style=STYLE, privacy="standard", seed=3)
    [call] = [r for r in network.calls if f"{r.method} {r.url.path}" == "POST /v1/standard/plans"]
    body = json.loads(call.content)
    assert (body["brief"], body["style"], body["seed"], body["params"]["mode"], body["params"]["duration_s"]) == (BRIEF, STYLE, 3, "plan", 25)
    assert body["options"]["max_shot_s"] == 20.0 and "style" not in body["options"]
    assert created(network) == []
    assert plan.privacy == "standard" and abs(plan.duration_s - 25) <= 0.5
    assert f"GET /v1/standard/plans/{plan.job_id}" in network.paths()

    # A revision keeps the plan's mode.
    revised = client.revise_plan(plan, "shorter shots")
    assert revised.privacy == "standard" and created(network) == []

    # The stored plan must match the receipt.
    job = client.plan(BRIEF, target_s=25, privacy="standard", wait=False)
    for _ in range(3):
        job.status()
    network.jobs[job.job_id].plan = revised
    with pytest.raises(KunoError) as refused:
        job.wait()
    assert refused.value.code == "integrity"
