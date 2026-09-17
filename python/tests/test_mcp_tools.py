"""The MCP server's tools (kunoworld.mcp.tools), without MCP: configuration, the budget rule, the local job store and its
permissions, and every tool against a fake gateway and enclave (kuno_fake_network.py), a Private storyboard included:
sealed shot prompts, the output key kept only on disk, stage `shot i/N`, and the video decrypted and checked here."""

from __future__ import annotations

import json
import os
import stat
import uuid
from pathlib import Path

import pytest

from kuno_fake_network import API_URL, PROFILES, FakeNetwork, detail
from kuno_protocol.canonical import sha256_hex
from kuno_protocol.profiles import storyboard_duration_s
from kuno_protocol.schemas import ShotPrompt, ShotSpec
from kunoworld.mcp.jobs import JobStore
from kunoworld.mcp.tools import Config, ConfigError, KunoTools, ToolFailure, describe_error
from kunoworld import KunoError

FAST = PROFILES["ltx-2.5-fast"]
PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 32
SCENE = "A small blue fishing boat with a red stripe, in a quiet harbor. Soft morning light, 35 mm film."
SECRET = "the skipper hums an old song about Marguerite"
SHOTS = [
    {"prompt": "The boat leaves the harbor, gulls circling.", "duration_s": 5},
    {"prompt": f"Close on the skipper at the wheel; {SECRET}.", "duration_s": 4, "join": "cut"},
    {"prompt": "Night: the boat's lamp alone on a dark sea.", "duration_s": 5, "join": "fresh"},
]


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def setup(tmp_path):
    network = FakeNetwork()
    config = Config(api_key="kw_live_test", api_url=API_URL, output_dir=tmp_path / "videos", jobs_dir=tmp_path / "home" / ".kunoworld" / "jobs")
    tools = KunoTools(config, client_factory=network.client, sleep=lambda _s: None)
    return network, tools, config


def with_config(tools: KunoTools, **changes) -> KunoTools:
    from dataclasses import replace

    return KunoTools(replace(tools.config, **changes), client_factory=tools._factory, store=tools.store, sleep=lambda _s: None)


# ---------------------------------------------------------------- configuration


def test_configuration_comes_from_the_environment_with_safe_defaults(tmp_path):
    config = Config.from_env({})
    assert (config.api_key, config.api_url, config.privacy, config.max_job_usd) == (None, "https://api.kunoworld.com", "private", None)
    assert config.jobs_dir == Path.home() / ".kunoworld" / "jobs"
    assert "not pinned" in config.attestation_trust

    config = Config.from_env({
        "KUNOWORLD_API_KEY": " kw_live_abc ", "KUNOWORLD_API_URL": "http://127.0.0.1:8080/", "KUNOWORLD_PRIVACY": "Standard",
        "KUNOWORLD_MAX_JOB_USD": "2.50", "KUNOWORLD_OUTPUT_DIR": str(tmp_path / "out"), "KUNOWORLD_JOBS_DIR": str(tmp_path / "jobs"),
        "KUNOWORLD_OWNER_PUBLIC_KEY": "b3duZXI", "KUNOWORLD_COUNTRY": "JP",
    })
    assert (config.api_key, config.api_url, config.privacy, config.max_job_usd, config.country) == (
        "kw_live_abc", "http://127.0.0.1:8080", "standard", 2.5, "JP")
    assert (config.output_dir, config.jobs_dir) == (tmp_path / "out", tmp_path / "jobs")
    assert "owner's signature" in config.attestation_trust

    for bad in ({"KUNOWORLD_PRIVACY": "public"}, {"KUNOWORLD_MAX_JOB_USD": "lots"}, {"KUNOWORLD_MAX_JOB_USD": "-1"}, {"KUNOWORLD_MAX_JOB_USD": "nan"}):
        with pytest.raises(ConfigError):
            Config.from_env(bad)


# ---------------------------------------------------------------- the job store


def test_handles_are_kept_in_a_private_directory_one_private_file_each(tmp_path):
    directory = tmp_path / "home" / ".kunoworld" / "jobs"
    store = JobStore(directory)
    job_id = str(uuid.uuid4())
    path = store.save({"job_id": job_id, "output_key": "k" * 43, "created_at": 1.0})
    assert (mode_of(directory), mode_of(path)) == (0o700, 0o600)
    assert store.load(job_id)["output_key"] == "k" * 43 and [p.name for p in directory.iterdir()] == [f"{job_id}.json"]

    # A directory someone made more open is tightened, and a rewrite keeps the file private.
    os.chmod(directory, 0o755)
    store.update(job_id, status="queued")
    assert (mode_of(directory), mode_of(path), store.load(job_id)["status"]) == (0o700, 0o600, "queued")

    # Only a job id names a file.
    for bad in ("../../etc/passwd", "x", job_id.upper()):
        assert store.load(bad) is None
        with pytest.raises(ValueError):
            store.save({"job_id": bad})
    store.delete(job_id)
    assert store.load(job_id) is None


# ---------------------------------------------------------------- tools


def test_list_models_is_compact_and_needs_no_key(setup):
    network, tools, _ = setup
    listing = with_config(tools, api_key=None).list_models()
    models = {m["id"]: m for m in listing["models"]}
    fast = models["ltx-2.5-fast"]
    assert listing["prices_are_placeholders"] is True
    assert fast["available"] is True and fast["storyboard"] == {"max_shots": 12, "max_total_s": 120, "joins": ["fresh", "continue", "cut"], "overlap_frames": 17}
    assert fast["usd_per_second"] == {"private": {"720p": 0.12, "1080p": 0.17}, "standard": {"720p": 0.09, "1080p": 0.13}}
    assert fast["duration_s"] == {"min": 2.0, "max": 20.0, "step": 1.0, "max_at_fps": {"48": 10.0, "50": 10.0}}
    assert (models["h3"]["available"], models["h3"]["unavailable_reason"]) == (False, "not licensed in this region")
    assert models["ltx-2.5-pro"]["unavailable_reason"] == "no workers online" and models["ltx-2.5-pro"]["storyboard"] is None
    assert "limits" not in fast and "vcu_weights" not in fast


def test_a_quote_through_the_tool_never_sends_a_prompt(setup):
    network, tools, _ = setup
    quote = tools.quote_price(model=FAST.id, shots=SHOTS, resolution="720p")
    assert quote["model"] == FAST.id and quote["settings"]["mode"] == "storyboard"
    assert [s["join"] for s in quote["settings"]["shots"]] == ["fresh", "cut", "fresh"]
    specs = [ShotSpec(duration_s=5, join="fresh"), ShotSpec(duration_s=4, join="cut"), ShotSpec(duration_s=5, join="fresh")]
    assert quote["price_usd"] == round(0.12 * storyboard_duration_s(FAST, specs, 24), 4) and quote["prices_are_placeholders"] is True
    assert SECRET.encode() not in network.sent()
    # Without the file, an image-to-video job is priced with the input it needs; a missing file is named.
    assert tools.quote_price(model=FAST.id, mode="image_to_video")["settings"]["input_roles"] == ["first_frame"]
    with pytest.raises(ToolFailure) as missing:
        tools.quote_price(model=FAST.id, first_frame_path="/nowhere/frame.png")
    assert missing.value.code == "input_not_found"


def test_generating_needs_a_budget_and_a_key(setup):
    network, tools, _ = setup
    with pytest.raises(ToolFailure) as refused:
        tools.generate_video("A fox in snow.", model=FAST.id)
    assert refused.value.code == "budget_required" and network.calls == []
    with pytest.raises(ToolFailure) as refused:
        with_config(tools, api_key=None).generate_video("A fox in snow.", model=FAST.id, max_price_usd=5)
    assert refused.value.code == "missing_api_key"
    with pytest.raises(ToolFailure) as refused:
        tools.generate_video("A fox in snow.", model=FAST.id, max_price_usd=-2)
    assert refused.value.code == "invalid_budget"


def test_over_budget_nothing_is_created_and_the_message_says_who_can_raise_the_limit(setup):
    network, tools, _ = setup
    network.price_usd = 3.0
    with pytest.raises(ToolFailure) as refused:
        tools.generate_video("A fox in snow.", model=FAST.id, max_price_usd=2)
    assert refused.value.code == "over_budget" and "max_price_usd of at least" in refused.value.message
    capped = with_config(tools, max_job_usd=1.0)
    with pytest.raises(ToolFailure) as refused:
        capped.generate_video("A fox in snow.", model=FAST.id, max_price_usd=5)  # the agent can't raise the server's cap
    assert "$1 limit set by KUNOWORLD_MAX_JOB_USD" in refused.value.message and "Only the user" in refused.value.message
    assert all(path in ("POST /v1/quote",) for path in network.paths())
    assert list(tools.store.records()) == []

    # The server's cap alone is enough of a budget.
    network.price_usd = None
    result = capped.generate_video("A fox in snow.", model=FAST.id, duration_s=5, privacy="standard")
    assert (result["status"], result["max_price_usd"], result["price_usd"]) == ("queued", 1.0, 0.45)


def test_a_private_storyboard_through_the_tools_end_to_end(setup):
    network, tools, config = setup
    started = tools.generate_video(SCENE, model=FAST.id, shots=SHOTS, resolution="720p", seed=11, max_price_usd=5)
    job_id = started["job_id"]
    assert (started["status"], started["privacy"], started["shots"], started["mode"]) == ("queued", "private", 3, "storyboard")
    assert started["price_usd"] == network.jobs[job_id].price and "not pinned" in started["attestation_checked_against"]

    # The enclave got the scene and every shot prompt sealed; the gateway never saw them in the clear.
    payload = network.jobs[job_id].payload
    assert (payload.prompt, payload.shots, payload.seed) == (SCENE, [ShotPrompt(prompt=s["prompt"]) for s in SHOTS], 11)
    assert SECRET.encode() not in network.sent() and SCENE.encode() not in network.sent()

    # The handle holds the output key, only on disk, with no prompt.
    handle = Path(started["handle_file"])
    assert handle.parent == config.jobs_dir and (mode_of(handle), mode_of(handle.parent)) == (0o600, 0o700)
    saved = json.loads(handle.read_text())
    assert saved["output_key"] and saved["signing_public_key"] and saved["status"] == "queued"
    assert SECRET not in handle.read_text() and SCENE not in handle.read_text()
    assert "output_key" not in json.dumps(started)

    # Each status request moves the fake job on a stage: generate_video's own saw it queued.
    with pytest.raises(ToolFailure) as early:
        tools.download_video(job_id)
    assert early.value.code == "not_ready" and "(shot 1/3)" in early.value.message
    assert [tools.get_job(job_id)["stage"] for _ in range(2)] == ["shot 2/3", "shot 3/3"]
    done = tools.get_job(job_id)
    assert (done["status"], done["can_download"]) == ("succeeded", True)

    download = tools.download_video(job_id, filename="../../harbor.mp4")
    video = Path(download["path"])
    assert video == config.output_dir / "harbor.mp4" and mode_of(video) == 0o600
    assert video.read_bytes() == network.jobs[job_id].video and download["sha256"] == sha256_hex(video.read_bytes())
    assert download["receipt"]["content_digest"] == download["sha256"] and download["receipt"]["job_id"] == job_id
    assert download["size_bytes"] == len(network.jobs[job_id].video) and len(download["checks"]) == 3
    assert json.loads(Path(download["receipt_path"]).read_text())["body"]["job_id"] == job_id
    assert tools.get_job(job_id)["saved_path"] == str(video)

    listed = tools.list_jobs()
    assert [j["job_id"] for j in listed["jobs"]] == [job_id] and listed["jobs"][0]["saved_path"] == str(video)
    assert "output_key" not in json.dumps(listed)


def test_downloads_never_replace_another_file(setup):
    network, tools, config = setup
    job_id = tools.generate_video("A fox.", model=FAST.id, max_price_usd=5, wait=True)["job_id"]
    config.output_dir.mkdir(parents=True, exist_ok=True)
    mine = config.output_dir / "fox.mp4"
    mine.write_bytes(b"the user's own film")
    first = tools.download_video(job_id, filename="fox")
    assert first["path"] == str(config.output_dir / "fox-2.mp4") and mine.read_bytes() == b"the user's own film"
    # The same video again reuses its own file.
    assert tools.download_video(job_id, filename="fox")["path"] == first["path"]


def test_waiting_reports_every_status_and_saves_the_video(setup):
    network, tools, config = setup
    seen = []
    result = tools.generate_video("", model=FAST.id, shots=SHOTS[:2], max_price_usd=5, wait=True, on_status=seen.append)
    assert [s.stage for s in seen] == ["shot 1/2", "shot 2/2", "done"]
    assert result["status"] == "succeeded" and Path(result["download"]["path"]).read_bytes() == network.jobs[result["job_id"]].video


def test_a_standard_job_needs_no_key_to_download(setup):
    network, tools, config = setup
    image = config.output_dir.parent / "frame.png"
    image.write_bytes(PNG)
    result = tools.generate_video("A glass flower turns.", model=FAST.id, first_frame_path=str(image), privacy="standard", max_price_usd=5)
    job_id = result["job_id"]
    assert (result["privacy"], result["mode"], network.jobs[job_id].body["prompt"]) == ("standard", "image_to_video", "A glass flower turns.")
    assert "output_key" not in json.loads(Path(result["handle_file"]).read_text())
    tools.store.delete(job_id)  # a Standard video opens with the account alone
    for _ in range(3):
        tools.get_job(job_id)
    assert tools.download_video(job_id)["privacy"] == "standard"


def test_a_private_video_without_its_key_here_cant_be_opened(setup):
    network, tools, _ = setup
    job_id = tools.generate_video("A fox.", model=FAST.id, max_price_usd=5, wait=True)["job_id"]
    tools.store.delete(job_id)
    with pytest.raises(ToolFailure) as refused:
        tools.download_video(job_id)
    assert refused.value.code == "missing_key" and "KunoWorld doesn't have it" in refused.value.message


def test_a_refused_submission_leaves_no_handle_behind(setup):
    network, tools, _ = setup
    network.refuse["POST /v1/videos"] = detail(403, "private_mode_not_eligible", "Private mode needs a verified payment.", reasons=["no_verified_payment"])
    with pytest.raises(KunoError) as refused:
        tools.generate_video("A fox.", model=FAST.id, max_price_usd=5)
    assert refused.value.code == "private_mode_not_eligible" and tools.store.records() == []
    assert describe_error(refused.value) == ("private_mode_not_eligible: Private mode needs a verified payment. "
                                             f"(reasons: no_verified_payment; {refused.value.explanation})")


def test_cancel_and_bad_job_ids(setup):
    network, tools, _ = setup
    job_id = tools.generate_video("A fox.", model=FAST.id, max_price_usd=5)["job_id"]
    canceled = tools.cancel_job(job_id)
    assert (canceled["status"], canceled["refunded"]) == ("canceled", True) and "refunded" in canceled["note"]
    assert tools.list_jobs(refresh=False)["jobs"][0]["status"] == "canceled"
    for tool in (tools.get_job, tools.cancel_job, tools.download_video):
        with pytest.raises(ToolFailure) as refused:
            tool("../jobs")
        assert refused.value.code == "invalid_job_id"


# ---------------------------------------------------------------- plans

BRIEF = 'A 30-second ad for a small coffee roastery, warm and handmade. End on "Roasted this morning."'


def test_planning_needs_a_budget_and_over_budget_nothing_is_created(setup):
    network, tools, _ = setup
    with pytest.raises(ToolFailure) as refused:
        tools.plan_video(BRIEF)
    assert refused.value.code == "budget_required" and network.calls == []
    with pytest.raises(ToolFailure) as refused:
        tools.plan_video(BRIEF, max_price_usd=0.05)
    assert refused.value.code == "over_budget" and "This plan would cost $0.1" in refused.value.message
    assert network.paths() == ["POST /v1/quote"] and tools.store.records() == []


def test_a_private_plan_through_the_tools_revised_and_rendered_by_its_id(setup):
    network, tools, config = setup
    planned = tools.plan_video(BRIEF, target_s=30, style="35mm film", max_price_usd=1)
    plan_id = planned["plan_id"]
    assert (planned["status"], planned["mode"], planned["privacy"], planned["target_s"], planned["can_download"]) == ("succeeded", "plan", "private", 30, False)
    compact = planned["plan"]
    assert abs(compact["stitched_s"] - 30) <= 0.5 and compact["settings"]["model"] == FAST.id and compact["repairs"]
    assert [shot["shot"] for shot in compact["shots"]] == list(range(1, len(compact["shots"]) + 1))
    assert planned["render_price"]["price_usd"] == round(0.12 * compact["stitched_s"], 4)
    # The brief and style were sealed; the handle keeps the key and, once finished, the plan, but never the brief.
    assert b"roastery" not in network.sent() and b"35mm film" not in network.sent()
    handle = Path(planned["handle_file"])
    saved = json.loads(handle.read_text())
    assert mode_of(handle) == 0o600 and saved["output_key"] and saved["kind"] == "plan" and saved["plan"]["title"] == compact["title"]
    assert BRIEF not in handle.read_text()
    assert "output_key" not in json.dumps(planned)

    # Only shot 2 is rewritten.
    revised = tools.revise_plan("darker, at night", plan_id=plan_id, shots=[2], max_price_usd=1)
    shots = revised["plan"]["shots"]
    assert revised["plan_id"] != plan_id and "darker, at night" in shots[1]["prompt"]
    assert [s for s in shots if s["shot"] != 2] == [s for s in compact["shots"] if s["shot"] != 2]

    # The plan an agent edited comes back in the same shape.
    edited = json.loads(json.dumps(revised["plan"]))
    edited["shots"][0]["prompt"] = "Extreme close-up; beans tumble into the cooler. The drum hums."
    again = tools.revise_plan("warmer light", plan=edited, shots=[3], max_price_usd=1)
    assert again["plan"]["shots"][0]["prompt"] == edited["shots"][0]["prompt"]

    rendered = tools.generate_video(plan_id=again["plan_id"], max_price_usd=10)
    job = network.jobs[rendered["job_id"]]
    final = again["plan"]
    assert (rendered["mode"], rendered["privacy"], job.params.duration_s) == ("storyboard", "private", final["stitched_s"])
    assert job.payload.prompt == final["scene"] and [s.prompt for s in job.payload.shots] == [s["prompt"] for s in final["shots"]]
    assert [(s.duration_s, s.join) for s in job.params.shots] == [(s["duration_s"], s["join"]) for s in final["shots"]]
    assert json.loads(Path(rendered["handle_file"]).read_text())["plan_id"] == again["plan_id"]

    # A plan isn't a video; plans list with their titles.
    with pytest.raises(ToolFailure) as refused:
        tools.download_video(plan_id)
    assert refused.value.code == "not_a_video"
    listed = {j["job_id"]: j for j in tools.list_jobs(limit=10)["jobs"]}
    assert listed[plan_id]["mode"] == "plan" and listed[plan_id]["plan_title"] == compact["title"]
    assert listed[rendered["job_id"]]["plan_id"] == again["plan_id"]


def test_a_plan_left_running_is_opened_by_get_job(setup):
    network, tools, _ = setup
    started = tools.plan_video(BRIEF, target_s=20, privacy="standard", max_price_usd=1, wait=False)
    assert started["status"] == "queued" and "get_job" in started["next"] and "plan" not in started
    assert tools.get_job(started["plan_id"])["stage"] == "planning"
    tools.get_job(started["plan_id"])
    done = tools.get_job(started["plan_id"])
    assert done["status"] == "succeeded" and done["plan"]["privacy"] == "standard" and done["render_price"]["privacy"] == "standard"
    assert "output_key" not in json.loads(Path(started["handle_file"]).read_text())
    # A Standard plan renders in Standard unless told otherwise.
    assert tools.generate_video(plan_id=started["plan_id"], max_price_usd=10)["privacy"] == "standard"


def test_plans_that_cant_be_used_say_why(setup):
    network, tools, _ = setup
    network.plan_failure = "plan_failed"
    failed = tools.plan_video(BRIEF, max_price_usd=1)
    assert (failed["status"], failed["error_code"], failed["refunded"]) == ("failed", "plan_failed", True)
    assert "rephrase" in failed["next"] and "plan" not in failed
    for call, code in (
        (lambda: tools.generate_video(plan_id=failed["plan_id"], max_price_usd=5), "not_ready"),
        (lambda: tools.generate_video(plan_id=str(uuid.uuid4()), max_price_usd=5), "unknown_plan"),
        (lambda: tools.generate_video(plan_id="nope", max_price_usd=5), "invalid_plan_id"),
        (lambda: tools.generate_video(max_price_usd=5), "prompt_required"),
        (lambda: tools.revise_plan("x", max_price_usd=1), "invalid_plan"),
        (lambda: tools.revise_plan("x", plan={"shots": []}, max_price_usd=1), "invalid_plan"),
    ):
        with pytest.raises(ToolFailure) as refused:
            call()
        assert refused.value.code == code

    network.plan_failure = None
    plan_id = tools.plan_video(BRIEF, max_price_usd=1)["plan_id"]
    with pytest.raises(KunoError) as conflicting:
        tools.generate_video("another scene", plan_id=plan_id, max_price_usd=5)
    assert conflicting.value.code == "invalid_params"

    network.enclave["features"] = []
    with pytest.raises(KunoError) as unavailable:
        tools.plan_video(BRIEF, max_price_usd=1)
    assert unavailable.value.code == "plans_unavailable" and "POST /v1/videos" not in network.paths()[-3:]


def test_list_models_shows_plan_prices(setup):
    network, tools, _ = setup
    fast = {m["id"]: m for m in tools.list_models()["models"]}[FAST.id]
    assert fast["plan"] == {"target_s": {"min": 4, "max": 120}, "max_brief_chars": 4000, "max_style_chars": 500, "usd": {"private": 0.1, "standard": 0.08}}
