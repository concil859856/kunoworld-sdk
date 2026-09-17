"""`kunoworld-mcp` as an MCP server: the tool list and schemas an agent sees, the privacy notice in the descriptions, errors
as readable text with the code, progress notifications while generate_video waits, and a stdio smoke test that starts the
real process and lists its tools. Needs the `mcp` extra; skipped without it."""

from __future__ import annotations

import json
import os
import sys

import anyio
import pytest

pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402
from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402

from kuno_fake_network import API_URL, PROFILES, FakeNetwork  # noqa: E402
from kunoworld.mcp.server import PRIVACY_NOTE, build_server  # noqa: E402
from kunoworld.mcp.tools import Config, KunoTools  # noqa: E402

TOOLS = {"list_models", "quote_price", "generate_video", "plan_video", "revise_plan", "get_job", "download_video", "cancel_job", "list_jobs"}
FAST = PROFILES["ltx-2.5-fast"]


def served(tmp_path, network: FakeNetwork, **config):
    settings = Config(api_key="kw_live_test", api_url=API_URL, output_dir=tmp_path / "videos", jobs_dir=tmp_path / "jobs", **config)
    tools = KunoTools(settings, client_factory=network.client, sleep=lambda _s: None)
    return build_server(tools=tools)


def payload(result) -> dict:
    assert not result.isError, result.content
    return result.structuredContent if result.structuredContent is not None else json.loads(result.content[0].text)


def test_the_tools_an_agent_sees(tmp_path):
    async def main():
        async with create_connected_server_and_client_session(served(tmp_path, FakeNetwork())) as session:
            listed = {tool.name: tool for tool in (await session.list_tools()).tools}
            assert set(listed) == TOOLS
            generate = listed["generate_video"]
            # A prompt, or a plan to render instead.
            assert "required" not in generate.inputSchema and "prompt" in generate.inputSchema["properties"]
            assert {"max_price_usd", "shots", "privacy", "first_frame_path", "wait", "seed", "plan_id"} <= set(generate.inputSchema["properties"])
            assert generate.inputSchema["$defs"]["ShotInput"]["properties"]["join"]["anyOf"][0]["enum"] == ["fresh", "continue", "cut"]
            # What the assistant's host can see is said where the agent reads it.
            assert PRIVACY_NOTE in generate.description and "whoever provides the assistant" in generate.description
            assert listed["quote_price"].annotations.readOnlyHint is True and generate.annotations.readOnlyHint is False
            assert set(listed["quote_price"].inputSchema["properties"]) == set(generate.inputSchema["properties"]) - {
                "prompt", "max_price_usd", "seed", "wait", "timeout_s", "plan_id"}
            plan = listed["plan_video"]
            assert plan.inputSchema["required"] == ["brief"] and PRIVACY_NOTE in plan.description and "first draft" in plan.description
            assert {"target_s", "style", "privacy", "max_price_usd", "model", "aspect_ratio"} <= set(plan.inputSchema["properties"])
            revise = listed["revise_plan"]
            assert {"plan_id", "plan", "instruction", "shots", "max_price_usd"} <= set(revise.inputSchema["properties"])
            assert not plan.annotations.readOnlyHint and PRIVACY_NOTE in revise.description

    anyio.run(main)


def test_calls_return_json_and_refusals_return_the_code_as_text(tmp_path):
    network = FakeNetwork()

    async def main():
        async with create_connected_server_and_client_session(served(tmp_path, network)) as session:
            quote = payload(await session.call_tool("quote_price", {"model": FAST.id, "shots": [{"duration_s": 5}, {"duration_s": 5, "join": "cut"}]}))
            assert quote["model"] == FAST.id and quote["settings"]["mode"] == "storyboard"

            refused = await session.call_tool("generate_video", {"prompt": "A fox in snow.", "model": FAST.id})
            assert refused.isError and "budget_required: Pass max_price_usd" in refused.content[0].text

            network.price_usd = 9.0
            over = await session.call_tool("generate_video", {"prompt": "A fox in snow.", "model": FAST.id, "max_price_usd": 1})
            assert over.isError and "over_budget: This video would cost $9" in over.content[0].text
            assert "POST /v1/videos" not in network.paths()

            bad = await session.call_tool("get_job", {"job_id": "not-a-job"})
            assert bad.isError and "invalid_job_id" in bad.content[0].text

    anyio.run(main)


def test_waiting_sends_progress_notifications(tmp_path):
    network = FakeNetwork()
    progress: list[tuple[float, float | None, str | None]] = []

    async def record(value: float, total: float | None, message: str | None) -> None:
        progress.append((value, total, message))

    async def main():
        async with create_connected_server_and_client_session(served(tmp_path, network)) as session:
            arguments = {
                "prompt": "A small boat in a harbor.", "model": FAST.id, "max_price_usd": 5, "wait": True,
                "shots": [{"prompt": "It leaves the harbor."}, {"prompt": "Night falls.", "join": "cut"}],
            }
            result = payload(await session.call_tool("generate_video", arguments, progress_callback=record))
            assert result["status"] == "succeeded" and os.path.isfile(result["download"]["path"])

    anyio.run(main)
    assert [message for _, _, message in progress] == ["running: shot 1/2", "running: shot 2/2", "succeeded: done"]
    assert progress[-1][:2] == (1.0, 1.0)


def test_a_plan_through_mcp_reports_progress_and_renders_by_its_id(tmp_path):
    network = FakeNetwork()
    progress: list[str | None] = []

    async def record(value: float, total: float | None, message: str | None) -> None:
        progress.append(message)

    async def main():
        async with create_connected_server_and_client_session(served(tmp_path, network)) as session:
            brief = {"brief": "A 20-second film about a lighthouse keeper's last night.", "target_s": 20, "max_price_usd": 1}
            planned = payload(await session.call_tool("plan_video", brief, progress_callback=record))
            assert planned["status"] == "succeeded" and planned["plan"]["plan_id"] == planned["plan_id"]
            assert abs(planned["plan"]["stitched_s"] - 20) <= 0.5 and planned["render_price"]["price_usd"] > 0
            rendered = payload(await session.call_tool("generate_video", {"plan_id": planned["plan_id"], "max_price_usd": 5}))
            assert (rendered["mode"], rendered["shots"], rendered["duration_s"]) == ("storyboard", len(planned["plan"]["shots"]), planned["plan"]["stitched_s"])

    anyio.run(main)
    assert progress == ["running: planning", "running: checking", "succeeded: done"]


def test_the_stdio_server_starts_and_lists_its_tools(tmp_path):
    """The real process, as an agent host starts it: `python -m kunoworld.mcp` with configuration in its environment. It
    must keep stdout for MCP alone, and start without a key (the tools then say one is missing)."""
    environment = {
        "PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), "KUNOWORLD_API_URL": "http://127.0.0.1:9",
        "KUNOWORLD_JOBS_DIR": str(tmp_path / "jobs"), "KUNOWORLD_OUTPUT_DIR": str(tmp_path / "videos"),
    }
    parameters = StdioServerParameters(command=sys.executable, args=["-m", "kunoworld.mcp"], env=environment)

    async def main():
        with anyio.fail_after(60):
            async with stdio_client(parameters) as (read, write), ClientSession(read, write) as session:
                initialized = await session.initialize()
                assert initialized.serverInfo.name == "kunoworld" and "KunoWorld" in (initialized.instructions or "")
                assert {tool.name for tool in (await session.list_tools()).tools} == TOOLS
                missing = await session.call_tool("get_job", {"job_id": "0f8fad5b-d9cb-469f-a165-70867728950e"})
                assert missing.isError and "missing_api_key" in missing.content[0].text

    anyio.run(main)
    assert not (tmp_path / "jobs").exists()


def test_a_bad_configuration_stops_the_server_with_a_message(tmp_path):
    import subprocess

    environment = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), "KUNOWORLD_MAX_JOB_USD": "plenty"}
    finished = subprocess.run([sys.executable, "-m", "kunoworld.mcp"], env=environment, capture_output=True, text=True, timeout=60)
    assert finished.returncode == 2 and finished.stdout == ""
    assert "KUNOWORLD_MAX_JOB_USD must be an amount in US dollars" in finished.stderr
