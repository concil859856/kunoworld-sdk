"""`kunoworld-mcp`: KunoWorld's local MCP server, over stdio, on the official MCP Python SDK's FastMCP.

It runs on the user's machine so that Private mode stays private: prompts, shot lists and images are encrypted here, to an
attested confidential GPU, and videos are decrypted here. A server hosted by KunoWorld would have to receive them readable.
The agent host is outside that guarantee, and every description below says so.

Configuration is by environment (README, "Agents (MCP)"): KUNOWORLD_API_KEY, KUNOWORLD_API_URL, KUNOWORLD_PRIVACY,
KUNOWORLD_MAX_JOB_USD, KUNOWORLD_OUTPUT_DIR, KUNOWORLD_JOBS_DIR, and for attestation without trusting the gateway,
KUNOWORLD_MANIFEST or KUNOWORLD_OWNER_PUBLIC_KEY. Nothing is logged about a job's content, and stdout carries only MCP.
"""

from __future__ import annotations

import functools
import sys
from collections.abc import Callable
from typing import Annotated, Any, Literal

import anyio
import anyio.from_thread
import anyio.to_thread
import httpx
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from ..client import KunoError
from .tools import Config, ConfigError, KunoTools, ToolFailure, describe_error

PRIVACY_NOTE = (
    "Privacy: in Private mode (the default) the prompt, shot prompts, images and the finished video are encrypted on this "
    "computer to an attested confidential GPU, so neither KunoWorld nor the GPU provider can see them. That does not cover "
    "this conversation: the AI assistant calling this tool, and whoever provides the assistant, see whatever the user types "
    "and whatever this tool returns. In Standard mode KunoWorld and the GPU provider can also see the prompt, the inputs "
    "and the video."
)

INSTRUCTIONS = f"""KunoWorld makes videos with audio from text, images or a storyboard of shots, on LTX-2.5 and MiniMax H3.

Workflow: list_models to choose a model and settings; quote_price for the exact price; tell the user the price and get
their agreement; generate_video with max_price_usd; get_job until it has succeeded; download_video to save it locally.
For a longer video from a brief, plan_video writes an editable storyboard first (a flat price, nothing rendered): show
it to the user, adjust it with revise_plan, then render it with generate_video and its plan_id.
Sexual content is banned in both modes, and blocked requests count against the account.

{PRIVACY_NOTE}"""

Privacy = Literal["private", "standard"]
Join = Literal["fresh", "continue", "cut"]
ToolMode = Literal["text_to_video", "image_to_video", "last_frame", "first_last_frame", "reference_to_video", "storyboard"]
AspectRatio = Literal["16:9", "9:16", "4:3", "3:4", "1:1", "21:9"]


class ShotInput(BaseModel):
    """One shot of a storyboard."""

    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(description="What happens in this shot: action, camera, sound and any dialogue. The model sees the "
                        "scene (the prompt argument), a blank line, then this.")
    duration_s: float | None = Field(default=None, description="Seconds, within the model's clip limits (LTX-2.5 Fast: 2 to 20 "
                                     "at 24 or 25 fps; workers on 96 GB cards take up to 11 s at 720p). Default 5.")
    join: Join | None = Field(default=None, description="continue: the same take goes on from the previous shot's last frames "
                              "and sound, with no visible seam. cut: a new picture over the same voice and room tone. fresh: "
                              "nothing carried over. Default: fresh for the first shot, continue after it.")


class QuoteShotInput(BaseModel):
    """One shot of a storyboard, for pricing: its prompt is optional and never sent."""

    model_config = ConfigDict(extra="forbid")

    prompt: str | None = Field(default=None, description="Ignored when quoting; never sent.")
    duration_s: float | None = Field(default=None, description="Seconds. Default 5.")
    join: Join | None = Field(default=None, description="fresh, continue or cut. Default: fresh first, continue after.")


# Descriptions shared by quote_price and generate_video, so an agent can call both with the same arguments.
Model = Annotated[str | None, Field(description="A model id from list_models, e.g. ltx-2.5-fast. Leave empty to let KunoWorld "
                                    "route by family. The job may fall back to another model (licence region, switched off, "
                                    "no capacity); the answer says so in fallback_reason.")]
Family = Annotated[str | None, Field(description="ltx-2.5 or minimax-h3, when no model is named.")]
ModeArg = Annotated[ToolMode | None, Field(description="Usually leave empty: it follows from the inputs (a first frame is "
                                           "image_to_video, first and last frames first_last_frame, reference images "
                                           "reference_to_video, shots storyboard).")]
Duration = Annotated[float | None, Field(description="Seconds, for a single clip. Leave empty for a storyboard, whose length "
                                         "comes from its shots. Default 5.")]
Resolution = Annotated[str | None, Field(description="720p or 1080p (LTX-2.5), 768p (MiniMax H3), 1440p or 2160p (LTX-2.5 4K). "
                                         "Default: the model's first.")]
Aspect = Annotated[AspectRatio | None, Field(description="Default 16:9.")]
Fps = Annotated[Literal[24, 25, 48, 50] | None, Field(description="Default 24. LTX-2.5 costs 1.5x at 48 or 50 fps; MiniMax H3 "
                                                      "is 24 only.")]
Audio = Annotated[bool, Field(description="Generate sound with the picture (speech, effects, music). Default true.")]
PrivacyArg = Annotated[Privacy | None, Field(description="private (default unless the server is configured otherwise): "
                                             "encrypted end to end to a confidential GPU. standard: cheaper, but KunoWorld "
                                             "and the GPU provider can see the prompt, inputs and video.")]
FirstFrame = Annotated[str | None, Field(description="Path to an image on this computer to start the video from (PNG, JPEG "
                                         "or WebP).")]
LastFrame = Annotated[str | None, Field(description="Path to an image on this computer for the video to end on.")]
References = Annotated[list[str] | None, Field(description="Paths to reference images on this computer (MiniMax H3 Director "
                                               "only).")]
JobId = Annotated[str, Field(description="The job_id generate_video or list_jobs returned.")]
PlanId = Annotated[str | None, Field(description="The plan_id plan_video or revise_plan returned. The plan is kept on this "
                                     "computer by this server.")]
PlanWait = Annotated[bool, Field(description="Wait for the plan (seconds to a minute) and return it. With false, follow it "
                                 "with get_job.")]
PlanTimeout = Annotated[float, Field(gt=0, le=3600, description="With wait: how long to wait, in seconds.")]

PLAN_RULES = (
    "The plan is written inside a confidential worker by LTX-2.5's small bundled language model, so treat it as a first "
    "draft: read it with the user. Each shot's prompt is what the video model renders after the scene; joins are fresh "
    "(new moment), cut (new angle, sound carries on) or continue (the same take goes on, same shot size). The shots are "
    "fitted to the target length and to the longest shot the workers render at this size, and every change code made to "
    "the planner's text is listed in repairs. Planning is optional: you can write the scene and shots yourself and pass "
    "them to generate_video."
)


def _wrap(tools: KunoTools) -> Callable[..., Any]:
    async def call(method: Callable[..., Any], /, **arguments: Any) -> Any:
        try:
            # The SDK is synchronous: run it off the event loop so the session keeps answering while a job renders.
            return await anyio.to_thread.run_sync(functools.partial(method, **arguments))
        except (KunoError, ToolFailure) as exc:
            raise ToolError(describe_error(exc)) from None
        except httpx.HTTPError as exc:
            raise ToolError(f"network: couldn't reach KunoWorld at {tools.config.api_url} ({type(exc).__name__}).") from None

    return call


def _progress(ctx: Context) -> Callable[[Any], None]:
    """Sends a job's status to the client as MCP progress, from the worker thread the SDK runs in."""

    def on_status(status) -> None:
        state = status.status.value
        message = f"{state}: {status.stage}" if status.stage and status.stage != state else state
        anyio.from_thread.run(ctx.report_progress, status.progress, 1.0, message)

    return on_status


def build_server(config: Config | None = None, tools: KunoTools | None = None) -> FastMCP:
    tools = tools or KunoTools(config or Config.from_env())
    call = _wrap(tools)
    server = FastMCP("kunoworld", instructions=INSTRUCTIONS, log_level="WARNING")
    read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)

    @server.tool(
        name="list_models",
        title="List KunoWorld video models",
        annotations=read_only,
        description="List KunoWorld's video models: ids, modes, clip durations, sizes, frame rates, prompt limits, storyboard "
        "limits (shots, stitched length), whether each is available now, and prices per output second for Private and "
        "Standard. Prices are placeholders during the development preview. Free, and creates nothing.",
    )
    async def list_models() -> dict[str, Any]:
        return await call(tools.list_models)

    @server.tool(
        name="quote_price",
        title="Quote the exact price of a video",
        annotations=read_only,
        description="The exact price KunoWorld would charge for a video, without making it: the gateway routes the request as it "
        "would a real job and prices the settings it would send. Takes the same settings as generate_video; no prompt is "
        "needed, and shot prompts are not sent. Returns price_usd, the model that would serve it (with any fallback), the "
        "settings priced, a breakdown (rate per second x billable seconds x multipliers, and the minimum charge), and the "
        "account balance. Quote before generate_video and agree the price with the user. Refusals name the problem the job "
        "would hit (invalid_params, privacy_mode_unavailable, region_restricted, no_capacity, private_mode_not_eligible).",
    )
    async def quote_price(
        model: Model = None,
        family: Family = None,
        mode: ModeArg = None,
        duration_s: Duration = None,
        resolution: Resolution = None,
        aspect_ratio: Aspect = None,
        fps: Fps = None,
        audio: Audio = True,
        privacy: PrivacyArg = None,
        first_frame_path: FirstFrame = None,
        last_frame_path: LastFrame = None,
        reference_image_paths: References = None,
        shots: Annotated[list[QuoteShotInput] | None, Field(description="A storyboard's shots: duration_s and join each.")] = None,
    ) -> dict[str, Any]:
        return await call(
            tools.quote_price, model=model, family=family, mode=mode, duration_s=duration_s, resolution=resolution,
            aspect_ratio=aspect_ratio, fps=fps, audio=audio, privacy=privacy, first_frame_path=first_frame_path,
            last_frame_path=last_frame_path, reference_image_paths=reference_image_paths,
            shots=None if shots is None else [shot.model_dump() for shot in shots],
        )

    @server.tool(
        name="generate_video",
        title="Generate a video",
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True),
        description="Make a video with KunoWorld. This spends the user's credit. It quotes the job first and refuses, creating "
        "and charging nothing, if the price is over max_price_usd (required unless the server sets KUNOWORLD_MAX_JOB_USD, "
        "which caps every job). Then it submits the job and returns its job_id straight away; renders take minutes, so follow "
        "it with get_job and save it with download_video. With wait=true it waits (sending progress) and saves the video.\n\n"
        "Storyboards: pass shots (2 to 12 on LTX-2.5 Fast, at most 120 s stitched) and use prompt for the scene every shot "
        "shares (characters, place, style). Each continue or cut join repeats the previous shot's last 17 frames, which are "
        "trimmed, so the video is a little shorter than its shots added up; the price is for the stitched seconds. A job that "
        "fails, is blocked or is canceled is refunded automatically.\n\n"
        "Sexual content is banned in both modes; a blocked request counts against the account. Don't depict real people "
        "without their consent.\n\n" + PRIVACY_NOTE,
    )
    async def generate_video(
        ctx: Context,
        prompt: Annotated[str | None, Field(description="What to show and hear: subject, action, setting, camera, lighting, "
                                            "sound, quoted dialogue. For a storyboard, the scene all shots share (may be "
                                            "empty). Required unless plan_id is given.")] = None,
        max_price_usd: Annotated[float | None, Field(description="The most this video may cost, in US dollars, as agreed with "
                                                     "the user. Required unless KUNOWORLD_MAX_JOB_USD is set; it can only "
                                                     "lower that cap.")] = None,
        model: Model = None,
        family: Family = None,
        mode: ModeArg = None,
        duration_s: Duration = None,
        resolution: Resolution = None,
        aspect_ratio: Aspect = None,
        fps: Fps = None,
        audio: Audio = True,
        seed: Annotated[int | None, Field(ge=0, le=2**31 - 1, description="Repeat a result with the same seed and settings. "
                                          "A storyboard's shot i uses seed + i.")] = None,
        privacy: PrivacyArg = None,
        first_frame_path: FirstFrame = None,
        last_frame_path: LastFrame = None,
        reference_image_paths: References = None,
        shots: Annotated[list[ShotInput] | None, Field(description="A storyboard: 2 or more shots, in order.")] = None,
        wait: Annotated[bool, Field(description="Wait for the video and save it before returning. Renders take minutes and "
                                    "some hosts time tool calls out: prefer false and get_job.")] = False,
        timeout_s: Annotated[float, Field(gt=0, le=7200, description="With wait: how long to wait, in seconds. The job goes on "
                                          "after that.")] = 1800.0,
        plan_id: Annotated[str | None, Field(description="Render a plan from plan_video or revise_plan as its storyboard: its "
                                             "scene, shots, model, size, frame rate and sound. Pass no prompt, shots or "
                                             "duration with it. Privacy defaults to the plan's.")] = None,
    ) -> dict[str, Any]:
        return await call(
            tools.generate_video, prompt=prompt, model=model, family=family, mode=mode, duration_s=duration_s,
            resolution=resolution, aspect_ratio=aspect_ratio, fps=fps, audio=audio, seed=seed, privacy=privacy,
            first_frame_path=first_frame_path, last_frame_path=last_frame_path, reference_image_paths=reference_image_paths,
            shots=None if shots is None else [shot.model_dump() for shot in shots], max_price_usd=max_price_usd, wait=wait,
            timeout_s=timeout_s, on_status=_progress(ctx) if wait else None, plan_id=plan_id,
        )

    @server.tool(
        name="plan_video",
        title="Plan a storyboard from a brief",
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True),
        description="Turn a brief (\"a 30-second ad for a small coffee roastery, warm and handmade\") into an editable storyboard "
        "plan: a title, a scene every shot shares, and 2 to 12 shots with prompts, lengths and joins, fitted to target_s. "
        "Nothing is rendered. This spends the user's credit: a flat price per plan whatever its length (list_models shows "
        "plan.usd; placeholders now, about $0.10 Private and $0.08 Standard), refused before anything is charged if over "
        "max_price_usd (required unless the server sets KUNOWORLD_MAX_JOB_USD). A plan that fails (plan_failed) or is "
        "blocked is refunded. Returns the plan compactly, its plan_id, and render_price, the price of rendering it. Then "
        "revise_plan or generate_video with plan_id.\n\n" + PLAN_RULES + "\n\n" + PRIVACY_NOTE,
    )
    async def plan_video(
        ctx: Context,
        brief: Annotated[str, Field(description="What the video is for, what happens and how it should feel. Put words to be "
                                    "spoken or a slogan in quotes. At most 4,000 characters.")],
        target_s: Annotated[float, Field(ge=4, le=120, description="The stitched length to aim for, in seconds (LTX-2.5 Fast: 4 "
                                         "to 120).")] = 30.0,
        max_price_usd: Annotated[float | None, Field(description="The most this plan may cost, in US dollars, as agreed with "
                                                     "the user. Required unless KUNOWORLD_MAX_JOB_USD is set.")] = None,
        model: Annotated[str | None, Field(description="The model the storyboard will render on. Plans are written for "
                                           "ltx-2.5-fast.")] = "ltx-2.5-fast",
        resolution: Resolution = None,
        aspect_ratio: Aspect = None,
        fps: Fps = None,
        audio: Audio = True,
        style: Annotated[str | None, Field(description="A look to keep to, e.g. '35mm film, warm'. At most 500 characters.")] = None,
        privacy: PrivacyArg = None,
        seed: Annotated[int | None, Field(ge=0, le=2**31 - 1, description="Seeds the planner.")] = None,
        wait: PlanWait = True,
        timeout_s: PlanTimeout = 300.0,
    ) -> dict[str, Any]:
        return await call(
            tools.plan_video, brief=brief, target_s=target_s, model=model, resolution=resolution, aspect_ratio=aspect_ratio,
            fps=fps, audio=audio, style=style, privacy=privacy, seed=seed, max_price_usd=max_price_usd, wait=wait,
            timeout_s=timeout_s, on_status=_progress(ctx) if wait else None,
        )

    @server.tool(
        name="revise_plan",
        title="Revise a storyboard plan",
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True),
        description="Rewrite a plan in the confidential worker under an instruction (\"make shot 3 a close-up, darker\"). With "
        "shots (numbered from 1) only those shots are rewritten, and the title, scene, notes and other shots come back "
        "unchanged; without it the whole plan is rewritten. Pass plan_id for a plan this server made, or plan: the plan as "
        "plan_video returned it, edited if you like (shot lengths are re-measured). A revision is a new plan with its own "
        "plan_id, at the plan price, under the same budget rule as plan_video.\n\n" + PLAN_RULES + "\n\n" + PRIVACY_NOTE,
    )
    async def revise_plan(
        ctx: Context,
        instruction: Annotated[str, Field(description="What to change. May be empty for a different take.")] = "",
        plan_id: PlanId = None,
        plan: Annotated[dict[str, Any] | None, Field(description="The plan itself, as plan_video returned it (or Plan v1 "
                                                     "JSON), when it has no plan_id here or you edited it.")] = None,
        shots: Annotated[list[int] | None, Field(description="Only rewrite these shots, numbered from 1.")] = None,
        max_price_usd: Annotated[float | None, Field(description="The most this revision may cost, in US dollars. Required "
                                                     "unless KUNOWORLD_MAX_JOB_USD is set.")] = None,
        style: Annotated[str | None, Field(description="A look to keep to.")] = None,
        privacy: PrivacyArg = None,
        seed: Annotated[int | None, Field(ge=0, le=2**31 - 1, description="Seeds the planner.")] = None,
        wait: PlanWait = True,
        timeout_s: PlanTimeout = 300.0,
    ) -> dict[str, Any]:
        return await call(
            tools.revise_plan, instruction=instruction, plan_id=plan_id, plan=plan, shots=shots, style=style, privacy=privacy,
            seed=seed, max_price_usd=max_price_usd, wait=wait, timeout_s=timeout_s, on_status=_progress(ctx) if wait else None,
        )

    @server.tool(
        name="get_job",
        title="Check a video job",
        annotations=read_only,
        description="A job's status: queued, running, succeeded, failed or canceled; its stage (a storyboard reads 'shot 3/8' "
        "while it renders, a plan 'planning' then 'checking'); progress from 0 to 1; the price held; and, when it failed, "
        "the error code. A finished plan comes back with the plan and the price of rendering it. A failed or canceled job is "
        "refunded automatically. Poll every 15 to 30 seconds while a video renders, every few seconds for a plan.",
    )
    async def get_job(job_id: JobId) -> dict[str, Any]:
        return await call(tools.get_job, job_id=job_id)

    @server.tool(
        name="download_video",
        title="Download and verify a finished video",
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True),
        description="Save a finished video to this computer and return its path, size, SHA-256 and a summary of its signed "
        "receipt. A Private video is checked against the receipt the attested GPU signed and decrypted here, with the key "
        "this server kept when it made the job; nobody else can open it. The video's contents never pass through this "
        "conversation, only its path. Existing files are never overwritten by a different video.",
    )
    async def download_video(
        job_id: JobId,
        filename: Annotated[str | None, Field(description="A file name for the video in the output directory, without "
                                              "folders. Default kunoworld-<job_id>.mp4.")] = None,
    ) -> dict[str, Any]:
        return await call(tools.download_video, job_id=job_id, filename=filename)

    @server.tool(
        name="cancel_job",
        title="Cancel a video job",
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True),
        description="Cancel a job that is still queued or running. Its price is refunded. A finished job is left as it is.",
    )
    async def cancel_job(job_id: JobId) -> dict[str, Any]:
        return await call(tools.cancel_job, job_id=job_id)

    @server.tool(
        name="list_jobs",
        title="List this server's video jobs",
        annotations=read_only,
        description="The jobs this MCP server started on this computer, newest first, with status, price quoted and where "
        "each saved video is. Jobs made elsewhere (the website, other programs) aren't listed.",
    )
    async def list_jobs(
        limit: Annotated[int, Field(ge=1, le=100, description="How many jobs, newest first.")] = 10,
        refresh: Annotated[bool, Field(description="Ask KunoWorld for the current status of unfinished jobs.")] = True,
    ) -> dict[str, Any]:
        return await call(tools.list_jobs, limit=limit, refresh=refresh)

    return server


def main(argv: list[str] | None = None) -> None:
    try:
        config = Config.from_env()
    except ConfigError as exc:
        print(f"kunoworld-mcp: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    build_server(config).run("stdio")
