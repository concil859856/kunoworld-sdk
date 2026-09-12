"""Client-side decisions that happen before anything is sent: mode inference,
parameter defaults, and how a fallback adapts a request to another model."""

from __future__ import annotations

import pytest

from kuno_protocol.profiles import InputRole, Mode, load_profiles
from kunoworld import Input, KunoError, infer_mode
from kunoworld.client import _fit_params

PROFILES = load_profiles()
PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 32


def roles(*names: str) -> list[InputRole]:
    return [InputRole(n) for n in names]


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ([], Mode.TEXT_TO_VIDEO),
        (["first_frame"], Mode.IMAGE_TO_VIDEO),
        (["last_frame"], Mode.LAST_FRAME),
        (["first_frame", "last_frame"], Mode.FIRST_LAST_FRAME),
        (["keyframe", "keyframe"], Mode.KEYFRAMES),
        (["reference_image", "reference_audio"], Mode.REFERENCE_TO_VIDEO),
        (["source_video"], Mode.VIDEO_EDIT),
        (["source_audio", "first_frame"], Mode.AUDIO_TO_VIDEO),
    ],
)
def test_mode_inference(given, expected):
    assert infer_mode(roles(*given)) == expected


def test_input_load_sniffs_the_type_and_rejects_unknown_bytes(tmp_path):
    item = Input.load(InputRole.FIRST_FRAME, PNG)
    assert item.mime == "image/png" and item.data == PNG

    path = tmp_path / "frame.png"
    path.write_bytes(PNG)
    assert Input.load(InputRole.FIRST_FRAME, path).mime == "image/png"

    with pytest.raises(KunoError) as exc:
        Input.load(InputRole.FIRST_FRAME, b"not an image")
    assert exc.value.code == "unsupported_media"


def test_defaults_come_from_the_chosen_profile():
    params = _fit_params(PROFILES["h3-turbo"], Mode.TEXT_TO_VIDEO, [], None, None, None, None, True, None)
    assert (params.resolution, params.aspect_ratio, params.fps) == ("768p", "16:9", 24)
    assert params.duration_s == 5 and params.audio is True


def test_explicit_values_are_kept_when_no_fallback_happened():
    params = _fit_params(PROFILES["ltx-2.5-fast"], Mode.TEXT_TO_VIDEO, [], 12, "1080p", "9:16", 50, True, None)
    assert (params.duration_s, params.resolution, params.aspect_ratio, params.fps) == (12, "1080p", "9:16", 50)


def test_a_fallback_adapts_settings_the_new_model_cannot_meet():
    """H3 at 768p/24fps for 14 s, rerouted to LTX, must land inside LTX's own limits."""
    params = _fit_params(PROFILES["ltx-2.5-fast"], Mode.TEXT_TO_VIDEO, [], 14, "768p", "21:9", 24, True, "region")
    assert params.resolution in PROFILES["ltx-2.5-fast"].limits.sizes
    assert params.aspect_ratio in PROFILES["ltx-2.5-fast"].limits.sizes[params.resolution]
    assert PROFILES["ltx-2.5-fast"].limits.min_duration_s <= params.duration_s <= PROFILES["ltx-2.5-fast"].limits.max_duration_s


def test_audio_is_dropped_for_a_model_that_cannot_make_it(monkeypatch):
    profile = PROFILES["ltx-2.5-fast"].model_copy(deep=True)
    profile.limits.audio = False
    params = _fit_params(profile, Mode.TEXT_TO_VIDEO, [], None, None, None, None, True, None)
    assert params.audio is False


def test_input_roles_are_recorded_in_order():
    inputs = [Input.load(InputRole.FIRST_FRAME, PNG), Input.load(InputRole.LAST_FRAME, PNG)]
    params = _fit_params(PROFILES["ltx-2.5-fast"], Mode.FIRST_LAST_FRAME, inputs, None, None, None, None, True, None)
    assert params.input_roles == [InputRole.FIRST_FRAME, InputRole.LAST_FRAME]
