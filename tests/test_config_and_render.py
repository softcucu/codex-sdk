from __future__ import annotations

import io
import json

import pytest

from codex_controller import OutputMode, ResumePolicy
from codex_controller.render import EventRenderer

from conftest import Notification


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("silent", OutputMode.QUIET),
        ("normal", OutputMode.HUMAN),
        ("codex", OutputMode.HUMAN),
        ("verbose", OutputMode.DEBUG),
    ],
)
def test_output_mode_aliases(value: str, expected: OutputMode) -> None:
    assert OutputMode.parse(value) is expected


def test_invalid_resume_policy_is_rejected() -> None:
    with pytest.raises(ValueError):
        ResumePolicy(max_attempts=-1)
    with pytest.raises(ValueError):
        ResumePolicy(jitter_ratio=2)


def test_human_renderer_shows_codex_style_activity() -> None:
    output = io.StringIO()
    renderer = EventRenderer("human", output)
    renderer.notification(
        Notification(
            "item/started",
            {"item": {"type": "commandExecution", "command": "pytest -q"}},
        )
    )
    renderer.notification(
        Notification(
            "item/completed",
            {
                "item": {
                    "type": "commandExecution",
                    "command": "pytest -q",
                    "exitCode": 0,
                    "durationMs": 250,
                }
            },
        )
    )
    renderer.close()

    assert "• Run pytest -q" in output.getvalue()
    assert "exit 0" in output.getvalue()


def test_debug_renderer_preserves_unknown_payload() -> None:
    output = io.StringIO()
    renderer = EventRenderer("debug", output)
    renderer.notification(Notification("future/event", {"newField": [1, 2, 3]}))

    record = json.loads(output.getvalue())
    assert record["event"] == "future/event"
    assert record["data"] == {"newField": [1, 2, 3]}


def test_debug_renderer_includes_pool_task_context() -> None:
    output = io.StringIO()
    renderer = EventRenderer(
        "debug",
        output,
        context={"pool_task_id": 7, "pool_task_kind": "goal"},
    )
    renderer.notification(Notification("turn/started", {"turn": {"id": "t"}}))

    record = json.loads(output.getvalue())
    assert record["context"] == {
        "pool_task_id": 7,
        "pool_task_kind": "goal",
    }
