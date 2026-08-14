from __future__ import annotations

import io
import json

import pytest
from openai_codex import CodexConfig

import codex_controller.config as config_module
import codex_controller.controller as controller_module
from codex_controller import (
    CodexController,
    ControllerConfig,
    OutputMode,
    ResumePolicy,
    resolve_codex_bin,
)
from codex_controller.render import EventRenderer

from conftest import Notification


class _CapturingBackend:
    configs: list[CodexConfig] = []

    def __init__(self, config: CodexConfig) -> None:
        type(self).configs.append(config)


@pytest.fixture
def capture_sdk_config(monkeypatch: pytest.MonkeyPatch) -> list[CodexConfig]:
    _CapturingBackend.configs = []
    monkeypatch.setattr(controller_module, "OfficialBackend", _CapturingBackend)
    return _CapturingBackend.configs


def test_default_codex_bin_uses_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        config_module.shutil,
        "which",
        lambda command: "/usr/local/bin/codex" if command == "codex" else None,
    )

    assert resolve_codex_bin(None) == "/usr/local/bin/codex"
    assert ControllerConfig().codex_bin == "/usr/local/bin/codex"


def test_explicit_codex_bin_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_lookup(_command: str) -> str | None:
        pytest.fail("PATH must not be searched for an explicit codex_bin")

    monkeypatch.setattr(config_module.shutil, "which", unexpected_lookup)

    assert resolve_codex_bin("/opt/codex/bin/codex") == "/opt/codex/bin/codex"
    assert ControllerConfig(codex_bin="/opt/custom/codex").codex_bin == (
        "/opt/custom/codex"
    )


def test_missing_path_codex_falls_back_to_sdk_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config_module.shutil, "which", lambda _command: None)

    assert resolve_codex_bin(None) is None
    assert ControllerConfig().codex_bin is None


def test_controller_passes_path_runtime_to_sdk(
    monkeypatch: pytest.MonkeyPatch,
    capture_sdk_config: list[CodexConfig],
) -> None:
    monkeypatch.setattr(config_module.shutil, "which", lambda _command: "/bin/codex")

    CodexController(cwd="/worktree", output_mode="quiet")

    assert len(capture_sdk_config) == 1
    assert capture_sdk_config[0].cwd == "/worktree"
    assert capture_sdk_config[0].codex_bin == "/bin/codex"


def test_controller_preserves_custom_sdk_config_while_resolving_runtime(
    monkeypatch: pytest.MonkeyPatch,
    capture_sdk_config: list[CodexConfig],
) -> None:
    monkeypatch.setattr(config_module.shutil, "which", lambda _command: "/bin/codex")
    supplied = CodexConfig(
        cwd="/worktree",
        config_overrides=('model="test-model"',),
        client_name="custom-client",
    )

    CodexController(codex_config=supplied, output_mode="quiet")

    assert len(capture_sdk_config) == 1
    resolved = capture_sdk_config[0]
    assert resolved is not supplied
    assert resolved.codex_bin == "/bin/codex"
    assert resolved.cwd == supplied.cwd
    assert resolved.config_overrides == supplied.config_overrides
    assert resolved.client_name == supplied.client_name


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
