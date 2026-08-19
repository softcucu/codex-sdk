from __future__ import annotations

import io

import pytest

from codex_controller import (
    CodexController,
    GoalResumeExhaustedError,
    OutputMode,
    ResumePolicy,
)

from conftest import DisconnectingBackend, FakeBackend, MalformedJsonBlockedBackend


def no_delay_policy(max_attempts: int | None = None) -> ResumePolicy:
    return ResumePolicy(
        max_attempts=max_attempts,
        initial_delay_seconds=0,
        max_delay_seconds=0,
        jitter_ratio=0,
    )


def test_goal_automatically_resumes_after_429_and_completes() -> None:
    backend = FakeBackend()
    output = io.StringIO()
    controller = CodexController(
        _backend=backend,
        output=output,
        output_mode=OutputMode.HUMAN,
        resume_policy=no_delay_policy(),
    )

    result = controller.goal(
        "make the tests pass", model="model-goal", token_budget=1000
    )

    assert result.completed
    assert result.goal.status == "complete"
    assert result.resume_count == 1
    assert result.final_response == "done"
    assert result.goal.tokens_used == 42
    assert result.model == "model-goal"
    assert backend.start_goal_calls == 1
    assert backend.resume_goal_calls == 1
    assert backend.goal_models == ["model-goal", "model-goal"]
    assert backend.start_thread_options == [
        {"ephemeral": False, "model": "model-goal"}
    ]
    rendered = output.getvalue()
    assert "rate limit" in rendered
    assert "resumed Goal" in rendered
    assert "goal   complete" in rendered


def test_context_manager_defers_thread_creation_until_goal_model_is_known() -> None:
    backend = FakeBackend(first_status="complete")
    controller = CodexController(
        _backend=backend,
        output=io.StringIO(),
        output_mode="quiet",
        resume_policy=no_delay_policy(),
    )

    with controller as active:
        assert active.thread_id is None
        result = active.goal("use the selected model", model="selected-model")

    assert result.completed
    assert backend.start_thread_options == [
        {"ephemeral": False, "model": "selected-model"}
    ]


def test_existing_thread_is_resumed_with_goal_model_override() -> None:
    backend = FakeBackend(first_status="complete")
    controller = CodexController(
        thread_id="thread-existing",
        _backend=backend,
        output=io.StringIO(),
        output_mode="quiet",
        resume_policy=no_delay_policy(),
    )

    result = controller.goal("continue with selected model", model="selected-model")

    assert result.completed
    assert backend.resume_thread_options == [{"model": "selected-model"}]


def test_quiet_mode_writes_nothing() -> None:
    backend = FakeBackend()
    output = io.StringIO()
    controller = CodexController(
        _backend=backend,
        output=output,
        output_mode="quiet",
        resume_policy=no_delay_policy(),
    )

    result = controller.goal("finish quietly")

    assert result.completed
    assert output.getvalue() == ""


def test_debug_mode_emits_jsonl_for_every_layer() -> None:
    import json

    backend = FakeBackend()
    output = io.StringIO()
    controller = CodexController(
        _backend=backend,
        output=output,
        output_mode="debug",
        resume_policy=no_delay_policy(),
    )

    controller.goal("debug this")

    records = [json.loads(line) for line in output.getvalue().splitlines()]
    assert records
    assert [record["sequence"] for record in records] == list(range(1, len(records) + 1))
    assert any(record["source"] == "codex" and record["event"] == "error" for record in records)
    assert any(
        record["source"] == "wrapper" and record["event"] == "goal.retry"
        for record in records
    )
    error_record = next(record for record in records if record["event"] == "error")
    assert error_record["data"]["error"]["codexErrorInfo"][
        "responseTooManyFailedAttempts"
    ]["httpStatusCode"] == 429


def test_resume_limit_exposes_partial_result() -> None:
    backend = FakeBackend()
    controller = CodexController(
        _backend=backend,
        output=io.StringIO(),
        output_mode="quiet",
        resume_policy=no_delay_policy(max_attempts=0),
    )

    with pytest.raises(GoalResumeExhaustedError) as caught:
        controller.goal("cannot resume")

    assert caught.value.partial_result is not None
    assert caught.value.partial_result.goal.status == "usageLimited"
    assert backend.resume_goal_calls == 0


def test_blocked_goal_is_returned_without_resume() -> None:
    backend = FakeBackend(first_status="blocked")
    controller = CodexController(
        _backend=backend,
        output=io.StringIO(),
        output_mode="quiet",
        resume_policy=no_delay_policy(),
    )

    result = controller.goal("blocked task")

    assert not result.completed
    assert result.goal.status == "blocked"
    assert backend.resume_goal_calls == 0


def test_blocked_goal_resumes_after_generated_tool_json_parse_error() -> None:
    backend = MalformedJsonBlockedBackend()
    output = io.StringIO()
    controller = CodexController(
        _backend=backend,
        output=output,
        output_mode="human",
        resume_policy=no_delay_policy(),
    )

    result = controller.goal("recover malformed tool arguments")

    assert result.completed
    assert result.resume_count == 1
    assert backend.start_goal_calls == 1
    assert backend.resume_goal_calls == 1
    assert "malformed generated JSON/tool arguments" in output.getvalue()


def test_repeated_generated_tool_json_error_stops_after_one_automatic_resume() -> None:
    backend = MalformedJsonBlockedBackend(repeat_on_resume=True)
    controller = CodexController(
        _backend=backend,
        output=io.StringIO(),
        output_mode="quiet",
        resume_policy=no_delay_policy(),
    )

    result = controller.goal("do not loop forever on malformed tool arguments")

    assert not result.completed
    assert result.goal.status == "blocked"
    assert result.resume_count == 1
    assert backend.start_goal_calls == 1
    assert backend.resume_goal_calls == 1


def test_transport_close_reconnects_then_resumes_existing_goal() -> None:
    backend = DisconnectingBackend()
    controller = CodexController(
        _backend=backend,
        output=io.StringIO(),
        output_mode="quiet",
        resume_policy=no_delay_policy(),
    )

    result = controller.goal("survive app-server restart")

    assert result.completed
    assert result.resume_count == 1
    assert backend.reconnect_calls == 1
    assert backend.start_goal_calls == 1
    assert backend.resume_goal_calls == 1


def test_regular_turn_returns_final_message() -> None:
    backend = FakeBackend()
    controller = CodexController(
        _backend=backend,
        output=io.StringIO(),
        output_mode="quiet",
    )

    result = controller.run("hello", model="model-turn")

    assert result.completed
    assert result.final_response == "hello"
    assert result.event_count == 4
    assert result.model == "model-turn"
    assert backend.turn_models == ["model-turn"]


def test_pause_get_and_clear_goal() -> None:
    backend = FakeBackend()
    controller = CodexController(
        _backend=backend,
        output=io.StringIO(),
        output_mode="quiet",
        resume_policy=no_delay_policy(max_attempts=0),
    )
    with pytest.raises(GoalResumeExhaustedError):
        controller.goal("leave persisted")

    paused = controller.pause_goal()
    assert paused.status == "paused"
    assert controller.get_goal() == paused
    assert controller.clear_goal()
    assert controller.get_goal() is None
