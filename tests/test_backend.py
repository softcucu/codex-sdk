from __future__ import annotations

import queue
from typing import Any

import pytest
from openai_codex._goal import _GoalOperationState, _GoalStreamClosed
from openai_codex.generated.v2_all import ErrorNotification
from openai_codex.models import Notification

from codex_controller._backend import OfficialBackend, _GoalNotificationWatchdog


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any, Any]] = []

    def request(self, method: str, params: Any, *, response_model: Any) -> Any:
        self.calls.append((method, params, response_model))
        return response_model()


class GoalStatusClient:
    def __init__(self, status: str) -> None:
        self.status = status
        self.calls = 0
        self.unregister_calls = 0
        self.cancel_calls = 0

    def request(self, method: str, params: Any, *, response_model: Any) -> Any:
        self.calls += 1
        assert method == "thread/goal/get"
        assert params == {"threadId": "thread-1"}
        return response_model.model_validate(
            {
                "goal": {
                    "createdAt": 1,
                    "objective": "finish the task",
                    "status": self.status,
                    "threadId": "thread-1",
                    "timeUsedSeconds": 800,
                    "tokensUsed": 100,
                    "updatedAt": 2,
                }
            }
        )

    def unregister_goal_operation(self, state: Any) -> None:
        self.unregister_calls += 1

    def cancel_goal_operation(self, state: Any) -> None:
        self.cancel_calls += 1


class WatchdogState:
    def __init__(self) -> None:
        self._notifications: queue.Queue[Any] = queue.Queue()
        self.completed_turn: Any = None

    def current_turn(self) -> str:
        return "turn-1"


def retryable_error(*, will_retry: bool) -> Notification:
    payload = ErrorNotification.model_validate(
        {
            "error": {
                "message": "429 rate limit exceeded",
                "codexErrorInfo": {
                    "responseTooManyFailedAttempts": {"httpStatusCode": 429}
                },
            },
            "threadId": "thread-1",
            "turnId": "turn-1",
            "willRetry": will_retry,
        }
    )
    return Notification(method="error", payload=payload)


def malformed_json_error(*, will_retry: bool) -> Notification:
    return Notification(
        method="error",
        payload={
            "error": {
                "message": "Unterminated string starting at line 1 column 8",
                "type": "invalid_request_error",
            },
            "threadId": "thread-1",
            "turnId": "turn-1",
            "willRetry": will_retry,
        },
    )


def test_goal_model_uses_thread_settings_update_protocol() -> None:
    client = RecordingClient()

    OfficialBackend._set_model(client, "thread-1", "selected-model")

    assert client.calls[0][0] == "thread/settings/update"
    assert client.calls[0][1] == {
        "threadId": "thread-1",
        "model": "selected-model",
    }


def test_empty_goal_model_is_rejected() -> None:
    with pytest.raises(ValueError):
        OfficialBackend._set_model(RecordingClient(), "thread-1", "  ")


def test_goal_watchdog_releases_stream_when_429_goal_is_persisted_terminal() -> None:
    client = GoalStatusClient("usageLimited")
    state = WatchdogState()
    error = retryable_error(will_retry=False)
    state._notifications.put(error)
    watchdog = _GoalNotificationWatchdog(
        client=client,
        state=state,
        thread_id="thread-1",
        poll_interval_seconds=0,
        stall_timeout_seconds=30,
    )

    assert watchdog() is error
    with pytest.raises(_GoalStreamClosed):
        watchdog()

    assert client.calls == 1


def test_goal_watchdog_releases_stream_after_nonretryable_400_error() -> None:
    client = GoalStatusClient("blocked")
    state = WatchdogState()
    error = malformed_json_error(will_retry=False)
    state._notifications.put(error)
    watchdog = _GoalNotificationWatchdog(
        client=client,
        state=state,
        thread_id="thread-1",
        poll_interval_seconds=0,
        stall_timeout_seconds=30,
    )

    assert watchdog() is error
    with pytest.raises(_GoalStreamClosed):
        watchdog()

    assert client.calls == 1


def test_goal_watchdog_times_out_stale_active_goal_after_429() -> None:
    client = GoalStatusClient("active")
    state = WatchdogState()
    error = retryable_error(will_retry=False)
    state._notifications.put(error)
    watchdog = _GoalNotificationWatchdog(
        client=client,
        state=state,
        thread_id="thread-1",
        poll_interval_seconds=0,
        stall_timeout_seconds=30,
    )

    assert watchdog() is error
    with pytest.raises(TimeoutError, match="active Goal stream"):
        watchdog()

    assert client.calls == 1


def test_goal_watchdog_does_not_poll_during_normal_tool_execution() -> None:
    client = GoalStatusClient("active")
    watchdog = _GoalNotificationWatchdog(
        client=client,
        state=WatchdogState(),
        thread_id="thread-1",
        poll_interval_seconds=0,
        stall_timeout_seconds=0,
    )

    watchdog._check_failed_stream()

    assert client.calls == 0


def test_official_goal_stream_ends_cleanly_after_missing_terminal_notification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(OfficialBackend, "_GOAL_STREAM_POLL_SECONDS", 0)
    client = GoalStatusClient("usageLimited")
    state = _GoalOperationState("thread-1")
    state.logical_turn_id = "turn-1"
    state.activate_turn_routing()
    state._notifications.put(retryable_error(will_retry=False))

    operation = OfficialBackend._goal_operation(client, state, "turn-1")
    events = list(operation.events)

    assert [event.method for event in events] == ["error"]
    assert state.is_finished()
    assert client.calls == 1
    assert client.unregister_calls == 1
    assert client.cancel_calls == 0
