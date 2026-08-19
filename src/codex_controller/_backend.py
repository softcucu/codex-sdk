from __future__ import annotations

import queue
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Protocol

from openai_codex import Codex, CodexConfig
from openai_codex._goal import _GoalNotificationStream, _GoalStreamClosed
from openai_codex.generated.v2_all import (
    IdleThreadStatus,
    ThreadGoalGetResponse,
    ThreadGoalSetResponse,
    ThreadGoalStatus,
)
from pydantic import BaseModel

from .errors import IncompatibleCodexSdkError, NoActiveGoalError


@dataclass(slots=True)
class Operation:
    id: str
    events: Iterator[Any]
    cancel_callback: Callable[[], None]

    def cancel(self) -> None:
        self.cancel_callback()

    def close(self) -> None:
        close = getattr(self.events, "close", None)
        if callable(close):
            close()


class Backend(Protocol):
    @property
    def thread_id(self) -> str | None: ...

    def connect(self) -> None: ...

    def close(self) -> None: ...

    def start_thread(self, **options: Any) -> str: ...

    def resume_thread(self, thread_id: str, **options: Any) -> str: ...

    def reconnect(self, thread_id: str) -> str: ...

    def start_turn(self, prompt: Any, **options: Any) -> Operation: ...

    def start_goal(
        self, objective: str, token_budget: int | None, model: str | None
    ) -> Operation: ...

    def resume_goal(self, model: str | None) -> Operation: ...

    def get_goal(self) -> Any | None: ...

    def pause_goal(self) -> Any: ...

    def clear_goal(self) -> Any: ...


class _ThreadSettingsUpdateResponse(BaseModel):
    pass


@dataclass(slots=True)
class _GoalNotificationWatchdog:
    """Release a Goal stream when a failed physical turn stops producing events.

    The SDK's logical Goal stream waits for both ``turn/completed`` and a
    terminal ``thread/goal/updated`` notification. A runtime can persist the
    terminal Goal state without delivering (or successfully decoding) that
    notification, especially after its internal retries end in HTTP 429. In
    that case the SDK blocks forever and the controller never gets a chance to
    issue ``/goal resume``.

    Polling starts only after an error or a failed turn has been seen, so a
    legitimately long-running tool call is not subject to this timeout. All
    errors are observed here because a non-retryable request error can also
    lose its terminal Goal notification and otherwise leave the stream stuck.
    """

    client: Any
    state: Any
    thread_id: str
    poll_interval_seconds: float
    stall_timeout_seconds: float
    clock: Callable[[], float] = time.monotonic
    _error_seen: bool = False
    _failed_completion_seen: bool = False
    _runtime_will_retry: bool | None = None
    _last_activity_at: float = 0.0

    def __post_init__(self) -> None:
        self._last_activity_at = self.clock()

    def __call__(self) -> Any:
        notifications = getattr(self.state, "_notifications", None)
        if notifications is None:
            # Compatibility fallback for a future SDK implementation. The
            # project pins the SDK minor version, whose state uses this queue.
            return self.client.next_goal_notification(self.state)

        while True:
            try:
                item = notifications.get(timeout=self.poll_interval_seconds)
            except queue.Empty:
                self._check_failed_stream()
                continue

            if isinstance(item, BaseException):
                raise item
            self._last_activity_at = self.clock()
            self._observe(item)
            return item

    def _observe(self, notification: Any) -> None:
        method = str(getattr(notification, "method", ""))
        payload = _model_data(getattr(notification, "payload", notification))

        if method == "error":
            self._error_seen = True
            if isinstance(payload, dict):
                will_retry = payload.get("willRetry", payload.get("will_retry"))
                if isinstance(will_retry, bool):
                    self._runtime_will_retry = will_retry
            return

        if method == "turn/started":
            self._clear_failure_signal()
            return

        if method != "turn/completed" or not isinstance(payload, dict):
            return
        turn = payload.get("turn")
        status = turn.get("status") if isinstance(turn, dict) else None
        if _enum_value(status) == "failed":
            self._failed_completion_seen = True
        elif status is not None:
            self._clear_failure_signal()

    def _clear_failure_signal(self) -> None:
        self._error_seen = False
        self._failed_completion_seen = False
        self._runtime_will_retry = None

    def _check_failed_stream(self) -> None:
        if not self._failure_suspected():
            return

        response = self.client.request(
            "thread/goal/get",
            {"threadId": self.thread_id},
            response_model=ThreadGoalGetResponse,
        )
        goal = response.goal
        status = None if goal is None else _enum_value(goal.status)
        if goal is None or status != ThreadGoalStatus.active.value:
            # End the SDK iterator normally. The controller immediately reads
            # the persisted Goal and either returns it or resumes it.
            raise _GoalStreamClosed()

        timeout = 0.0 if self._runtime_will_retry is False else self.stall_timeout_seconds
        stalled_for = self.clock() - self._last_activity_at
        if stalled_for >= timeout:
            raise TimeoutError(
                "timed out after "
                f"{stalled_for:.1f}s waiting for an active Goal stream to recover "
                "from an error or failed turn"
            )

    def _failure_suspected(self) -> bool:
        if self._error_seen or self._failed_completion_seen:
            return True
        completed = getattr(self.state, "completed_turn", None)
        current_turn = getattr(self.state, "current_turn", None)
        active_turn_id = current_turn() if callable(current_turn) else None
        status = None if completed is None else _enum_value(getattr(completed, "status", None))
        return active_turn_id is None and status == "failed"


class OfficialBackend:
    """Small compatibility layer over the official ``openai-codex`` SDK.

    Goal lifecycle RPCs are present in the stable SDK/runtime but are not yet
    exposed by the SDK's high-level ``Thread`` object. Keeping the protocol
    access in this one module makes future SDK migrations local and explicit.
    """

    _GOAL_START_TIMEOUT_SECONDS = 30.0
    _GOAL_STREAM_POLL_SECONDS = 1.0
    _GOAL_STREAM_STALL_TIMEOUT_SECONDS = 30.0

    def __init__(self, config: CodexConfig | None = None) -> None:
        self._config = config or CodexConfig()
        self._codex: Codex | None = None
        self._thread: Any = None

    @property
    def thread_id(self) -> str | None:
        return None if self._thread is None else str(self._thread.id)

    def connect(self) -> None:
        if self._codex is None:
            self._codex = Codex(self._config)

    def close(self) -> None:
        codex, self._codex = self._codex, None
        self._thread = None
        if codex is not None:
            codex.close()

    def start_thread(self, **options: Any) -> str:
        self.connect()
        assert self._codex is not None
        self._thread = self._codex.thread_start(**options)
        return str(self._thread.id)

    def resume_thread(self, thread_id: str, **options: Any) -> str:
        self.connect()
        assert self._codex is not None
        self._thread = self._codex.thread_resume(thread_id, **options)
        return str(self._thread.id)

    def reconnect(self, thread_id: str) -> str:
        self.close()
        self.connect()
        return self.resume_thread(thread_id)

    def start_turn(self, prompt: Any, **options: Any) -> Operation:
        thread = self._require_thread()
        handle = thread.turn(prompt, **options)
        return Operation(
            id=str(handle.id),
            events=handle.stream(),
            cancel_callback=handle.interrupt,
        )

    def start_goal(
        self,
        objective: str,
        token_budget: int | None,
        model: str | None,
    ) -> Operation:
        if not objective.strip():
            raise ValueError("objective must not be empty")
        if token_budget is not None and token_budget <= 0:
            raise ValueError("token_budget must be > 0 or None")
        client, thread_id = self._client_and_thread_id()
        self._assert_goal_support(client)

        with client._thread_start_lock(thread_id):
            thread = client.thread_read(thread_id).thread
            if not isinstance(thread.status.root, IdleThreadStatus):
                raise RuntimeError(f"thread must be idle before starting a Goal: {thread_id}")
            if thread.ephemeral or thread.path is None:
                raise RuntimeError(f"thread must be persisted before starting a Goal: {thread_id}")
            if model is not None:
                self._set_model(client, thread_id, model)

            state = client.reserve_goal_operation(thread_id)
            activated = False
            try:
                client.thread_goal_clear(thread_id)
                state.activate_turn_routing()
                payload: dict[str, Any] = {
                    "threadId": thread_id,
                    "objective": objective,
                    "status": ThreadGoalStatus.active.value,
                }
                if token_budget is not None:
                    payload["tokenBudget"] = token_budget
                client.request(
                    "thread/goal/set",
                    payload,
                    response_model=ThreadGoalSetResponse,
                )
                activated = True
                logical_turn_id = state.wait_for_start(self._GOAL_START_TIMEOUT_SECONDS)
                if logical_turn_id is None:
                    raise RuntimeError("timed out waiting for the first Goal turn")
                return self._goal_operation(client, state, logical_turn_id)
            except BaseException:
                if activated:
                    client.cancel_goal_operation(state)
                state.finish()
                client.unregister_goal_operation(state)
                raise

    def resume_goal(self, model: str | None) -> Operation:
        client, thread_id = self._client_and_thread_id()
        self._assert_goal_support(client)
        current = self.get_goal()
        if current is None:
            raise NoActiveGoalError(f"thread {thread_id} has no Goal to resume")

        with client._thread_start_lock(thread_id):
            state = client.reserve_goal_operation(thread_id)
            activated = False
            try:
                if model is not None:
                    self._set_model(client, thread_id, model)
                state.activate_turn_routing()
                client.thread_goal_set(thread_id, status=ThreadGoalStatus.active)
                activated = True
                logical_turn_id = state.wait_for_start(self._GOAL_START_TIMEOUT_SECONDS)
                if logical_turn_id is None:
                    raise RuntimeError("timed out waiting for the resumed Goal turn")
                return self._goal_operation(client, state, logical_turn_id)
            except BaseException:
                if activated:
                    client.cancel_goal_operation(state)
                state.finish()
                client.unregister_goal_operation(state)
                raise

    def get_goal(self) -> Any | None:
        client, thread_id = self._client_and_thread_id()
        response = client.request(
            "thread/goal/get",
            {"threadId": thread_id},
            response_model=ThreadGoalGetResponse,
        )
        return response.goal

    def pause_goal(self) -> Any:
        client, thread_id = self._client_and_thread_id()
        if self.get_goal() is None:
            raise NoActiveGoalError(f"thread {thread_id} has no Goal to pause")
        return client.thread_goal_set(thread_id, status=ThreadGoalStatus.paused)

    def clear_goal(self) -> Any:
        client, thread_id = self._client_and_thread_id()
        return client.thread_goal_clear(thread_id)

    def _require_thread(self) -> Any:
        if self._thread is None:
            raise RuntimeError("no Codex thread is selected")
        return self._thread

    def _client_and_thread_id(self) -> tuple[Any, str]:
        thread = self._require_thread()
        return thread._client, str(thread.id)

    @staticmethod
    def _assert_goal_support(client: Any) -> None:
        required = (
            "reserve_goal_operation",
            "unregister_goal_operation",
            "next_goal_notification",
            "thread_goal_set",
            "thread_goal_clear",
        )
        missing = [name for name in required if not hasattr(client, name)]
        if missing:
            raise IncompatibleCodexSdkError(
                "installed openai-codex SDK lacks Goal protocol support: " + ", ".join(missing)
            )

    @staticmethod
    def _set_model(client: Any, thread_id: str, model: str) -> None:
        if not model.strip():
            raise ValueError("model must not be empty")
        client.request(
            "thread/settings/update",
            {"threadId": thread_id, "model": model},
            response_model=_ThreadSettingsUpdateResponse,
        )

    @classmethod
    def _goal_operation(cls, client: Any, state: Any, logical_turn_id: str) -> Operation:
        watchdog = _GoalNotificationWatchdog(
            client=client,
            state=state,
            thread_id=state.thread_id,
            poll_interval_seconds=cls._GOAL_STREAM_POLL_SECONDS,
            stall_timeout_seconds=cls._GOAL_STREAM_STALL_TIMEOUT_SECONDS,
        )
        stream = _GoalNotificationStream(
            state=state,
            next_notification=watchdog,
            unregister=lambda: client.unregister_goal_operation(state),
            cancel_goal=lambda: client.cancel_goal_operation(state),
        )
        return Operation(
            id=str(logical_turn_id),
            events=stream,
            cancel_callback=lambda: client.cancel_goal_operation(state),
        )


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _model_data(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(by_alias=True, mode="json")
    if isinstance(value, dict):
        return {str(key): _model_data(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_model_data(item) for item in value]
    return _enum_value(value)
