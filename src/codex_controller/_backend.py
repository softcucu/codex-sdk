from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterator, Protocol

from openai_codex import Codex, CodexConfig
from openai_codex._goal import _GoalNotificationStream
from openai_codex.generated.v2_all import (
    IdleThreadStatus,
    ThreadGoalGetResponse,
    ThreadGoalSetResponse,
    ThreadGoalStatus,
)

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

    def start_goal(self, objective: str, token_budget: int | None) -> Operation: ...

    def resume_goal(self) -> Operation: ...

    def get_goal(self) -> Any | None: ...

    def pause_goal(self) -> Any: ...

    def clear_goal(self) -> Any: ...


class OfficialBackend:
    """Small compatibility layer over the official ``openai-codex`` SDK.

    Goal lifecycle RPCs are present in the stable SDK/runtime but are not yet
    exposed by the SDK's high-level ``Thread`` object. Keeping the protocol
    access in this one module makes future SDK migrations local and explicit.
    """

    _GOAL_START_TIMEOUT_SECONDS = 30.0

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

    def start_goal(self, objective: str, token_budget: int | None) -> Operation:
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

    def resume_goal(self) -> Operation:
        client, thread_id = self._client_and_thread_id()
        self._assert_goal_support(client)
        current = self.get_goal()
        if current is None:
            raise NoActiveGoalError(f"thread {thread_id} has no Goal to resume")

        with client._thread_start_lock(thread_id):
            state = client.reserve_goal_operation(thread_id)
            activated = False
            try:
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
    def _goal_operation(client: Any, state: Any, logical_turn_id: str) -> Operation:
        stream = _GoalNotificationStream(
            state=state,
            next_notification=lambda: client.next_goal_notification(state),
            unregister=lambda: client.unregister_goal_operation(state),
            cancel_goal=lambda: client.cancel_goal_operation(state),
        )
        return Operation(
            id=str(logical_turn_id),
            events=stream,
            cancel_callback=lambda: client.cancel_goal_operation(state),
        )
