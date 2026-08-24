from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator

from codex_controller._backend import Operation


@dataclass
class Notification:
    method: str
    payload: Any


def completed_events(text: str = "done") -> list[Notification]:
    return [
        Notification(
            "item/agentMessage/delta",
            {"itemId": "message-1", "turnId": "turn-2", "delta": text},
        ),
        Notification(
            "item/completed",
            {
                "turnId": "turn-2",
                "item": {
                    "id": "message-1",
                    "type": "agentMessage",
                    "phase": "finalAnswer",
                    "text": text,
                },
            },
        ),
        Notification(
            "thread/tokenUsage/updated",
            {"turnId": "turn-2", "tokenUsage": {"total": {"totalTokens": 42}}},
        ),
        Notification(
            "turn/completed",
            {"turn": {"id": "turn-2", "status": "completed", "durationMs": 1000}},
        ),
    ]


class FakeBackend:
    def __init__(self, *, first_status: str = "usageLimited") -> None:
        self._thread_id: str | None = None
        self.goal: dict[str, Any] | None = None
        self.first_status = first_status
        self.start_goal_calls = 0
        self.resume_goal_calls = 0
        self.reconnect_calls = 0
        self.cancel_calls = 0
        self.closed = False
        self.turn_models: list[str | None] = []
        self.goal_models: list[str | None] = []
        self.start_thread_options: list[dict[str, Any]] = []
        self.resume_thread_options: list[dict[str, Any]] = []

    @property
    def thread_id(self) -> str | None:
        return self._thread_id

    def connect(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True
        self._thread_id = None

    def start_thread(self, **options: Any) -> str:
        assert options.get("ephemeral") is False
        self.start_thread_options.append(dict(options))
        self._thread_id = "thread-1"
        return self._thread_id

    def resume_thread(self, thread_id: str, **options: Any) -> str:
        self.resume_thread_options.append(dict(options))
        self._thread_id = thread_id
        return thread_id

    def reconnect(self, thread_id: str) -> str:
        self.reconnect_calls += 1
        self._thread_id = thread_id
        return thread_id

    def start_turn(self, prompt: Any, **options: Any) -> Operation:
        self.turn_models.append(options.get("model"))
        return Operation("turn-normal", iter(completed_events(str(prompt))), self._cancel)

    def start_goal(
        self, objective: str, token_budget: int | None, model: str | None
    ) -> Operation:
        self.start_goal_calls += 1
        self.goal_models.append(model)
        self.goal = self._goal_payload(objective, self.first_status, token_budget)
        error = {
            "message": "429 rate limit exceeded",
            "codexErrorInfo": {"responseTooManyFailedAttempts": {"httpStatusCode": 429}},
        }
        events = [
            Notification(
                "error",
                {"turnId": "turn-1", "error": error, "willRetry": False},
            ),
            Notification(
                "turn/completed",
                {"turn": {"id": "turn-1", "status": "failed", "error": error}},
            ),
        ]
        return Operation("turn-1", iter(events), self._cancel)

    def resume_goal(self, model: str | None) -> Operation:
        self.resume_goal_calls += 1
        self.goal_models.append(model)
        assert self.goal is not None
        self.goal = self._goal_payload(
            str(self.goal["objective"]), "complete", self.goal.get("tokenBudget")
        )
        self.goal["tokensUsed"] = 42
        return Operation("turn-2", iter(completed_events()), self._cancel)

    def get_goal(self) -> Any | None:
        return self.goal

    def pause_goal(self) -> Any:
        if self.goal is None:
            raise RuntimeError("no goal")
        self.goal["status"] = "paused"
        return type("Response", (), {"goal": self.goal})()

    def clear_goal(self) -> Any:
        self.goal = None
        return {"cleared": True}

    def _cancel(self) -> None:
        self.cancel_calls += 1

    def _goal_payload(
        self, objective: str, status: str, token_budget: int | None
    ) -> dict[str, Any]:
        return {
            "threadId": self._thread_id or "thread-1",
            "objective": objective,
            "status": status,
            "tokenBudget": token_budget,
            "tokensUsed": 0,
            "timeUsedSeconds": 1,
        }


class MalformedJsonBlockedBackend(FakeBackend):
    def __init__(
        self, *, repeat_on_resume: bool = False, object_error: bool = False
    ) -> None:
        super().__init__(first_status="blocked")
        self.repeat_on_resume = repeat_on_resume
        self.object_error = object_error

    def start_goal(
        self, objective: str, token_budget: int | None, model: str | None
    ) -> Operation:
        self.start_goal_calls += 1
        self.goal_models.append(model)
        self.goal = self._goal_payload(objective, "blocked", token_budget)
        return self._malformed_operation("turn-1")

    def resume_goal(self, model: str | None) -> Operation:
        if not self.repeat_on_resume:
            return super().resume_goal(model)
        self.resume_goal_calls += 1
        self.goal_models.append(model)
        assert self.goal is not None
        self.goal = self._goal_payload(
            str(self.goal["objective"]), "blocked", self.goal.get("tokenBudget")
        )
        return self._malformed_operation("turn-2")

    def _malformed_operation(self, turn_id: str) -> Operation:
        error_data = {
            "message": (
                '{"error":{"message":"Unterminated string starting at line 1 '
                'column 8 (char 7)","type":"BadRequestError","param":null,'
                '"code":400}}'
            ),
            "type": "invalid_request_error",
            "param": "",
            "code": None,
        }
        if self.object_error:
            error = _ModelError(error_data)
            error_payload: Any = _ErrorPayload(turn_id, error)
            completed_payload: Any = _TurnCompletedPayload(turn_id, error)
        else:
            error = error_data
            error_payload = {"turnId": turn_id, "error": error, "willRetry": False}
            completed_payload = {
                "turn": {"id": turn_id, "status": "failed", "error": error}
            }
        events = [
            Notification("error", error_payload),
            Notification("turn/completed", completed_payload),
        ]
        return Operation(turn_id, iter(events), self._cancel)


class _ModelError:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def model_dump(self, **_options: Any) -> dict[str, Any]:
        return self.data


class _ErrorPayload:
    def __init__(self, turn_id: str, error: _ModelError) -> None:
        self.turn_id = turn_id
        self.error = error

    def model_dump(self, **_options: Any) -> dict[str, Any]:
        return {
            "turnId": self.turn_id,
            "error": self.error.model_dump(),
            "willRetry": False,
        }


class _Turn:
    def __init__(self, turn_id: str, error: _ModelError) -> None:
        self.id = turn_id
        self.status = "failed"
        self.error = error

    def model_dump(self, **_options: Any) -> dict[str, Any]:
        return {"id": self.id, "status": self.status, "error": self.error.model_dump()}


class _TurnCompletedPayload:
    def __init__(self, turn_id: str, error: _ModelError) -> None:
        self.turn = _Turn(turn_id, error)

    def model_dump(self, **_options: Any) -> dict[str, Any]:
        return {"turn": self.turn.model_dump()}


class DisconnectingBackend(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.disconnected = False

    def start_goal(
        self, objective: str, token_budget: int | None, model: str | None
    ) -> Operation:
        from openai_codex import TransportClosedError

        self.start_goal_calls += 1
        self.goal_models.append(model)
        self.goal = self._goal_payload(objective, "usageLimited", token_budget)
        self.disconnected = True

        def fail() -> Iterator[Notification]:
            raise TransportClosedError()
            yield  # pragma: no cover

        return Operation("turn-disconnected", fail(), self._cancel)

    def get_goal(self) -> Any | None:
        if self.disconnected:
            raise RuntimeError("transport closed")
        return self.goal

    def reconnect(self, thread_id: str) -> str:
        self.disconnected = False
        return super().reconnect(thread_id)
