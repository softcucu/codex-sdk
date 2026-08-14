from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class GoalState:
    thread_id: str
    objective: str
    status: str
    token_budget: int | None = None
    tokens_used: int = 0
    time_used_seconds: int = 0

    @property
    def completed(self) -> bool:
        return self.status == "complete"


@dataclass(slots=True)
class RunResult:
    thread_id: str
    turn_id: str
    status: str
    final_response: str | None = None
    items: list[Any] = field(default_factory=list)
    usage: Any = None
    error: Any = None
    event_count: int = 0

    @property
    def completed(self) -> bool:
        return self.status == "completed"


@dataclass(slots=True)
class GoalResult:
    thread_id: str
    goal: GoalState
    resume_count: int
    final_response: str | None = None
    items: list[Any] = field(default_factory=list)
    usage: Any = None
    last_turn_status: str | None = None
    last_error: Any = None
    event_count: int = 0

    @property
    def completed(self) -> bool:
        return self.goal.completed


def enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def model_to_data(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(by_alias=True, mode="json")
    if hasattr(value, "root"):
        return model_to_data(value.root)
    if isinstance(value, dict):
        return {str(key): model_to_data(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [model_to_data(item) for item in value]
    converted = enum_value(value)
    if converted is not value:
        return model_to_data(converted)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def normalize_goal(goal: Any, *, fallback_thread_id: str = "") -> GoalState | None:
    if goal is None:
        return None
    data = model_to_data(goal)
    if not isinstance(data, dict):
        raise TypeError(f"unexpected goal payload: {type(goal).__name__}")
    return GoalState(
        thread_id=str(data.get("threadId", fallback_thread_id)),
        objective=str(data.get("objective", "")),
        status=str(data.get("status", "unknown")),
        token_budget=data.get("tokenBudget") if isinstance(data.get("tokenBudget"), int) else None,
        tokens_used=int(data.get("tokensUsed", 0)),
        time_used_seconds=int(data.get("timeUsedSeconds", 0)),
    )

