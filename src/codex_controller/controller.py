from __future__ import annotations

import random
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from openai_codex import CodexConfig, TransportClosedError, is_retryable_error

from ._backend import Backend, OfficialBackend, Operation
from .config import ControllerConfig, OutputMode, ResumePolicy
from .errors import GoalResumeExhaustedError, NoActiveGoalError
from .models import GoalResult, GoalState, RunResult, model_to_data, normalize_goal
from .render import EventRenderer


_RETRYABLE_GOAL_STATUSES = {"paused", "usageLimited"}
_NON_RETRYABLE_GOAL_STATUSES = {"blocked", "budgetLimited", "complete"}
_RETRYABLE_HTTP_STATUSES = {408, 409, 425, 429, 500, 502, 503, 504}
_RETRYABLE_TEXT = re.compile(
    r"(?:\b(?:408|409|425|429|500|502|503|504)\b|"
    r"(?:rate|usage)[ -]?limit|server.?overload|temporar(?:y|ily) unavailable|"
    r"response stream (?:disconnected|connection failed)|connection (?:reset|closed|failed)|"
    r"transport closed|too many failed attempts|retry limit|timed? ?out)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class _Collected:
    turn_id: str
    status: str | None = None
    final_response: str | None = None
    items: list[Any] = field(default_factory=list)
    usage: Any = None
    error: Any = None
    event_count: int = 0


class CodexController:
    """Synchronous Python controller for Codex threads, turns, and Goals.

    The default output mode is :attr:`OutputMode.HUMAN`. Goal runs automatically
    issue the protocol equivalent of ``/goal resume`` after retryable stops such
    as HTTP 429, server overload, response-stream disconnects, and an
    unexpectedly paused Goal.
    """

    def __init__(
        self,
        *,
        cwd: str | None = None,
        thread_id: str | None = None,
        codex_bin: str | None = None,
        codex_config: CodexConfig | None = None,
        output_mode: OutputMode | str = OutputMode.HUMAN,
        output: Any = None,
        log_context: dict[str, Any] | None = None,
        resume_policy: ResumePolicy | None = None,
        _backend: Backend | None = None,
        _sleep: Callable[[float], None] = time.sleep,
        _clock: Callable[[], float] = time.monotonic,
        _random: Callable[[], float] = random.random,
    ) -> None:
        if codex_config is not None and (cwd is not None or codex_bin is not None):
            raise ValueError("pass either codex_config or cwd/codex_bin, not both")
        public_config = ControllerConfig(
            cwd=cwd,
            codex_bin=codex_bin,
            output_mode=output_mode,
            output=output,
            resume_policy=resume_policy,
        )
        sdk_config = codex_config or CodexConfig(cwd=cwd, codex_bin=codex_bin)
        self._backend = _backend or OfficialBackend(sdk_config)
        self._renderer = EventRenderer(
            public_config.output_mode,
            public_config.output,
            context=log_context,
        )
        assert public_config.resume_policy is not None
        self._resume_policy = public_config.resume_policy
        self._thread_id = thread_id
        self._connected = False
        self._sleep = _sleep
        self._clock = _clock
        self._random = _random
        self._operation_lock = threading.RLock()

    def __enter__(self) -> "CodexController":
        # Connect eagerly, but leave thread creation to the first operation so
        # a per-operation model can be applied by thread/start itself.
        self._ensure_connected()
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        self.close()

    @property
    def thread_id(self) -> str | None:
        return self._thread_id

    def close(self) -> None:
        with self._operation_lock:
            try:
                self._backend.close()
            finally:
                self._connected = False
                self._renderer.close()

    def start_thread(self, **options: Any) -> str:
        """Create and select a persisted Codex thread."""
        with self._operation_lock:
            self._ensure_connected()
            options.setdefault("ephemeral", False)
            thread_id = self._backend.start_thread(**options)
            self._thread_id = thread_id
            self._renderer.wrapper_event("thread.started", thread_id=thread_id)
            return thread_id

    def resume_thread(self, thread_id: str, **options: Any) -> str:
        """Resume and select an existing Codex thread by ID."""
        with self._operation_lock:
            self._ensure_connected()
            resumed_id = self._backend.resume_thread(thread_id, **options)
            self._thread_id = resumed_id
            self._renderer.wrapper_event("thread.resumed", thread_id=resumed_id)
            return resumed_id

    def run(
        self,
        prompt: Any,
        *,
        model: str | None = None,
        **turn_options: Any,
    ) -> RunResult:
        """Run one turn, optionally overriding its model and subsequent thread turns."""
        if model is not None:
            if not model.strip():
                raise ValueError("model must not be empty")
            turn_options["model"] = model
        with self._operation_lock:
            thread_options = {"model": model} if model is not None else {}
            thread_id = self._ensure_thread(**thread_options)
            operation = self._backend.start_turn(prompt, **turn_options)
            try:
                collected = self._collect(operation)
            except KeyboardInterrupt:
                operation.cancel()
                raise
            finally:
                operation.close()
            return RunResult(
                thread_id=thread_id,
                turn_id=collected.turn_id,
                status=collected.status or "unknown",
                model=model,
                final_response=collected.final_response,
                items=collected.items,
                usage=collected.usage,
                error=collected.error,
                event_count=collected.event_count,
            )

    def goal(
        self,
        objective: str,
        *,
        model: str | None = None,
        token_budget: int | None = None,
        thread_options: dict[str, Any] | None = None,
    ) -> GoalResult:
        """Start a new Goal and keep resuming it after transient stops.

        Starting a new Goal replaces any existing Goal on the selected thread,
        matching the ``/goal <objective>`` lifecycle.
        """
        if not objective.strip():
            raise ValueError("objective must not be empty")
        if model is not None and not model.strip():
            raise ValueError("model must not be empty")
        with self._operation_lock:
            if self._thread_id is None:
                options = dict(thread_options or {})
                if model is not None:
                    options.setdefault("model", model)
                self.start_thread(**options)
            else:
                options = {"model": model} if model is not None else {}
                self._ensure_thread(**options)
            return self._run_goal_loop(
                objective=objective,
                token_budget=token_budget,
                model=model,
                start_new=True,
            )

    def resume_goal(self, *, model: str | None = None) -> GoalResult:
        """Resume an existing Goal, optionally changing its model first."""
        if model is not None and not model.strip():
            raise ValueError("model must not be empty")
        with self._operation_lock:
            thread_options = {"model": model} if model is not None else {}
            self._ensure_thread(**thread_options)
            current = self.get_goal()
            if current is None:
                raise NoActiveGoalError(f"thread {self._thread_id} has no Goal to resume")
            if current.completed:
                return GoalResult(
                    thread_id=current.thread_id,
                    goal=current,
                    resume_count=0,
                    model=model,
                )
            return self._run_goal_loop(
                objective=current.objective,
                token_budget=current.token_budget,
                model=model,
                start_new=False,
            )

    def get_goal(self) -> GoalState | None:
        """Return the selected thread's current persisted Goal."""
        with self._operation_lock:
            thread_id = self._ensure_thread()
            return normalize_goal(self._backend.get_goal(), fallback_thread_id=thread_id)

    def pause_goal(self) -> GoalState:
        """Pause the current Goal (the ``/goal pause`` equivalent)."""
        with self._operation_lock:
            self._ensure_thread()
            response = self._backend.pause_goal()
            raw_goal = getattr(response, "goal", None)
            goal = normalize_goal(raw_goal, fallback_thread_id=self._thread_id or "")
            if goal is None:
                raise NoActiveGoalError("Codex did not return a Goal after pausing")
            return goal

    def clear_goal(self) -> bool:
        """Clear the current Goal (the ``/goal clear`` equivalent)."""
        with self._operation_lock:
            self._ensure_thread()
            response = self._backend.clear_goal()
            data = model_to_data(response)
            return bool(data.get("cleared", False)) if isinstance(data, dict) else False

    def _run_goal_loop(
        self,
        *,
        objective: str,
        token_budget: int | None,
        model: str | None,
        start_new: bool,
    ) -> GoalResult:
        assert self._thread_id is not None
        thread_id = self._thread_id
        started_at = self._clock()
        resume_count = 0
        action = "start" if start_new else "resume"
        items: list[Any] = []
        final_response: str | None = None
        usage: Any = None
        event_count = 0
        last_status: str | None = None
        last_error: Any = None
        current_goal: GoalState | None = None

        while True:
            operation: Operation | None = None
            transport_lost = False
            caught_retryable_exception = False
            try:
                if action == "start":
                    self._renderer.wrapper_event(
                        "goal.started", objective=objective, model=model
                    )
                    operation = self._backend.start_goal(objective, token_budget, model)
                else:
                    self._renderer.wrapper_event(
                        "goal.resumed", attempt=resume_count, model=model
                    )
                    operation = self._backend.resume_goal(model)

                collected = self._collect(operation)
                items.extend(collected.items)
                final_response = collected.final_response or final_response
                usage = collected.usage or usage
                event_count += collected.event_count
                last_status = collected.status
                last_error = collected.error
                current_goal = normalize_goal(
                    self._backend.get_goal(), fallback_thread_id=thread_id
                )
            except KeyboardInterrupt:
                if operation is not None:
                    operation.cancel()
                else:
                    try:
                        self._backend.pause_goal()
                    except Exception:
                        pass
                raise
            except BaseException as exc:
                self._renderer.exception(exc, context="Goal interrupted")
                last_error = exc
                transport_lost = isinstance(exc, TransportClosedError)
                retryable_exception = self._is_retryable_exception(exc)
                if retryable_exception and operation is not None:
                    try:
                        operation.cancel()
                    except Exception:
                        pass
                try:
                    current_goal = normalize_goal(
                        self._backend.get_goal(), fallback_thread_id=thread_id
                    )
                except Exception:
                    current_goal = None
                if not retryable_exception:
                    raise
                caught_retryable_exception = True
            finally:
                if operation is not None:
                    operation.close()

            if current_goal is not None and current_goal.completed:
                result = self._goal_result(
                    current_goal,
                    resume_count,
                    model,
                    final_response,
                    items,
                    usage,
                    last_status,
                    last_error,
                    event_count,
                )
                self._renderer.wrapper_event(
                    "goal.completed",
                    tokens_used=current_goal.tokens_used,
                    resume_count=resume_count,
                )
                return result

            if current_goal is not None and current_goal.status in _NON_RETRYABLE_GOAL_STATUSES:
                result = self._goal_result(
                    current_goal,
                    resume_count,
                    model,
                    final_response,
                    items,
                    usage,
                    last_status,
                    last_error,
                    event_count,
                )
                self._renderer.wrapper_event("goal.stopped", status=current_goal.status)
                return result

            retryable_stop = (
                current_goal is not None and current_goal.status in _RETRYABLE_GOAL_STATUSES
            ) or self._is_retryable_error_payload(last_error) or caught_retryable_exception
            if current_goal is not None and current_goal.status == "active":
                retryable_stop = True

            if not retryable_stop:
                fallback = current_goal or GoalState(
                    thread_id=thread_id,
                    objective=objective,
                    status="unknown",
                    token_budget=token_budget,
                )
                result = self._goal_result(
                    fallback,
                    resume_count,
                    model,
                    final_response,
                    items,
                    usage,
                    last_status,
                    last_error,
                    event_count,
                )
                self._renderer.wrapper_event("goal.stopped", status=fallback.status)
                return result

            partial = self._goal_result(
                current_goal
                or GoalState(
                    thread_id=thread_id,
                    objective=objective,
                    status="unknown",
                    token_budget=token_budget,
                ),
                resume_count,
                model,
                final_response,
                items,
                usage,
                last_status,
                last_error,
                event_count,
            )
            self._check_resume_budget(resume_count, started_at, partial)
            delay = self._retry_delay(resume_count)
            reason = self._retry_reason(current_goal, last_error)
            self._renderer.wrapper_event(
                "goal.retry",
                attempt=resume_count + 1,
                delay_seconds=delay,
                reason=reason,
            )
            if delay > 0:
                self._sleep(delay)

            if transport_lost:
                self._renderer.wrapper_event("runtime.reconnecting", thread_id=thread_id)
                self._backend.reconnect(thread_id)
                self._connected = True
            elif self._backend.thread_id is None:
                self._backend.reconnect(thread_id)
                self._connected = True

            if current_goal is None:
                try:
                    current_goal = normalize_goal(
                        self._backend.get_goal(), fallback_thread_id=thread_id
                    )
                except Exception:
                    current_goal = None

            resume_count += 1
            action = "resume" if current_goal is not None or not start_new else "start"

    def _collect(self, operation: Operation) -> _Collected:
        result = _Collected(turn_id=operation.id)
        for event in operation.events:
            result.event_count += 1
            self._renderer.notification(event)
            method = str(getattr(event, "method", ""))
            payload_obj = getattr(event, "payload", event)
            payload = model_to_data(payload_obj)
            if not isinstance(payload, dict):
                continue
            if method == "item/completed":
                item_obj = getattr(payload_obj, "item", payload.get("item"))
                result.items.append(item_obj)
                item = payload.get("item")
                if isinstance(item, dict) and item.get("type") == "agentMessage":
                    phase = item.get("phase")
                    if phase in {None, "finalAnswer"} and item.get("text"):
                        result.final_response = str(item["text"])
            elif method == "thread/tokenUsage/updated":
                result.usage = getattr(payload_obj, "token_usage", payload.get("tokenUsage"))
            elif method == "error":
                result.error = getattr(payload_obj, "error", payload.get("error"))
            elif method == "turn/completed":
                turn_obj = getattr(payload_obj, "turn", None)
                turn = payload.get("turn")
                if isinstance(turn, dict):
                    result.status = str(turn.get("status", "unknown"))
                    error = getattr(turn_obj, "error", None) if turn_obj is not None else None
                    result.error = error or turn.get("error") or result.error
        return result

    def _ensure_connected(self) -> None:
        if not self._connected:
            self._backend.connect()
            self._connected = True

    def _ensure_thread(self, **options: Any) -> str:
        self._ensure_connected()
        if self._backend.thread_id is not None:
            self._thread_id = self._backend.thread_id
            return self._thread_id
        if self._thread_id is not None:
            return self.resume_thread(self._thread_id, **options)
        return self.start_thread(**options)

    def _check_resume_budget(
        self,
        resume_count: int,
        started_at: float,
        partial: GoalResult,
    ) -> None:
        policy = self._resume_policy
        if policy.max_attempts is not None and resume_count >= policy.max_attempts:
            raise GoalResumeExhaustedError(
                f"Goal automatic resume limit reached ({policy.max_attempts})",
                partial_result=partial,
            )
        if (
            policy.max_elapsed_seconds is not None
            and self._clock() - started_at >= policy.max_elapsed_seconds
        ):
            raise GoalResumeExhaustedError(
                f"Goal automatic resume time limit reached ({policy.max_elapsed_seconds}s)",
                partial_result=partial,
            )

    def _retry_delay(self, resume_count: int) -> float:
        policy = self._resume_policy
        base = min(
            policy.max_delay_seconds,
            policy.initial_delay_seconds * (policy.multiplier**resume_count),
        )
        if base == 0 or policy.jitter_ratio == 0:
            return base
        jitter = base * policy.jitter_ratio
        return max(0.0, base - jitter + 2 * jitter * self._random())

    @staticmethod
    def _goal_result(
        goal: GoalState,
        resume_count: int,
        model: str | None,
        final_response: str | None,
        items: list[Any],
        usage: Any,
        last_status: str | None,
        last_error: Any,
        event_count: int,
    ) -> GoalResult:
        return GoalResult(
            thread_id=goal.thread_id,
            goal=goal,
            resume_count=resume_count,
            model=model,
            final_response=final_response,
            items=list(items),
            usage=usage,
            last_turn_status=last_status,
            last_error=last_error,
            event_count=event_count,
        )

    @staticmethod
    def _is_retryable_exception(exc: BaseException) -> bool:
        if isinstance(exc, TransportClosedError):
            return True
        try:
            if is_retryable_error(exc):
                return True
        except Exception:
            pass
        return CodexController._is_retryable_error_payload(exc)

    @staticmethod
    def _is_retryable_error_payload(error: Any) -> bool:
        if error is None:
            return False
        data = model_to_data(error)
        return _data_contains_retryable_signal(data)

    @staticmethod
    def _retry_reason(goal: GoalState | None, error: Any) -> str:
        if goal is not None and goal.status == "usageLimited":
            return "Codex usage/rate limit stopped the Goal"
        if goal is not None and goal.status == "paused":
            return "Goal was paused by an interruption"
        data = model_to_data(error)
        if _data_contains_http_status(data, 429):
            return "HTTP 429 stopped the Goal"
        if error is not None:
            message = str(data.get("message", error)) if isinstance(data, dict) else str(error)
            return f"transient Codex error: {message}"
        return "active Goal became idle unexpectedly"


def _data_contains_retryable_signal(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = key.replace("_", "").lower()
            if normalized_key == "httpstatuscode" and item in _RETRYABLE_HTTP_STATUSES:
                return True
            if normalized_key in {"codexerrorinfo", "errorinfo"} and isinstance(item, str):
                if item in {
                    "serverOverloaded",
                    "usageLimitExceeded",
                    "internalServerError",
                    "responseStreamDisconnected",
                    "responseStreamConnectionFailed",
                    "httpConnectionFailed",
                    "responseTooManyFailedAttempts",
                }:
                    return True
            if _data_contains_retryable_signal(item):
                return True
        return False
    if isinstance(value, list):
        return any(_data_contains_retryable_signal(item) for item in value)
    if isinstance(value, str):
        return bool(_RETRYABLE_TEXT.search(value))
    return False


def _data_contains_http_status(value: Any, status: int) -> bool:
    if isinstance(value, dict):
        return any(
            (
                key.replace("_", "").lower() == "httpstatuscode"
                and item == status
            )
            or _data_contains_http_status(item, status)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_data_contains_http_status(item, status) for item in value)
    return False
