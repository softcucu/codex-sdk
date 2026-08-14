from __future__ import annotations

import itertools
import json
import sys
import tempfile
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, TextIO

from openai_codex import CodexConfig

from .config import OutputMode, ResumePolicy
from .controller import CodexController
from .models import GoalResult, RunResult


@dataclass(frozen=True, slots=True)
class RunTask:
    prompt: Any
    model: str | None = None
    cwd: str | None = None
    thread_id: str | None = None
    thread_options: dict[str, Any] = field(default_factory=dict)
    turn_options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GoalTask:
    objective: str
    model: str | None = None
    cwd: str | None = None
    thread_id: str | None = None
    token_budget: int | None = None
    thread_options: dict[str, Any] = field(default_factory=dict)


class CodexThreadPool:
    """Run independent Codex threads concurrently using Python worker threads.

    Each submitted task owns a separate :class:`CodexController`, app-server
    connection, and Codex thread. This avoids sharing mutable thread state or a
    turn stream between workers. Human/debug output is buffered per task and
    emitted atomically when that task ends, so concurrent logs do not interleave.
    """

    def __init__(
        self,
        *,
        max_workers: int = 4,
        cwd: str | None = None,
        codex_bin: str | None = None,
        codex_config: CodexConfig | None = None,
        output_mode: OutputMode | str = OutputMode.HUMAN,
        output: TextIO | None = None,
        resume_policy: ResumePolicy | None = None,
        _controller_factory: Callable[..., CodexController] = CodexController,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        if codex_config is not None and (cwd is not None or codex_bin is not None):
            raise ValueError("pass either codex_config or cwd/codex_bin, not both")
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="codex-worker",
        )
        self._cwd = cwd
        self._codex_bin = codex_bin
        self._codex_config = codex_config
        self._output_mode = OutputMode.parse(output_mode)
        self._output = output or sys.stdout
        self._resume_policy = resume_policy
        self._controller_factory = _controller_factory
        self._task_ids = itertools.count(1)
        self._output_lock = threading.Lock()
        self._shutdown = False

    def __enter__(self) -> "CodexThreadPool":
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        self.shutdown()

    def submit_run(
        self,
        prompt: Any,
        *,
        model: str | None = None,
        cwd: str | None = None,
        thread_id: str | None = None,
        thread_options: dict[str, Any] | None = None,
        **turn_options: Any,
    ) -> Future[RunResult]:
        """Submit one normal turn on its own Codex thread."""
        task = RunTask(
            prompt=prompt,
            model=model,
            cwd=cwd,
            thread_id=thread_id,
            thread_options=dict(thread_options or {}),
            turn_options=dict(turn_options),
        )
        return self._submit("run", task, self._execute_run)

    def submit_goal(
        self,
        objective: str,
        *,
        model: str | None = None,
        cwd: str | None = None,
        thread_id: str | None = None,
        token_budget: int | None = None,
        thread_options: dict[str, Any] | None = None,
    ) -> Future[GoalResult]:
        """Submit one resilient Goal on its own Codex thread."""
        task = GoalTask(
            objective=objective,
            model=model,
            cwd=cwd,
            thread_id=thread_id,
            token_budget=token_budget,
            thread_options=dict(thread_options or {}),
        )
        return self._submit("goal", task, self._execute_goal)

    def submit_resume_goal(
        self,
        thread_id: str,
        *,
        model: str | None = None,
        cwd: str | None = None,
    ) -> Future[GoalResult]:
        """Resume one persisted Goal concurrently with other tasks."""
        task = GoalTask(
            objective="",
            model=model,
            cwd=cwd,
            thread_id=thread_id,
        )
        return self._submit("resume-goal", task, self._execute_resume_goal)

    def map_runs(self, tasks: Iterable[RunTask]) -> list[RunResult]:
        """Run a batch concurrently and return results in input order."""
        futures = [
            self.submit_run(
                task.prompt,
                model=task.model,
                cwd=task.cwd,
                thread_id=task.thread_id,
                thread_options=task.thread_options,
                **task.turn_options,
            )
            for task in tasks
        ]
        return [future.result() for future in futures]

    def map_goals(self, tasks: Iterable[GoalTask]) -> list[GoalResult]:
        """Run a Goal batch concurrently and return results in input order."""
        futures = [
            self.submit_goal(
                task.objective,
                model=task.model,
                cwd=task.cwd,
                thread_id=task.thread_id,
                token_budget=task.token_budget,
                thread_options=task.thread_options,
            )
            for task in tasks
        ]
        return [future.result() for future in futures]

    def shutdown(self, *, wait: bool = True, cancel_futures: bool = False) -> None:
        """Stop accepting work and close the underlying executor."""
        if self._shutdown:
            return
        self._shutdown = True
        self._executor.shutdown(wait=wait, cancel_futures=cancel_futures)

    def _submit(self, kind: str, task: Any, operation: Callable[[Any, Any], Any]) -> Future[Any]:
        if self._shutdown:
            raise RuntimeError("CodexThreadPool has been shut down")
        task_id = next(self._task_ids)
        return self._executor.submit(self._run_isolated, task_id, kind, task, operation)

    def _run_isolated(
        self,
        task_id: int,
        kind: str,
        task: RunTask | GoalTask,
        operation: Callable[[CodexController, Any], Any],
    ) -> Any:
        task_output = tempfile.SpooledTemporaryFile(
            max_size=1024 * 1024,
            mode="w+",
            encoding="utf-8",
        )
        controller: CodexController | None = None
        try:
            controller = self._make_controller(task, task_output, task_id, kind)
            return operation(controller, task)
        finally:
            try:
                if controller is not None:
                    controller.close()
            finally:
                try:
                    self._emit_task_output(task_id, kind, task_output)
                finally:
                    task_output.close()

    def _make_controller(
        self,
        task: RunTask | GoalTask,
        task_output: TextIO,
        task_id: int,
        kind: str,
    ) -> CodexController:
        base_cwd = self._codex_config.cwd if self._codex_config is not None else self._cwd
        task_cwd = task.cwd if task.cwd is not None else base_cwd
        kwargs: dict[str, Any] = {
            "thread_id": task.thread_id,
            "output_mode": self._output_mode,
            "output": task_output,
            "resume_policy": self._resume_policy,
            "log_context": {"pool_task_id": task_id, "pool_task_kind": kind},
        }
        if self._codex_config is not None:
            kwargs["codex_config"] = replace(self._codex_config, cwd=task_cwd)
        else:
            kwargs["cwd"] = task_cwd
            kwargs["codex_bin"] = self._codex_bin
        return self._controller_factory(**kwargs)

    @staticmethod
    def _execute_run(controller: CodexController, task: RunTask) -> RunResult:
        if task.thread_id is not None:
            options: dict[str, Any] = {"cwd": task.cwd}
            if task.model is not None:
                options["model"] = task.model
            controller.resume_thread(task.thread_id, **options)
        elif task.thread_options:
            options = dict(task.thread_options)
            if task.model is not None:
                options.setdefault("model", task.model)
            controller.start_thread(**options)
        return controller.run(task.prompt, model=task.model, **task.turn_options)

    @staticmethod
    def _execute_goal(controller: CodexController, task: GoalTask) -> GoalResult:
        if task.thread_id is not None:
            options: dict[str, Any] = {"cwd": task.cwd}
            if task.model is not None:
                options["model"] = task.model
            controller.resume_thread(task.thread_id, **options)
        return controller.goal(
            task.objective,
            model=task.model,
            token_budget=task.token_budget,
            thread_options=task.thread_options,
        )

    @staticmethod
    def _execute_resume_goal(controller: CodexController, task: GoalTask) -> GoalResult:
        assert task.thread_id is not None
        options: dict[str, Any] = {"cwd": task.cwd}
        if task.model is not None:
            options["model"] = task.model
        controller.resume_thread(task.thread_id, **options)
        return controller.resume_goal(model=task.model)

    def _emit_task_output(self, task_id: int, kind: str, rendered: TextIO) -> None:
        if self._output_mode is OutputMode.QUIET:
            return
        rendered.seek(0)
        first_chunk = rendered.read(64 * 1024)
        if not first_chunk:
            return
        with self._output_lock:
            if self._output_mode is OutputMode.HUMAN:
                self._output.write(f"=== Codex task {task_id} ({kind}) ===\n")
            else:
                marker = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "sequence": 0,
                    "source": "pool",
                    "event": "task.output.started",
                    "data": {"pool_task_id": task_id, "pool_task_kind": kind},
                }
                self._output.write(
                    json.dumps(marker, ensure_ascii=False, separators=(",", ":")) + "\n"
                )
            last_chunk = first_chunk
            self._output.write(first_chunk)
            while True:
                chunk = rendered.read(64 * 1024)
                if not chunk:
                    break
                self._output.write(chunk)
                last_chunk = chunk
            if self._output_mode is OutputMode.HUMAN and not last_chunk.endswith("\n"):
                self._output.write("\n")
            self._output.flush()
