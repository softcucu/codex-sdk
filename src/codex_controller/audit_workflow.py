from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import time
import unicodedata
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from string import Template
from typing import Any, Callable, Iterable, TextIO

from openai_codex import ApprovalMode, Sandbox

from .config import OutputMode, ResumePolicy
from .controller import CodexController


_STATE_SCHEMA_VERSION = 1
_AUDIT_VERDICTS = {
    "VULNERABLE",
    "NO_CONFIRMED_VULNERABILITY",
    "INCONCLUSIVE",
}
_TERMINAL_GOAL_FAILURES = {"blocked", "budgetLimited"}
_TASK_KINDS = {"attack-surface", "message", "protocol"}


class AuditWorkflowError(RuntimeError):
    """Base error raised by the vulnerability-audit workflow."""


class AuditWorkflowAlreadyRunningError(AuditWorkflowError):
    """Raised when another process owns the same workflow directory."""


class AuditOutputValidationError(AuditWorkflowError):
    """Raised when a Goal reports completion but its artifacts are invalid."""


class AuditWorkflowStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AuditWorkflowConfig:
    project_dir: str | Path
    output_dir: str | Path | None = None
    codex_bin: str | None = None
    model: str | None = None
    attack_surface_model: str | None = None
    message_model: str | None = None
    protocol_model: str | None = None
    attack_surface_token_budget: int | None = None
    message_token_budget: int | None = None
    protocol_token_budget: int | None = None
    max_workers: int = 4
    task_retries: int = 2
    task_retry_delay_seconds: float = 5.0
    resume_policy: ResumePolicy = field(default_factory=ResumePolicy)
    output_mode: OutputMode | str = OutputMode.HUMAN
    output: TextIO | None = field(default=None, compare=False, repr=False)
    attack_surface_prompt: str | Path | None = None
    message_prompt: str | Path | None = None
    protocol_prompt: str | Path | None = None

    def __post_init__(self) -> None:
        project_dir = Path(self.project_dir).expanduser().resolve()
        if not project_dir.is_dir():
            raise ValueError(f"project directory does not exist: {project_dir}")

        if self.output_dir is None:
            output_dir = project_dir / "protocol-analysis"
        else:
            configured_output = Path(self.output_dir).expanduser()
            output_dir = (
                configured_output
                if configured_output.is_absolute()
                else project_dir / configured_output
            ).resolve()
        try:
            output_dir.relative_to(project_dir)
        except ValueError as exc:
            raise ValueError("output_dir must be inside project_dir") from exc

        if self.max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        if self.task_retries < 0:
            raise ValueError("task_retries must be >= 0")
        if self.task_retry_delay_seconds < 0:
            raise ValueError("task_retry_delay_seconds must be >= 0")
        for name, value in (
            ("attack_surface_token_budget", self.attack_surface_token_budget),
            ("message_token_budget", self.message_token_budget),
            ("protocol_token_budget", self.protocol_token_budget),
        ):
            if value is not None and value <= 0:
                raise ValueError(f"{name} must be > 0 or None")
        for name, value in (
            ("model", self.model),
            ("attack_surface_model", self.attack_surface_model),
            ("message_model", self.message_model),
            ("protocol_model", self.protocol_model),
        ):
            if value is not None and not value.strip():
                raise ValueError(f"{name} must not be empty")

        object.__setattr__(self, "project_dir", project_dir)
        object.__setattr__(self, "output_dir", output_dir)
        object.__setattr__(self, "output_mode", OutputMode.parse(self.output_mode))


@dataclass(frozen=True, slots=True)
class AuditWorkflowResult:
    status: AuditWorkflowStatus
    output_dir: Path
    results_dir: Path
    message_total: int = 0
    message_completed: int = 0
    message_failed: int = 0
    protocol_total: int = 0
    protocol_completed: int = 0
    protocol_failed: int = 0
    inconclusive_tasks: tuple[str, ...] = ()
    failed_tasks: tuple[str, ...] = ()
    confirmed_findings: int = 0

    @property
    def completed(self) -> bool:
        return self.status is AuditWorkflowStatus.COMPLETE

    @property
    def exit_code(self) -> int:
        if self.status is AuditWorkflowStatus.COMPLETE:
            return 0
        if self.status is AuditWorkflowStatus.PARTIAL:
            return 2
        return 1


@dataclass(frozen=True, slots=True)
class _ProtocolRecord:
    protocol_id: str
    protocol_name: str
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _MessageRecord:
    protocol_id: str
    message_id: str
    message_name: str
    direction: str
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _SurfaceInventory:
    protocols: tuple[_ProtocolRecord, ...]
    messages: tuple[_MessageRecord, ...]
    hashes: dict[str, str]


@dataclass(frozen=True, slots=True)
class _TaskSpec:
    task_id: str
    kind: str
    objective: str
    input_hash: str
    model: str | None
    token_budget: int | None
    protocol_id: str | None = None
    protocol_name: str | None = None
    message_id: str | None = None
    message_name: str | None = None
    direction: str | None = None


@dataclass(frozen=True, slots=True)
class _ValidatedOutput:
    verdict: str | None
    findings_count: int
    audit_path: Path | None
    report_path: Path | None
    hashes: dict[str, str]


@dataclass(frozen=True, slots=True)
class _TaskOutcome:
    task_id: str
    kind: str
    completed: bool
    verdict: str | None = None
    findings_count: int = 0
    audit_path: Path | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class _GoalExecution:
    completed: bool
    status: str
    error: str | None = None


class _WorkflowFileLock:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._handle: TextIO | None = None

    def __enter__(self) -> "_WorkflowFileLock":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        handle = self._path.open("a+", encoding="utf-8")
        try:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise AuditWorkflowAlreadyRunningError(
                    f"another audit workflow is using {self._path.parent.parent}"
                ) from exc
        except ImportError:  # pragma: no cover - supported runtime is normally POSIX
            handle.close()
            raise AuditWorkflowError("workflow file locking is not supported on this OS")
        except BaseException:
            handle.close()
            raise
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()} started_at={_utc_now()}\n")
        handle.flush()
        self._handle = handle
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        assert self._handle is not None
        try:
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None


class VulnerabilityAuditWorkflow:
    """Run a durable attack-surface and vulnerability-audit workflow.

    Goal-level transient recovery is delegated to :class:`CodexController`.
    This class persists the higher-level task graph and Codex thread IDs so a
    later process can resume an interrupted Goal or skip a validated result.
    """

    def __init__(
        self,
        config: AuditWorkflowConfig,
        *,
        _controller_factory: Callable[..., CodexController] = CodexController,
        _sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self._controller_factory = _controller_factory
        self._sleep = _sleep
        self._output = config.output or sys.stdout
        self._output_lock = threading.Lock()
        self._state_lock = threading.RLock()

        self.output_dir = Path(config.output_dir)
        self.workflow_dir = self.output_dir / ".workflow"
        self.results_root = self.output_dir / "vulnerability-analysis"
        self.results_dir = self.results_root / "results"
        self.logs_dir = self.workflow_dir / "logs"
        self.state_path = self.workflow_dir / "state.json"
        self.lock_path = self.workflow_dir / "workflow.lock"
        self.attack_marker_path = self.output_dir / "ATTACK_SURFACE_COMPLETE.json"
        self.finished_path = self.results_root / "WORKFLOW_FINISHED.json"
        self.index_path = self.results_root / "RESULT_INDEX.jsonl"
        self.summary_path = self.results_root / "SUMMARY.md"
        self.coverage_path = self.results_root / "coverage.md"
        self._state: dict[str, Any] = {}

    def run(self, *, force: bool = False) -> AuditWorkflowResult:
        self.workflow_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        with _WorkflowFileLock(self.lock_path):
            self._load_state()
            if force:
                self._reset_for_force()

            attack_spec = self._attack_surface_spec()
            attack_outcome = self._execute_task(attack_spec)
            if not attack_outcome.completed:
                return self._finalize_surface_failure(attack_outcome)

            surface = self._validate_surface()
            message_specs = self._message_specs(surface)
            message_outcomes = self._execute_batch(message_specs)
            protocol_specs = self._protocol_specs(surface, message_outcomes)
            protocol_outcomes = self._execute_batch(protocol_specs)
            return self._finalize(message_outcomes, protocol_outcomes)

    def _load_state(self) -> None:
        with self._state_lock:
            if not self.state_path.exists():
                self._state = self._new_state(generation=1)
                self._save_state_locked()
                return
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise AuditWorkflowError(f"cannot read workflow state: {exc}") from exc
            if not isinstance(data, dict) or data.get("schema_version") != _STATE_SCHEMA_VERSION:
                raise AuditWorkflowError("unsupported or invalid workflow state")
            if not isinstance(data.get("tasks"), dict):
                raise AuditWorkflowError("workflow state has no valid tasks object")
            self._state = data

    @staticmethod
    def _new_state(*, generation: int) -> dict[str, Any]:
        now = _utc_now()
        return {
            "schema_version": _STATE_SCHEMA_VERSION,
            "generation": generation,
            "workflow_status": "running",
            "created_at": now,
            "updated_at": now,
            "tasks": {},
        }

    def _reset_for_force(self) -> None:
        with self._state_lock:
            generation = int(self._state.get("generation", 0)) + 1
            self._archive_completion_markers(generation)
            self._state = self._new_state(generation=generation)
            self._save_state_locked()

    def _archive_completion_markers(self, generation: int) -> None:
        archive = self.workflow_dir / "force-archives" / f"generation-{generation}"
        candidates = [self.attack_marker_path, self.finished_path]
        candidates.extend(sorted(self.results_dir.glob("*.complete.json")))
        existing = [path for path in candidates if path.exists()]
        if not existing:
            return
        archive.mkdir(parents=True, exist_ok=True)
        for path in existing:
            target = archive / path.name
            if target.exists():
                target = archive / f"{path.stem}-{_short_hash(str(path))}{path.suffix}"
            os.replace(path, target)

    def _save_state_locked(self) -> None:
        self._state["updated_at"] = _utc_now()
        _atomic_write_json(self.state_path, self._state)

    def _attack_surface_spec(self) -> _TaskSpec:
        prompt = self._read_prompt(
            "attack_surface_analysis_goal.txt", self.config.attack_surface_prompt
        )
        objective = re.sub(r"^\s*/goal(?:\s+|$)", "", prompt, count=1)
        default_output = Path(self.config.project_dir) / "protocol-analysis"
        if self.output_dir != default_output:
            objective += (
                "\n\n## 本次输出目录\n\n"
                "将提示词中的 `./protocol-analysis/` 替换为 "
                f"`{_prompt_text(self.output_dir)}/`，"
                "其他输出要求不变。\n"
            )
        return _TaskSpec(
            task_id="attack-surface",
            kind="attack-surface",
            objective=objective,
            input_hash=_hash_text(objective),
            model=self.config.attack_surface_model or self.config.model,
            token_budget=self.config.attack_surface_token_budget,
        )

    def _message_specs(self, surface: _SurfaceInventory) -> list[_TaskSpec]:
        template = Template(
            self._read_prompt(
                "message_vulnerability_analysis_goal.txt", self.config.message_prompt
            )
        )
        protocol_by_id = {item.protocol_id: item for item in surface.protocols}
        messages = sorted(
            surface.messages,
            key=lambda item: (item.protocol_id, item.direction, item.message_id),
        )
        bases = [
            "--".join(
                (
                    "message",
                    _slug(item.protocol_id),
                    _slug(item.direction),
                    _slug(item.message_id),
                )
            )
            for item in messages
        ]
        task_ids = _disambiguate_task_ids(
            bases,
            [f"{item.protocol_id}\0{item.direction}\0{item.message_id}" for item in messages],
        )

        specs: list[_TaskSpec] = []
        for item, task_id in zip(messages, task_ids):
            protocol = protocol_by_id[item.protocol_id]
            objective = template.substitute(
                task_id=task_id,
                protocol_id=_json_string_content(item.protocol_id),
                protocol_name=_prompt_text(protocol.protocol_name),
                message_id=_json_string_content(item.message_id),
                message_name=_prompt_text(item.message_name),
                direction=_json_string_content(item.direction),
                output_dir=_prompt_text(self.results_dir),
            )
            input_hash = _hash_json(
                {
                    "objective": objective,
                    "protocol": protocol.raw,
                    "message": item.raw,
                }
            )
            specs.append(
                _TaskSpec(
                    task_id=task_id,
                    kind="message",
                    objective=objective,
                    input_hash=input_hash,
                    model=self.config.message_model or self.config.model,
                    token_budget=self.config.message_token_budget,
                    protocol_id=item.protocol_id,
                    protocol_name=protocol.protocol_name,
                    message_id=item.message_id,
                    message_name=item.message_name,
                    direction=item.direction,
                )
            )
        return specs

    def _protocol_specs(
        self,
        surface: _SurfaceInventory,
        message_outcomes: list[_TaskOutcome],
    ) -> list[_TaskSpec]:
        template = Template(
            self._read_prompt(
                "protocol_vulnerability_analysis_goal.txt", self.config.protocol_prompt
            )
        )
        protocols = sorted(surface.protocols, key=lambda item: item.protocol_id)
        bases = [f"protocol--{_slug(item.protocol_id)}" for item in protocols]
        task_ids = _disambiguate_task_ids(
            bases,
            [item.protocol_id for item in protocols],
        )
        outcomes_by_identity: dict[tuple[str | None, str | None, str | None], _TaskOutcome] = {}
        for outcome in message_outcomes:
            key = (
                self._state_task_protocol(outcome.task_id),
                self._state_task_message(outcome.task_id),
                self._state_task_direction(outcome.task_id),
            )
            if key in outcomes_by_identity:
                raise AuditWorkflowError(f"duplicate message task identity: {key}")
            outcomes_by_identity[key] = outcome
        member_data: dict[str, list[dict[str, Any]]] = {
            item.protocol_id: [] for item in protocols
        }
        for message in surface.messages:
            outcome = outcomes_by_identity.get(
                (message.protocol_id, message.message_id, message.direction)
            )
            member_data.setdefault(message.protocol_id, []).append(
                {
                    "message": message.raw,
                    "task_id": outcome.task_id if outcome else None,
                    "completed": outcome.completed if outcome else False,
                    "verdict": outcome.verdict if outcome else None,
                    "audit_sha256": (
                        _sha256_file(outcome.audit_path)
                        if outcome is not None and outcome.audit_path is not None
                        and outcome.audit_path.exists()
                        else None
                    ),
                }
            )

        specs: list[_TaskSpec] = []
        for protocol, task_id in zip(protocols, task_ids):
            objective = template.substitute(
                task_id=task_id,
                protocol_id=_json_string_content(protocol.protocol_id),
                protocol_name=_prompt_text(protocol.protocol_name),
                output_dir=_prompt_text(self.results_dir),
            )
            input_hash = _hash_json(
                {
                    "objective": objective,
                    "protocol": protocol.raw,
                    "messages": member_data.get(protocol.protocol_id, []),
                }
            )
            specs.append(
                _TaskSpec(
                    task_id=task_id,
                    kind="protocol",
                    objective=objective,
                    input_hash=input_hash,
                    model=self.config.protocol_model or self.config.model,
                    token_budget=self.config.protocol_token_budget,
                    protocol_id=protocol.protocol_id,
                    protocol_name=protocol.protocol_name,
                )
            )
        return specs

    def _execute_batch(self, specs: list[_TaskSpec]) -> list[_TaskOutcome]:
        if not specs:
            return []
        outcomes: dict[str, _TaskOutcome] = {}
        with ThreadPoolExecutor(
            max_workers=self.config.max_workers,
            thread_name_prefix="codex-audit",
        ) as executor:
            futures: dict[Future[_TaskOutcome], _TaskSpec] = {
                executor.submit(self._execute_task, spec): spec for spec in specs
            }
            try:
                for future in as_completed(futures):
                    spec = futures[future]
                    try:
                        outcomes[spec.task_id] = future.result()
                    except Exception as exc:
                        outcomes[spec.task_id] = self._exhaust_unexpected(spec, exc)
            except KeyboardInterrupt:
                for future in futures:
                    future.cancel()
                raise
        return [outcomes[spec.task_id] for spec in specs]

    def _execute_task(self, spec: _TaskSpec) -> _TaskOutcome:
        if spec.kind not in _TASK_KINDS:
            raise ValueError(f"unsupported task kind: {spec.kind}")
        self._ensure_task_state(spec)
        existing = self._validated_completion(spec)
        if existing is not None:
            self._mark_task_completed(spec, existing)
            return self._outcome_from_validated(spec, existing)

        max_attempts = self.config.task_retries + 1
        while True:
            task = self._task_snapshot(spec.task_id)
            if task.get("status") == "exhausted" or (
                int(task.get("attempt_count", 0)) >= max_attempts
                and not task.get("thread_id")
                and task.get("status") != "starting"
            ):
                return self._mark_exhausted(spec, task.get("last_error"))

            execution: _GoalExecution
            if task.get("thread_id"):
                execution = self._resume_attempt(spec, task)
            else:
                execution = self._start_attempt(spec)

            if execution.completed:
                try:
                    validated = self._validate_output(spec)
                    self._write_completion_marker(spec, validated)
                except Exception as exc:
                    execution = _GoalExecution(
                        completed=False,
                        status="invalid-output",
                        error=str(exc),
                    )
                else:
                    self._mark_task_completed(spec, validated)
                    return self._outcome_from_validated(spec, validated)

            self._record_attempt_failure(spec, execution)
            task = self._task_snapshot(spec.task_id)
            if int(task.get("attempt_count", 0)) >= max_attempts:
                return self._mark_exhausted(spec, execution.error or execution.status)
            delay = min(
                60.0,
                self.config.task_retry_delay_seconds
                * (2 ** max(0, int(task.get("attempt_count", 1)) - 1)),
            )
            if delay > 0:
                self._sleep(delay)

    def _ensure_task_state(self, spec: _TaskSpec) -> None:
        with self._state_lock:
            tasks = self._state["tasks"]
            current = tasks.get(spec.task_id)
            if current is not None and current.get("input_hash") == spec.input_hash:
                return
            tasks[spec.task_id] = {
                "task_id": spec.task_id,
                "kind": spec.kind,
                "status": "pending",
                "input_hash": spec.input_hash,
                "objective_hash": _hash_text(spec.objective),
                "attempt_count": 0,
                "thread_id": None,
                "last_error": None,
                "verdict": None,
                "protocol_id": spec.protocol_id,
                "message_id": spec.message_id,
                "direction": spec.direction,
                "history": [],
                "created_at": _utc_now(),
                "updated_at": _utc_now(),
            }
            self._save_state_locked()

    def _task_snapshot(self, task_id: str) -> dict[str, Any]:
        with self._state_lock:
            return json.loads(json.dumps(self._state["tasks"][task_id]))

    def _start_attempt(self, spec: _TaskSpec) -> _GoalExecution:
        with self._state_lock:
            task = self._state["tasks"][spec.task_id]
            recovering_unstarted_attempt = (
                task.get("status") == "starting"
                and not task.get("thread_id")
                and int(task.get("attempt_count", 0)) > 0
                and bool(task.get("history"))
            )
            attempt = int(task.get("attempt_count", 0))
            if not recovering_unstarted_attempt:
                attempt += 1
                task["attempt_count"] = attempt
            task["status"] = "starting"
            task["thread_id"] = None
            task["updated_at"] = _utc_now()
            if recovering_unstarted_attempt:
                task["history"][-1]["recovered_at"] = _utc_now()
            else:
                task.setdefault("history", []).append(
                    {
                        "attempt": attempt,
                        "status": "starting",
                        "thread_id": None,
                        "started_at": _utc_now(),
                    }
                )
            self._save_state_locked()

        if spec.kind == "attack-surface":
            self._archive_attack_artifacts(attempt)
        else:
            self._archive_task_artifacts(spec, attempt)

        controller: CodexController | None = None
        log_path, log_handle, log_offset = self._open_attempt_log(spec, attempt)
        try:
            controller = self._make_controller(spec, log_handle)
            options: dict[str, Any] = {
                "sandbox": Sandbox.workspace_write,
                "approval_mode": ApprovalMode.deny_all,
            }
            if spec.model is not None:
                options["model"] = spec.model
            thread_id = controller.start_thread(**options)
            with self._state_lock:
                task = self._state["tasks"][spec.task_id]
                task["status"] = "running"
                task["thread_id"] = thread_id
                task["history"][-1]["status"] = "running"
                task["history"][-1]["thread_id"] = thread_id
                task["updated_at"] = _utc_now()
                self._save_state_locked()
            result = controller.goal(
                spec.objective,
                model=spec.model,
                token_budget=spec.token_budget,
            )
            return _execution_from_result(result)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            return _GoalExecution(False, "exception", _exception_text(exc))
        finally:
            if controller is not None:
                try:
                    controller.close()
                except Exception as exc:
                    log_handle.write(f"controller close failed: {_exception_text(exc)}\n")
            try:
                log_handle.close()
            finally:
                self._emit_attempt_log(log_path, log_offset, spec, attempt)

    def _resume_attempt(self, spec: _TaskSpec, task: dict[str, Any]) -> _GoalExecution:
        thread_id = str(task["thread_id"])
        attempt = max(1, int(task.get("attempt_count", 1)))
        controller: CodexController | None = None
        log_path, log_handle, log_offset = self._open_attempt_log(spec, attempt)
        try:
            controller = self._make_controller(spec, log_handle, thread_id=thread_id)
            options: dict[str, Any] = {
                "sandbox": Sandbox.workspace_write,
                "approval_mode": ApprovalMode.deny_all,
            }
            if spec.model is not None:
                options["model"] = spec.model
            controller.resume_thread(thread_id, **options)
            current = controller.get_goal()
            if current is None:
                return _GoalExecution(False, "missing-goal", "persisted thread has no Goal")
            objective = str(getattr(current, "objective", ""))
            if objective and _hash_text(objective) != task.get("objective_hash"):
                return _GoalExecution(
                    False,
                    "objective-mismatch",
                    "persisted thread Goal does not match this task",
                )
            status = str(getattr(current, "status", "unknown"))
            if status == "complete":
                return _GoalExecution(True, status)
            if status in _TERMINAL_GOAL_FAILURES:
                return _GoalExecution(False, status, f"Goal stopped with status {status}")
            result = controller.resume_goal(model=spec.model)
            return _execution_from_result(result)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            return _GoalExecution(False, "exception", _exception_text(exc))
        finally:
            if controller is not None:
                try:
                    controller.close()
                except Exception as exc:
                    log_handle.write(f"controller close failed: {_exception_text(exc)}\n")
            try:
                log_handle.close()
            finally:
                self._emit_attempt_log(log_path, log_offset, spec, attempt)

    def _record_attempt_failure(
        self, spec: _TaskSpec, execution: _GoalExecution
    ) -> None:
        with self._state_lock:
            task = self._state["tasks"][spec.task_id]
            error = execution.error or f"Goal stopped with status {execution.status}"
            task["status"] = "pending"
            task["thread_id"] = None
            task["last_error"] = error
            task["updated_at"] = _utc_now()
            history = task.get("history", [])
            if history:
                history[-1]["status"] = "failed"
                history[-1]["goal_status"] = execution.status
                history[-1]["error"] = error
                history[-1]["finished_at"] = _utc_now()
            self._save_state_locked()

    def _mark_task_completed(
        self, spec: _TaskSpec, validated: _ValidatedOutput
    ) -> None:
        with self._state_lock:
            task = self._state["tasks"][spec.task_id]
            task["status"] = "completed"
            task["verdict"] = validated.verdict
            task["last_error"] = None
            task["updated_at"] = _utc_now()
            history = task.get("history", [])
            if history and history[-1].get("status") == "running":
                history[-1]["status"] = "completed"
                history[-1]["finished_at"] = _utc_now()
            self._save_state_locked()

    def _mark_exhausted(self, spec: _TaskSpec, error: Any) -> _TaskOutcome:
        message = str(error or "task retry limit exhausted")
        with self._state_lock:
            task = self._state["tasks"][spec.task_id]
            task["status"] = "exhausted"
            task["thread_id"] = None
            task["last_error"] = message
            task["verdict"] = "INCONCLUSIVE" if spec.kind != "attack-surface" else None
            task["updated_at"] = _utc_now()
            self._save_state_locked()
        audit_path = None
        if spec.kind != "attack-surface":
            audit_path = self._existing_failure_audit(spec)
            if audit_path is None:
                audit_path = self._write_failure_audit(spec, message)
        return _TaskOutcome(
            task_id=spec.task_id,
            kind=spec.kind,
            completed=False,
            verdict="INCONCLUSIVE" if spec.kind != "attack-surface" else None,
            audit_path=audit_path,
            error=message,
        )

    def _exhaust_unexpected(self, spec: _TaskSpec, exc: Exception) -> _TaskOutcome:
        self._ensure_task_state(spec)
        return self._mark_exhausted(spec, f"unexpected workflow error: {_exception_text(exc)}")

    def _validated_completion(self, spec: _TaskSpec) -> _ValidatedOutput | None:
        marker_path = self._completion_marker_path(spec)
        if not marker_path.is_file():
            return None
        if spec.kind == "attack-surface":
            # Attack-surface analysis is intentionally allowed to be imported
            # from an earlier/manual run. An empty marker is sufficient to
            # prevent this expensive stage from running again; validation here
            # only ensures the inventories needed by downstream tasks exist.
            return self._validate_output(spec)
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            if not isinstance(marker, dict):
                return None
            if marker.get("status") != "complete":
                return None
            if marker.get("task_id") != spec.task_id:
                return None
            if marker.get("input_hash") != spec.input_hash:
                return None
            validated = self._validate_output(spec)
            if marker.get("output_hashes") != validated.hashes:
                return None
            return validated
        except (OSError, UnicodeError, json.JSONDecodeError, AuditOutputValidationError):
            return None

    def _validate_output(self, spec: _TaskSpec) -> _ValidatedOutput:
        if spec.kind == "attack-surface":
            surface = self._validate_surface()
            return _ValidatedOutput(
                verdict=None,
                findings_count=0,
                audit_path=None,
                report_path=None,
                hashes=surface.hashes,
            )
        return self._validate_audit(spec)

    def _validate_surface(self) -> _SurfaceInventory:
        required = {
            "PROTOCOL_SURFACE.md": self.output_dir / "PROTOCOL_SURFACE.md",
            "protocol_inventory.jsonl": self.output_dir / "protocol_inventory.jsonl",
            "message_inventory.jsonl": self.output_dir / "message_inventory.jsonl",
            "coverage.md": self.output_dir / "coverage.md",
        }
        missing = [name for name, path in required.items() if not path.is_file()]
        if missing:
            raise AuditOutputValidationError(
                "attack-surface output is missing: " + ", ".join(missing)
            )
        for name in ("PROTOCOL_SURFACE.md", "coverage.md"):
            if not required[name].read_text(encoding="utf-8").strip():
                raise AuditOutputValidationError(f"attack-surface output is empty: {name}")

        protocol_data = _read_jsonl(required["protocol_inventory.jsonl"])
        message_data = _read_jsonl(required["message_inventory.jsonl"])
        protocols = _normalize_protocols(protocol_data)
        messages = _normalize_messages(message_data, protocols)
        hashes = {name: _sha256_file(path) for name, path in required.items()}
        return _SurfaceInventory(tuple(protocols), tuple(messages), hashes)

    def _validate_audit(self, spec: _TaskSpec) -> _ValidatedOutput:
        audit_path = self.results_dir / f"{spec.task_id}.audit.json"
        report_path = self.results_dir / f"{spec.task_id}.漏洞报告.md"
        if not audit_path.is_file():
            raise AuditOutputValidationError(f"missing audit file: {audit_path.name}")
        try:
            data = json.loads(audit_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AuditOutputValidationError(
                f"invalid JSON in {audit_path.name}: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise AuditOutputValidationError("audit result must be a JSON object")
        expected = {
            "task_id": spec.task_id,
            "protocol_id": spec.protocol_id,
        }
        if spec.kind == "message":
            expected.update(
                {
                    "message_id": spec.message_id,
                    "direction": spec.direction,
                }
            )
        for key, value in expected.items():
            if data.get(key) != value:
                raise AuditOutputValidationError(
                    f"{audit_path.name}: {key} must be {value!r}"
                )

        verdict = data.get("verdict")
        if verdict not in _AUDIT_VERDICTS:
            raise AuditOutputValidationError(f"{audit_path.name}: invalid verdict")
        if not isinstance(data.get("summary"), str) or not data["summary"].strip():
            raise AuditOutputValidationError(f"{audit_path.name}: summary is required")
        findings = data.get("findings")
        if not isinstance(findings, list):
            raise AuditOutputValidationError(f"{audit_path.name}: findings must be a list")
        if not isinstance(data.get("coverage_gaps"), list):
            raise AuditOutputValidationError(
                f"{audit_path.name}: coverage_gaps must be a list"
            )
        if spec.kind == "message":
            for key in ("reachability", "controllable_fields", "preconditions"):
                if key not in data:
                    raise AuditOutputValidationError(f"{audit_path.name}: missing {key}")
        else:
            for key in ("attack_surface", "protocol_model", "security_invariants"):
                if key not in data:
                    raise AuditOutputValidationError(f"{audit_path.name}: missing {key}")

        required_finding = {
            "id",
            "title",
            "severity",
            "root_cause",
            "impact",
            "evidence",
            "remediation",
        }
        required_finding.add("attack_path" if spec.kind == "message" else "attack_sequence")
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                raise AuditOutputValidationError(
                    f"{audit_path.name}: finding {index} must be an object"
                )
            missing = required_finding - finding.keys()
            if missing:
                raise AuditOutputValidationError(
                    f"{audit_path.name}: finding {index} is missing {sorted(missing)}"
                )
            if finding.get("severity") not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                raise AuditOutputValidationError(
                    f"{audit_path.name}: finding {index} has invalid severity"
                )
            if not isinstance(finding.get("evidence"), list) or not finding["evidence"]:
                raise AuditOutputValidationError(
                    f"{audit_path.name}: finding {index} requires evidence"
                )

        vulnerable = bool(findings)
        if vulnerable != (verdict == "VULNERABLE"):
            raise AuditOutputValidationError(
                f"{audit_path.name}: verdict and findings are inconsistent"
            )
        if vulnerable:
            if not report_path.is_file() or not report_path.read_text(
                encoding="utf-8"
            ).strip():
                raise AuditOutputValidationError(
                    f"{audit_path.name}: confirmed findings require {report_path.name}"
                )
        elif report_path.exists():
            raise AuditOutputValidationError(
                f"{audit_path.name}: report must not exist without confirmed findings"
            )

        hashes = {audit_path.name: _sha256_file(audit_path)}
        if vulnerable:
            hashes[report_path.name] = _sha256_file(report_path)
        return _ValidatedOutput(
            verdict=str(verdict),
            findings_count=len(findings),
            audit_path=audit_path,
            report_path=report_path if vulnerable else None,
            hashes=hashes,
        )

    def _write_completion_marker(
        self, spec: _TaskSpec, validated: _ValidatedOutput
    ) -> None:
        task = self._task_snapshot(spec.task_id)
        marker = {
            "schema_version": 1,
            "task_id": spec.task_id,
            "task_kind": spec.kind,
            "status": "complete",
            "input_hash": spec.input_hash,
            "thread_id": task.get("thread_id"),
            "attempt_count": task.get("attempt_count", 0),
            "verdict": validated.verdict,
            "findings_count": validated.findings_count,
            "output_hashes": validated.hashes,
            "completed_at": _utc_now(),
        }
        _atomic_write_json(self._completion_marker_path(spec), marker)

    def _completion_marker_path(self, spec: _TaskSpec) -> Path:
        if spec.kind == "attack-surface":
            return self.attack_marker_path
        return self.results_dir / f"{spec.task_id}.complete.json"

    def _outcome_from_validated(
        self, spec: _TaskSpec, validated: _ValidatedOutput
    ) -> _TaskOutcome:
        return _TaskOutcome(
            task_id=spec.task_id,
            kind=spec.kind,
            completed=True,
            verdict=validated.verdict,
            findings_count=validated.findings_count,
            audit_path=validated.audit_path,
        )

    def _write_failure_audit(self, spec: _TaskSpec, error: str) -> Path:
        attempt = int(self._task_snapshot(spec.task_id).get("attempt_count", 0))
        self._archive_task_artifacts(spec, max(1, attempt))
        data: dict[str, Any] = {
            "task_id": spec.task_id,
            "protocol_id": spec.protocol_id,
            "verdict": "INCONCLUSIVE",
            "summary": "审计任务在重试耗尽后仍未成功完成。",
            "findings": [],
            "coverage_gaps": [error],
            "execution_status": "failed",
        }
        if spec.kind == "message":
            data.update(
                {
                    "message_id": spec.message_id,
                    "direction": spec.direction,
                    "reachability": "未完成",
                    "controllable_fields": [],
                    "preconditions": [],
                }
            )
        else:
            data.update(
                {
                    "attack_surface": "未完成",
                    "protocol_model": [],
                    "security_invariants": [],
                }
            )
        path = self.results_dir / f"{spec.task_id}.audit.json"
        _atomic_write_json(path, data)
        return path

    def _existing_failure_audit(self, spec: _TaskSpec) -> Path | None:
        path = self.results_dir / f"{spec.task_id}.audit.json"
        report = self.results_dir / f"{spec.task_id}.漏洞报告.md"
        marker = self.results_dir / f"{spec.task_id}.complete.json"
        if not path.is_file() or report.exists() or marker.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        if data.get("task_id") != spec.task_id:
            return None
        if data.get("execution_status") != "failed":
            return None
        if data.get("verdict") != "INCONCLUSIVE":
            return None
        return path

    def _archive_attack_artifacts(self, attempt: int) -> None:
        candidates = [
            self.output_dir / "PROTOCOL_SURFACE.md",
            self.output_dir / "protocol_inventory.jsonl",
            self.output_dir / "message_inventory.jsonl",
            self.output_dir / "coverage.md",
            self.output_dir / "protocols",
            self.attack_marker_path,
        ]
        existing = [path for path in candidates if path.exists()]
        if not existing:
            return
        archive = (
            self.workflow_dir
            / "failed-artifacts"
            / "attack-surface"
            / f"attempt-{attempt}-{_timestamp_slug()}"
        )
        archive.mkdir(parents=True, exist_ok=True)
        for path in existing:
            os.replace(path, archive / path.name)

    def _archive_task_artifacts(self, spec: _TaskSpec, attempt: int) -> None:
        candidates = [
            self.results_dir / f"{spec.task_id}.audit.json",
            self.results_dir / f"{spec.task_id}.漏洞报告.md",
            self.results_dir / f"{spec.task_id}.complete.json",
        ]
        existing = [path for path in candidates if path.exists()]
        if not existing:
            return
        archive = (
            self.workflow_dir
            / "failed-artifacts"
            / spec.task_id
            / f"attempt-{attempt}-{_timestamp_slug()}"
        )
        archive.mkdir(parents=True, exist_ok=True)
        for path in existing:
            os.replace(path, archive / path.name)

    def _make_controller(
        self,
        spec: _TaskSpec,
        output: TextIO,
        *,
        thread_id: str | None = None,
    ) -> CodexController:
        return self._controller_factory(
            cwd=str(self.config.project_dir),
            codex_bin=self.config.codex_bin,
            thread_id=thread_id,
            output_mode=self.config.output_mode,
            output=output,
            log_context={"audit_task_id": spec.task_id, "audit_task_kind": spec.kind},
            resume_policy=self.config.resume_policy,
        )

    def _open_attempt_log(
        self, spec: _TaskSpec, attempt: int
    ) -> tuple[Path, TextIO, int]:
        log_path = self.logs_dir / f"{spec.task_id}.attempt-{attempt}.log"
        handle = log_path.open("a+", encoding="utf-8")
        handle.seek(0, os.SEEK_END)
        return log_path, handle, handle.tell()

    def _emit_attempt_log(
        self, path: Path, offset: int, spec: _TaskSpec, attempt: int
    ) -> None:
        if self.config.output_mode is OutputMode.QUIET:
            return
        try:
            with path.open("r", encoding="utf-8") as handle:
                handle.seek(offset)
                rendered = handle.read()
        except OSError:
            return
        if not rendered:
            return
        with self._output_lock:
            self._output.write(
                f"=== Audit task {spec.task_id} ({spec.kind}, attempt {attempt}) ===\n"
            )
            self._output.write(rendered)
            if not rendered.endswith("\n"):
                self._output.write("\n")
            self._output.flush()

    def _read_prompt(self, name: str, override: str | Path | None) -> str:
        if override is not None:
            path = Path(override).expanduser().resolve()
            candidates = [path]
        else:
            module_dir = Path(__file__).resolve().parent
            candidates = [
                module_dir / "prompts" / name,
                module_dir.parent / "prompts" / name,
            ]
        for path in candidates:
            if path.is_file():
                try:
                    return path.read_text(encoding="utf-8")
                except (OSError, UnicodeError) as exc:
                    raise AuditWorkflowError(f"cannot read prompt {path}: {exc}") from exc
        raise AuditWorkflowError(
            f"prompt not found: {name}; checked {', '.join(str(path) for path in candidates)}"
        )

    def _state_task_protocol(self, task_id: str) -> str | None:
        with self._state_lock:
            task = self._state["tasks"].get(task_id, {})
            value = task.get("protocol_id")
            return str(value) if value is not None else None

    def _state_task_message(self, task_id: str) -> str | None:
        with self._state_lock:
            task = self._state["tasks"].get(task_id, {})
            value = task.get("message_id")
            return str(value) if value is not None else None

    def _state_task_direction(self, task_id: str) -> str | None:
        with self._state_lock:
            task = self._state["tasks"].get(task_id, {})
            value = task.get("direction")
            return str(value) if value is not None else None

    def _finalize_surface_failure(
        self, outcome: _TaskOutcome
    ) -> AuditWorkflowResult:
        error = outcome.error or "attack-surface analysis did not complete"
        result = AuditWorkflowResult(
            status=AuditWorkflowStatus.FAILED,
            output_dir=self.output_dir,
            results_dir=self.results_dir,
            failed_tasks=(outcome.task_id,),
        )
        _atomic_write_text(
            self.summary_path,
            "# Vulnerability Audit Summary\n\n"
            "The workflow could not start vulnerability auditing because attack-surface "
            f"analysis failed.\n\n- Error: {error}\n",
        )
        _atomic_write_text(
            self.coverage_path,
            "# Vulnerability Audit Coverage\n\n"
            "- Attack-surface analysis: failed\n"
            "- Message audits: not started\n"
            "- Protocol audits: not started\n"
            f"- Failure: {error}\n",
        )
        self._write_finished(result)
        self._set_workflow_status(result.status)
        return result

    def _finalize(
        self,
        message_outcomes: list[_TaskOutcome],
        protocol_outcomes: list[_TaskOutcome],
    ) -> AuditWorkflowResult:
        all_outcomes = message_outcomes + protocol_outcomes
        failed = tuple(outcome.task_id for outcome in all_outcomes if not outcome.completed)
        inconclusive = tuple(
            outcome.task_id
            for outcome in all_outcomes
            if outcome.completed and outcome.verdict == "INCONCLUSIVE"
        )
        findings = sum(outcome.findings_count for outcome in all_outcomes)
        status = (
            AuditWorkflowStatus.PARTIAL
            if failed or inconclusive
            else AuditWorkflowStatus.COMPLETE
        )
        result = AuditWorkflowResult(
            status=status,
            output_dir=self.output_dir,
            results_dir=self.results_dir,
            message_total=len(message_outcomes),
            message_completed=sum(item.completed for item in message_outcomes),
            message_failed=sum(not item.completed for item in message_outcomes),
            protocol_total=len(protocol_outcomes),
            protocol_completed=sum(item.completed for item in protocol_outcomes),
            protocol_failed=sum(not item.completed for item in protocol_outcomes),
            inconclusive_tasks=inconclusive,
            failed_tasks=failed,
            confirmed_findings=findings,
        )
        self._write_result_index(all_outcomes)
        self._write_summary(result, all_outcomes)
        self._write_coverage(result, all_outcomes)
        self._write_finished(result)
        self._set_workflow_status(result.status)
        return result

    def _write_result_index(self, outcomes: Iterable[_TaskOutcome]) -> None:
        lines: list[str] = []
        for outcome in outcomes:
            task = self._task_snapshot(outcome.task_id)
            record = {
                "task_kind": outcome.kind,
                "task_id": outcome.task_id,
                "execution_status": "completed" if outcome.completed else "failed",
                "protocol_id": task.get("protocol_id"),
                "message_id": task.get("message_id"),
                "direction": task.get("direction"),
                "verdict": outcome.verdict,
                "audit_path": (
                    str(outcome.audit_path.relative_to(self.results_root))
                    if outcome.audit_path is not None
                    else None
                ),
                "error": outcome.error,
            }
            lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
        _atomic_write_text(self.index_path, "\n".join(lines) + ("\n" if lines else ""))

    def _write_summary(
        self, result: AuditWorkflowResult, outcomes: list[_TaskOutcome]
    ) -> None:
        lines = [
            "# Vulnerability Audit Summary",
            "",
            f"- Workflow status: `{result.status.value}`",
            f"- Message audits: {result.message_completed}/{result.message_total} completed",
            f"- Protocol audits: {result.protocol_completed}/{result.protocol_total} completed",
            f"- Confirmed findings: {result.confirmed_findings}",
            f"- Failed tasks: {len(result.failed_tasks)}",
            f"- Inconclusive completed tasks: {len(result.inconclusive_tasks)}",
            "",
        ]
        finding_lines: list[str] = []
        for outcome in outcomes:
            if outcome.audit_path is None or not outcome.audit_path.is_file():
                continue
            try:
                data = json.loads(outcome.audit_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            for finding in data.get("findings", []) if isinstance(data, dict) else []:
                if isinstance(finding, dict):
                    finding_lines.append(
                        f"- `{outcome.task_id}` / `{finding.get('id', 'unknown')}`: "
                        f"{finding.get('title', 'untitled')} "
                        f"({finding.get('severity', 'UNKNOWN')})"
                    )
        lines.extend(["## Confirmed Findings", ""])
        lines.extend(finding_lines or ["No confirmed findings."])
        if result.failed_tasks:
            lines.extend(["", "## Failed Tasks", ""])
            for task_id in result.failed_tasks:
                task = self._task_snapshot(task_id)
                lines.append(f"- `{task_id}`: {task.get('last_error', 'unknown error')}")
        _atomic_write_text(self.summary_path, "\n".join(lines).rstrip() + "\n")

    def _write_coverage(
        self, result: AuditWorkflowResult, outcomes: list[_TaskOutcome]
    ) -> None:
        lines = [
            "# Vulnerability Audit Coverage",
            "",
            "## Execution Coverage",
            "",
            "| Task | Kind | Execution | Verdict | Gap |",
            "|---|---|---|---|---|",
        ]
        for outcome in outcomes:
            gap = outcome.error or (
                "audit conclusion is inconclusive"
                if outcome.verdict == "INCONCLUSIVE"
                else ""
            )
            lines.append(
                "| `{}` | {} | {} | {} | {} |".format(
                    outcome.task_id,
                    outcome.kind,
                    "completed" if outcome.completed else "failed",
                    outcome.verdict or "N/A",
                    _markdown_cell(gap),
                )
            )
        lines.extend(
            [
                "",
                "## Remaining Gaps",
                "",
                (
                    "All scheduled audits completed with conclusive results."
                    if result.status is AuditWorkflowStatus.COMPLETE
                    else "Failed and inconclusive tasks above remain audit blind spots."
                ),
                "",
                "Target repository changes are intentionally not used to invalidate or "
                "restart completed tasks.",
            ]
        )
        _atomic_write_text(self.coverage_path, "\n".join(lines).rstrip() + "\n")

    def _write_finished(self, result: AuditWorkflowResult) -> None:
        _atomic_write_json(
            self.finished_path,
            {
                "schema_version": 1,
                "status": result.status.value,
                "message_total": result.message_total,
                "message_completed": result.message_completed,
                "message_failed": result.message_failed,
                "protocol_total": result.protocol_total,
                "protocol_completed": result.protocol_completed,
                "protocol_failed": result.protocol_failed,
                "confirmed_findings": result.confirmed_findings,
                "failed_tasks": list(result.failed_tasks),
                "inconclusive_tasks": list(result.inconclusive_tasks),
                "finished_at": _utc_now(),
            },
        )

    def _set_workflow_status(self, status: AuditWorkflowStatus) -> None:
        with self._state_lock:
            self._state["workflow_status"] = status.value
            self._save_state_locked()


def _execution_from_result(result: Any) -> _GoalExecution:
    completed = bool(getattr(result, "completed", False))
    goal = getattr(result, "goal", None)
    status = str(getattr(goal, "status", "complete" if completed else "unknown"))
    error = getattr(result, "last_error", None)
    return _GoalExecution(completed, status, _exception_text(error) if error else None)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditOutputValidationError(
                        f"{path.name}:{line_number}: invalid JSON: {exc.msg}"
                    ) from exc
                if not isinstance(value, dict):
                    raise AuditOutputValidationError(
                        f"{path.name}:{line_number}: record must be an object"
                    )
                records.append(value)
    except (OSError, UnicodeError) as exc:
        raise AuditOutputValidationError(f"cannot read {path}: {exc}") from exc
    return records


def _normalize_protocols(records: list[dict[str, Any]]) -> list[_ProtocolRecord]:
    protocols: list[_ProtocolRecord] = []
    seen: set[str] = set()
    for index, raw in enumerate(records, 1):
        protocol_value = raw.get("protocol")
        protocol_id = _first_text(raw, "protocol_id", "protocolId", "id")
        protocol_name = _first_text(raw, "protocol_name", "protocolName", "name")
        if isinstance(protocol_value, dict):
            protocol_id = protocol_id or _first_text(
                protocol_value, "protocol_id", "protocolId", "id"
            )
            protocol_name = protocol_name or _first_text(
                protocol_value, "protocol_name", "protocolName", "name"
            )
        elif isinstance(protocol_value, str):
            protocol_name = protocol_name or protocol_value.strip()
        protocol_id = protocol_id or (_slug(protocol_name) if protocol_name else None)
        protocol_name = protocol_name or protocol_id
        if not protocol_id or not protocol_name:
            raise AuditOutputValidationError(
                f"protocol_inventory.jsonl:{index}: protocol id/name is required"
            )
        normalized_key = _identity_key(protocol_id)
        if normalized_key in seen:
            raise AuditOutputValidationError(
                f"protocol_inventory.jsonl:{index}: duplicate protocol {protocol_id!r}"
            )
        seen.add(normalized_key)
        protocols.append(_ProtocolRecord(protocol_id, protocol_name, raw))
    return protocols


def _normalize_messages(
    records: list[dict[str, Any]], protocols: list[_ProtocolRecord]
) -> list[_MessageRecord]:
    by_key = {_identity_key(item.protocol_id): item for item in protocols}
    for item in protocols:
        by_key.setdefault(_identity_key(item.protocol_name), item)
    messages: list[_MessageRecord] = []
    seen: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(records, 1):
        protocol_value = raw.get("protocol")
        message_value = raw.get("message")
        combined = raw.get("protocol/message")
        protocol_text = _first_text(raw, "protocol_id", "protocolId")
        message_id = _first_text(raw, "message_id", "messageId", "id")
        message_name = _first_text(raw, "message_name", "messageName", "name")
        if isinstance(protocol_value, dict):
            protocol_text = protocol_text or _first_text(
                protocol_value, "protocol_id", "protocolId", "id", "name"
            )
        elif isinstance(protocol_value, str):
            protocol_text = protocol_text or protocol_value.strip()
        if isinstance(message_value, dict):
            message_id = message_id or _first_text(
                message_value, "message_id", "messageId", "id"
            )
            message_name = message_name or _first_text(
                message_value, "message_name", "messageName", "name"
            )
        elif isinstance(message_value, str):
            message_name = message_name or message_value.strip()
        if isinstance(combined, str) and "/" in combined:
            combined_protocol, combined_message = combined.split("/", 1)
            protocol_text = protocol_text or combined_protocol.strip()
            message_name = message_name or combined_message.strip()

        if not protocol_text and len(protocols) == 1:
            protocol_text = protocols[0].protocol_id
        protocol = by_key.get(_identity_key(protocol_text or ""))
        if protocol is None:
            raise AuditOutputValidationError(
                f"message_inventory.jsonl:{index}: unknown protocol {protocol_text!r}"
            )
        message_id = message_id or (_slug(message_name) if message_name else None)
        message_name = message_name or message_id
        if not message_id or not message_name:
            raise AuditOutputValidationError(
                f"message_inventory.jsonl:{index}: message id/name is required"
            )
        direction = _first_text(raw, "direction") or "UNKNOWN"
        direction = direction.strip().upper().replace("-", "_")
        if direction not in {"RX", "TX", "BIDIRECTIONAL", "INTERNAL", "UNKNOWN"}:
            direction = "UNKNOWN"
        key = (
            _identity_key(protocol.protocol_id),
            _identity_key(message_id),
            direction,
        )
        if key in seen:
            raise AuditOutputValidationError(
                f"message_inventory.jsonl:{index}: duplicate message identity"
            )
        seen.add(key)
        messages.append(
            _MessageRecord(
                protocol.protocol_id,
                message_id,
                message_name,
                direction,
                raw,
            )
        )
    return messages


def _first_text(data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _identity_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(character for character in normalized if character.isalnum())


def _slug(value: str | None) -> str:
    normalized = unicodedata.normalize("NFKD", value or "")
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_value).strip("-")
    return (slug or "item")[:48]


def _disambiguate_task_ids(bases: list[str], identities: list[str]) -> list[str]:
    counts: dict[str, int] = {}
    for base in bases:
        counts[base] = counts.get(base, 0) + 1
    return [
        base if counts[base] == 1 else f"{base}--{_short_hash(identity)}"
        for base, identity in zip(bases, identities)
    ]


def _prompt_text(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text.replace("`", "'")[:1000]


def _json_string_content(value: Any) -> str:
    return json.dumps(str(value), ensure_ascii=False)[1:-1]


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hash_json(value: Any) -> str:
    serialized = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return _hash_text(serialized)


def _short_hash(value: str) -> str:
    return _hash_text(value)[:10]


def _sha256_file(path: Path | None) -> str:
    if path is None:
        raise ValueError("path is required")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_json(path: Path, value: Any) -> None:
    _atomic_write_text(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _atomic_write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _exception_text(value: Any) -> str:
    if isinstance(value, BaseException):
        return f"{type(value).__name__}: {value}"
    return str(value)


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
