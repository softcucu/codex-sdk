from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import (
    FIRST_COMPLETED,
    Future,
    ThreadPoolExecutor,
    as_completed,
    wait,
)
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from string import Template
from typing import Any, Callable, Iterable, TextIO
from urllib.parse import unquote, urlparse

from openai_codex import ApprovalMode, Sandbox

from .codeql_database_builder import build_repository_codeql_databases
from .config import OutputMode, ResumePolicy
from .controller import CodexController


_STATE_SCHEMA_VERSION = 1
_MAX_GOAL_OBJECTIVE_CHARS = 4000
_GOAL_OBJECTIVE_PREVIEW_CHARS = 1000
_TERMINAL_GOAL_FAILURES = {"blocked", "budgetLimited"}
_REVIEW_VERDICT_MAP = {
    "problem": "confirmed",
    "no_problem": "false_positive",
    "inconclusive": "inconclusive",
    # Accept review files produced by older workflow runs when resuming.
    "confirmed": "confirmed",
    "false_positive": "false_positive",
}
class CodeQLAuditWorkflowError(RuntimeError):
    """Base failure for the Git-history-driven CodeQL workflow."""


class CodeQLAuditAlreadyRunningError(CodeQLAuditWorkflowError):
    """Raised when another process owns the same workflow directory."""


class CodeQLAuditOutputValidationError(CodeQLAuditWorkflowError):
    """Raised when an LLM Goal completes without valid required artifacts."""


class CodeQLAuditStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class CodeQLAuditWorkflowConfig:
    project_dir: str | Path
    output_dir: str | Path | None = None
    codeql: str = "codeql"
    codex_bin: str | None = None
    model: str | None = None
    history_model: str | None = None
    review_model: str | None = None
    history_token_budget: int | None = None
    review_token_budget: int | None = None
    target_loc: int = 400_000
    max_loc: int = 400_000
    min_loc: int = 100_000
    database_threads: int | None = 0
    database_ram_mb: int | None = None
    scan_threads: int | None = 0
    scan_ram_mb: int | None = None
    scan_workers: int = 2
    history_workers: int = 4
    review_workers: int = 4
    history_max_commits: int | None = None
    max_findings: int | None = None
    max_findings_per_rule: int | None = None
    task_retries: int = 2
    task_retry_delay_seconds: float = 5.0
    exclude_dirs: tuple[str, ...] = ()
    materialize_mode: str = "hardlink"
    resume_policy: ResumePolicy = field(default_factory=ResumePolicy)
    output_mode: OutputMode | str = OutputMode.HUMAN
    output: TextIO | None = field(default=None, compare=False, repr=False)
    history_prompt: str | Path | None = None
    review_prompt: str | Path | None = None

    def __post_init__(self) -> None:
        project = Path(self.project_dir).expanduser().resolve()
        if not project.is_dir():
            raise ValueError(f"project directory does not exist: {project}")
        configured_output = (
            project / "codeql-git-audit"
            if self.output_dir is None
            else Path(self.output_dir).expanduser()
        )
        output = (
            configured_output
            if configured_output.is_absolute()
            else project / configured_output
        ).resolve()
        try:
            output.relative_to(project)
        except ValueError as exc:
            raise ValueError("output_dir must be inside project_dir for Goal sandbox access") from exc
        if self.target_loc <= 0 or self.max_loc <= 0 or self.target_loc > self.max_loc:
            raise ValueError("target_loc/max_loc must be positive and target_loc <= max_loc")
        if self.min_loc < 0:
            raise ValueError("min_loc must be >= 0")
        for name in ("scan_workers", "history_workers", "review_workers"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be >= 1")
        for name in (
            "history_max_commits",
            "max_findings",
            "max_findings_per_rule",
        ):
            value = getattr(self, name)
            if value is not None and value < 1:
                raise ValueError(f"{name} must be >= 1 or None")
        if self.task_retries < 0 or self.task_retry_delay_seconds < 0:
            raise ValueError("task retries and retry delay must be non-negative")
        for name in ("history_token_budget", "review_token_budget"):
            value = getattr(self, name)
            if value is not None and value <= 0:
                raise ValueError(f"{name} must be > 0 or None")
        if self.materialize_mode not in {"hardlink", "copy", "symlink"}:
            raise ValueError("invalid materialize_mode")
        object.__setattr__(self, "project_dir", project)
        object.__setattr__(self, "output_dir", output)
        object.__setattr__(self, "output_mode", OutputMode.parse(self.output_mode))


@dataclass(frozen=True, slots=True)
class CodeQLAuditWorkflowResult:
    status: CodeQLAuditStatus
    output_dir: Path
    database_total: int = 0
    database_completed: int = 0
    commit_total: int = 0
    commit_completed: int = 0
    security_commit_total: int = 0
    rules_total: int = 0
    scan_failed: int = 0
    suspicious_total: int = 0
    reviewed_total: int = 0
    confirmed_total: int = 0
    false_positive_total: int = 0
    inconclusive_total: int = 0
    failed_tasks: tuple[str, ...] = ()

    @property
    def completed(self) -> bool:
        return self.status is CodeQLAuditStatus.COMPLETE

    @property
    def exit_code(self) -> int:
        if self.status is CodeQLAuditStatus.COMPLETE:
            return 0
        if self.status is CodeQLAuditStatus.PARTIAL:
            return 2
        return 1


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    name: str
    description: str
    query_path: Path
    severity: str
    precision: str
    evidence_commits: tuple[str, ...]
    test_path: Path
    positive_cases: tuple[str, ...]
    negative_cases: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _PublishedRule:
    rule: _Rule
    raw_pattern: dict[str, Any]
    path: Path


@dataclass(frozen=True, slots=True)
class _CommitAssessment:
    commit: str
    verdict: str
    rules: tuple[_Rule, ...]
    raw_patterns: tuple[dict[str, Any], ...]
    path: Path


@dataclass(frozen=True, slots=True)
class _HistoryStageResult:
    rules: tuple[_Rule, ...]
    failures: tuple[str, ...]
    commit_total: int
    commit_completed: int
    security_commit_total: int


@dataclass(frozen=True, slots=True)
class _Finding:
    finding_id: str
    rule_id: str
    message: str
    path: str
    start_line: int
    start_column: int
    end_line: int | None
    end_column: int | None
    database_id: str
    sarif_path: Path
    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _Review:
    finding_id: str
    verdict: str
    confidence: str
    summary: str
    path: Path


class _WorkflowFileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle: TextIO | None = None

    def __enter__(self) -> "_WorkflowFileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+", encoding="utf-8")
        try:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CodeQLAuditAlreadyRunningError(
                    f"another CodeQL audit is using {self.path.parent.parent}"
                ) from exc
        except BaseException:
            handle.close()
            raise
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()} started_at={_utc_now()}\n")
        handle.flush()
        self.handle = handle
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        assert self.handle is not None
        try:
            import fcntl

            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()


class CodeQLGitAuditWorkflow:
    """Four-stage Git-history-driven CodeQL audit.

    Database creation and per-commit history Goals run concurrently. As soon as
    databases are complete, each individually published rule starts its scans;
    neither later commits, later rules, nor Goal completion are a barrier.
    Findings from every completed scan immediately enter confirmation Goals.
    """

    def __init__(
        self,
        config: CodeQLAuditWorkflowConfig,
        *,
        _controller_factory: Callable[..., CodexController] = CodexController,
        _database_builder: Callable[..., dict[str, Any]] = build_repository_codeql_databases,
        _subprocess_run: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
        _sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.project_dir = Path(config.project_dir)
        self.output_dir = Path(config.output_dir)
        self.database_dir = self.output_dir / "database-stage"
        self.database_input_path = self.database_dir / "workflow-input.json"
        self.history_dir = self.output_dir / "history-analysis"
        self.queries_dir = self.history_dir / "queries"
        self.ready_rules_dir = self.history_dir / "ready-rules"
        self.commit_results_dir = self.history_dir / "commits"
        self.query_tests_dir = self.history_dir / "query-tests"
        self.patterns_path = self.history_dir / "patterns.json"
        self.scans_dir = self.output_dir / "scans"
        self.findings_dir = self.output_dir / "findings"
        self.reviews_dir = self.output_dir / "reviews"
        self.confirmed_dir = self.output_dir / "confirmed"
        self.workflow_dir = self.output_dir / ".workflow"
        self.logs_dir = self.workflow_dir / "logs"
        self.goal_prompts_dir = self.workflow_dir / "goal-prompts"
        self.state_path = self.workflow_dir / "state.json"
        self.lock_path = self.workflow_dir / "workflow.lock"
        self.summary_path = self.output_dir / "SUMMARY.md"
        self._controller_factory = _controller_factory
        self._database_builder = _database_builder
        self._subprocess_run = _subprocess_run
        self._sleep = _sleep
        self._state_lock = threading.RLock()
        self._output_lock = threading.Lock()
        self._rule_test_lock = threading.Lock()
        self._rule_test_results: dict[str, str | None] = {}
        self._rule_test_inflight: dict[str, threading.Event] = {}
        self._state: dict[str, Any] = {}
        self._output = config.output or sys.stdout

    def run(self, *, force: bool = False) -> CodeQLAuditWorkflowResult:
        self._prepare_directories()
        with _WorkflowFileLock(self.lock_path):
            if force:
                self._clear_force_artifacts()
                self._prepare_directories()
            self._load_state(force=force)
            stage_errors: list[str] = []
            manifest: dict[str, Any] | None = None
            rules: list[_Rule] = []
            pipeline: dict[str, Any] | None = None
            completed_history: _HistoryStageResult | None = None

            with ThreadPoolExecutor(max_workers=2, thread_name_prefix="codeql-prerequisite") as executor:
                database_future = executor.submit(self._database_stage, force)
                history_future = executor.submit(self._history_stage, force)
                try:
                    manifest = database_future.result()
                except KeyboardInterrupt:
                    database_future.cancel()
                    history_future.cancel()
                    raise
                except Exception as exc:
                    stage_errors.append(f"database: {_exception_text(exc)}")

                if manifest is not None:
                    database_entries = self._completed_database_entries(manifest)
                    if database_entries:
                        # Do not wait for history_future here. Ready rules are
                        # discovered and scanned while that Goal keeps running.
                        pipeline = self._scan_and_review_streaming(
                            database_entries,
                            history_future,
                            force=force,
                        )
                        rules = pipeline["rules"]
                    else:
                        stage_errors.append(
                            "database: no valid CodeQL databases were created"
                        )
                if pipeline is None:
                    try:
                        completed_history = history_future.result()
                        rules = list(completed_history.rules)
                        stage_errors.extend(completed_history.failures)
                    except KeyboardInterrupt:
                        history_future.cancel()
                        raise
                    except Exception as exc:
                        stage_errors.append(f"history: {_exception_text(exc)}")

            if manifest is None or pipeline is None:
                total_databases = (
                    len(manifest.get("shards", ())) if manifest is not None else 0
                )
                result = CodeQLAuditWorkflowResult(
                    status=CodeQLAuditStatus.FAILED,
                    output_dir=self.output_dir,
                    database_total=total_databases,
                    database_completed=(
                        len(self._completed_database_entries(manifest))
                        if manifest is not None
                        else 0
                    ),
                    commit_total=(
                        completed_history.commit_total
                        if completed_history is not None
                        else 0
                    ),
                    commit_completed=(
                        completed_history.commit_completed
                        if completed_history is not None
                        else 0
                    ),
                    security_commit_total=(
                        completed_history.security_commit_total
                        if completed_history is not None
                        else 0
                    ),
                    rules_total=len(rules),
                    failed_tasks=tuple(stage_errors),
                )
                self._write_summary(result)
                self._set_workflow_status(result.status)
                return result

            database_entries = self._completed_database_entries(manifest)
            total_databases = len(manifest.get("shards", ()))
            failures = stage_errors + pipeline["failures"]
            if (
                not pipeline["history_completed"]
                or (
                    pipeline["commit_total"] > 0
                    and pipeline["commit_completed"] == 0
                )
            ) and not rules:
                status = CodeQLAuditStatus.FAILED
            elif failures or pipeline["inconclusive"]:
                status = CodeQLAuditStatus.PARTIAL
            else:
                status = CodeQLAuditStatus.COMPLETE
            result = CodeQLAuditWorkflowResult(
                status=status,
                output_dir=self.output_dir,
                database_total=total_databases,
                database_completed=len(database_entries),
                commit_total=pipeline["commit_total"],
                commit_completed=pipeline["commit_completed"],
                security_commit_total=pipeline["security_commit_total"],
                rules_total=len(rules),
                scan_failed=pipeline["scan_failed"],
                suspicious_total=pipeline["suspicious"],
                reviewed_total=pipeline["reviewed"],
                confirmed_total=pipeline["confirmed"],
                false_positive_total=pipeline["false_positive"],
                inconclusive_total=pipeline["inconclusive"],
                failed_tasks=tuple(failures),
            )
            self._write_summary(result)
            self._set_workflow_status(result.status)
            return result

    def _prepare_directories(self) -> None:
        for directory in (
            self.output_dir,
            self.history_dir,
            self.queries_dir,
            self.ready_rules_dir,
            self.commit_results_dir,
            self.query_tests_dir,
            self.scans_dir,
            self.findings_dir,
            self.reviews_dir,
            self.confirmed_dir,
            self.logs_dir,
            self.goal_prompts_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    def _clear_force_artifacts(self) -> None:
        for directory in (
            self.database_dir,
            self.history_dir,
            self.scans_dir,
            self.findings_dir,
            self.reviews_dir,
            self.confirmed_dir,
            self.logs_dir,
            self.goal_prompts_dir,
        ):
            directory.resolve().relative_to(self.output_dir.resolve())
            if directory.is_dir():
                shutil.rmtree(directory)

    def _load_state(self, *, force: bool) -> None:
        with self._state_lock:
            if self.state_path.is_file() and not force:
                try:
                    state = json.loads(self.state_path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    raise CodeQLAuditWorkflowError(f"cannot read workflow state: {exc}") from exc
                if not isinstance(state, dict) or state.get("schema_version") != _STATE_SCHEMA_VERSION:
                    raise CodeQLAuditWorkflowError("invalid or unsupported workflow state")
                self._state = state
                return
            generation = 1
            if self.state_path.is_file():
                try:
                    old = json.loads(self.state_path.read_text(encoding="utf-8"))
                    generation = int(old.get("generation", 0)) + 1
                except (OSError, ValueError, json.JSONDecodeError):
                    generation = 1
            now = _utc_now()
            self._state = {
                "schema_version": _STATE_SCHEMA_VERSION,
                "generation": generation,
                "workflow_status": "running",
                "created_at": now,
                "updated_at": now,
                "tasks": {},
            }
            self._save_state_locked()

    def _save_state_locked(self) -> None:
        self._state["updated_at"] = _utc_now()
        _atomic_json(self.state_path, self._state)

    def _set_workflow_status(self, status: CodeQLAuditStatus) -> None:
        with self._state_lock:
            self._state["workflow_status"] = status.value
            self._save_state_locked()

    def _database_stage(self, force: bool) -> dict[str, Any]:
        manifest_path = self.database_dir / "manifest.json"
        database_input = {
            "git_head": self._git_fingerprint(),
            "target_loc": self.config.target_loc,
            "max_loc": self.config.max_loc,
            "min_loc": self.config.min_loc,
            "exclude_dirs": sorted(self.config.exclude_dirs),
            "materialize_mode": self.config.materialize_mode,
        }
        database_input_hash = _hash_json(database_input)
        input_matches = False
        if self.database_input_path.is_file():
            try:
                previous_input = json.loads(
                    self.database_input_path.read_text(encoding="utf-8")
                )
                input_matches = previous_input.get("input_hash") == database_input_hash
            except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
                pass
        if not force and manifest_path.is_file():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                completed = self._completed_database_entries(manifest)
                if (
                    input_matches
                    and completed
                    and len(completed) == len(manifest.get("shards", ()))
                ):
                    return manifest
            except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
                pass
        rebuild = force or (manifest_path.exists() and not input_matches)
        manifest = self._database_builder(
            self.project_dir,
            self.database_dir,
            codeql=self.config.codeql,
            target_loc=self.config.target_loc,
            max_loc=self.config.max_loc,
            min_loc=self.config.min_loc,
            exclude_dirs=tuple(self.config.exclude_dirs) + (self.output_dir.name,),
            threads=self.config.database_threads,
            ram_mb=self.config.database_ram_mb,
            materialize_mode=self.config.materialize_mode,
            force=rebuild,
            resume=not rebuild,
            progress=self.config.output_mode is not OutputMode.QUIET,
        )
        failed = [
            entry
            for entry in manifest.get("shards", ())
            if str(entry.get("status", "")).startswith("failed")
        ]
        if failed:
            raise CodeQLAuditWorkflowError(f"{len(failed)} database shard(s) failed")
        _atomic_json(
            self.database_input_path,
            {
                "input_hash": database_input_hash,
                "input": database_input,
                "completed_at": _utc_now(),
            },
        )
        return manifest

    def _completed_database_entries(self, manifest: Any) -> list[dict[str, Any]]:
        if not isinstance(manifest, dict) or not isinstance(manifest.get("shards"), list):
            return []
        completed: list[dict[str, Any]] = []
        for entry in manifest["shards"]:
            if not isinstance(entry, dict):
                continue
            status = entry.get("status")
            database = Path(str(entry.get("database", "")))
            if status in {"built", "skipped-existing"} and _valid_codeql_database(database):
                completed.append(entry)
        return completed

    def _history_stage(self, force: bool) -> _HistoryStageResult:
        git_head = self._git_fingerprint()
        commits = self._list_git_commits()
        self._install_history_qlpack()
        assessments: dict[str, _CommitAssessment] = {}
        failures: list[str] = []

        with ThreadPoolExecutor(
            max_workers=self.config.history_workers,
            thread_name_prefix="git-commit-audit",
        ) as executor:
            futures = {
                executor.submit(self._analyze_git_commit, commit, git_head, force): commit
                for commit in commits
            }
            try:
                for future in as_completed(futures):
                    commit = futures[future]
                    try:
                        assessments[commit] = future.result()
                    except Exception as exc:
                        failures.append(
                            f"commit:{commit}: {_exception_text(exc)}"
                        )
            except KeyboardInterrupt:
                for future in futures:
                    future.cancel()
                raise

        raw_patterns: list[dict[str, Any]] = []
        rules: list[_Rule] = []
        seen_rule_ids: set[str] = set()
        security_commits = 0
        for commit in commits:
            assessment = assessments.get(commit)
            if assessment is None:
                continue
            if assessment.verdict == "security_fix":
                security_commits += 1
            for rule, raw in zip(assessment.rules, assessment.raw_patterns):
                if rule.rule_id in seen_rule_ids:
                    failures.append(
                        f"commit:{commit}: duplicate rule id across commits: {rule.rule_id}"
                    )
                    continue
                seen_rule_ids.add(rule.rule_id)
                rules.append(rule)
                raw_patterns.append(raw)

        _atomic_json(
            self.patterns_path,
            {
                "schema_version": 1,
                "git_head": git_head,
                "repository_summary": (
                    f"Programmatically dispatched {len(commits)} commits to independent "
                    f"security-fix Goals; {security_commits} were classified as security fixes."
                ),
                "patterns": raw_patterns,
            },
        )
        _atomic_json(
            self.history_dir / "history-summary.json",
            {
                "schema_version": 1,
                "git_head": git_head,
                "commit_total": len(commits),
                "commit_completed": len(assessments),
                "security_commit_total": security_commits,
                "rules_total": len(rules),
                "failures": failures,
                "completed_at": _utc_now(),
            },
        )
        validated_rules = self._validate_history_output(expected_git_head=git_head)
        return _HistoryStageResult(
            rules=tuple(validated_rules),
            failures=tuple(failures),
            commit_total=len(commits),
            commit_completed=len(assessments),
            security_commit_total=security_commits,
        )

    def _list_git_commits(self) -> list[str]:
        command = [
            "git",
            "-C",
            str(self.project_dir),
            "rev-list",
            "--date-order",
        ]
        if self.config.history_max_commits is not None:
            command.append(f"--max-count={self.config.history_max_commits}")
        command.append("HEAD")
        completed = self._subprocess_run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise CodeQLAuditWorkflowError(
                f"cannot enumerate Git commits: {completed.stderr.strip()}"
            )
        commits = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        if not commits:
            raise CodeQLAuditWorkflowError("Git repository has no commits to analyze")
        return commits

    def _install_history_qlpack(self) -> None:
        _atomic_text(
            self.history_dir / "qlpack.yml",
            "name: local/git-history-audit\n"
            "version: 0.0.1\n"
            "dependencies:\n"
            '  codeql/cpp-all: "*"\n',
        )

    def _analyze_git_commit(
        self, commit: str, git_head: str, force: bool
    ) -> _CommitAssessment:
        report_path = self.commit_results_dir / f"{commit}.json"
        if not force:
            try:
                return self._validate_commit_assessment(commit, git_head, report_path)
            except CodeQLAuditOutputValidationError:
                pass
        prompt = Template(
            self._read_prompt(
                "git_history_codeql_rules_goal.txt", self.config.history_prompt
            )
        ).substitute(
            commit=commit,
            git_head=git_head,
            commit_report_path=self._project_path(report_path),
            queries_dir=self._project_path(self.queries_dir),
            query_tests_dir=self._project_path(self.query_tests_dir),
            ready_rules_dir=self._project_path(self.ready_rules_dir),
            output_dir=self._project_path(self.history_dir),
            codeql_executable=self.config.codeql,
        )
        self._run_goal(
            f"git-commit--{commit}",
            prompt,
            model=self.config.history_model or self.config.model,
            token_budget=self.config.history_token_budget,
            validate=lambda: self._validate_commit_assessment(
                commit, git_head, report_path
            ),
            force=force,
        )
        return self._validate_commit_assessment(commit, git_head, report_path)

    def _validate_commit_assessment(
        self, commit: str, git_head: str, report_path: Path
    ) -> _CommitAssessment:
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CodeQLAuditOutputValidationError(
                f"invalid commit assessment {report_path.name}: {exc}"
            ) from exc
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            raise CodeQLAuditOutputValidationError(
                f"commit assessment {commit} must use schema_version=1"
            )
        if data.get("commit") != commit or data.get("git_head") != git_head:
            raise CodeQLAuditOutputValidationError(
                f"commit assessment identity mismatch for {commit}"
            )
        verdict = str(data.get("verdict", ""))
        if verdict not in {"security_fix", "not_security_fix", "inconclusive"}:
            raise CodeQLAuditOutputValidationError(
                f"invalid security-fix verdict for {commit}: {verdict!r}"
            )
        _nonempty_string(data.get("summary"), f"{commit}.summary")
        vulnerabilities = data.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise CodeQLAuditOutputValidationError(
                f"{commit}.vulnerabilities must be an array"
            )
        if verdict == "security_fix" and not vulnerabilities:
            raise CodeQLAuditOutputValidationError(
                f"security-fix commit {commit} must describe at least one vulnerability"
            )
        if verdict != "security_fix" and vulnerabilities:
            raise CodeQLAuditOutputValidationError(
                f"non-security verdict for {commit} cannot contain vulnerabilities"
            )

        rule_ids: list[str] = []
        seen_rule_ids: set[str] = set()
        for index, vulnerability in enumerate(vulnerabilities):
            if not isinstance(vulnerability, dict):
                raise CodeQLAuditOutputValidationError(
                    f"{commit}.vulnerabilities[{index}] must be an object"
                )
            for field_name in ("id", "title", "summary", "security_impact"):
                _nonempty_string(
                    vulnerability.get(field_name),
                    f"{commit}.vulnerabilities[{index}].{field_name}",
                )
            evidence = vulnerability.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                raise CodeQLAuditOutputValidationError(
                    f"{commit}.vulnerabilities[{index}] requires diff evidence"
                )
            raw_rules = vulnerability.get("rules")
            if not isinstance(raw_rules, list) or not raw_rules:
                raise CodeQLAuditOutputValidationError(
                    f"{commit}.vulnerabilities[{index}] requires at least one CodeQL rule"
                )
            for rule_index, raw_rule in enumerate(raw_rules):
                label = f"{commit}.vulnerabilities[{index}].rules[{rule_index}]"
                if not isinstance(raw_rule, dict):
                    raise CodeQLAuditOutputValidationError(f"{label} is not an object")
                rule_id = str(raw_rule.get("id", ""))
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", rule_id):
                    raise CodeQLAuditOutputValidationError(
                        f"invalid or missing rule id in {label}: {rule_id!r}"
                    )
                if rule_id in seen_rule_ids:
                    raise CodeQLAuditOutputValidationError(
                        f"duplicate rule id in commit {commit}: {rule_id}"
                    )
                seen_rule_ids.add(rule_id)
                rule_ids.append(rule_id)

        published = self._ready_rules_for_commit(commit, git_head)
        published_by_id = {item.rule.rule_id: item for item in published}
        if set(published_by_id) != seen_rule_ids:
            raise CodeQLAuditOutputValidationError(
                f"ready rules for {commit} do not exactly match its commit assessment"
            )
        rules: list[_Rule] = []
        raw_patterns: list[dict[str, Any]] = []
        canonical_patterns: dict[str, dict[str, Any]] = {}
        for rule_id in rule_ids:
            published_rule = published_by_id[rule_id]
            rule = published_rule.rule
            if commit not in rule.evidence_commits:
                raise CodeQLAuditOutputValidationError(
                    f"rule {rule.rule_id} does not cite its source commit {commit}"
                )
            self._ensure_rule_tests_pass(rule)
            canonical = dict(published_rule.raw_pattern)
            rules.append(rule)
            raw_patterns.append(canonical)
            canonical_patterns[rule_id] = canonical

        # A ready marker is published only after its query and tests are complete,
        # so it is the canonical representation of a rule.  The Goal also writes a
        # copy into the commit report; normalize that copy here instead of failing
        # the entire commit because independently rendered JSON drifted.
        report_changed = False
        for vulnerability in vulnerabilities:
            normalized_rules: list[dict[str, Any]] = []
            for raw_rule in vulnerability.get("rules", ()):
                canonical = canonical_patterns[str(raw_rule["id"])]
                normalized_rules.append(canonical)
                if raw_rule != canonical:
                    report_changed = True
            vulnerability["rules"] = normalized_rules
        if report_changed:
            _atomic_json(report_path, data)
        return _CommitAssessment(
            commit=commit,
            verdict=verdict,
            rules=tuple(rules),
            raw_patterns=tuple(raw_patterns),
            path=report_path,
        )

    def _ready_rules_for_commit(
        self, commit: str, git_head: str
    ) -> list[_PublishedRule]:
        rules: list[_PublishedRule] = []
        seen: set[str] = set()
        for path in sorted(self.ready_rules_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if (
                not isinstance(data, dict)
                or data.get("schema_version") != 1
                or data.get("status") != "ready"
                or data.get("git_head") != git_head
                or data.get("source_commit") != commit
            ):
                continue
            raw_pattern = data.get("pattern")
            rule = self._validate_rule(raw_pattern, f"ready rule {path.name}")
            if rule.rule_id in seen:
                raise CodeQLAuditOutputValidationError(
                    f"duplicate ready rule for {commit}: {rule.rule_id}"
                )
            seen.add(rule.rule_id)
            rules.append(
                _PublishedRule(
                    rule=rule,
                    raw_pattern=dict(raw_pattern),
                    path=path,
                )
            )
        return rules

    def _git_fingerprint(self) -> str:
        completed = self._subprocess_run(
            ["git", "-C", str(self.project_dir), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise CodeQLAuditWorkflowError("target project is not a readable Git repository")
        return completed.stdout.strip()

    def _validate_history_output(
        self, *, expected_git_head: str | None = None
    ) -> list[_Rule]:
        try:
            data = json.loads(self.patterns_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CodeQLAuditOutputValidationError(f"invalid patterns.json: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            raise CodeQLAuditOutputValidationError("patterns.json must use schema_version=1")
        if expected_git_head is not None and data.get("git_head") != expected_git_head:
            raise CodeQLAuditOutputValidationError(
                "patterns.json git_head does not match the current repository HEAD"
            )
        raw_patterns = data.get("patterns")
        if not isinstance(raw_patterns, list):
            raise CodeQLAuditOutputValidationError("patterns.json patterns must be an array")
        qlpack = self.history_dir / "qlpack.yml"
        if raw_patterns:
            if not qlpack.is_file():
                raise CodeQLAuditOutputValidationError("non-empty rules require qlpack.yml")
            qlpack_text = qlpack.read_text(encoding="utf-8")
            if "codeql/cpp-all" not in qlpack_text:
                raise CodeQLAuditOutputValidationError(
                    "qlpack.yml must depend on codeql/cpp-all"
                )

        rules: list[_Rule] = []
        seen: set[str] = set()
        for index, raw in enumerate(raw_patterns):
            rule = self._validate_rule(raw, f"pattern {index}")
            rule_id = rule.rule_id
            if rule_id in seen:
                raise CodeQLAuditOutputValidationError(f"duplicate rule id: {rule_id}")
            seen.add(rule_id)
            rules.append(rule)
        return rules

    def _validate_rule(self, raw: Any, label: str) -> _Rule:
        if not isinstance(raw, dict):
            raise CodeQLAuditOutputValidationError(f"{label} is not an object")
        required = {
            "id",
            "name",
            "description",
            "query_path",
            "severity",
            "precision",
            "evidence_commits",
            "evidence",
            "tests",
        }
        if not required.issubset(raw):
            raise CodeQLAuditOutputValidationError(f"{label} misses required fields")
        rule_id = str(raw["id"])
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", rule_id):
            raise CodeQLAuditOutputValidationError(f"unsafe rule id: {rule_id!r}")
        query_relative = Path(str(raw["query_path"]))
        if query_relative.is_absolute() or ".." in query_relative.parts:
            raise CodeQLAuditOutputValidationError(f"unsafe query path for {rule_id}")
        query_path = (self.history_dir / query_relative).resolve()
        try:
            query_path.relative_to(self.queries_dir.resolve())
        except ValueError as exc:
            raise CodeQLAuditOutputValidationError(
                f"query for {rule_id} must be below queries/"
            ) from exc
        if query_path.suffix != ".ql" or not query_path.is_file():
            raise CodeQLAuditOutputValidationError(f"missing .ql query for {rule_id}")
        query_text = query_path.read_text(encoding="utf-8")
        if "select" not in query_text.casefold() or "from" not in query_text.casefold():
            raise CodeQLAuditOutputValidationError(f"query {query_path.name} is incomplete")
        metadata_id = re.search(r"(?m)^\s*\*?\s*@id\s+(\S+)\s*$", query_text)
        if metadata_id is None or metadata_id.group(1) != rule_id:
            raise CodeQLAuditOutputValidationError(
                f"query {query_path.name} @id must equal {rule_id}"
            )
        commits = raw["evidence_commits"]
        if (
            not isinstance(commits, list)
            or not commits
            or not all(isinstance(item, str) and item.strip() for item in commits)
        ):
            raise CodeQLAuditOutputValidationError(
                f"invalid evidence_commits for {rule_id}"
            )
        evidence = raw["evidence"]
        if not isinstance(evidence, list) or not evidence:
            raise CodeQLAuditOutputValidationError(
                f"missing historical evidence for {rule_id}"
            )
        tests = raw["tests"]
        if not isinstance(tests, dict):
            raise CodeQLAuditOutputValidationError(
                f"rule {rule_id} tests must be an object"
            )
        test_relative = Path(str(tests.get("test_path", "")))
        if (
            not test_relative.parts
            or test_relative.is_absolute()
            or ".." in test_relative.parts
        ):
            raise CodeQLAuditOutputValidationError(
                f"unsafe query test path for {rule_id}"
            )
        test_path = (self.history_dir / test_relative).resolve()
        try:
            test_path.relative_to(self.query_tests_dir.resolve())
        except ValueError as exc:
            raise CodeQLAuditOutputValidationError(
                f"query tests for {rule_id} must be below query-tests/"
            ) from exc
        if not test_path.is_dir():
            raise CodeQLAuditOutputValidationError(
                f"missing query test directory for {rule_id}: {test_relative}"
            )
        positive_cases = _validate_case_files(
            tests.get("positive_cases"), test_path, rule_id, "positive_cases"
        )
        negative_cases = _validate_case_files(
            tests.get("negative_cases"), test_path, rule_id, "negative_cases"
        )
        if set(positive_cases) & set(negative_cases):
            raise CodeQLAuditOutputValidationError(
                f"positive and negative cases overlap for {rule_id}"
            )
        qlref_path = test_path / "test.qlref"
        expected_path = test_path / "test.expected"
        if not expected_path.is_file():
            raise CodeQLAuditOutputValidationError(
                f"query tests for {rule_id} require test.expected"
            )
        expected_qlref = query_relative.as_posix()
        with self._rule_test_lock:
            try:
                qlref_text = qlref_path.read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError):
                qlref_text = ""
            if qlref_text != expected_qlref:
                _atomic_text(qlref_path, expected_qlref + "\n")
                self._emit_status(
                    f"[codeql-test] normalized test.qlref for {rule_id}"
                )
        expected_text = expected_path.read_text(encoding="utf-8")
        if not all(case in expected_text for case in positive_cases):
            raise CodeQLAuditOutputValidationError(
                f"test.expected for {rule_id} must contain every positive case"
            )
        if any(case in expected_text for case in negative_cases):
            raise CodeQLAuditOutputValidationError(
                f"test.expected for {rule_id} must not contain negative cases"
            )
        return _Rule(
            rule_id=rule_id,
            name=_nonempty_string(raw["name"], f"{rule_id}.name"),
            description=_nonempty_string(raw["description"], f"{rule_id}.description"),
            query_path=query_path,
            severity=_nonempty_string(raw["severity"], f"{rule_id}.severity"),
            precision=_nonempty_string(raw["precision"], f"{rule_id}.precision"),
            evidence_commits=tuple(commits),
            test_path=test_path,
            positive_cases=positive_cases,
            negative_cases=negative_cases,
        )

    def _discover_ready_rules(
        self, *, expected_git_head: str, allowed_commits: set[str]
    ) -> tuple[list[_Rule], list[str]]:
        rules: list[_Rule] = []
        errors: list[str] = []
        seen: set[str] = set()
        qlpack = self.history_dir / "qlpack.yml"
        try:
            qlpack_ready = qlpack.is_file() and "codeql/cpp-all" in qlpack.read_text(
                encoding="utf-8"
            )
        except (OSError, UnicodeError):
            qlpack_ready = False
        for path in sorted(self.ready_rules_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if (
                    not isinstance(data, dict)
                    or data.get("schema_version") != 1
                    or data.get("status") != "ready"
                ):
                    raise CodeQLAuditOutputValidationError(
                        "marker must use schema_version=1 and status=ready"
                    )
                if data.get("git_head") != expected_git_head:
                    continue
                source_commit = data.get("source_commit")
                if not isinstance(source_commit, str) or not re.fullmatch(
                    r"[0-9a-fA-F]{4,64}", source_commit
                ):
                    raise CodeQLAuditOutputValidationError(
                        "ready rule must identify one source_commit"
                    )
                if source_commit not in allowed_commits:
                    continue
                if not qlpack_ready:
                    raise CodeQLAuditOutputValidationError(
                        "rule was published before a valid qlpack.yml"
                    )
                rule = self._validate_rule(data.get("pattern"), f"ready rule {path.name}")
                if rule.rule_id in seen:
                    raise CodeQLAuditOutputValidationError(
                        f"duplicate ready rule id: {rule.rule_id}"
                    )
                seen.add(rule.rule_id)
                rules.append(rule)
            except (OSError, UnicodeError, json.JSONDecodeError, CodeQLAuditOutputValidationError) as exc:
                errors.append(f"{path.name}: {exc}")
        return rules, errors

    def _ensure_rule_tests_pass(self, rule: _Rule) -> None:
        signature = _rule_test_signature(rule)
        while True:
            with self._rule_test_lock:
                if signature in self._rule_test_results:
                    cached_error = self._rule_test_results[signature]
                    if cached_error is not None:
                        raise CodeQLAuditOutputValidationError(cached_error)
                    return
                event = self._rule_test_inflight.get(signature)
                if event is None:
                    event = threading.Event()
                    self._rule_test_inflight[signature] = event
                    owner = True
                else:
                    owner = False
            if owner:
                break
            event.wait()

        try:
            codeql = _resolve_executable(self.config.codeql)
            command = [
                codeql,
                "test",
                "run",
                str(rule.test_path),
                f"--search-path={self.history_dir}",
            ]
            if self.config.scan_threads is not None:
                command.append(f"--threads={self.config.scan_threads}")
            if self.config.scan_ram_mb is not None:
                command.append(f"--ram={self.config.scan_ram_mb}")
            self._emit_status(f"[codeql-test] started {rule.rule_id}")
            completed = self._subprocess_run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            output = str(completed.stdout or "")
            test_log_path = self.logs_dir / (
                f"codeql-test--{_safe_name(rule.rule_id)}--{signature[:10]}.log"
            )
            _atomic_text(test_log_path, output)
            if completed.returncode != 0:
                error = (
                    f"CodeQL tests failed for {rule.rule_id}: {output[-2000:]}"
                )
                with self._rule_test_lock:
                    self._rule_test_results[signature] = error
                self._emit_status(
                    f"[codeql-test] failed {rule.rule_id}; log={test_log_path}"
                )
                raise CodeQLAuditOutputValidationError(error)
            with self._rule_test_lock:
                self._rule_test_results[signature] = None
            self._emit_status(f"[codeql-test] passed {rule.rule_id}")
        finally:
            with self._rule_test_lock:
                finished = self._rule_test_inflight.pop(signature, None)
                if finished is not None:
                    finished.set()

    def _scan_and_review_streaming(
        self,
        databases: list[dict[str, Any]],
        history_future: Future[_HistoryStageResult],
        *,
        force: bool,
    ) -> dict[str, Any]:
        totals: dict[str, Any] = {
            "scan_failed": 0,
            "suspicious": 0,
            "reviewed": 0,
            "confirmed": 0,
            "false_positive": 0,
            "inconclusive": 0,
            "failures": [],
            "history_completed": False,
            "commit_total": 0,
            "commit_completed": 0,
            "security_commit_total": 0,
            "rules": [],
        }
        expected_git_head = self._git_fingerprint()
        allowed_commits = set(self._list_git_commits())
        known_files = self._known_repository_files()
        available_rules: dict[str, _Rule] = {}
        ready_signatures: dict[str, str] = {}
        rule_test_errors: dict[str, str] = {}
        scheduled: set[tuple[str, str]] = set()
        seen_findings: set[str] = set()
        per_rule: dict[str, int] = {}
        scan_futures: dict[
            Future[list[_Finding]], tuple[dict[str, Any], _Rule]
        ] = {}
        review_futures: dict[Future[_Review], _Finding] = {}
        rule_test_futures: dict[Future[None], _Rule] = {}
        history_resolved = False
        reported_rule_changes: set[str] = set()

        with ThreadPoolExecutor(
            max_workers=self.config.review_workers,
            thread_name_prefix="codeql-review",
        ) as review_executor, ThreadPoolExecutor(
            max_workers=self.config.scan_workers,
            thread_name_prefix="codeql-scan",
        ) as scan_executor, ThreadPoolExecutor(
            max_workers=self.config.scan_workers,
            thread_name_prefix="codeql-rule-test",
        ) as rule_test_executor:
            try:
                while True:
                    ready_rules, ready_errors = self._discover_ready_rules(
                        expected_git_head=expected_git_head,
                        allowed_commits=allowed_commits,
                    )
                    for rule in ready_rules:
                        signature = _rule_signature(rule)
                        previous = ready_signatures.get(rule.rule_id)
                        if previous is None:
                            ready_signatures[rule.rule_id] = signature
                            future = rule_test_executor.submit(
                                self._ensure_rule_tests_pass, rule
                            )
                            rule_test_futures[future] = rule
                        elif (
                            previous != signature
                            and rule.rule_id not in reported_rule_changes
                        ):
                            totals["failures"].append(
                                f"ready-rule:{rule.rule_id}: query or metadata changed after publication"
                            )
                            reported_rule_changes.add(rule.rule_id)

                    if history_future.done() and not history_resolved:
                        history_resolved = True
                        try:
                            history_result = history_future.result()
                        except Exception as exc:
                            totals["failures"].append(
                                f"history: {_exception_text(exc)}"
                            )
                            final_rules = []
                        else:
                            totals["history_completed"] = True
                            totals["commit_total"] = history_result.commit_total
                            totals["commit_completed"] = history_result.commit_completed
                            totals["security_commit_total"] = (
                                history_result.security_commit_total
                            )
                            totals["failures"].extend(history_result.failures)
                            final_rules = list(history_result.rules)
                            final_ids = {rule.rule_id for rule in final_rules}
                            for rule_id in sorted(set(available_rules) - final_ids):
                                totals["failures"].append(
                                    f"history:{rule_id}: published ready rule missing from final patterns"
                                )
                            for rule in final_rules:
                                ready_signature = ready_signatures.get(rule.rule_id)
                                final_signature = _rule_signature(rule)
                                if (
                                    ready_signature is not None
                                    and ready_signature != final_signature
                                    and rule.rule_id not in reported_rule_changes
                                ):
                                    totals["failures"].append(
                                        f"history:{rule.rule_id}: final rule differs from published ready rule"
                                    )
                                    reported_rule_changes.add(rule.rule_id)
                                available_rules.setdefault(rule.rule_id, rule)
                            if ready_errors:
                                totals["failures"].extend(
                                    f"ready-rule:{error}" for error in ready_errors
                                )

                    for future in [
                        item for item in rule_test_futures if item.done()
                    ]:
                        rule = rule_test_futures.pop(future)
                        try:
                            future.result()
                        except Exception as exc:
                            rule_test_errors[rule.rule_id] = _exception_text(exc)
                        else:
                            rule_test_errors.pop(rule.rule_id, None)
                            available_rules[rule.rule_id] = rule

                    for rule in list(available_rules.values()):
                        query_hash = _hash_files([rule.query_path])
                        for entry in databases:
                            shard_id = str(entry["shard_id"])
                            pair = (shard_id, rule.rule_id)
                            if pair in scheduled:
                                continue
                            scheduled.add(pair)
                            future = scan_executor.submit(
                                self._scan_rule_database,
                                entry,
                                rule,
                                query_hash,
                                known_files,
                                force,
                            )
                            scan_futures[future] = (entry, rule)

                    for scan_future in [
                        future for future in scan_futures if future.done()
                    ]:
                        entry, rule = scan_futures.pop(scan_future)
                        shard_id = str(entry.get("shard_id", "unknown"))
                        try:
                            findings = scan_future.result()
                        except Exception as exc:
                            totals["scan_failed"] += 1
                            totals["failures"].append(
                                f"scan:{shard_id}:{rule.rule_id}: {_exception_text(exc)}"
                            )
                            continue
                        for finding in findings:
                            if finding.finding_id in seen_findings:
                                continue
                            if (
                                self.config.max_findings is not None
                                and totals["suspicious"] >= self.config.max_findings
                            ):
                                continue
                            count = per_rule.get(finding.rule_id, 0)
                            if (
                                self.config.max_findings_per_rule is not None
                                and count >= self.config.max_findings_per_rule
                            ):
                                continue
                            seen_findings.add(finding.finding_id)
                            per_rule[finding.rule_id] = count + 1
                            totals["suspicious"] += 1
                            self._write_finding(finding)
                            future = review_executor.submit(
                                self._review_finding, finding, rule, force
                            )
                            review_futures[future] = finding

                    for future in [
                        item for item in review_futures if item.done()
                    ]:
                        finding = review_futures.pop(future)
                        try:
                            review = future.result()
                        except Exception as exc:
                            totals["inconclusive"] += 1
                            totals["failures"].append(
                                f"review:{finding.finding_id}: {_exception_text(exc)}"
                            )
                            continue
                        totals["reviewed"] += 1
                        totals[review.verdict] += 1

                    if (
                        history_resolved
                        and not rule_test_futures
                        and not scan_futures
                        and not review_futures
                    ):
                        break

                    pending: set[Future[Any]] = (
                        set(rule_test_futures)
                        | set(scan_futures)
                        | set(review_futures)
                    )
                    if not history_resolved:
                        pending.add(history_future)
                    if pending:
                        wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
                    else:
                        self._sleep(0.2)
            except KeyboardInterrupt:
                for future in rule_test_futures:
                    future.cancel()
                for future in scan_futures:
                    future.cancel()
                for future in review_futures:
                    future.cancel()
                raise

        totals["rules"] = sorted(
            available_rules.values(), key=lambda rule: rule.rule_id
        )
        totals["failures"].extend(
            f"ready-rule:{rule_id}: {error}"
            for rule_id, error in sorted(rule_test_errors.items())
        )
        return totals

    def _scan_rule_database(
        self,
        entry: dict[str, Any],
        rule: _Rule,
        query_hash: str,
        known_files: set[str],
        force: bool,
    ) -> list[_Finding]:
        shard_id = str(entry["shard_id"])
        database = Path(str(entry["database"]))
        pair_digest = hashlib.sha256(
            f"{shard_id}\0{rule.rule_id}".encode("utf-8")
        ).hexdigest()[:10]
        scan_name = (
            f"{_safe_name(shard_id)}--{_safe_name(rule.rule_id)}--{pair_digest}"
        )
        sarif_path = self.scans_dir / f"{scan_name}.sarif"
        metadata_path = self.scans_dir / f"{scan_name}.scan.json"
        scan_key = _hash_json(
            {
                "database": str(database),
                "database_mtime_ns": database.stat().st_mtime_ns,
                "query_hash": query_hash,
                "rule_id": rule.rule_id,
                "shard": shard_id,
            }
        )
        if not force and sarif_path.is_file() and metadata_path.is_file():
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                if (
                    metadata.get("scan_key") == scan_key
                    and metadata.get("status", "completed") == "completed"
                ):
                    return self._parse_sarif(sarif_path, shard_id, known_files)
            except (OSError, UnicodeError, json.JSONDecodeError):
                pass

        codeql = _resolve_executable(self.config.codeql)
        command = [
            codeql,
            "database",
            "analyze",
            str(database),
            str(rule.query_path),
            "--format=sarifv2.1.0",
            f"--output={sarif_path}",
            "--rerun",
        ]
        if self.config.scan_threads is not None:
            command.append(f"--threads={self.config.scan_threads}")
        if self.config.scan_ram_mb is not None:
            command.append(f"--ram={self.config.scan_ram_mb}")
        _atomic_json(
            metadata_path,
            {
                "scan_key": scan_key,
                "status": "running",
                "shard_id": shard_id,
                "rule_id": rule.rule_id,
                "started_at": _utc_now(),
            },
        )
        self._emit_status(
            f"[codeql-scan] started shard={shard_id} rule={rule.rule_id}"
        )
        scan_log_path = self.scans_dir / f"{scan_name}.log"
        try:
            completed = self._subprocess_run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            output = str(completed.stdout or "")
            _atomic_text(scan_log_path, output)
            if completed.returncode != 0:
                raise CodeQLAuditWorkflowError(
                    f"CodeQL returned {completed.returncode}: {output[-2000:]}"
                )
            findings = self._parse_sarif(sarif_path, shard_id, known_files)
        except Exception as exc:
            _atomic_json(
                metadata_path,
                {
                    "scan_key": scan_key,
                    "status": "failed",
                    "shard_id": shard_id,
                    "rule_id": rule.rule_id,
                    "failed_at": _utc_now(),
                    "error": _exception_text(exc),
                    "log_path": self._project_path(scan_log_path),
                },
            )
            self._emit_status(
                f"[codeql-scan] failed shard={shard_id} rule={rule.rule_id}; "
                f"log={scan_log_path}"
            )
            raise
        _atomic_json(
            metadata_path,
            {
                "scan_key": scan_key,
                "status": "completed",
                "shard_id": shard_id,
                "rule_id": rule.rule_id,
                "finding_count": len(findings),
                "completed_at": _utc_now(),
                "log_path": self._project_path(scan_log_path),
            },
        )
        self._emit_status(
            f"[codeql-scan] completed shard={shard_id} rule={rule.rule_id} "
            f"findings={len(findings)}"
        )
        return findings

    def _parse_sarif(
        self, sarif_path: Path, database_id: str, known_files: set[str]
    ) -> list[_Finding]:
        try:
            data = json.loads(sarif_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CodeQLAuditWorkflowError(f"invalid SARIF {sarif_path}: {exc}") from exc
        findings: list[_Finding] = []
        for run in data.get("runs", ()) if isinstance(data, dict) else ():
            if not isinstance(run, dict):
                continue
            for result in run.get("results", ()):
                if not isinstance(result, dict):
                    continue
                rule_id = str(result.get("ruleId") or "unknown-rule")
                message_data = result.get("message", {})
                message = str(message_data.get("text") or message_data.get("markdown") or "")
                locations = result.get("locations") or []
                location = locations[0] if locations and isinstance(locations[0], dict) else {}
                physical = location.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})
                path = _normalize_sarif_path(str(artifact.get("uri", "")), known_files)
                start_line = _positive_or_default(region.get("startLine"), 1)
                start_column = _positive_or_default(region.get("startColumn"), 1)
                end_line = _optional_positive(region.get("endLine"))
                end_column = _optional_positive(region.get("endColumn"))
                identity = {
                    "rule_id": rule_id,
                    "message": message,
                    "path": path,
                    "start_line": start_line,
                    "start_column": start_column,
                }
                finding_id = hashlib.sha256(
                    json.dumps(identity, sort_keys=True).encode("utf-8")
                ).hexdigest()[:20]
                findings.append(
                    _Finding(
                        finding_id=finding_id,
                        rule_id=rule_id,
                        message=message,
                        path=path,
                        start_line=start_line,
                        start_column=start_column,
                        end_line=end_line,
                        end_column=end_column,
                        database_id=database_id,
                        sarif_path=sarif_path,
                        raw=result,
                    )
                )
        return findings

    def _known_repository_files(self) -> set[str]:
        known: set[str] = set()
        filelists = self.database_dir / "filelists"
        for path in filelists.glob("*.files.txt"):
            try:
                known.update(
                    line.strip()
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                )
            except OSError:
                continue
        return known

    def _write_finding(self, finding: _Finding) -> None:
        _atomic_json(
            self.findings_dir / f"{finding.finding_id}.json",
            {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "message": finding.message,
                "path": finding.path,
                "start_line": finding.start_line,
                "start_column": finding.start_column,
                "end_line": finding.end_line,
                "end_column": finding.end_column,
                "database_id": finding.database_id,
                "sarif_path": self._project_path(finding.sarif_path),
            },
        )

    def _review_finding(
        self, finding: _Finding, rule: _Rule, force: bool
    ) -> _Review:
        review_path = self.reviews_dir / f"{finding.finding_id}.json"
        if not force and review_path.is_file():
            try:
                review = self._validate_review(finding, review_path)
                self._sync_confirmed_review(review)
                return review
            except CodeQLAuditOutputValidationError:
                pass
        prompt = Template(
            self._read_prompt("codeql_finding_review_goal.txt", self.config.review_prompt)
        ).substitute(
            finding_id=finding.finding_id,
            review_path=self._project_path(review_path),
            source_path=finding.path,
            source_line=finding.start_line,
            problem_name=rule.name,
            problem_description=rule.description,
            candidate_description=finding.message,
        )
        self._run_goal(
            f"review--{finding.finding_id}",
            prompt,
            model=self.config.review_model or self.config.model,
            token_budget=self.config.review_token_budget,
            validate=lambda: self._validate_review(finding, review_path),
            force=force,
        )
        review = self._validate_review(finding, review_path)
        self._sync_confirmed_review(review)
        return review

    def _sync_confirmed_review(self, review: _Review) -> None:
        destination = self.confirmed_dir / review.path.name
        if review.verdict == "confirmed":
            shutil.copy2(review.path, destination)
        elif destination.is_file():
            destination.unlink()

    def _validate_review(self, finding: _Finding, path: Path) -> _Review:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CodeQLAuditOutputValidationError(f"invalid review {path.name}: {exc}") from exc
        if not isinstance(data, dict) or data.get("finding_id") != finding.finding_id:
            raise CodeQLAuditOutputValidationError("review finding_id mismatch")
        output_verdict = str(data.get("verdict", ""))
        verdict = _REVIEW_VERDICT_MAP.get(output_verdict)
        if verdict is None:
            raise CodeQLAuditOutputValidationError(
                f"invalid review verdict: {output_verdict!r}"
            )
        if output_verdict in {"problem", "no_problem", "inconclusive"}:
            _nonempty_string(data.get("problem_type"), "review.problem_type")
            cwe_ids = data.get("cwe_ids")
            if not isinstance(cwe_ids, list) or any(
                not isinstance(item, str) or not re.fullmatch(r"CWE-[1-9][0-9]*", item)
                for item in cwe_ids
            ):
                raise CodeQLAuditOutputValidationError(
                    "review cwe_ids must contain valid CWE identifiers"
                )
        confidence = str(data.get("confidence", ""))
        if confidence not in {"high", "medium", "low"}:
            raise CodeQLAuditOutputValidationError("invalid review confidence")
        summary = _nonempty_string(data.get("summary"), "review.summary")
        evidence = data.get("evidence")
        if not isinstance(evidence, list):
            raise CodeQLAuditOutputValidationError("review evidence must be an array")
        if verdict == "confirmed" and not evidence:
            raise CodeQLAuditOutputValidationError("problem review requires code evidence")
        return _Review(finding.finding_id, verdict, confidence, summary, path)

    def _run_goal(
        self,
        task_id: str,
        objective: str,
        *,
        model: str | None,
        token_budget: int | None,
        validate: Callable[[], Any],
        force: bool,
    ) -> None:
        objective = self._dispatchable_goal_objective(task_id, objective)
        objective_hash = hashlib.sha256(objective.encode("utf-8")).hexdigest()
        if not force:
            try:
                validate()
                with self._state_lock:
                    task = self._state.get("tasks", {}).get(task_id)
                    if task and task.get("objective_hash") == objective_hash:
                        task["status"] = "completed"
                        self._save_state_locked()
                return
            except CodeQLAuditOutputValidationError:
                pass

        if not force:
            snapshot = self._goal_task_snapshot(task_id)
            if (
                snapshot.get("status") == "running"
                and snapshot.get("objective_hash") == objective_hash
                and snapshot.get("thread_id")
            ):
                completed, resume_error = self._resume_saved_goal(
                    task_id,
                    objective_hash,
                    str(snapshot["thread_id"]),
                    model=model,
                    validate=validate,
                )
                if completed:
                    return
                self._record_goal_failure(
                    task_id, resume_error or "saved Goal could not be resumed"
                )

        for retry in range(self.config.task_retries + 1):
            if retry and self.config.task_retry_delay_seconds:
                self._sleep(self.config.task_retry_delay_seconds * (2 ** (retry - 1)))
            execution_error: str | None = None
            controller: CodexController | None = None
            log_path = self.logs_dir / f"{_safe_name(task_id)}.attempt-{retry + 1}.log"
            log_handle = log_path.open("w+", encoding="utf-8")
            try:
                controller = self._controller_factory(
                    cwd=str(self.project_dir),
                    codex_bin=self.config.codex_bin,
                    output_mode=self.config.output_mode,
                    output=log_handle,
                    log_context={"codeql_audit_task_id": task_id},
                    resume_policy=self.config.resume_policy,
                )
                options: dict[str, Any] = {
                    "sandbox": Sandbox.workspace_write,
                    "approval_mode": ApprovalMode.deny_all,
                }
                if model is not None:
                    options["model"] = model
                thread_id = controller.start_thread(**options)
                self._record_goal_start(task_id, objective_hash, thread_id, retry + 1)
                result = controller.goal(objective, model=model, token_budget=token_budget)
                completed = bool(getattr(result, "completed", False))
                goal = getattr(result, "goal", None)
                goal_status = str(getattr(goal, "status", "unknown"))
                if not completed:
                    execution_error = str(
                        getattr(result, "last_error", None)
                        or f"Goal stopped with status {goal_status}"
                    )
                else:
                    try:
                        validate()
                    except Exception as exc:
                        execution_error = _exception_text(exc)
                    else:
                        self._record_goal_complete(task_id)
                        return
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                execution_error = _exception_text(exc)
            finally:
                if controller is not None:
                    try:
                        controller.close()
                    except Exception:
                        pass
                log_handle.close()
                self._emit_log(log_path, task_id, retry + 1)
            self._record_goal_failure(task_id, execution_error or "unknown Goal failure")
        raise CodeQLAuditWorkflowError(
            f"Goal {task_id} exhausted retries: {execution_error or 'unknown failure'}"
        )

    def _dispatchable_goal_objective(self, task_id: str, prompt: str) -> str:
        objective = _goal_objective(prompt)
        if len(objective) <= _MAX_GOAL_OBJECTIVE_CHARS:
            return objective

        prompt_hash = hashlib.sha256(objective.encode("utf-8")).hexdigest()
        prompt_path = self.goal_prompts_dir / f"{_safe_name(task_id)}.md"
        _atomic_text(prompt_path, objective + "\n")
        preview = ""
        for paragraph in objective.split("\n\n"):
            candidate = f"{preview}\n\n{paragraph}" if preview else paragraph
            if len(candidate) > _GOAL_OBJECTIVE_PREVIEW_CHARS:
                break
            preview = candidate
        if not preview:
            preview = objective[: _GOAL_OBJECTIVE_PREVIEW_CHARS - 3] + "..."
        dispatched = (
            f"{preview}\n\n"
            f"完整任务说明（SHA-256 `{prompt_hash}`）位于 "
            f"`{self._project_path(prompt_path)}`。先完整读取该 UTF-8 文件，再严格执行"
            "其中全部要求；该说明文件只读，不得修改。"
        )
        if len(dispatched) > _MAX_GOAL_OBJECTIVE_CHARS:
            raise CodeQLAuditWorkflowError(
                f"Goal {task_id} objective indirection is {len(dispatched)} characters; "
                f"maximum is {_MAX_GOAL_OBJECTIVE_CHARS}"
            )
        return dispatched

    def _goal_task_snapshot(self, task_id: str) -> dict[str, Any]:
        with self._state_lock:
            return dict(self._state.get("tasks", {}).get(task_id, {}))

    def _resume_saved_goal(
        self,
        task_id: str,
        objective_hash: str,
        thread_id: str,
        *,
        model: str | None,
        validate: Callable[[], Any],
    ) -> tuple[bool, str | None]:
        controller: CodexController | None = None
        attempt = _positive_or_default(
            self._goal_task_snapshot(task_id).get("attempt"), 1
        )
        log_path = self.logs_dir / f"{_safe_name(task_id)}.attempt-{attempt}.log"
        log_handle = log_path.open("a+", encoding="utf-8")
        try:
            controller = self._controller_factory(
                cwd=str(self.project_dir),
                codex_bin=self.config.codex_bin,
                thread_id=thread_id,
                output_mode=self.config.output_mode,
                output=log_handle,
                log_context={"codeql_audit_task_id": task_id},
                resume_policy=self.config.resume_policy,
            )
            options: dict[str, Any] = {
                "sandbox": Sandbox.workspace_write,
                "approval_mode": ApprovalMode.deny_all,
            }
            if model is not None:
                options["model"] = model
            controller.resume_thread(thread_id, **options)
            goal = controller.get_goal()
            if goal is None:
                return False, "saved thread has no active Goal"
            saved_objective = str(getattr(goal, "objective", ""))
            if saved_objective and hashlib.sha256(
                saved_objective.encode("utf-8")
            ).hexdigest() != objective_hash:
                return False, "saved Goal objective does not match this task"
            status = str(getattr(goal, "status", "unknown"))
            if status == "complete":
                result_completed = True
            elif status in _TERMINAL_GOAL_FAILURES:
                return False, f"saved Goal stopped with status {status}"
            else:
                result = controller.resume_goal(model=model)
                result_completed = bool(getattr(result, "completed", False))
                if not result_completed:
                    resumed_goal = getattr(result, "goal", None)
                    resumed_status = str(getattr(resumed_goal, "status", "unknown"))
                    return False, str(
                        getattr(result, "last_error", None)
                        or f"resumed Goal stopped with status {resumed_status}"
                    )
            if result_completed:
                try:
                    validate()
                except Exception as exc:
                    return False, _exception_text(exc)
                self._record_goal_complete(task_id)
                return True, None
            return False, "saved Goal did not complete"
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            return False, _exception_text(exc)
        finally:
            if controller is not None:
                try:
                    controller.close()
                except Exception:
                    pass
            log_handle.close()
            self._emit_log(log_path, task_id, attempt)

    def _record_goal_start(
        self, task_id: str, objective_hash: str, thread_id: str, attempt: int
    ) -> None:
        with self._state_lock:
            task = self._state["tasks"].setdefault(task_id, {})
            task.update(
                {
                    "kind": "goal",
                    "status": "running",
                    "objective_hash": objective_hash,
                    "thread_id": thread_id,
                    "attempt": attempt,
                    "updated_at": _utc_now(),
                }
            )
            self._save_state_locked()

    def _record_goal_complete(self, task_id: str) -> None:
        with self._state_lock:
            self._state["tasks"][task_id].update(
                {"status": "completed", "last_error": None, "updated_at": _utc_now()}
            )
            self._save_state_locked()

    def _record_goal_failure(self, task_id: str, error: str) -> None:
        with self._state_lock:
            task = self._state["tasks"].setdefault(task_id, {})
            task.update(
                {"status": "failed", "last_error": error, "updated_at": _utc_now()}
            )
            self._save_state_locked()

    def _emit_log(self, path: Path, task_id: str, attempt: int) -> None:
        if self.config.output_mode is OutputMode.QUIET:
            return
        try:
            rendered = path.read_text(encoding="utf-8")
        except OSError:
            return
        if not rendered:
            return
        with self._output_lock:
            self._output.write(f"=== CodeQL audit Goal {task_id} (attempt {attempt}) ===\n")
            self._output.write(rendered)
            if not rendered.endswith("\n"):
                self._output.write("\n")
            self._output.flush()

    def _emit_status(self, message: str) -> None:
        if self.config.output_mode is OutputMode.QUIET:
            return
        with self._output_lock:
            self._output.write(message.rstrip() + "\n")
            self._output.flush()

    def _read_prompt(self, name: str, override: str | Path | None) -> str:
        if override is not None:
            candidates = [Path(override).expanduser().resolve()]
        else:
            module_dir = Path(__file__).resolve().parent
            candidates = [module_dir / "prompts" / name, module_dir.parent / "prompts" / name]
        for path in candidates:
            if path.is_file():
                return path.read_text(encoding="utf-8")
        raise CodeQLAuditWorkflowError(
            f"prompt not found: {name}; checked {', '.join(map(str, candidates))}"
        )

    def _project_path(self, path: Path) -> str:
        relative = path.resolve().relative_to(self.project_dir)
        return "./" + relative.as_posix()

    def _write_summary(self, result: CodeQLAuditWorkflowResult) -> None:
        lines = [
            "# Git-history-driven CodeQL audit",
            "",
            f"- Status: `{result.status.value}`",
            f"- Databases: {result.database_completed}/{result.database_total}",
            f"- Git commits analyzed: {result.commit_completed}/{result.commit_total}",
            f"- Security-fix commits: {result.security_commit_total}",
            f"- Generated rules: {result.rules_total}",
            f"- Suspicious findings selected for review: {result.suspicious_total}",
            f"- Reviews completed: {result.reviewed_total}",
            f"- Confirmed: {result.confirmed_total}",
            f"- False positives: {result.false_positive_total}",
            f"- Inconclusive: {result.inconclusive_total}",
            "",
            "Confirmed review JSON files are written to `confirmed/` as soon as each Goal finishes.",
        ]
        if result.failed_tasks:
            lines.extend(["", "## Failures", ""])
            lines.extend(f"- {item}" for item in result.failed_tasks)
        _atomic_text(self.summary_path, "\n".join(lines) + "\n")


def _valid_codeql_database(path: Path) -> bool:
    return path.is_dir() and (
        (path / "codeql-database.yml").is_file() or (path / "db-cpp").is_dir()
    )


def _goal_objective(prompt: str) -> str:
    objective = re.sub(r"^\s*/goal(?:\s+|$)", "", prompt, count=1).strip()
    if not objective:
        raise CodeQLAuditWorkflowError("Goal prompt has no objective after /goal")
    return objective


def _normalize_sarif_path(uri: str, known_files: set[str]) -> str:
    parsed = urlparse(uri)
    raw = unquote(parsed.path if parsed.scheme == "file" else uri).replace("\\", "/")
    raw = raw.lstrip("./")
    if raw in known_files:
        return raw
    matches = [relative for relative in known_files if raw.endswith("/" + relative)]
    if matches:
        return max(matches, key=len)
    return raw


def _resolve_executable(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or path.parent != Path("."):
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve())
        raise FileNotFoundError(f"executable not found or not executable: {value}")
    found = shutil.which(value)
    if found is None:
        raise FileNotFoundError(f"executable not found in PATH: {value}")
    return found


def _nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CodeQLAuditOutputValidationError(f"{name} must be a non-empty string")
    return value.strip()


def _validate_case_files(
    value: Any, test_path: Path, rule_id: str, field_name: str
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        raise CodeQLAuditOutputValidationError(
            f"{field_name} for {rule_id} must contain at least one file"
        )
    cases: list[str] = []
    seen: set[str] = set()
    for item in value:
        relative = Path(item)
        if relative.is_absolute() or ".." in relative.parts:
            raise CodeQLAuditOutputValidationError(
                f"unsafe {field_name} path for {rule_id}: {item!r}"
            )
        normalized = relative.as_posix()
        path = (test_path / relative).resolve()
        try:
            path.relative_to(test_path.resolve())
        except ValueError as exc:
            raise CodeQLAuditOutputValidationError(
                f"{field_name} escapes test directory for {rule_id}: {item!r}"
            ) from exc
        if path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
            raise CodeQLAuditOutputValidationError(
                f"{field_name} for {rule_id} must be C/C++ source fixtures"
            )
        if not path.is_file():
            raise CodeQLAuditOutputValidationError(
                f"missing {field_name} file for {rule_id}: {normalized}"
            )
        if normalized in seen:
            raise CodeQLAuditOutputValidationError(
                f"duplicate {field_name} file for {rule_id}: {normalized}"
            )
        seen.add(normalized)
        cases.append(normalized)
    return tuple(cases)


def _positive_or_default(value: Any, default: int) -> int:
    parsed = _optional_positive(value)
    return parsed if parsed is not None else default


def _optional_positive(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _safe_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-")
    return normalized[:120] or "item"


def _hash_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _hash_files(paths: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path).encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _rule_signature(rule: _Rule) -> str:
    return _hash_json(
        {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "description": rule.description,
            "query_path": str(rule.query_path),
            "query_sha256": _hash_files([rule.query_path]),
            "severity": rule.severity,
            "precision": rule.precision,
            "evidence_commits": rule.evidence_commits,
            "test_signature": _rule_test_signature(rule),
        }
    )


def _rule_test_signature(rule: _Rule) -> str:
    fixture_paths = [
        rule.query_path,
        rule.test_path / "test.qlref",
        rule.test_path / "test.expected",
        *(rule.test_path / case for case in rule.positive_cases),
        *(rule.test_path / case for case in rule.negative_cases),
    ]
    return _hash_files(fixture_paths)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    os.replace(temporary, path)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _exception_text(value: Any) -> str:
    return f"{type(value).__name__}: {value}"
