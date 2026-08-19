from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_controller import (
    AuditOutputValidationError,
    AuditWorkflowConfig,
    AuditWorkflowStatus,
    VulnerabilityAuditWorkflow,
)


class WorkflowFakeController:
    lock = threading.Lock()
    next_thread = 1
    threads: dict[str, dict[str, Any]] = {}
    goal_calls: list[str] = []
    resume_calls: list[str] = []
    terminal_failures: dict[str, int] = {}
    invalid_outputs: dict[str, int] = {}
    interrupt_once: set[str] = set()

    @classmethod
    def reset(cls) -> None:
        cls.next_thread = 1
        cls.threads = {}
        cls.goal_calls = []
        cls.resume_calls = []
        cls.terminal_failures = {}
        cls.invalid_outputs = {}
        cls.interrupt_once = set()

    def __init__(self, **kwargs: Any) -> None:
        self.cwd = Path(kwargs["cwd"])
        self.thread_id = kwargs.get("thread_id")

    def start_thread(self, **_options: Any) -> str:
        with self.lock:
            thread_id = f"thread-{type(self).next_thread}"
            type(self).next_thread += 1
            type(self).threads[thread_id] = {"objective": "", "status": "empty"}
        self.thread_id = thread_id
        return thread_id

    def resume_thread(self, thread_id: str, **_options: Any) -> str:
        assert thread_id in type(self).threads
        self.thread_id = thread_id
        return thread_id

    def goal(self, objective: str, **_options: Any) -> Any:
        assert self.thread_id is not None
        task_id = self._task_id(objective)
        with self.lock:
            type(self).goal_calls.append(task_id)
            type(self).threads[self.thread_id] = {
                "objective": objective,
                "status": "active",
                "task_id": task_id,
            }
        if task_id in type(self).interrupt_once:
            type(self).interrupt_once.remove(task_id)
            type(self).threads[self.thread_id]["status"] = "paused"
            raise KeyboardInterrupt
        return self._finish(objective, task_id)

    def resume_goal(self, **_options: Any) -> Any:
        assert self.thread_id is not None
        state = type(self).threads[self.thread_id]
        task_id = str(state["task_id"])
        type(self).resume_calls.append(task_id)
        return self._finish(str(state["objective"]), task_id)

    def get_goal(self) -> Any:
        assert self.thread_id is not None
        state = type(self).threads[self.thread_id]
        if state["status"] == "empty":
            return None
        return SimpleNamespace(
            objective=state["objective"],
            status=state["status"],
        )

    def close(self) -> None:
        pass

    def _finish(self, objective: str, task_id: str) -> Any:
        assert self.thread_id is not None
        remaining_failures = type(self).terminal_failures.get(task_id, 0)
        if remaining_failures > 0:
            type(self).terminal_failures[task_id] = remaining_failures - 1
            type(self).threads[self.thread_id]["status"] = "blocked"
            return SimpleNamespace(
                completed=False,
                goal=SimpleNamespace(status="blocked"),
                last_error="simulated terminal failure",
            )

        invalid = type(self).invalid_outputs.get(task_id, 0)
        if invalid > 0:
            type(self).invalid_outputs[task_id] = invalid - 1
            self._write_invalid(task_id)
        elif task_id == "attack-surface":
            self._write_surface()
        else:
            self._write_audit(objective, task_id)
        type(self).threads[self.thread_id]["status"] = "complete"
        return SimpleNamespace(
            completed=True,
            goal=SimpleNamespace(status="complete"),
            last_error=None,
        )

    def _write_surface(self) -> None:
        root = self.cwd / "protocol-analysis"
        root.mkdir(parents=True, exist_ok=True)
        (root / "high_risk_modules.json").write_text(
            json.dumps(
                [
                    {
                        "name": "Demo",
                        "is_high_risk": True,
                        "code_dir": ".",
                        "reason": "Handles attacker-controlled requests.",
                    }
                ]
            ),
            encoding="utf-8",
        )

    def _write_invalid(self, task_id: str) -> None:
        if task_id == "attack-surface":
            root = self.cwd / "protocol-analysis"
            root.mkdir(parents=True, exist_ok=True)
            (root / "high_risk_modules.json").write_text("[]", encoding="utf-8")
            return
        results = self.cwd / "protocol-analysis" / "vulnerability-analysis" / "results"
        results.mkdir(parents=True, exist_ok=True)
        (results / f"{task_id}.audit.json").write_text("{}\n", encoding="utf-8")

    def _write_audit(self, objective: str, task_id: str) -> None:
        module_match = re.search(r"外部高风险模块 `([^`]+)`", objective)
        report_match = re.search(r"只允许生成漏洞报告 `([^`]+)`", objective)
        assert module_match is not None, objective
        assert report_match is not None, objective
        module_name = module_match.group(1)
        report = Path(report_match.group(1))
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            f"# {module_name} DoS\n",
            encoding="utf-8",
        )

    @staticmethod
    def _task_id(objective: str) -> str:
        if "high_risk_modules.json" in objective:
            return "attack-surface"
        match = re.search(r"外部高风险模块 `([^`]+)`", objective)
        assert match is not None, objective
        slug = re.sub(r"[^a-z0-9]+", "-", match.group(1).lower()).strip("-")
        return f"module--{slug or 'item'}"


@pytest.fixture(autouse=True)
def reset_fake_controller() -> None:
    WorkflowFakeController.reset()


def workflow(tmp_path: Path, **overrides: Any) -> VulnerabilityAuditWorkflow:
    config = AuditWorkflowConfig(
        project_dir=tmp_path,
        output_mode="quiet",
        task_retry_delay_seconds=0,
        **overrides,
    )
    return VulnerabilityAuditWorkflow(
        config,
        _controller_factory=WorkflowFakeController,
    )


def test_workflow_completes_with_flat_uniquely_named_results_and_reuses_them(
    tmp_path: Path,
) -> None:
    first = workflow(tmp_path).run()

    assert first.status is AuditWorkflowStatus.COMPLETE
    assert first.message_completed == 0
    assert first.protocol_completed == 1
    results = first.results_dir
    assert (results / "Demo-DoS-001.md").is_file()
    assert list(results.glob("*.json")) == []
    assert (
        tmp_path
        / "protocol-analysis"
        / ".workflow"
        / "completions"
        / "module--demo.complete.json"
    ).is_file()
    assert len(WorkflowFakeController.goal_calls) == 2

    second = workflow(tmp_path).run()

    assert second.status is AuditWorkflowStatus.COMPLETE
    assert len(WorkflowFakeController.goal_calls) == 2
    assert WorkflowFakeController.resume_calls == []


def test_attack_surface_schema_is_installed_before_bounded_goal_is_created(
    tmp_path: Path,
) -> None:
    active = workflow(tmp_path)

    spec = active._attack_surface_spec()

    assert len(spec.objective) <= 4000
    assert "${inventory_schema_path}" not in spec.objective
    assert "./protocol-analysis/inventory_schema.json" in spec.objective
    schema = json.loads(
        (tmp_path / "protocol-analysis" / "inventory_schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert "module_record" in schema["$defs"]
    assert "high_risk_modules.json" in spec.objective
    assert "只能包含以下四个字段" in spec.objective


def test_empty_manual_attack_surface_marker_skips_expensive_first_stage(
    tmp_path: Path,
) -> None:
    fake = WorkflowFakeController(cwd=str(tmp_path))
    fake._write_surface()
    marker = tmp_path / "protocol-analysis" / "ATTACK_SURFACE_COMPLETE.json"
    marker.touch()

    result = workflow(tmp_path).run()

    assert result.status is AuditWorkflowStatus.COMPLETE
    assert "attack-surface" not in WorkflowFakeController.goal_calls
    assert WorkflowFakeController.goal_calls == ["module--demo"]


def test_module_dos_prompt_is_assembled_from_high_risk_module(tmp_path: Path) -> None:
    fake = WorkflowFakeController(cwd=str(tmp_path))
    fake._write_surface()
    active = workflow(tmp_path)

    spec = active._module_specs(active._validate_surface())[0]

    assert "外部高风险模块 `Demo`" in spec.objective
    assert "DoS漏洞" in spec.objective
    assert "可通过外部消息触发" in spec.objective
    assert "Demo-DoS-001.md" in spec.objective


def test_non_high_risk_modules_are_validated_but_not_scheduled(
    tmp_path: Path,
) -> None:
    fake = WorkflowFakeController(cwd=str(tmp_path))
    fake._write_surface()
    root = tmp_path / "protocol-analysis"
    docs = tmp_path / "docs"
    docs.mkdir()
    (root / "high_risk_modules.json").write_text(
        json.dumps(
            [
                {
                    "name": "Demo",
                    "is_high_risk": True,
                    "code_dir": ".",
                    "reason": "Handles attacker-controlled requests.",
                },
                {
                    "name": "Documentation",
                    "is_high_risk": False,
                    "code_dir": "docs",
                    "reason": None,
                },
            ]
        ),
        encoding="utf-8",
    )
    (root / "ATTACK_SURFACE_COMPLETE.json").touch()

    result = workflow(tmp_path).run()

    assert result.status is AuditWorkflowStatus.COMPLETE
    assert "attack-surface" not in WorkflowFakeController.goal_calls
    assert WorkflowFakeController.goal_calls == ["module--demo"]


@pytest.mark.parametrize(
    ("record", "error"),
    [
        (
            {
                "name": "Demo",
                "is_high_risk": "true",
                "code_dir": ".",
                "reason": "External input.",
            },
            "is_high_risk must be a JSON boolean",
        ),
        (
            {
                "name": "Demo",
                "is_high_risk": True,
                "code_dir": ".",
                "reason": None,
            },
            "requires a non-empty reason",
        ),
        (
            {
                "name": "Demo",
                "is_high_risk": False,
                "code_dir": ".",
                "reason": "Not exposed.",
            },
            "must use null for reason",
        ),
        (
            {
                "name": "Demo",
                "is_high_risk": False,
                "code_dir": "../outside",
                "reason": None,
            },
            "normalized repository-relative directory",
        ),
        (
            {
                "name": "Demo",
                "is_high_risk": False,
                "code_dir": ".",
                "reason": None,
                "extra": "not allowed",
            },
            "fields must be exactly",
        ),
    ],
)
def test_high_risk_module_json_contract_is_strict(
    tmp_path: Path,
    record: dict[str, Any],
    error: str,
) -> None:
    active = workflow(tmp_path)
    active.output_dir.mkdir(parents=True)
    (active.output_dir / "high_risk_modules.json").write_text(
        json.dumps([record]), encoding="utf-8"
    )

    with pytest.raises(AuditOutputValidationError, match=error):
        active._validate_surface()


def test_interrupted_goal_is_resumed_from_persisted_thread(tmp_path: Path) -> None:
    task_id = "module--demo"
    WorkflowFakeController.interrupt_once.add(task_id)

    with pytest.raises(KeyboardInterrupt):
        workflow(tmp_path, max_workers=1).run()

    state = json.loads(
        (tmp_path / "protocol-analysis" / ".workflow" / "state.json").read_text(
            encoding="utf-8"
        )
    )
    assert state["tasks"][task_id]["status"] == "running"
    assert state["tasks"][task_id]["thread_id"]

    result = workflow(tmp_path, max_workers=1).run()

    assert result.status is AuditWorkflowStatus.COMPLETE
    assert WorkflowFakeController.resume_calls == [task_id]
    assert WorkflowFakeController.goal_calls.count(task_id) == 1


def test_terminal_failure_retries_then_records_partial_coverage(tmp_path: Path) -> None:
    task_id = "module--demo"
    WorkflowFakeController.terminal_failures[task_id] = 3

    result = workflow(tmp_path, max_workers=1, task_retries=2).run()

    assert result.status is AuditWorkflowStatus.PARTIAL
    assert result.exit_code == 2
    assert result.message_failed == 0
    assert result.protocol_failed == 1
    assert WorkflowFakeController.goal_calls.count(task_id) == 3
    assert list(result.results_dir.iterdir()) == []
    assert not (
        tmp_path
        / "protocol-analysis"
        / ".workflow"
        / "completions"
        / f"{task_id}.complete.json"
    ).exists()
    assert task_id in (
        tmp_path
        / "protocol-analysis"
        / "vulnerability-analysis"
        / "coverage.md"
    ).read_text(encoding="utf-8")

    calls_before = list(WorkflowFakeController.goal_calls)
    resumed = workflow(tmp_path, max_workers=1, task_retries=2).run()
    assert resumed.status is AuditWorkflowStatus.PARTIAL
    assert WorkflowFakeController.goal_calls == calls_before


def test_completed_goal_with_invalid_output_uses_a_fresh_attempt(tmp_path: Path) -> None:
    task_id = "module--demo"
    WorkflowFakeController.invalid_outputs[task_id] = 1

    result = workflow(tmp_path, max_workers=1).run()

    assert result.status is AuditWorkflowStatus.COMPLETE
    assert WorkflowFakeController.goal_calls.count(task_id) == 2
    state = json.loads(
        (tmp_path / "protocol-analysis" / ".workflow" / "state.json").read_text(
            encoding="utf-8"
        )
    )
    assert state["tasks"][task_id]["attempt_count"] == 2
    archived = list(
        (tmp_path / "protocol-analysis" / ".workflow" / "failed-artifacts").rglob(
            f"{task_id}.audit.json"
        )
    )
    assert archived


def test_attack_surface_invalid_output_is_retried_before_scheduling_audits(
    tmp_path: Path,
) -> None:
    WorkflowFakeController.invalid_outputs["attack-surface"] = 1

    result = workflow(tmp_path, max_workers=1).run()

    assert result.status is AuditWorkflowStatus.COMPLETE
    assert WorkflowFakeController.goal_calls.count("attack-surface") == 2
    marker = json.loads(
        (tmp_path / "protocol-analysis" / "ATTACK_SURFACE_COMPLETE.json").read_text(
            encoding="utf-8"
        )
    )
    assert marker["status"] == "complete"
    assert marker["attempt_count"] == 2


def test_attack_surface_exhaustion_stops_dependent_tasks(tmp_path: Path) -> None:
    WorkflowFakeController.terminal_failures["attack-surface"] = 3

    result = workflow(tmp_path, max_workers=1, task_retries=2).run()

    assert result.status is AuditWorkflowStatus.FAILED
    assert result.exit_code == 1
    assert result.failed_tasks == ("attack-surface",)
    assert WorkflowFakeController.goal_calls == [
        "attack-surface",
        "attack-surface",
        "attack-surface",
    ]
    finished = json.loads(
        (
            tmp_path
            / "protocol-analysis"
            / "vulnerability-analysis"
            / "WORKFLOW_FINISHED.json"
        ).read_text(encoding="utf-8")
    )
    assert finished["status"] == "failed"


def test_target_source_changes_do_not_invalidate_completed_tasks(tmp_path: Path) -> None:
    first = workflow(tmp_path).run()
    calls = list(WorkflowFakeController.goal_calls)
    (tmp_path / "new-source-file.c").write_text("changed", encoding="utf-8")

    second = workflow(tmp_path).run()

    assert first.status is AuditWorkflowStatus.COMPLETE
    assert second.status is AuditWorkflowStatus.COMPLETE
    assert WorkflowFakeController.goal_calls == calls


def test_confirmed_dos_finding_is_counted_without_extra_report(tmp_path: Path) -> None:
    task_id = "module--demo"

    result = workflow(tmp_path).run()

    assert result.status is AuditWorkflowStatus.COMPLETE
    assert result.confirmed_findings == 1
    report = result.results_dir / "Demo-DoS-001.md"
    assert report.is_file()
    marker = json.loads(
        (
            tmp_path
            / "protocol-analysis"
            / ".workflow"
            / "completions"
            / f"{task_id}.complete.json"
        ).read_text(encoding="utf-8")
    )
    assert marker["findings_count"] == 1
    assert set(marker["output_hashes"]) == {"Demo-DoS-001.md"}


def test_force_starts_new_generation_and_reruns_all_tasks(tmp_path: Path) -> None:
    first = workflow(tmp_path).run()
    assert first.status is AuditWorkflowStatus.COMPLETE
    assert len(WorkflowFakeController.goal_calls) == 2

    second = workflow(tmp_path).run(force=True)

    assert second.status is AuditWorkflowStatus.COMPLETE
    assert len(WorkflowFakeController.goal_calls) == 4
    state = json.loads(
        (tmp_path / "protocol-analysis" / ".workflow" / "state.json").read_text(
            encoding="utf-8"
        )
    )
    assert state["generation"] == 2
    assert list(
        (tmp_path / "protocol-analysis" / ".workflow" / "force-archives").rglob(
            "*.complete.json"
        )
    )


def test_restart_reuses_attempt_reserved_before_thread_id_was_saved(
    tmp_path: Path,
) -> None:
    active = workflow(tmp_path, max_workers=1, task_retries=2)
    active.workflow_dir.mkdir(parents=True, exist_ok=True)
    active.results_dir.mkdir(parents=True, exist_ok=True)
    active.logs_dir.mkdir(parents=True, exist_ok=True)
    active._load_state()
    spec = active._attack_surface_spec()
    active._ensure_task_state(spec)
    with active._state_lock:
        task = active._state["tasks"][spec.task_id]
        task["status"] = "starting"
        task["attempt_count"] = 3
        task["history"] = [
            {
                "attempt": 3,
                "status": "starting",
                "thread_id": None,
                "started_at": "2026-01-01T00:00:00+00:00",
            }
        ]
        active._save_state_locked()

    result = workflow(tmp_path, max_workers=1, task_retries=2).run()

    assert result.status is AuditWorkflowStatus.COMPLETE
    state = json.loads(
        (tmp_path / "protocol-analysis" / ".workflow" / "state.json").read_text(
            encoding="utf-8"
        )
    )
    assert state["tasks"]["attack-surface"]["attempt_count"] == 3
    assert WorkflowFakeController.goal_calls.count("attack-surface") == 1
