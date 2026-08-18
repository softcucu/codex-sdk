from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_controller import (
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
    vulnerable_tasks: set[str] = set()

    @classmethod
    def reset(cls) -> None:
        cls.next_thread = 1
        cls.threads = {}
        cls.goal_calls = []
        cls.resume_calls = []
        cls.terminal_failures = {}
        cls.invalid_outputs = {}
        cls.interrupt_once = set()
        cls.vulnerable_tasks = set()

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
        (root / "protocols" / "demo").mkdir(parents=True, exist_ok=True)
        (root / "PROTOCOL_SURFACE.md").write_text("# Demo protocol\n", encoding="utf-8")
        (root / "coverage.md").write_text("# Coverage\n\nComplete.\n", encoding="utf-8")
        (root / "protocol_inventory.jsonl").write_text(
            json.dumps({"protocol_id": "demo", "protocol_name": "Demo"}) + "\n",
            encoding="utf-8",
        )
        (root / "message_inventory.jsonl").write_text(
            json.dumps(
                {
                    "protocol_id": "demo",
                    "message_id": "hello",
                    "message_name": "Hello",
                    "direction": "RX",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "protocols" / "demo" / "summary.md").write_text(
            "# Demo\n", encoding="utf-8"
        )
        (root / "protocols" / "demo" / "messages.jsonl").write_text(
            "{}\n", encoding="utf-8"
        )

    def _write_invalid(self, task_id: str) -> None:
        if task_id == "attack-surface":
            root = self.cwd / "protocol-analysis"
            root.mkdir(parents=True, exist_ok=True)
            (root / "PROTOCOL_SURFACE.md").write_text("", encoding="utf-8")
            return
        results = self.cwd / "protocol-analysis" / "vulnerability-analysis" / "results"
        results.mkdir(parents=True, exist_ok=True)
        (results / f"{task_id}.audit.json").write_text("{}\n", encoding="utf-8")

    def _write_audit(self, objective: str, task_id: str) -> None:
        results = self.cwd / "protocol-analysis" / "vulnerability-analysis" / "results"
        results.mkdir(parents=True, exist_ok=True)
        protocol_id = self._json_field(objective, "protocol_id")
        if task_id.startswith("message--"):
            data = {
                "task_id": task_id,
                "protocol_id": protocol_id,
                "message_id": self._json_field(objective, "message_id"),
                "direction": self._json_field(objective, "direction"),
                "verdict": "NO_CONFIRMED_VULNERABILITY",
                "summary": "No confirmed issue.",
                "reachability": "external -> parser -> handler",
                "controllable_fields": ["payload"],
                "preconditions": ["connected"],
                "findings": [],
                "coverage_gaps": [],
            }
            if task_id in type(self).vulnerable_tasks:
                data["verdict"] = "VULNERABLE"
                data["findings"] = [
                    {
                        "id": "DEMO-1",
                        "title": "Demo vulnerability",
                        "severity": "HIGH",
                        "cwe": "CWE-20",
                        "root_cause": "Missing validation",
                        "attack_path": ["external input", "unsafe handler"],
                        "impact": "process crash",
                        "evidence": [
                            {
                                "file": "src/demo.c",
                                "symbol": "handle_demo",
                                "line": "10-20",
                                "description": "unchecked input",
                            }
                        ],
                        "remediation": "validate input",
                    }
                ]
        else:
            data = {
                "task_id": task_id,
                "protocol_id": protocol_id,
                "verdict": "NO_CONFIRMED_VULNERABILITY",
                "summary": "No confirmed protocol issue.",
                "attack_surface": "external demo endpoint",
                "protocol_model": ["hello request"],
                "security_invariants": ["session binding"],
                "findings": [],
                "coverage_gaps": [],
            }
        (results / f"{task_id}.audit.json").write_text(
            json.dumps(data), encoding="utf-8"
        )
        if task_id in type(self).vulnerable_tasks:
            (results / f"{task_id}.漏洞报告.md").write_text(
                "# Demo vulnerability\n", encoding="utf-8"
            )

    @staticmethod
    def _json_field(objective: str, name: str) -> str:
        match = re.search(rf'"{re.escape(name)}": "([^"]+)"', objective)
        assert match is not None, (name, objective)
        return match.group(1)

    @staticmethod
    def _task_id(objective: str) -> str:
        if "完整、可验证、可复用的协议与消息处理面清单" in objective:
            return "attack-surface"
        return WorkflowFakeController._json_field(objective, "task_id")


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
    assert first.message_completed == 1
    assert first.protocol_completed == 1
    results = first.results_dir
    assert (results / "message--demo--rx--hello.audit.json").is_file()
    assert (results / "message--demo--rx--hello.complete.json").is_file()
    assert (results / "protocol--demo.audit.json").is_file()
    assert (results / "protocol--demo.complete.json").is_file()
    assert len(WorkflowFakeController.goal_calls) == 3

    second = workflow(tmp_path).run()

    assert second.status is AuditWorkflowStatus.COMPLETE
    assert len(WorkflowFakeController.goal_calls) == 3
    assert WorkflowFakeController.resume_calls == []


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
    assert WorkflowFakeController.goal_calls == [
        "message--demo--rx--hello",
        "protocol--demo",
    ]


def test_existing_inventory_with_msg_type_name_is_backward_compatible(
    tmp_path: Path,
) -> None:
    fake = WorkflowFakeController(cwd=str(tmp_path))
    fake._write_surface()
    root = tmp_path / "protocol-analysis"
    (root / "message_inventory.jsonl").write_text(
        json.dumps(
            {
                "protocol_id": "demo",
                "msg_type_name": "HelloMessage",
                "direction": "RX",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "ATTACK_SURFACE_COMPLETE.json").touch()

    result = workflow(tmp_path).run()

    assert result.status is AuditWorkflowStatus.COMPLETE
    assert "attack-surface" not in WorkflowFakeController.goal_calls
    assert "message--demo--rx--hellomessage" in WorkflowFakeController.goal_calls


def test_interrupted_goal_is_resumed_from_persisted_thread(tmp_path: Path) -> None:
    task_id = "message--demo--rx--hello"
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
    task_id = "message--demo--rx--hello"
    WorkflowFakeController.terminal_failures[task_id] = 3

    result = workflow(tmp_path, max_workers=1, task_retries=2).run()

    assert result.status is AuditWorkflowStatus.PARTIAL
    assert result.exit_code == 2
    assert result.message_failed == 1
    assert result.protocol_completed == 1
    assert WorkflowFakeController.goal_calls.count(task_id) == 3
    failure_audit = json.loads(
        (result.results_dir / f"{task_id}.audit.json").read_text(encoding="utf-8")
    )
    assert failure_audit["execution_status"] == "failed"
    assert failure_audit["verdict"] == "INCONCLUSIVE"
    assert not (result.results_dir / f"{task_id}.complete.json").exists()
    assert task_id in (
        tmp_path
        / "protocol-analysis"
        / "vulnerability-analysis"
        / "coverage.md"
    ).read_text(encoding="utf-8")

    archived_before = list(
        (tmp_path / "protocol-analysis" / ".workflow" / "failed-artifacts").rglob(
            f"{task_id}.audit.json"
        )
    )
    calls_before = list(WorkflowFakeController.goal_calls)
    resumed = workflow(tmp_path, max_workers=1, task_retries=2).run()
    archived_after = list(
        (tmp_path / "protocol-analysis" / ".workflow" / "failed-artifacts").rglob(
            f"{task_id}.audit.json"
        )
    )
    assert resumed.status is AuditWorkflowStatus.PARTIAL
    assert WorkflowFakeController.goal_calls == calls_before
    assert archived_after == archived_before


def test_completed_goal_with_invalid_output_uses_a_fresh_attempt(tmp_path: Path) -> None:
    task_id = "message--demo--rx--hello"
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


def test_confirmed_finding_requires_and_indexes_task_report(tmp_path: Path) -> None:
    task_id = "message--demo--rx--hello"
    WorkflowFakeController.vulnerable_tasks.add(task_id)

    result = workflow(tmp_path).run()

    assert result.status is AuditWorkflowStatus.COMPLETE
    assert result.confirmed_findings == 1
    assert (result.results_dir / f"{task_id}.漏洞报告.md").is_file()
    marker = json.loads(
        (result.results_dir / f"{task_id}.complete.json").read_text(encoding="utf-8")
    )
    assert marker["findings_count"] == 1
    assert f"{task_id}.漏洞报告.md" in marker["output_hashes"]


def test_force_starts_new_generation_and_reruns_all_tasks(tmp_path: Path) -> None:
    first = workflow(tmp_path).run()
    assert first.status is AuditWorkflowStatus.COMPLETE
    assert len(WorkflowFakeController.goal_calls) == 3

    second = workflow(tmp_path).run(force=True)

    assert second.status is AuditWorkflowStatus.COMPLETE
    assert len(WorkflowFakeController.goal_calls) == 6
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
