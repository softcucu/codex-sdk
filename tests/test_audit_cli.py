from __future__ import annotations

from pathlib import Path

from codex_controller import AuditWorkflowResult, AuditWorkflowStatus
from codex_controller import audit_cli


def test_audit_cli_returns_partial_exit_code(monkeypatch, tmp_path: Path) -> None:
    captured = {}

    class FakeWorkflow:
        def __init__(self, config):
            captured["config"] = config

        def run(self, *, force=False):
            captured["force"] = force
            return AuditWorkflowResult(
                status=AuditWorkflowStatus.PARTIAL,
                output_dir=tmp_path / "protocol-analysis",
                results_dir=tmp_path / "protocol-analysis" / "results",
                message_total=2,
                message_completed=1,
                message_failed=1,
            )

    monkeypatch.setattr(audit_cli, "VulnerabilityAuditWorkflow", FakeWorkflow)

    exit_code = audit_cli.main(
        [
            "-C",
            str(tmp_path),
            "--max-workers",
            "3",
            "--task-retries",
            "4",
            "--force",
        ]
    )

    assert exit_code == 2
    assert captured["config"].max_workers == 3
    assert captured["config"].task_retries == 4
    assert captured["force"] is True
