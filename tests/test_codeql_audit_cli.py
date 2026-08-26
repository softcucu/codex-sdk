from __future__ import annotations

from codex_controller import CodeQLAuditStatus, CodeQLAuditWorkflowResult
from codex_controller import codeql_audit_cli


def test_codeql_audit_cli_wires_concurrency_options(monkeypatch, tmp_path) -> None:
    captured = {}

    class FakeWorkflow:
        def __init__(self, config):
            captured["config"] = config

        def run(self, *, force=False, skip_database_build=False):
            captured["force"] = force
            captured["skip_database_build"] = skip_database_build
            return CodeQLAuditWorkflowResult(
                status=CodeQLAuditStatus.PARTIAL,
                output_dir=tmp_path / "codeql-git-audit",
            )

    monkeypatch.setattr(codeql_audit_cli, "CodeQLGitAuditWorkflow", FakeWorkflow)

    exit_code = codeql_audit_cli.main(
        [
            "-C",
            str(tmp_path),
            "--scan-workers",
            "3",
            "--history-workers",
            "5",
            "--review-workers",
            "7",
            "--force",
            "--skip-database-build",
        ]
    )

    assert exit_code == 2
    assert captured["config"].scan_workers == 3
    assert captured["config"].history_workers == 5
    assert captured["config"].review_workers == 7
    assert captured["force"] is True
    assert captured["skip_database_build"] is True
