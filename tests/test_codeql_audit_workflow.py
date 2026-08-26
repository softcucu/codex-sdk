from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from codex_controller import (
    CodeQLAuditStatus,
    CodeQLAuditWorkflowConfig,
    CodeQLGitAuditWorkflow,
)


def _write_query_test(
    root: Path, directory_name: str, query_name: str
) -> dict[str, Any]:
    test_dir = root / "query-tests" / directory_name
    test_dir.mkdir(parents=True, exist_ok=True)
    (test_dir / "positive.cpp").write_text(
        "void bad(char *dst, const char *src) { unsafe_copy(dst, src); }\n",
        encoding="utf-8",
    )
    (test_dir / "negative.cpp").write_text(
        "void good(char *dst, const char *src) { bounded_copy(dst, src); }\n",
        encoding="utf-8",
    )
    (test_dir / "test.qlref").write_text(
        f"queries/{query_name}\n", encoding="utf-8"
    )
    (test_dir / "test.expected").write_text(
        "| positive.cpp:1:6:1:8 | bad |\n", encoding="utf-8"
    )
    return {
        "test_path": f"query-tests/{directory_name}",
        "positive_cases": ["positive.cpp"],
        "negative_cases": ["negative.cpp"],
    }


class GoalOnlyController:
    calls: list[str] = []
    history_started = threading.Event()
    review_started = threading.Event()

    @classmethod
    def reset(cls) -> None:
        cls.calls = []
        cls.history_started = threading.Event()
        cls.review_started = threading.Event()

    def __init__(self, **kwargs: Any) -> None:
        self.cwd = Path(kwargs["cwd"])

    def start_thread(self, **_kwargs: Any) -> str:
        return f"thread-{len(type(self).calls) + 1}"

    def goal(self, objective: str, **_kwargs: Any) -> Any:
        assert not objective.lstrip().startswith("/goal")
        assert len(objective) <= 4000
        if "审计 Git 提交" in objective:
            type(self).calls.append("history")
            type(self).history_started.set()
            commit_match = re.search(r"Git 提交 `([^`]+)`", objective)
            assert commit_match is not None, objective
            self._write_history(commit_match.group(1))
        else:
            type(self).calls.append("review")
            self._write_review(objective)
        return SimpleNamespace(
            completed=True,
            goal=SimpleNamespace(status="complete"),
            last_error=None,
        )

    def close(self) -> None:
        pass

    def _write_history(self, commit: str) -> None:
        root = self.cwd / "codeql-git-audit" / "history-analysis"
        queries = root / "queries"
        ready = root / "ready-rules"
        commits = root / "commits"
        queries.mkdir(parents=True, exist_ok=True)
        ready.mkdir(parents=True, exist_ok=True)
        commits.mkdir(parents=True, exist_ok=True)
        (queries / "demo.ql").write_text(
            "/**\n * @kind problem\n * @id demo/history-rule\n */\n"
            "import cpp\nfrom Function f\nwhere f.getName() = \"bad\"\nselect f\n",
            encoding="utf-8",
        )
        pattern = {
            "id": "demo/history-rule",
            "name": "Demo rule",
            "description": "Historical missing check",
            "query_path": "queries/demo.ql",
            "severity": "error",
            "precision": "high",
            "evidence_commits": [commit],
            "evidence": [
                {
                    "commit": commit,
                    "path": "src/demo.c",
                    "symbols": ["bad"],
                    "reason": "The diff added the missing check.",
                }
            ],
            "tests": _write_query_test(root, f"{commit}-demo", "demo.ql"),
        }
        (ready / f"{commit}-demo.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "ready",
                    "git_head": "abc123",
                    "source_commit": commit,
                    "pattern": pattern,
                }
            ),
            encoding="utf-8",
        )
        (commits / f"{commit}.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "git_head": "abc123",
                    "commit": commit,
                    "verdict": "security_fix",
                    "summary": "The commit fixes an attacker-reachable missing check.",
                    "vulnerabilities": [
                        {
                            "id": "demo-vuln",
                            "title": "Missing check",
                            "summary": "The fix adds the missing validation.",
                            "security_impact": "Attacker-controlled memory corruption.",
                            "evidence": [{"path": "src/demo.c"}],
                            "rules": [pattern],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def _write_review(self, objective: str) -> None:
        type(self).review_started.set()
        assert "结构化疑似问题" not in objective
        assert "产生告警" not in objective
        assert "CodeQL 查询" not in objective
        assert "当前代码位置的待核验描述：`unchecked historical pattern`" in objective
        match = re.search(r"任务标识 `([0-9a-f]+)`", objective)
        assert match is not None
        finding_id = match.group(1)
        path = self.cwd / "codeql-git-audit" / "reviews" / f"{finding_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "finding_id": finding_id,
                    "verdict": "problem",
                    "problem_type": "missing bounds validation",
                    "cwe_ids": ["CWE-787"],
                    "confidence": "high",
                    "summary": "Attacker-controlled length reaches an unchecked copy.",
                    "attack_path": ["packet", "parser", "copy"],
                    "evidence": [
                        {
                            "path": "src/demo.c",
                            "line": 7,
                            "symbol": "bad",
                            "explanation": "No bound is enforced.",
                        }
                    ],
                    "counter_evidence": [],
                    "impact": "memory corruption",
                    "trigger_conditions": ["oversized packet"],
                    "remediation": "validate the length",
                }
            ),
            encoding="utf-8",
        )


def test_four_stage_pipeline_uses_parallel_prerequisites_and_goal_reviews(
    tmp_path: Path,
) -> None:
    GoalOnlyController.reset()
    builder_started = threading.Event()

    def fake_builder(repo: Path, output: Path, **_kwargs: Any) -> dict[str, Any]:
        builder_started.set()
        assert GoalOnlyController.history_started.wait(timeout=2)
        database = output / "databases" / "shard_0001_fast"
        slow_database = output / "databases" / "shard_0002_slow"
        (database / "db-cpp").mkdir(parents=True)
        (slow_database / "db-cpp").mkdir(parents=True)
        filelists = output / "filelists"
        filelists.mkdir()
        (filelists / "shard_0001_fast.files.txt").write_text(
            "src/demo.c\n", encoding="utf-8"
        )
        (filelists / "shard_0002_slow.files.txt").write_text(
            "src/slow.c\n", encoding="utf-8"
        )
        manifest = {
            "repository": str(repo),
            "output_dir": str(output),
            "shards": [
                {
                    "shard_id": "shard_0001_fast",
                    "database": str(database),
                    "status": "built",
                },
                {
                    "shard_id": "shard_0002_slow",
                    "database": str(slow_database),
                    "status": "built",
                },
            ],
        }
        output.mkdir(parents=True, exist_ok=True)
        (output / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return manifest

    def fake_subprocess(command, **_kwargs):
        if command[:3] == ["git", "-C", str(tmp_path)]:
            return SimpleNamespace(returncode=0, stdout="abc123\n", stderr="")
        if command[1:3] == ["test", "run"]:
            return SimpleNamespace(returncode=0, stdout="tests passed", stderr="")
        is_slow_database = Path(command[3]).name == "shard_0002_slow"
        if is_slow_database:
            assert GoalOnlyController.review_started.wait(timeout=2), (
                "finding review did not start while another database scan was running"
            )
        output_argument = next(item for item in command if item.startswith("--output="))
        sarif = Path(output_argument.split("=", 1)[1])
        scan_metadata = json.loads(
            sarif.with_suffix(".scan.json").read_text(encoding="utf-8")
        )
        assert scan_metadata["status"] == "running"
        results = [] if is_slow_database else [
            {
                "ruleId": "demo/history-rule",
                "message": {"text": "unchecked historical pattern"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "file:///tmp/slice/src/demo.c"
                            },
                            "region": {"startLine": 7, "startColumn": 3},
                        }
                    }
                ],
            }
        ]
        sarif.write_text(
            json.dumps(
                {
                    "runs": [
                        {
                            "results": results
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    config = CodeQLAuditWorkflowConfig(
        project_dir=tmp_path,
        output_mode="quiet",
        task_retry_delay_seconds=0,
        scan_workers=2,
        review_workers=2,
    )
    result = CodeQLGitAuditWorkflow(
        config,
        _controller_factory=GoalOnlyController,
        _database_builder=fake_builder,
        _subprocess_run=fake_subprocess,
    ).run()

    assert builder_started.is_set()
    assert result.status is CodeQLAuditStatus.COMPLETE
    assert result.database_completed == 2
    assert result.rules_total == 1
    assert result.suspicious_total == 1
    assert result.reviewed_total == 1
    assert result.confirmed_total == 1
    assert GoalOnlyController.calls == ["history", "review"]
    confirmed = list((tmp_path / "codeql-git-audit" / "confirmed").glob("*.json"))
    assert len(confirmed) == 1
    finding = json.loads(
        next((tmp_path / "codeql-git-audit" / "findings").glob("*.json")).read_text(
            encoding="utf-8"
        )
    )
    assert finding["path"] == "src/demo.c"
    completed_scans = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (tmp_path / "codeql-git-audit" / "scans").glob("*.scan.json")
    ]
    assert completed_scans
    assert all(item["status"] == "completed" for item in completed_scans)


def test_empty_history_patterns_complete_without_codeql_scan(tmp_path: Path) -> None:
    class EmptyHistoryController(GoalOnlyController):
        def _write_history(self, commit: str) -> None:
            root = self.cwd / "codeql-git-audit" / "history-analysis"
            commits = root / "commits"
            commits.mkdir(parents=True, exist_ok=True)
            (commits / f"{commit}.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "git_head": "abc123",
                        "commit": commit,
                        "verdict": "not_security_fix",
                        "summary": "No security-relevant behavior changed.",
                        "vulnerabilities": [],
                    }
                ),
                encoding="utf-8",
            )

    EmptyHistoryController.reset()

    def fake_builder(repo: Path, output: Path, **_kwargs: Any) -> dict[str, Any]:
        EmptyHistoryController.history_started.wait(timeout=2)
        database = output / "databases" / "one"
        (database / "db-cpp").mkdir(parents=True)
        return {
            "shards": [
                {"shard_id": "one", "database": str(database), "status": "built"}
            ]
        }

    def fake_subprocess(command, **_kwargs):
        assert command[0] == "git"
        return SimpleNamespace(returncode=0, stdout="abc123\n", stderr="")

    result = CodeQLGitAuditWorkflow(
        CodeQLAuditWorkflowConfig(
            project_dir=tmp_path,
            output_mode="quiet",
            task_retry_delay_seconds=0,
        ),
        _controller_factory=EmptyHistoryController,
        _database_builder=fake_builder,
        _subprocess_run=fake_subprocess,
    ).run()

    assert result.status is CodeQLAuditStatus.COMPLETE
    assert result.rules_total == 0
    assert result.suspicious_total == 0


def test_first_ready_rule_scans_before_history_goal_completes(tmp_path: Path) -> None:
    class StreamingHistoryController(GoalOnlyController):
        ready_published = threading.Event()
        scan_started = threading.Event()
        history_finished = threading.Event()

        @classmethod
        def reset(cls) -> None:
            super().reset()
            cls.ready_published = threading.Event()
            cls.scan_started = threading.Event()
            cls.history_finished = threading.Event()

        def _write_history(self, commit: str) -> None:
            root = self.cwd / "codeql-git-audit" / "history-analysis"
            queries = root / "queries"
            ready = root / "ready-rules"
            queries.mkdir(parents=True, exist_ok=True)
            ready.mkdir(parents=True, exist_ok=True)
            (root / "qlpack.yml").write_text(
                'name: local/git-history-audit\nversion: 0.0.1\n'
                'dependencies:\n  codeql/cpp-all: "*"\n',
                encoding="utf-8",
            )
            (queries / "streaming.ql").write_text(
                "/**\n * @kind problem\n * @id demo/streaming-rule\n */\n"
                "import cpp\nfrom Function f\nselect f\n",
                encoding="utf-8",
            )
            pattern = {
                "id": "demo/streaming-rule",
                "name": "Streaming rule",
                "description": "Published before history analysis completes.",
                "query_path": "queries/streaming.ql",
                "severity": "error",
                "precision": "high",
                "evidence_commits": ["abc123"],
                "evidence": [
                    {
                        "commit": "abc123",
                        "path": "src/demo.c",
                        "symbols": ["bad"],
                        "reason": "Historical fix evidence.",
                    }
                ],
                "tests": _write_query_test(
                    root, f"{commit}-streaming", "streaming.ql"
                ),
            }
            (ready / "streaming.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "status": "ready",
                        "git_head": "abc123",
                        "source_commit": commit,
                        "pattern": pattern,
                    }
                ),
                encoding="utf-8",
            )
            type(self).ready_published.set()
            assert type(self).scan_started.wait(timeout=2), (
                "workflow waited for the history Goal instead of scanning the ready rule"
            )
            commits = root / "commits"
            commits.mkdir(parents=True, exist_ok=True)
            (commits / f"{commit}.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "git_head": "abc123",
                        "commit": commit,
                        "verdict": "security_fix",
                        "summary": "The commit fixes one security issue.",
                        "vulnerabilities": [
                            {
                                "id": "streamed-vuln",
                                "title": "Streaming vulnerability",
                                "summary": "A missing validation was fixed.",
                                "security_impact": "Attacker-triggered failure.",
                                "evidence": [{"path": "src/demo.c"}],
                                "rules": [pattern],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            type(self).history_finished.set()

    StreamingHistoryController.reset()

    def fake_builder(repo: Path, output: Path, **_kwargs: Any) -> dict[str, Any]:
        database = output / "databases" / "one"
        (database / "db-cpp").mkdir(parents=True)
        return {
            "shards": [
                {"shard_id": "one", "database": str(database), "status": "built"}
            ]
        }

    def fake_subprocess(command, **_kwargs):
        if command[0] == "git":
            return SimpleNamespace(returncode=0, stdout="abc123\n", stderr="")
        if command[1:3] == ["test", "run"]:
            return SimpleNamespace(returncode=0, stdout="tests passed", stderr="")
        assert StreamingHistoryController.ready_published.is_set()
        assert not StreamingHistoryController.history_finished.is_set()
        StreamingHistoryController.scan_started.set()
        output_argument = next(item for item in command if item.startswith("--output="))
        Path(output_argument.split("=", 1)[1]).write_text(
            json.dumps({"runs": [{"results": []}]}), encoding="utf-8"
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    result = CodeQLGitAuditWorkflow(
        CodeQLAuditWorkflowConfig(
            project_dir=tmp_path,
            output_mode="quiet",
            task_retry_delay_seconds=0,
            scan_workers=1,
        ),
        _controller_factory=StreamingHistoryController,
        _database_builder=fake_builder,
        _subprocess_run=fake_subprocess,
    ).run()

    assert result.status is CodeQLAuditStatus.COMPLETE
    assert result.rules_total == 1
    assert StreamingHistoryController.scan_started.is_set()
    assert StreamingHistoryController.history_finished.is_set()


def test_program_dispatches_one_goal_per_git_commit(tmp_path: Path) -> None:
    commits = ["c" * 40, "b" * 40, "a" * 40]
    dispatched_objectives: list[str] = []

    class PerCommitController(GoalOnlyController):
        def goal(self, objective: str, **_kwargs: Any) -> Any:
            assert not objective.lstrip().startswith("/goal")
            assert len(objective) <= 4000
            dispatched_objectives.append(objective)
            commit_match = re.search(r"Git 提交 `([0-9a-f]+)`", objective)
            head_match = re.search(r"基线 HEAD 为 `([0-9a-f]+)`", objective)
            assert commit_match is not None
            assert head_match is not None
            commit = commit_match.group(1)
            type(self).calls.append(commit)
            report = (
                self.cwd
                / "codeql-git-audit"
                / "history-analysis"
                / "commits"
                / f"{commit}.json"
            )
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "git_head": head_match.group(1),
                        "commit": commit,
                        "verdict": "not_security_fix",
                        "summary": "This commit is an ordinary refactor.",
                        "vulnerabilities": [],
                    }
                ),
                encoding="utf-8",
            )
            return SimpleNamespace(
                completed=True,
                goal=SimpleNamespace(status="complete"),
                last_error=None,
            )

    PerCommitController.reset()

    def fake_builder(repo: Path, output: Path, **_kwargs: Any) -> dict[str, Any]:
        database = output / "databases" / "one"
        (database / "db-cpp").mkdir(parents=True)
        return {
            "shards": [
                {"shard_id": "one", "database": str(database), "status": "built"}
            ]
        }

    def fake_subprocess(command, **_kwargs):
        if "rev-parse" in command:
            return SimpleNamespace(returncode=0, stdout=commits[0] + "\n", stderr="")
        assert "rev-list" in command
        return SimpleNamespace(
            returncode=0, stdout="\n".join(commits) + "\n", stderr=""
        )

    result = CodeQLGitAuditWorkflow(
        CodeQLAuditWorkflowConfig(
            project_dir=tmp_path,
            output_mode="quiet",
            task_retry_delay_seconds=0,
            history_workers=3,
        ),
        _controller_factory=PerCommitController,
        _database_builder=fake_builder,
        _subprocess_run=fake_subprocess,
    ).run()

    assert result.status is CodeQLAuditStatus.COMPLETE
    assert result.commit_total == 3
    assert result.commit_completed == 3
    assert result.security_commit_total == 0
    assert sorted(PerCommitController.calls) == sorted(commits)
    prompt = (
        Path(__file__).parents[1]
        / "src"
        / "prompts"
        / "git_history_codeql_rules_goal.txt"
    ).read_text(encoding="utf-8")
    assert prompt.startswith("/goal ")
    assert len(prompt) > 4000
    assert all(".workflow/goal-prompts/" in item for item in dispatched_objectives)
    saved_prompts = sorted(
        (tmp_path / "codeql-git-audit" / ".workflow" / "goal-prompts").glob(
            "git-commit--*.md"
        )
    )
    assert len(saved_prompts) == len(commits)
    assert all(len(path.read_text(encoding="utf-8")) > 4000 for path in saved_prompts)
    assert all(
        not path.read_text(encoding="utf-8").lstrip().startswith("/goal")
        for path in saved_prompts
    )
    assert all(
        path.read_text(encoding="utf-8").rstrip().endswith("任务才算完成。")
        for path in saved_prompts
    )


def test_rule_cannot_scan_when_positive_negative_codeql_test_fails(
    tmp_path: Path,
) -> None:
    GoalOnlyController.reset()
    database_scan_started = threading.Event()

    def fake_builder(repo: Path, output: Path, **_kwargs: Any) -> dict[str, Any]:
        database = output / "databases" / "one"
        (database / "db-cpp").mkdir(parents=True)
        return {
            "shards": [
                {"shard_id": "one", "database": str(database), "status": "built"}
            ]
        }

    def fake_subprocess(command, **_kwargs):
        if command[0] == "git":
            return SimpleNamespace(returncode=0, stdout="abc123\n", stderr="")
        if command[1:3] == ["test", "run"]:
            return SimpleNamespace(
                returncode=1,
                stdout="negative.cpp produced an unexpected result",
                stderr="",
            )
        database_scan_started.set()
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    result = CodeQLGitAuditWorkflow(
        CodeQLAuditWorkflowConfig(
            project_dir=tmp_path,
            output_mode="quiet",
            task_retries=0,
            task_retry_delay_seconds=0,
        ),
        _controller_factory=GoalOnlyController,
        _database_builder=fake_builder,
        _subprocess_run=fake_subprocess,
    ).run()

    assert result.status is CodeQLAuditStatus.FAILED
    assert result.rules_total == 0
    assert not database_scan_started.is_set()
    assert any("CodeQL tests failed" in failure for failure in result.failed_tasks)


def _prepare_history_validation(tmp_path: Path) -> tuple[CodeQLGitAuditWorkflow, Path]:
    workflow = CodeQLGitAuditWorkflow(
        CodeQLAuditWorkflowConfig(
            project_dir=tmp_path,
            codeql="/bin/true",
            output_mode="quiet",
            task_retry_delay_seconds=0,
        )
    )
    workflow._prepare_directories()
    workflow._install_history_qlpack()
    GoalOnlyController(cwd=str(tmp_path))._write_history("abc123")
    report_path = (
        tmp_path
        / "codeql-git-audit"
        / "history-analysis"
        / "commits"
        / "abc123.json"
    )
    return workflow, report_path


def test_missing_qlref_is_rebuilt_from_canonical_query_path(tmp_path: Path) -> None:
    workflow, report_path = _prepare_history_validation(tmp_path)
    qlref = (
        tmp_path
        / "codeql-git-audit"
        / "history-analysis"
        / "query-tests"
        / "abc123-demo"
        / "test.qlref"
    )
    qlref.unlink()

    assessment = workflow._validate_commit_assessment(
        "abc123", "abc123", report_path
    )

    assert assessment.rules[0].rule_id == "demo/history-rule"
    assert qlref.read_text(encoding="utf-8") == "queries/demo.ql\n"


def test_ready_marker_is_canonical_when_commit_rule_copy_drifts(
    tmp_path: Path,
) -> None:
    workflow, report_path = _prepare_history_validation(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report_rule = report["vulnerabilities"][0]["rules"][0]
    report_rule["name"] = "Drifted report-only name"
    report_rule["description"] = "This stale copy must not block scanning."
    report_path.write_text(json.dumps(report), encoding="utf-8")

    assessment = workflow._validate_commit_assessment(
        "abc123", "abc123", report_path
    )

    assert assessment.rules[0].name == "Demo rule"
    normalized = json.loads(report_path.read_text(encoding="utf-8"))
    normalized_rule = normalized["vulnerabilities"][0]["rules"][0]
    assert normalized_rule["name"] == "Demo rule"
    assert normalized_rule["description"] == "Historical missing check"
