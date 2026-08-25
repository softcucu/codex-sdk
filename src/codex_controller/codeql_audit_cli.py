from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .codeql_audit_workflow import (
    CodeQLAuditWorkflowConfig,
    CodeQLAuditWorkflowError,
    CodeQLGitAuditWorkflow,
)
from .config import OutputMode, ResumePolicy


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return parsed


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def _non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def _project_dir(value: str) -> str:
    path = Path(value).expanduser().resolve()
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"project directory does not exist: {path}")
    return str(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codex-codeql-git-audit",
        description=(
            "Build semantic CodeQL DB shards while independent Codex Goals classify "
            "one Git commit each; scan every rule as soon as it is published and "
            "review findings with independent Goals."
        ),
    )
    parser.add_argument("--cwd", "-C", type=_project_dir, default=_project_dir("."))
    parser.add_argument(
        "--output-dir",
        help="output directory inside the project (default: codeql-git-audit)",
    )
    parser.add_argument("--codeql", default="codeql", help="CodeQL CLI executable")
    parser.add_argument("--codex-bin", help="path to a specific Codex executable")
    parser.add_argument("--model", help="default Codex model")
    parser.add_argument("--history-model", help="model for Git-history rule generation")
    parser.add_argument("--review-model", help="model for finding confirmation")
    parser.add_argument(
        "--history-token-budget",
        type=_positive_int,
        help="token budget for each per-commit Goal",
    )
    parser.add_argument(
        "--review-token-budget",
        type=_positive_int,
        help="token budget for each finding-review Goal",
    )
    parser.add_argument("--target-loc", type=_positive_int, default=400_000)
    parser.add_argument("--max-loc", type=_positive_int, default=400_000)
    parser.add_argument("--min-loc", type=_non_negative_int, default=100_000)
    parser.add_argument("--database-threads", type=_non_negative_int, default=0)
    parser.add_argument("--database-ram", type=_positive_int, dest="database_ram_mb")
    parser.add_argument("--scan-threads", type=_non_negative_int, default=0)
    parser.add_argument("--scan-ram", type=_positive_int, dest="scan_ram_mb")
    parser.add_argument("--scan-workers", type=_positive_int, default=2)
    parser.add_argument(
        "--history-workers",
        type=_positive_int,
        default=4,
        help="concurrent per-commit security-fix Goals (default: 4)",
    )
    parser.add_argument("--review-workers", type=_positive_int, default=4)
    parser.add_argument(
        "--history-max-commits",
        type=_positive_int,
        help="analyze only the newest N commits (default: all commits)",
    )
    parser.add_argument(
        "--max-findings",
        type=_positive_int,
        help="optional global review cap (default: review every deduplicated finding)",
    )
    parser.add_argument(
        "--max-findings-per-rule",
        type=_positive_int,
        help="optional per-rule review cap (default: unlimited)",
    )
    parser.add_argument("--task-retries", type=_non_negative_int, default=2)
    parser.add_argument("--task-retry-delay", type=_non_negative_float, default=5.0)
    parser.add_argument("--max-resumes", type=_non_negative_int)
    parser.add_argument("--max-elapsed-seconds", type=float)
    parser.add_argument("--exclude-dir", action="append", default=[])
    parser.add_argument(
        "--materialize-mode",
        choices=["hardlink", "copy", "symlink"],
        default="hardlink",
    )
    parser.add_argument(
        "--output-mode",
        choices=[mode.value for mode in OutputMode],
        default=OutputMode.HUMAN.value,
    )
    parser.add_argument("--force", action="store_true", help="rerun every stage")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.max_elapsed_seconds is not None and args.max_elapsed_seconds <= 0:
        print("error: --max-elapsed-seconds must be > 0", file=sys.stderr)
        return 1
    try:
        config = CodeQLAuditWorkflowConfig(
            project_dir=args.cwd,
            output_dir=args.output_dir,
            codeql=args.codeql,
            codex_bin=args.codex_bin,
            model=args.model,
            history_model=args.history_model,
            review_model=args.review_model,
            history_token_budget=args.history_token_budget,
            review_token_budget=args.review_token_budget,
            target_loc=args.target_loc,
            max_loc=args.max_loc,
            min_loc=args.min_loc,
            database_threads=args.database_threads,
            database_ram_mb=args.database_ram_mb,
            scan_threads=args.scan_threads,
            scan_ram_mb=args.scan_ram_mb,
            scan_workers=args.scan_workers,
            history_workers=args.history_workers,
            review_workers=args.review_workers,
            history_max_commits=args.history_max_commits,
            max_findings=args.max_findings,
            max_findings_per_rule=args.max_findings_per_rule,
            task_retries=args.task_retries,
            task_retry_delay_seconds=args.task_retry_delay,
            exclude_dirs=tuple(args.exclude_dir),
            materialize_mode=args.materialize_mode,
            resume_policy=ResumePolicy(
                max_attempts=args.max_resumes,
                max_elapsed_seconds=args.max_elapsed_seconds,
            ),
            output_mode=args.output_mode,
        )
        result = CodeQLGitAuditWorkflow(config).run(force=args.force)
    except KeyboardInterrupt:
        print("Interrupted; generated artifacts and Goal state were kept.", file=sys.stderr)
        return 130
    except (CodeQLAuditWorkflowError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        f"CodeQL Git audit {result.status.value}: "
        f"databases={result.database_completed}/{result.database_total}, "
        f"commits={result.commit_completed}/{result.commit_total}, "
        f"security_commits={result.security_commit_total}, "
        f"rules={result.rules_total}, suspicious={result.suspicious_total}, "
        f"confirmed={result.confirmed_total}, inconclusive={result.inconclusive_total}; "
        f"output={result.output_dir}"
    )
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
