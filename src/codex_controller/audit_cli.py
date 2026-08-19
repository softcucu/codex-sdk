from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .audit_workflow import (
    AuditWorkflowConfig,
    AuditWorkflowError,
    VulnerabilityAuditWorkflow,
)
from .config import OutputMode, ResumePolicy


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def _positive_int(value: str) -> int:
    parsed = _non_negative_int(value)
    if parsed == 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return parsed


def _non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def _positive_float(value: str) -> float:
    parsed = _non_negative_float(value)
    if parsed == 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return parsed


def _project_directory(value: str) -> str:
    path = Path(value).expanduser().resolve()
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"project directory does not exist: {path}")
    return str(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codex-vuln-audit",
        description=(
            "Run durable high-risk-module discovery and DoS vulnerability audits."
        ),
    )
    parser.add_argument(
        "--cwd",
        "-C",
        type=_project_directory,
        default=_project_directory("."),
        help="target project directory (default: current directory)",
    )
    parser.add_argument(
        "--output-dir",
        help="output directory inside the target project (default: protocol-analysis)",
    )
    parser.add_argument("--codex-bin", help="path to a specific Codex executable")
    parser.add_argument("--model", help="default model for all workflow stages")
    parser.add_argument("--attack-surface-model", help="model for attack-surface analysis")
    parser.add_argument("--message-model", help="model for message audits")
    parser.add_argument("--protocol-model", help="model for high-risk module DoS audits")
    parser.add_argument("--attack-surface-token-budget", type=_positive_int)
    parser.add_argument("--message-token-budget", type=_positive_int)
    parser.add_argument("--protocol-token-budget", type=_positive_int)
    parser.add_argument(
        "--max-workers",
        type=_positive_int,
        default=4,
        help="maximum concurrent high-risk module Goals (default: 4)",
    )
    parser.add_argument(
        "--task-retries",
        type=_non_negative_int,
        default=2,
        help="fresh Goal retries after terminal task failures (default: 2)",
    )
    parser.add_argument(
        "--task-retry-delay",
        type=_non_negative_float,
        default=5.0,
        help="initial delay between fresh Goal attempts (default: 5 seconds)",
    )
    parser.add_argument(
        "--max-resumes",
        type=_non_negative_int,
        default=None,
        help="maximum automatic resumes inside each Goal (default: unlimited)",
    )
    parser.add_argument("--max-elapsed-seconds", type=_positive_float)
    parser.add_argument("--initial-delay", type=_non_negative_float, default=5.0)
    parser.add_argument("--max-delay", type=_non_negative_float, default=300.0)
    parser.add_argument(
        "--output-mode",
        choices=[mode.value for mode in OutputMode],
        default=OutputMode.HUMAN.value,
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="start a new workflow generation and rerun all stages",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    resume_policy = ResumePolicy(
        max_attempts=args.max_resumes,
        max_elapsed_seconds=args.max_elapsed_seconds,
        initial_delay_seconds=args.initial_delay,
        max_delay_seconds=args.max_delay,
    )
    try:
        config = AuditWorkflowConfig(
            project_dir=args.cwd,
            output_dir=args.output_dir,
            codex_bin=args.codex_bin,
            model=args.model,
            attack_surface_model=args.attack_surface_model,
            message_model=args.message_model,
            protocol_model=args.protocol_model,
            attack_surface_token_budget=args.attack_surface_token_budget,
            message_token_budget=args.message_token_budget,
            protocol_token_budget=args.protocol_token_budget,
            max_workers=args.max_workers,
            task_retries=args.task_retries,
            task_retry_delay_seconds=args.task_retry_delay,
            resume_policy=resume_policy,
            output_mode=args.output_mode,
        )
        result = VulnerabilityAuditWorkflow(config).run(force=args.force)
    except KeyboardInterrupt:
        print(
            "Interrupted; workflow state and active Goal thread IDs were saved.",
            file=sys.stderr,
        )
        return 130
    except (AuditWorkflowError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(
        f"audit workflow {result.status.value}: "
        f"{result.high_risk_module_completed}/"
        f"{result.high_risk_module_total} high-risk modules, "
        f"{result.confirmed_findings} confirmed findings; "
        f"results: {result.results_dir}"
    )
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
