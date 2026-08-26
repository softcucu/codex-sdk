"""Command-line entry point for running Codex against a project.

Example:
    .venv/bin/python main.py \
        --project-path /path/to/repository \
        --model your-codex-model \
        --retry-count 3 \
        --prompt "Fix the failing tests and verify the result"
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from codex_controller import (
    ApprovalMode,
    CodexController,
    ResumePolicy,
    Sandbox,
)


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be greater than or equal to 0")
    return parsed


def _positive_int(value: str) -> int:
    parsed = _non_negative_int(value)
    if parsed == 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def _non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be greater than or equal to 0")
    return parsed


def _positive_float(value: str) -> float:
    parsed = _non_negative_float(value)
    if parsed == 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def _project_directory(value: str) -> str:
    path = Path(value).expanduser().resolve()
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"project directory does not exist: {path}")
    return str(path)


def _prompt_from_file(value: str) -> str:
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"prompt file does not exist: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise argparse.ArgumentTypeError(
            f"cannot read prompt file as UTF-8: {path}: {exc}"
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a Codex task in the specified project directory."
    )
    parser.add_argument(
        "-C",
        "--project-path",
        "--cwd",
        dest="project_path",
        type=_project_directory,
        default=_project_directory("."),
        help="Codex project directory (default: current directory)",
    )
    parser.add_argument("-m", "--model", help="Codex model; defaults to Codex configuration")
    parser.add_argument(
        "-r",
        "--retry-count",
        "--max-resumes",
        dest="retry_count",
        type=_non_negative_int,
        default=None,
        help="maximum automatic Goal resumes (default: unlimited)",
    )
    prompt_source = parser.add_mutually_exclusive_group(required=True)
    prompt_source.add_argument(
        "-p",
        "--prompt",
        dest="prompt",
        help="task prompt or Goal objective",
    )
    prompt_source.add_argument(
        "--prompt-file",
        dest="prompt",
        metavar="PATH",
        type=_prompt_from_file,
        help="read the task prompt from a UTF-8 text file",
    )
    parser.add_argument(
        "--task-type",
        choices=("goal", "run"),
        default="goal",
        help="resilient Goal or one ordinary turn (default: goal)",
    )
    parser.add_argument(
        "--token-budget",
        type=_positive_int,
        help="Goal token budget; only used with --task-type goal",
    )
    parser.add_argument(
        "--max-elapsed-seconds",
        type=_positive_float,
        help="maximum total time spent running/resuming a Goal",
    )
    parser.add_argument(
        "--initial-delay",
        type=_non_negative_float,
        default=5.0,
        help="initial retry delay in seconds (default: 5)",
    )
    parser.add_argument(
        "--max-delay",
        type=_non_negative_float,
        default=300.0,
        help="maximum retry delay in seconds (default: 300)",
    )
    parser.add_argument(
        "--output-mode",
        choices=("quiet", "human", "debug"),
        default="human",
        help="Codex event output format (default: human)",
    )
    parser.add_argument("--thread-id", help="continue an existing Codex thread")
    parser.add_argument(
        "--codex-bin",
        help="path to a specific Codex executable (default: codex on PATH, then SDK runtime)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    policy = ResumePolicy(
        max_attempts=args.retry_count,
        max_elapsed_seconds=args.max_elapsed_seconds,
        initial_delay_seconds=args.initial_delay,
        max_delay_seconds=args.max_delay,
    )

    codex: CodexController | None = None
    try:
        codex = CodexController(
            cwd=args.project_path,
            codex_bin=args.codex_bin,
            thread_id=args.thread_id,
            output_mode=args.output_mode,
            resume_policy=policy,
        )
        thread_options = {
            "sandbox": Sandbox.workspace_write,
            "approval_mode": ApprovalMode.deny_all,
        }
        if args.model is not None:
            thread_options["model"] = args.model
        if args.thread_id is None:
            codex.start_thread(**thread_options)
        else:
            codex.resume_thread(args.thread_id, **thread_options)

        if args.task_type == "run":
            result = codex.run(args.prompt, model=args.model)
        else:
            result = codex.goal(
                args.prompt,
                model=args.model,
                token_budget=args.token_budget,
            )
        return 0 if result.completed else 2
    except KeyboardInterrupt:
        print("Interrupted; the Goal has been paused.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if codex is not None:
            codex.close()


if __name__ == "__main__":
    raise SystemExit(main())
