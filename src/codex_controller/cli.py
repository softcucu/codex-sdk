from __future__ import annotations

import argparse
import sys
from typing import Sequence

from .config import OutputMode, ResumePolicy
from .controller import CodexController


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codex-goal",
        description="Run Codex turns and resilient Goals from Python's command line.",
    )
    parser.add_argument("--cwd", "-C", help="Codex working directory")
    parser.add_argument(
        "--codex-bin",
        help="Use a specific Codex executable (default: codex on PATH, then SDK runtime)",
    )
    parser.add_argument(
        "--output-mode",
        choices=[mode.value for mode in OutputMode],
        default=OutputMode.HUMAN.value,
    )
    parser.add_argument("--thread-id", help="Resume an existing Codex thread")
    parser.add_argument("--model", help="Model override for this run or Goal")
    parser.add_argument(
        "--max-resumes",
        type=int,
        default=None,
        help="Maximum automatic Goal resumes; default is unlimited",
    )
    parser.add_argument("--initial-delay", type=float, default=5.0)
    parser.add_argument("--max-delay", type=float, default=300.0)

    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Run one ordinary Codex turn")
    run.add_argument("prompt")

    goal = commands.add_parser("goal", help="Start a new resilient Goal")
    goal.add_argument("objective")
    goal.add_argument("--token-budget", type=int)

    commands.add_parser("resume-goal", help="Resume the thread's existing Goal")
    commands.add_parser("show-goal", help="Print the current Goal state")
    commands.add_parser("pause-goal", help="Pause the current Goal")
    commands.add_parser("clear-goal", help="Clear the current Goal")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    policy = ResumePolicy(
        max_attempts=args.max_resumes,
        initial_delay_seconds=args.initial_delay,
        max_delay_seconds=args.max_delay,
    )
    try:
        with CodexController(
            cwd=args.cwd,
            codex_bin=args.codex_bin,
            thread_id=args.thread_id,
            output_mode=args.output_mode,
            resume_policy=policy,
        ) as codex:
            if args.command == "run":
                result = codex.run(args.prompt, model=args.model)
                return 0 if result.completed else 2
            if args.command == "goal":
                result = codex.goal(
                    args.objective,
                    model=args.model,
                    token_budget=args.token_budget,
                )
                return 0 if result.completed else 2
            if args.command == "resume-goal":
                result = codex.resume_goal(model=args.model)
                return 0 if result.completed else 2
            if args.command == "show-goal":
                goal = codex.get_goal()
                print("No Goal" if goal is None else goal)
                return 0
            if args.command == "pause-goal":
                print(codex.pause_goal())
                return 0
            if args.command == "clear-goal":
                return 0 if codex.clear_goal() else 2
    except KeyboardInterrupt:
        print("Interrupted; the Goal has been paused.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
