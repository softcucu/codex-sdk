"""Resilient Python control for OpenAI Codex and thread-scoped Goals."""

from openai_codex import ApprovalMode, CodexConfig, Sandbox

from .config import ControllerConfig, OutputMode, ResumePolicy, resolve_codex_bin
from .controller import CodexController
from .errors import (
    CodexControllerError,
    GoalResumeExhaustedError,
    IncompatibleCodexSdkError,
    NoActiveGoalError,
)
from .models import GoalResult, GoalState, RunResult
from .pool import CodexThreadPool, GoalTask, RunTask

__all__ = [
    "ApprovalMode",
    "CodexConfig",
    "Sandbox",
    "CodexController",
    "ControllerConfig",
    "OutputMode",
    "ResumePolicy",
    "resolve_codex_bin",
    "GoalState",
    "GoalResult",
    "RunResult",
    "CodexThreadPool",
    "GoalTask",
    "RunTask",
    "CodexControllerError",
    "GoalResumeExhaustedError",
    "IncompatibleCodexSdkError",
    "NoActiveGoalError",
]

__version__ = "0.2.3"
