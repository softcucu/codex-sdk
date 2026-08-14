"""Resilient Python control for OpenAI Codex and thread-scoped Goals."""

from openai_codex import ApprovalMode, CodexConfig, Sandbox

from .config import ControllerConfig, OutputMode, ResumePolicy
from .controller import CodexController
from .errors import (
    CodexControllerError,
    GoalResumeExhaustedError,
    IncompatibleCodexSdkError,
    NoActiveGoalError,
)
from .models import GoalResult, GoalState, RunResult

__all__ = [
    "ApprovalMode",
    "CodexConfig",
    "Sandbox",
    "CodexController",
    "ControllerConfig",
    "OutputMode",
    "ResumePolicy",
    "GoalState",
    "GoalResult",
    "RunResult",
    "CodexControllerError",
    "GoalResumeExhaustedError",
    "IncompatibleCodexSdkError",
    "NoActiveGoalError",
]

__version__ = "0.1.0"

