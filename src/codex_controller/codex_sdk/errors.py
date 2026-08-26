from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import GoalResult


class CodexControllerError(RuntimeError):
    """Base exception raised by this package."""


class NoActiveGoalError(CodexControllerError):
    """The current thread does not have a Goal to resume or control."""


class GoalResumeExhaustedError(CodexControllerError):
    """The configured automatic resume limit was reached."""

    def __init__(self, message: str, *, partial_result: "GoalResult | None" = None) -> None:
        super().__init__(message)
        self.partial_result = partial_result


class IncompatibleCodexSdkError(CodexControllerError):
    """The installed official SDK does not expose the expected Goal protocol."""

