from __future__ import annotations

import shutil
from dataclasses import dataclass
from enum import Enum
from typing import TextIO


class OutputMode(str, Enum):
    """How Codex activity is written to the configured output stream."""

    QUIET = "quiet"
    HUMAN = "human"
    DEBUG = "debug"

    @classmethod
    def parse(cls, value: "OutputMode | str") -> "OutputMode":
        if isinstance(value, cls):
            return value
        aliases = {
            "silent": cls.QUIET,
            "none": cls.QUIET,
            "normal": cls.HUMAN,
            "codex": cls.HUMAN,
            "verbose": cls.DEBUG,
        }
        normalized = value.strip().lower()
        if normalized in aliases:
            return aliases[normalized]
        try:
            return cls(normalized)
        except ValueError as exc:
            choices = ", ".join(mode.value for mode in cls)
            raise ValueError(f"output_mode must be one of: {choices}") from exc


def resolve_codex_bin(codex_bin: str | None) -> str | None:
    """Resolve the Codex runtime used by this wrapper.

    An explicit path always wins. Otherwise prefer the ``codex`` executable on
    ``PATH`` so SDK-driven app-server requests use the same runtime as an
    interactive Codex invocation. If Codex is not installed on ``PATH``, leave
    the value unset and let ``openai-codex`` use its pinned bundled runtime.
    """
    if codex_bin is not None:
        return codex_bin
    return shutil.which("codex")


@dataclass(frozen=True, slots=True)
class ResumePolicy:
    """Retry policy used when an active Goal is stopped transiently.

    ``max_attempts=None`` keeps resuming until the Goal reaches a non-retryable
    terminal state or the caller interrupts the process.
    """

    max_attempts: int | None = None
    max_elapsed_seconds: float | None = None
    initial_delay_seconds: float = 5.0
    max_delay_seconds: float = 300.0
    multiplier: float = 2.0
    jitter_ratio: float = 0.2

    def __post_init__(self) -> None:
        if self.max_attempts is not None and self.max_attempts < 0:
            raise ValueError("max_attempts must be >= 0 or None")
        if self.max_elapsed_seconds is not None and self.max_elapsed_seconds <= 0:
            raise ValueError("max_elapsed_seconds must be > 0 or None")
        if self.initial_delay_seconds < 0:
            raise ValueError("initial_delay_seconds must be >= 0")
        if self.max_delay_seconds < 0:
            raise ValueError("max_delay_seconds must be >= 0")
        if self.multiplier < 1:
            raise ValueError("multiplier must be >= 1")
        if not 0 <= self.jitter_ratio <= 1:
            raise ValueError("jitter_ratio must be between 0 and 1")


@dataclass(slots=True)
class ControllerConfig:
    """Runtime configuration for :class:`CodexController`."""

    cwd: str | None = None
    codex_bin: str | None = None
    output_mode: OutputMode | str = OutputMode.HUMAN
    output: TextIO | None = None
    resume_policy: ResumePolicy | None = None

    def __post_init__(self) -> None:
        self.codex_bin = resolve_codex_bin(self.codex_bin)
        self.output_mode = OutputMode.parse(self.output_mode)
        if self.resume_policy is None:
            self.resume_policy = ResumePolicy()
