"""Resilient Codex control primitives and reusable audit workflows."""

from __future__ import annotations

import sys as _sys

from openai_codex import ApprovalMode, CodexConfig, Sandbox

from .common.config import ControllerConfig, OutputMode, ResumePolicy, resolve_codex_bin
from .common.controller import CodexController
from .common.errors import (
    CodexControllerError,
    GoalResumeExhaustedError,
    IncompatibleCodexSdkError,
    NoActiveGoalError,
)
from .common.models import GoalResult, GoalState, RunResult
from .common.pool import CodexThreadPool, GoalTask, RunTask
from .workflows.codeql_git_audit.workflow import (
    CodeQLAuditAlreadyRunningError,
    CodeQLAuditOutputValidationError,
    CodeQLAuditStatus,
    CodeQLAuditWorkflowConfig,
    CodeQLAuditWorkflowError,
    CodeQLAuditWorkflowResult,
    CodeQLGitAuditWorkflow,
)
from .workflows.vulnerability_audit.workflow import (
    AuditOutputValidationError,
    AuditWorkflowAlreadyRunningError,
    AuditWorkflowConfig,
    AuditWorkflowError,
    AuditWorkflowResult,
    AuditWorkflowStatus,
    VulnerabilityAuditWorkflow,
)

# Keep the pre-refactor module paths importable. These are module aliases rather
# than duplicate shim files, so implementation code still has one canonical home.
from .common import _backend as _backend
from .common import cli as cli
from .common import config as config
from .common import controller as controller
from .common import errors as errors
from .common import models as models
from .common import pool as pool
from .common import render as render
from .workflows.codeql_git_audit import cli as codeql_audit_cli
from .workflows.codeql_git_audit import cmake_splitter as codeql_cmake_split_db_semantic_v4
from .workflows.codeql_git_audit import database_builder as codeql_database_builder
from .workflows.codeql_git_audit import workflow as codeql_audit_workflow
from .workflows.vulnerability_audit import cli as audit_cli
from .workflows.vulnerability_audit import workflow as audit_workflow

_COMPATIBILITY_MODULES = {
    "_backend": _backend,
    "audit_cli": audit_cli,
    "audit_workflow": audit_workflow,
    "cli": cli,
    "codeql_audit_cli": codeql_audit_cli,
    "codeql_audit_workflow": codeql_audit_workflow,
    "codeql_cmake_split_db_semantic_v4": codeql_cmake_split_db_semantic_v4,
    "codeql_database_builder": codeql_database_builder,
    "config": config,
    "controller": controller,
    "errors": errors,
    "models": models,
    "pool": pool,
    "render": render,
}
for _module_name, _module in _COMPATIBILITY_MODULES.items():
    _sys.modules.setdefault(f"{__name__}.{_module_name}", _module)


__all__ = [
    "ApprovalMode",
    "CodexConfig",
    "Sandbox",
    "AuditWorkflowConfig",
    "AuditWorkflowResult",
    "AuditWorkflowStatus",
    "VulnerabilityAuditWorkflow",
    "AuditWorkflowError",
    "AuditWorkflowAlreadyRunningError",
    "AuditOutputValidationError",
    "CodeQLAuditWorkflowConfig",
    "CodeQLAuditWorkflowResult",
    "CodeQLAuditStatus",
    "CodeQLGitAuditWorkflow",
    "CodeQLAuditWorkflowError",
    "CodeQLAuditAlreadyRunningError",
    "CodeQLAuditOutputValidationError",
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
