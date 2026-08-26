from __future__ import annotations

import importlib

import codex_controller
from codex_controller.codex_sdk import CodexController
from codex_controller.workflows.codeql_git_audit import CodeQLGitAuditWorkflow
from codex_controller.workflows.vulnerability_audit import VulnerabilityAuditWorkflow


def test_workflows_are_exposed_from_their_canonical_packages() -> None:
    assert CodexController is codex_controller.CodexController
    assert CodeQLGitAuditWorkflow is codex_controller.CodeQLGitAuditWorkflow
    assert VulnerabilityAuditWorkflow is codex_controller.VulnerabilityAuditWorkflow


def test_legacy_module_paths_alias_the_canonical_modules() -> None:
    old_module = importlib.import_module("codex_controller.codeql_database_builder")
    new_module = importlib.import_module(
        "codex_controller.workflows.codeql_git_audit.database_builder"
    )

    assert old_module is new_module
