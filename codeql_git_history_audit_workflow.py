#!/usr/bin/env python3
"""Source-tree launcher for the Git-history-driven CodeQL audit workflow."""

from codex_controller.workflows.codeql_git_audit.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
