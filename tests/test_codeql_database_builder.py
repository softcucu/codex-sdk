from __future__ import annotations

from pathlib import Path

from codex_controller.codeql_database_builder import build_repository_codeql_databases


def test_non_cmake_repository_uses_build_boundaries_and_include_closure(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / "src" / "server").mkdir(parents=True)
    (repo / "include").mkdir()
    (repo / "Makefile").write_text("all:\n\t@true\n", encoding="utf-8")
    (repo / "src" / "server" / "meson.build").write_text(
        "# semantic boundary\n", encoding="utf-8"
    )
    (repo / "src" / "server" / "main.c").write_text(
        '#include "public.h"\nint main(void) { return api(); }\n',
        encoding="utf-8",
    )
    (repo / "include" / "public.h").write_text(
        "int api(void);\n", encoding="utf-8"
    )

    output = repo / "audit-output" / "database-stage"
    manifest = build_repository_codeql_databases(
        repo,
        output,
        plan_only=True,
        target_loc=10,
        max_loc=20,
        min_loc=0,
        progress=False,
    )

    assert manifest["analysis_mode"].startswith("non-cmake")
    assert manifest["repository_stats"]["indexed_cpp_files"] == 2
    assert manifest["repository_stats"]["build_boundary_modules"] >= 2
    assert manifest["shards"]
    planned_files = set()
    for filelist in (output / "filelists").glob("*.files.txt"):
        planned_files.update(filelist.read_text(encoding="utf-8").splitlines())
    assert planned_files == {"include/public.h", "src/server/main.c"}


def test_cmake_repository_delegates_to_v4(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "CMakeLists.txt").write_text("project(demo)\n", encoding="utf-8")
    captured = {}

    class FakeV4:
        @staticmethod
        def build_split_codeql_databases(repo_path, output_dir, **kwargs):
            captured["repo"] = repo_path
            captured["output"] = output_dir
            captured["kwargs"] = kwargs
            return {"analysis_mode": "v4", "shards": []}

    monkeypatch.setattr(
        "codex_controller.codeql_database_builder._load_cmake_v4",
        lambda: FakeV4,
    )

    result = build_repository_codeql_databases(
        repo,
        repo / "out",
        plan_only=True,
        progress=False,
    )

    assert result["analysis_mode"] == "v4"
    assert captured["repo"] == repo.resolve()
    assert captured["kwargs"]["plan_only"] is True
