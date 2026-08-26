from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence


CPP_SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cp",
    ".cpp",
    ".cxx",
    ".c++",
    ".m",
    ".mm",
}
CPP_HEADER_EXTENSIONS = {
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".h++",
    ".inc",
    ".inl",
    ".ipp",
    ".tpp",
    ".txx",
}
CPP_EXTENSIONS = CPP_SOURCE_EXTENSIONS | CPP_HEADER_EXTENSIONS

DEFAULT_EXCLUDED_DIRECTORIES = {
    ".cache",
    ".ccache",
    ".git",
    ".hg",
    ".idea",
    ".svn",
    ".vscode",
    "BUILD",
    "Build",
    "__pycache__",
    "build",
    "codeql-db",
    "dist",
    "node_modules",
    "out",
}

NON_CMAKE_BUILD_FILES = {
    "BUILD",
    "BUILD.bazel",
    "GNUmakefile",
    "Makefile",
    "configure.ac",
    "configure.in",
    "makefile",
    "meson.build",
    "SConstruct",
}
NON_CMAKE_BUILD_SUFFIXES = {".mk", ".pri", ".pro"}
CONVENTIONAL_SOURCE_DIRECTORIES = {
    "apps",
    "components",
    "include",
    "lib",
    "libs",
    "modules",
    "packages",
    "plugins",
    "src",
    "tools",
}

_INCLUDE_RE = re.compile(
    r"^\s*#\s*include\s*([<\"])([^>\"]+)[>\"]", re.MULTILINE
)


class CodeQLDatabaseBuildError(RuntimeError):
    """Raised when repository partitioning or CodeQL DB creation fails."""


@dataclass(slots=True)
class _GenericUnit:
    unit_id: str
    module: str
    files: set[str]
    loc: int
    source_files: int
    header_files: int
    oversized: bool = False


@dataclass(slots=True)
class _GenericShard:
    shard_id: str
    modules: list[str]
    unit_ids: list[str]
    files: set[str]
    loc: int
    source_files: int
    header_files: int
    oversized: bool = False


def build_repository_codeql_databases(
    repo_path: str | Path,
    output_dir: str | Path,
    *,
    codeql: str = "codeql",
    target_loc: int = 400_000,
    max_loc: int = 400_000,
    min_loc: int = 100_000,
    exclude_dirs: Sequence[str] = (),
    max_include_ambiguity: int = 20,
    language: str = "c-cpp",
    threads: int | None = 0,
    ram_mb: int | None = None,
    materialize_mode: str = "hardlink",
    force: bool = False,
    resume: bool = True,
    plan_only: bool = False,
    stop_on_error: bool = False,
    progress: bool = True,
) -> dict[str, Any]:
    """Build semantic CodeQL database shards for a C/C++ repository.

    CMake repositories use the v4 CMake target/dependency implementation. Other
    repositories use build-description directories plus repository-local include
    relationships as conservative semantic boundaries.
    """

    repo = Path(repo_path).expanduser().resolve()
    output = Path(output_dir).expanduser().resolve()
    if not repo.is_dir():
        raise FileNotFoundError(f"repository does not exist: {repo}")
    if language != "c-cpp":
        raise ValueError("the semantic splitter currently supports language='c-cpp'")
    if target_loc <= 0 or max_loc <= 0 or min_loc < 0:
        raise ValueError("target_loc/max_loc must be positive and min_loc non-negative")
    if target_loc > max_loc:
        raise ValueError("target_loc cannot exceed max_loc")
    if materialize_mode not in {"hardlink", "copy", "symlink"}:
        raise ValueError("invalid materialize_mode")

    excludes = set(DEFAULT_EXCLUDED_DIRECTORIES) | set(exclude_dirs)
    try:
        relative_output = output.relative_to(repo)
    except ValueError:
        pass
    else:
        if relative_output.parts:
            excludes.add(relative_output.parts[0])

    if _has_cmake(repo, excludes):
        splitter = _load_cmake_v4()
        return splitter.build_split_codeql_databases(
            repo,
            output,
            codeql=codeql,
            target_loc=target_loc,
            max_loc=max_loc,
            min_loc=min_loc,
            exclude_dirs=tuple(sorted(excludes)),
            max_include_ambiguity=max_include_ambiguity,
            language=language,
            threads=threads,
            ram_mb=ram_mb,
            materialize_mode=materialize_mode,
            force=force,
            resume=resume,
            plan_only=plan_only,
            stop_on_error=stop_on_error,
            progress=progress,
        )

    return _build_generic_cpp_databases(
        repo,
        output,
        codeql=codeql,
        target_loc=target_loc,
        max_loc=max_loc,
        min_loc=min_loc,
        excludes=excludes,
        max_include_ambiguity=max_include_ambiguity,
        threads=threads,
        ram_mb=ram_mb,
        materialize_mode=materialize_mode,
        force=force,
        resume=resume,
        plan_only=plan_only,
        stop_on_error=stop_on_error,
        progress=progress,
    )


def _load_cmake_v4() -> Any:
    errors: list[str] = []
    for name in (
        "codex_controller.workflows.codeql_git_audit.cmake_splitter",
        "codeql_cmake_split_db_semantic_v4",
        "codex_controller.codeql_cmake_split_db_semantic_v4",
    ):
        try:
            return importlib.import_module(name)
        except ImportError as exc:
            errors.append(str(exc))
    source_checkout = Path(__file__).resolve().with_name("cmake_splitter.py")
    if source_checkout.is_file():
        spec = importlib.util.spec_from_file_location(
            "_codex_controller_cmake_split_v4", source_checkout
        )
        if spec is not None and spec.loader is not None:
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            try:
                spec.loader.exec_module(module)
            except BaseException:
                sys.modules.pop(spec.name, None)
                raise
            return module
    raise CodeQLDatabaseBuildError(
        "cannot import codeql_cmake_split_db_semantic_v4; "
        "install the package with the bundled splitter (" + "; ".join(errors) + ")"
    )


def _has_cmake(repo: Path, excludes: set[str]) -> bool:
    for path in _walk_files(repo, excludes):
        if path.name.lower() == "cmakelists.txt":
            return True
    return False


def _walk_files(repo: Path, excludes: set[str]) -> Iterator[Path]:
    for base, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in excludes)
        root = Path(base)
        for filename in sorted(files):
            yield root / filename


def _build_generic_cpp_databases(
    repo: Path,
    output: Path,
    *,
    codeql: str,
    target_loc: int,
    max_loc: int,
    min_loc: int,
    excludes: set[str],
    max_include_ambiguity: int,
    threads: int | None,
    ram_mb: int | None,
    materialize_mode: str,
    force: bool,
    resume: bool,
    plan_only: bool,
    stop_on_error: bool,
    progress: bool,
) -> dict[str, Any]:
    started = time.monotonic()
    output.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    build_dirs: set[str] = set()
    for path in _walk_files(repo, excludes):
        relative = path.relative_to(repo).as_posix()
        if path.suffix.lower() in CPP_EXTENSIONS:
            paths[relative] = path
        if path.name in NON_CMAKE_BUILD_FILES or path.suffix.lower() in NON_CMAKE_BUILD_SUFFIXES:
            build_dirs.add(path.parent.relative_to(repo).as_posix() or ".")
    if not paths:
        raise CodeQLDatabaseBuildError("no C/C++ source or header files found")

    loc = {relative: _count_loc(path) for relative, path in paths.items()}
    module_roots = _discover_generic_modules(paths, build_dirs)
    owner_files: dict[str, set[str]] = {module: set() for module in module_roots}
    for relative in paths:
        owner_files[_nearest_module(relative, module_roots)].add(relative)

    include_graph, unresolved = _build_include_graph(
        paths,
        max_include_ambiguity=max_include_ambiguity,
    )
    units: list[_GenericUnit] = []
    empty_modules: list[str] = []
    for module in sorted(module_roots):
        owned = owner_files[module]
        if not owned:
            empty_modules.append(module)
            continue
        units.extend(
            _generic_module_units(
                module,
                owned,
                include_graph,
                loc,
                max_loc=max_loc,
            )
        )
    if not units:
        raise CodeQLDatabaseBuildError("no semantic C/C++ units could be derived")
    shards = _pack_generic_units(units, loc, target_loc, max_loc, min_loc)

    manifest: dict[str, Any] = {
        "repository": str(repo),
        "output_dir": str(output),
        "analysis_mode": "non-cmake build-boundaries + directory ownership + include closure",
        "codeql_build_mode": "none",
        "sizing_policy": {
            "target_loc": target_loc,
            "max_loc": max_loc,
            "min_loc": min_loc,
        },
        "repository_stats": {
            "build_boundary_modules": len(module_roots),
            "indexed_cpp_files": len(paths),
            "indexed_cpp_loc": sum(loc.values()),
            "atomic_units": len(units),
            "planned_shards": len(shards),
            "unresolved_includes": unresolved,
        },
        "empty_or_metadata_only_modules": empty_modules,
        "shards": [
            {
                "shard_id": shard.shard_id,
                "database": str(output / "databases" / shard.shard_id),
                "status": "planned",
                "loc": shard.loc,
                "files": len(shard.files),
                "source_files": shard.source_files,
                "header_files": shard.header_files,
                "modules": shard.modules,
                "targets": [],
                "unit_ids": shard.unit_ids,
                "oversized": shard.oversized,
            }
            for shard in shards
        ],
        "limitations": [
            "Without CMake, static build-file and directory boundaries approximate build targets.",
            "Repository-local include closure is conservative and ambiguous includes may be duplicated.",
            "build-mode=none does not reproduce an instrumented C/C++ build.",
        ],
    }
    manifest_path = output / "manifest.json"
    _atomic_json(manifest_path, manifest)
    filelists = output / "filelists"
    filelists.mkdir(exist_ok=True)
    for shard in shards:
        (filelists / f"{shard.shard_id}.files.txt").write_text(
            "\n".join(sorted(shard.files)) + "\n", encoding="utf-8"
        )
    if plan_only:
        return manifest

    codeql_executable = _resolve_executable(codeql)
    temp_root = output / ".tmp_slices"
    temp_root.mkdir(exist_ok=True)
    failures = 0
    for index, (entry, shard) in enumerate(zip(manifest["shards"], shards), 1):
        if progress:
            print(
                f"[codeql-db] {index}/{len(shards)} {shard.shard_id}: "
                f"{shard.loc:,} LOC, {len(shard.files):,} files",
                flush=True,
            )
        result = _create_generic_database(
            codeql_executable,
            repo,
            output,
            shard,
            temp_root,
            threads=threads,
            ram_mb=ram_mb,
            materialize_mode=materialize_mode,
            force=force,
            resume=resume,
        )
        entry.update(result)
        if result["status"].startswith("failed"):
            failures += 1
        _atomic_json(manifest_path, manifest)
        if failures and stop_on_error:
            break

    if temp_root.is_dir():
        try:
            temp_root.rmdir()
        except OSError:
            pass
    manifest["summary"] = {
        "built": sum(item.get("status") == "built" for item in manifest["shards"]),
        "skipped_existing": sum(
            item.get("status") == "skipped-existing" for item in manifest["shards"]
        ),
        "failed": sum(
            str(item.get("status", "")).startswith("failed")
            for item in manifest["shards"]
        ),
        "total": len(manifest["shards"]),
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }
    _atomic_json(manifest_path, manifest)
    return manifest


def _discover_generic_modules(
    files: dict[str, Path], build_dirs: set[str]
) -> list[str]:
    candidates = set(build_dirs)
    source_parents = {
        Path(relative).parent.as_posix() or "."
        for relative in files
        if Path(relative).suffix.lower() in CPP_SOURCE_EXTENSIONS
    }
    top_level_with_sources: set[str] = set()
    conventional_children: set[str] = set()
    for parent in source_parents:
        parts = Path(parent).parts
        if parts:
            top_level_with_sources.add(parts[0])
        if len(parts) >= 2 and parts[0].casefold() in CONVENTIONAL_SOURCE_DIRECTORIES:
            conventional_children.add(Path(*parts[:2]).as_posix())
    candidates.update(top_level_with_sources)
    candidates.update(conventional_children)
    candidates.add(".")
    return sorted(candidates, key=lambda item: (len(Path(item).parts), item))


def _nearest_module(relative_file: str, modules: Sequence[str]) -> str:
    parent_parts = Path(relative_file).parent.parts
    matches: list[str] = []
    for module in modules:
        if module == ".":
            matches.append(module)
            continue
        parts = Path(module).parts
        if parent_parts[: len(parts)] == parts:
            matches.append(module)
    return max(matches, key=lambda item: (len(Path(item).parts), item))


def _build_include_graph(
    files: dict[str, Path],
    *,
    max_include_ambiguity: int,
) -> tuple[dict[str, set[str]], int]:
    suffix_index: dict[str, list[str]] = defaultdict(list)
    for relative in files:
        parts = Path(relative).parts
        for index in range(len(parts)):
            suffix_index[Path(*parts[index:]).as_posix()].append(relative)

    graph: dict[str, set[str]] = {}
    unresolved = 0
    for relative, path in files.items():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            graph[relative] = set()
            continue
        edges: set[str] = set()
        for match in _INCLUDE_RE.finditer(text):
            quote, include = match.groups()
            normalized = include.replace("\\", "/")
            candidates: list[str] = []
            if quote == '"':
                local = posixpath.normpath(
                    posixpath.join(posixpath.dirname(relative), normalized)
                )
                if not local.startswith("../") and local in files:
                    candidates.append(local)
            suffix_key = posixpath.normpath(normalized)
            if not suffix_key.startswith("../"):
                candidates.extend(suffix_index.get(suffix_key, ()))
            candidates.extend(suffix_index.get(posixpath.basename(suffix_key), ()))
            unique = sorted(set(candidates))
            if not unique or len(unique) > max_include_ambiguity:
                unresolved += 1
                continue
            edges.update(unique)
        graph[relative] = edges
    return graph, unresolved


def _generic_module_units(
    module: str,
    owned: set[str],
    graph: dict[str, set[str]],
    loc: dict[str, int],
    *,
    max_loc: int,
) -> list[_GenericUnit]:
    sources = sorted(
        (item for item in owned if Path(item).suffix.lower() in CPP_SOURCE_EXTENSIONS),
        key=lambda item: (Path(item).parent.as_posix(), item),
    )
    local_headers = {
        item for item in owned if Path(item).suffix.lower() in CPP_HEADER_EXTENSIONS
    }
    if not sources:
        return [_make_generic_unit(f"module:{module}", module, local_headers, loc, max_loc)]

    all_related = _include_closure(set(sources), graph) | local_headers
    if _loc(all_related, loc) <= max_loc:
        return [_make_generic_unit(f"module:{module}", module, all_related, loc, max_loc)]

    chunks: list[list[str]] = []
    current: list[str] = []
    current_related: set[str] = set()
    for source in sources:
        source_related = _include_closure({source}, graph)
        candidate = current_related | source_related
        if current and _loc(candidate, loc) > max_loc:
            chunks.append(current)
            current = []
            current_related = set()
        current.append(source)
        current_related.update(source_related)
    if current:
        chunks.append(current)

    units: list[_GenericUnit] = []
    covered_headers: set[str] = set()
    for index, chunk in enumerate(chunks, 1):
        related = _include_closure(set(chunk), graph)
        covered_headers.update(related & local_headers)
        units.append(
            _make_generic_unit(
                f"module:{module}:part{index:03d}", module, related, loc, max_loc
            )
        )
    orphan_headers = local_headers - covered_headers
    if orphan_headers:
        for header in sorted(orphan_headers):
            smallest = min(units, key=lambda unit: unit.loc)
            candidate = smallest.files | {header}
            if _loc(candidate, loc) <= max_loc:
                smallest.files.add(header)
                smallest.loc = _loc(smallest.files, loc)
                smallest.header_files += 1
            else:
                units.append(
                    _make_generic_unit(
                        f"module:{module}:headers{len(units) + 1:03d}",
                        module,
                        {header},
                        loc,
                        max_loc,
                    )
                )
    return units


def _include_closure(seeds: set[str], graph: dict[str, set[str]]) -> set[str]:
    result = set(seeds)
    queue = deque(seeds)
    while queue:
        current = queue.popleft()
        for related in graph.get(current, ()):
            if related not in result:
                result.add(related)
                queue.append(related)
    return result


def _make_generic_unit(
    unit_id: str,
    module: str,
    files: set[str],
    loc: dict[str, int],
    max_loc: int,
) -> _GenericUnit:
    source_count = sum(Path(item).suffix.lower() in CPP_SOURCE_EXTENSIONS for item in files)
    header_count = sum(Path(item).suffix.lower() in CPP_HEADER_EXTENSIONS for item in files)
    total_loc = _loc(files, loc)
    return _GenericUnit(
        unit_id=unit_id,
        module=module,
        files=set(files),
        loc=total_loc,
        source_files=source_count,
        header_files=header_count,
        oversized=total_loc > max_loc,
    )


def _pack_generic_units(
    units: Sequence[_GenericUnit],
    loc: dict[str, int],
    target_loc: int,
    max_loc: int,
    min_loc: int,
) -> list[_GenericShard]:
    groups: list[list[_GenericUnit]] = []
    current: list[_GenericUnit] = []
    current_files: set[str] = set()
    for unit in sorted(units, key=lambda item: (item.module, item.unit_id)):
        candidate = current_files | unit.files
        candidate_loc = _loc(candidate, loc)
        current_loc = _loc(current_files, loc)
        should_close = bool(current) and (
            candidate_loc > max_loc
            or (
                current_loc >= min_loc
                and candidate_loc >= target_loc
                and abs(target_loc - current_loc) <= abs(target_loc - candidate_loc)
            )
        )
        if should_close:
            groups.append(current)
            current = []
            current_files = set()
        current.append(unit)
        current_files.update(unit.files)
        if _loc(current_files, loc) > max_loc:
            groups.append(current)
            current = []
            current_files = set()
    if current:
        groups.append(current)

    if len(groups) > 1:
        tail_files = set().union(*(unit.files for unit in groups[-1]))
        previous_files = set().union(*(unit.files for unit in groups[-2]))
        if _loc(tail_files, loc) < min_loc and _loc(tail_files | previous_files, loc) <= max_loc:
            groups[-2].extend(groups.pop())

    shards: list[_GenericShard] = []
    for index, group in enumerate(groups, 1):
        files = set().union(*(unit.files for unit in group))
        modules = sorted({unit.module for unit in group})
        total_loc = _loc(files, loc)
        slug = _slug(modules[0] if modules else "root")
        shards.append(
            _GenericShard(
                shard_id=f"shard_{index:04d}_{slug}",
                modules=modules,
                unit_ids=[unit.unit_id for unit in group],
                files=files,
                loc=total_loc,
                source_files=sum(
                    Path(item).suffix.lower() in CPP_SOURCE_EXTENSIONS for item in files
                ),
                header_files=sum(
                    Path(item).suffix.lower() in CPP_HEADER_EXTENSIONS for item in files
                ),
                oversized=total_loc > max_loc or any(unit.oversized for unit in group),
            )
        )
    return shards


def _create_generic_database(
    codeql: str,
    repo: Path,
    output: Path,
    shard: _GenericShard,
    temp_root: Path,
    *,
    threads: int | None,
    ram_mb: int | None,
    materialize_mode: str,
    force: bool,
    resume: bool,
) -> dict[str, Any]:
    database = output / "databases" / shard.shard_id
    if _valid_database(database) and resume and not force:
        return {"status": "skipped-existing", "returncode": 0, "elapsed_seconds": 0.0}
    if database.exists():
        if not force:
            raise FileExistsError(f"database path already exists: {database}")
        if database.is_dir():
            shutil.rmtree(database)
        else:
            database.unlink()

    task_started = time.monotonic()
    slice_dir = Path(tempfile.mkdtemp(prefix=f"{shard.shard_id}-", dir=temp_root))
    try:
        for relative in sorted(shard.files):
            source = (repo / relative).resolve()
            source.relative_to(repo)
            if not source.is_file():
                continue
            destination = slice_dir / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if materialize_mode == "copy":
                shutil.copy2(source, destination)
            elif materialize_mode == "symlink":
                destination.symlink_to(source)
            else:
                try:
                    os.link(source, destination)
                except OSError:
                    shutil.copy2(source, destination)
        command = [
            codeql,
            "database",
            "create",
            str(database),
            "--language=c-cpp",
            "--build-mode=none",
            f"--source-root={slice_dir}",
        ]
        if threads is not None:
            command.append(f"--threads={threads}")
        if ram_mb is not None:
            command.append(f"--ram={ram_mb}")
        completed = subprocess.run(command, check=False)
        if completed.returncode != 0:
            if database.exists():
                shutil.rmtree(database, ignore_errors=True)
            return {
                "status": "failed",
                "returncode": completed.returncode,
                "elapsed_seconds": round(time.monotonic() - task_started, 2),
            }
        return {
            "status": "built",
            "returncode": 0,
            "elapsed_seconds": round(time.monotonic() - task_started, 2),
        }
    finally:
        shutil.rmtree(slice_dir, ignore_errors=True)


def _valid_database(path: Path) -> bool:
    return path.is_dir() and (
        (path / "codeql-database.yml").is_file() or (path / "db-cpp").is_dir()
    )


def _resolve_executable(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or path.parent != Path("."):
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve())
        raise FileNotFoundError(f"executable not found or not executable: {value}")
    found = shutil.which(value)
    if found is None:
        raise FileNotFoundError(f"executable not found in PATH: {value}")
    return found


def _count_loc(path: Path) -> int:
    try:
        with path.open("rb") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def _loc(files: Iterable[str], loc: dict[str, int]) -> int:
    return sum(loc.get(item, 0) for item in set(files))


def _slug(value: str, max_length: int = 48) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip("./"))
    normalized = normalized.strip("._-") or "root"
    if len(normalized) <= max_length:
        return normalized
    digest = hashlib.sha256(normalized.encode()).hexdigest()[:8]
    return normalized[: max_length - 9] + "_" + digest


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)
