#!/usr/bin/env python3
"""
cmake_codeql_slicer.py

Static CMake project slicer for very large C/C++ repositories.

Goal
----
Given a repository, treat every directory containing CMakeLists.txt as a module.
Without configuring or compiling the project, statically approximate:
  * module parent/child hierarchy
  * C/C++ code size (local and subtree)
  * CMake targets and target-to-target dependencies
  * source files referenced by add_library/add_executable/target_sources
  * include directories
  * transitive repository-local #include closure
  * a conservative "minimal" source slice suitable for CodeQL build-mode=none

This is intentionally conservative for security auditing: when CMake conditions or
ambiguous include resolution exist, it prefers a union of possible files rather
than dropping files.

No third-party Python packages are required.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import glob as globlib
import hashlib
import json
import os
import re
import posixpath
import shutil
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple


SOURCE_EXTS = {
    ".c", ".cc", ".cpp", ".cxx", ".c++", ".cp",
    ".m", ".mm",  # occasionally mixed Objective-C/C++ projects
}
HEADER_EXTS = {
    ".h", ".hh", ".hpp", ".hxx", ".h++",
    ".inc", ".inl", ".ipp", ".tpp", ".txx",
}
CODE_EXTS = SOURCE_EXTS | HEADER_EXTS

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg", ".idea", ".vscode",
    "node_modules", "__pycache__",
    "build", "Build", "BUILD", "out", "dist",
    ".cache", ".ccache", ".codeql", "codeql-db",
}

CMAKE_SCOPE_KEYWORDS = {
    "PRIVATE", "PUBLIC", "INTERFACE",
    "BEFORE", "AFTER", "SYSTEM",
    "LINK_PRIVATE", "LINK_PUBLIC", "LINK_INTERFACE_LIBRARIES",
}

TARGET_TYPE_KEYWORDS = {
    "STATIC", "SHARED", "MODULE", "OBJECT", "INTERFACE", "UNKNOWN",
    "IMPORTED", "GLOBAL", "ALIAS", "EXCLUDE_FROM_ALL",
}

TARGET_SOURCE_KEYWORDS = {
    "PRIVATE", "PUBLIC", "INTERFACE",
    "FILE_SET", "TYPE", "BASE_DIRS", "FILES",
    "HEADERS", "CXX_MODULES",
}

LINK_MODIFIERS = {"debug", "optimized", "general"}

PATH_VAR_BUILTINS = {
    "CMAKE_SOURCE_DIR",
    "PROJECT_SOURCE_DIR",
    "CMAKE_CURRENT_SOURCE_DIR",
    "CMAKE_CURRENT_LIST_DIR",
}

def _is_resolved_target_name(name: str) -> bool:
    """Return False for CMake target names that still contain unevaluated syntax.

    A static parser must never turn literals such as ``${target_name}`` or
    generator expressions into real targets; doing so can merge unrelated
    commands into one giant fake target and explode the shard count.
    """
    if not name:
        return False
    return not (
        "${" in name or "$<" in name or "$ENV{" in name or
        "@" in name or ";" in name or "\n" in name
    )


@dataclass
class Command:
    name: str
    args: List[str]
    file: Path
    line: int


@dataclass
class Target:
    name: str
    kind: str = "UNKNOWN"
    defined_file: Optional[str] = None
    defined_dir: Optional[str] = None
    sources: Set[str] = field(default_factory=set)
    include_dirs: Set[str] = field(default_factory=set)
    links: Set[str] = field(default_factory=set)
    build_deps: Set[str] = field(default_factory=set)
    aliases: Set[str] = field(default_factory=set)
    unresolved_sources: Set[str] = field(default_factory=set)
    unresolved_include_dirs: Set[str] = field(default_factory=set)


@dataclass
class Module:
    path: str
    cmake_file: str
    parent: Optional[str]
    children: List[str]
    depth: int
    direct_targets: List[str] = field(default_factory=list)
    subtree_targets: List[str] = field(default_factory=list)
    local_code_files: List[str] = field(default_factory=list)
    subtree_code_files: List[str] = field(default_factory=list)
    local_loc: int = 0
    subtree_loc: int = 0
    direct_cmake_sources: List[str] = field(default_factory=list)
    dependency_targets: List[str] = field(default_factory=list)
    include_dirs: List[str] = field(default_factory=list)
    related_files: List[str] = field(default_factory=list)
    related_loc: int = 0
    related_source_files: int = 0
    related_header_files: int = 0
    unresolved_includes: List[str] = field(default_factory=list)
    unresolved_cmake_references: List[str] = field(default_factory=list)
    fallback_used: bool = False


class CMakeStaticAnalyzer:
    def __init__(self, repo: Path, excludes: Set[str], max_include_ambiguity: int = 20, progress: bool = True):
        self.repo = repo.resolve()
        self.excludes = set(excludes)
        self.max_include_ambiguity = max_include_ambiguity
        self.progress = progress
        self.skip_loc = False
        self._started = time.monotonic()
        self._repo_scanned = False

        self.modules: Dict[str, Module] = {}
        self.commands: List[Command] = []
        self.variables: Dict[str, Set[str]] = defaultdict(set)
        self.targets: Dict[str, Target] = {}
        self.alias_to_target: Dict[str, str] = {}

        self.dir_global_includes: Dict[str, Set[str]] = defaultdict(set)
        self.dir_global_links: Dict[str, Set[str]] = defaultdict(set)
        self.cmake_files_seen: Set[Path] = set()
        self.unresolved_variables: Set[str] = set()
        self.parse_warnings: List[str] = []

        self.repo_code_files: List[Path] = []
        self.rel_to_path: Dict[str, Path] = {}
        self.basename_index: Dict[str, List[Path]] = defaultdict(list)
        self.cmake_script_name_index: Dict[str, List[Path]] = defaultdict(list)
        self._loc_cache: Dict[str, int] = {}
        self._include_parse_cache: Dict[str, List[Tuple[str, bool]]] = {}
        self._target_dep_cache: Dict[Tuple[str, bool], Set[str]] = {}
        self._target_related_cache: Dict[Tuple[str, bool], Tuple[Set[str], Set[str], Set[str], Set[str]]] = {}
        self._include_resolution_cache: Dict[Tuple[str, bool, str, Tuple[str, ...]], Tuple[Tuple[str, ...], bool]] = {}
        self.slow_include_seconds = 3.0

    def log(self, message: str) -> None:
        if self.progress:
            elapsed = time.monotonic() - self._started
            print(f"[{elapsed:8.1f}s] {message}", file=sys.stderr, flush=True)

    # ---------- filesystem ----------

    def is_excluded(self, path: Path) -> bool:
        try:
            rel = path.resolve().relative_to(self.repo)
        except Exception:
            return False
        return any(part in self.excludes for part in rel.parts)

    def walk_files(self, root: Optional[Path] = None) -> Iterator[Path]:
        root = root or self.repo
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in self.excludes]
            b = Path(base)
            for name in files:
                yield b / name

    def rel(self, p: Path) -> Optional[str]:
        try:
            return p.resolve().relative_to(self.repo).as_posix()
        except Exception:
            return None

    def is_repo_file(self, p: Path) -> bool:
        try:
            rp = p.resolve()
            rp.relative_to(self.repo)
            return rp.is_file() and not self.is_excluded(rp)
        except Exception:
            return False

    # ---------- module discovery ----------

    def scan_repository(self) -> None:
        """Single filesystem walk: discover modules, CMake scripts and C/C++ files."""
        if self._repo_scanned:
            return
        self.log("scanning repository filesystem ...")
        cmake_lists: List[Path] = []
        code_files: List[Path] = []
        seen = 0
        for p in self.walk_files():
            seen += 1
            if seen % 20000 == 0:
                self.log(f"filesystem scan: {seen:,} files, {len(cmake_lists):,} modules, {len(code_files):,} C/C++ files")
            low_name = p.name.lower()
            if low_name == "cmakelists.txt":
                cmake_lists.append(p.resolve())
            elif p.suffix.lower() == ".cmake":
                try:
                    rp = p.resolve()
                except OSError:
                    rp = p
                self.cmake_script_name_index[low_name].append(rp)

            if p.suffix.lower() in CODE_EXTS:
                try:
                    rp = p.resolve()
                except OSError:
                    rp = p
                rel = self.rel(rp)
                if rel is not None:
                    code_files.append(rp)
                    self.rel_to_path[rel] = rp
                    self.basename_index[rp.name].append(rp)

        cmake_lists.sort(key=lambda p: (len(p.relative_to(self.repo).parts), p.as_posix()))
        module_dirs = {p.parent.resolve() for p in cmake_lists}
        for cm in cmake_lists:
            d = cm.parent.resolve()
            rel_dir = self.rel(d) or "."
            parent = None
            cur = d.parent
            while True:
                if cur in module_dirs:
                    parent = self.rel(cur) or "."
                    break
                if cur == self.repo or self.repo not in cur.parents:
                    break
                cur = cur.parent
            self.modules[rel_dir] = Module(
                path=rel_dir,
                cmake_file=self.rel(cm) or cm.as_posix(),
                parent=parent,
                children=[],
                depth=0 if rel_dir == "." else len(Path(rel_dir).parts),
            )
        for m in self.modules.values():
            if m.parent in self.modules:
                self.modules[m.parent].children.append(m.path)
        for m in self.modules.values():
            m.children.sort()

        self.repo_code_files = sorted(code_files)
        self._repo_scanned = True
        self.log(f"filesystem scan done: {seen:,} files, {len(self.modules):,} modules, {len(self.repo_code_files):,} C/C++ files, {sum(map(len, self.cmake_script_name_index.values())):,} .cmake scripts")

    def discover_modules(self) -> None:
        self.scan_repository()

    # ---------- CMake lexical parsing ----------

    @staticmethod
    def _strip_comments(text: str) -> str:
        """Remove # line comments and #[=[ bracket comments ]=] conservatively."""
        out = []
        i = 0
        n = len(text)
        quote = False
        while i < n:
            ch = text[i]
            if ch == '"':
                quote = not quote
                out.append(ch)
                i += 1
                continue
            if not quote and ch == '#':
                # bracket comment: #[[...]] or #[=[...]=]
                m = re.match(r"#\[(=*)\[", text[i:])
                if m:
                    eq = m.group(1)
                    end = "]" + eq + "]"
                    j = text.find(end, i + len(m.group(0)))
                    if j == -1:
                        # preserve newlines so line numbers remain approximately useful
                        out.extend("\n" if c == "\n" else " " for c in text[i:])
                        break
                    segment = text[i:j + len(end)]
                    out.extend("\n" if c == "\n" else " " for c in segment)
                    i = j + len(end)
                    continue
                # normal line comment
                j = text.find("\n", i)
                if j == -1:
                    out.extend(" " for _ in text[i:])
                    break
                out.extend(" " for _ in text[i:j])
                out.append("\n")
                i = j + 1
                continue
            out.append(ch)
            i += 1
        return "".join(out)

    @staticmethod
    def _split_args(s: str) -> List[str]:
        args: List[str] = []
        cur: List[str] = []
        i = 0
        n = len(s)
        quote = False

        def flush():
            if cur:
                token = "".join(cur).strip()
                if token:
                    args.append(token)
                cur.clear()

        while i < n:
            ch = s[i]
            if ch == '"':
                quote = not quote
                i += 1
                continue
            if not quote:
                # bracket argument [=[...]=]
                m = re.match(r"\[(=*)\[", s[i:])
                if m:
                    eq = m.group(1)
                    end = "]" + eq + "]"
                    j = s.find(end, i + len(m.group(0)))
                    if j != -1:
                        cur.append(s[i + len(m.group(0)):j])
                        i = j + len(end)
                        continue
                if ch.isspace():
                    flush()
                    i += 1
                    continue
            if ch == '\\' and i + 1 < n:
                # Keep escaped content but remove the escape marker for common cases.
                cur.append(s[i + 1])
                i += 2
                continue
            cur.append(ch)
            i += 1
        flush()
        return args

    def parse_cmake_file(self, path: Path) -> List[Command]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            self.parse_warnings.append(f"cannot read {path}: {e}")
            return []
        text = self._strip_comments(text)
        commands: List[Command] = []
        i = 0
        n = len(text)

        while i < n:
            m = re.search(r"(?i)([A-Za-z_][A-Za-z0-9_]*)\s*\(", text[i:])
            if not m:
                break
            name = m.group(1)
            start = i + m.start()
            p = i + m.end() - 1  # points to '('
            line = text.count("\n", 0, start) + 1
            depth = 1
            j = p + 1
            quote = False
            bracket_end: Optional[str] = None
            while j < n and depth > 0:
                if bracket_end:
                    if text.startswith(bracket_end, j):
                        j += len(bracket_end)
                        bracket_end = None
                    else:
                        j += 1
                    continue
                ch = text[j]
                if ch == '"':
                    quote = not quote
                    j += 1
                    continue
                if not quote:
                    bm = re.match(r"\[(=*)\[", text[j:])
                    if bm:
                        bracket_end = "]" + bm.group(1) + "]"
                        j += len(bm.group(0))
                        continue
                    if ch == '(':
                        depth += 1
                    elif ch == ')':
                        depth -= 1
                        if depth == 0:
                            break
                j += 1
            if depth != 0:
                self.parse_warnings.append(f"unbalanced CMake command in {path}:{line}: {name}")
                break
            body = text[p + 1:j]
            args = self._split_args(body)
            commands.append(Command(name=name.lower(), args=args, file=path.resolve(), line=line))
            i = j + 1
        return commands

    # ---------- variable and generator expression handling ----------

    def builtin_vars(self, cmd: Command) -> Dict[str, List[str]]:
        cur = cmd.file.parent.resolve()
        return {
            "CMAKE_SOURCE_DIR": [str(self.repo)],
            "PROJECT_SOURCE_DIR": [str(self.repo)],
            "CMAKE_CURRENT_SOURCE_DIR": [str(cur)],
            "CMAKE_CURRENT_LIST_DIR": [str(cur)],
            "CMAKE_CURRENT_LIST_FILE": [str(cmd.file)],
        }

    @staticmethod
    def _normalize_genex(token: str) -> str:
        # Useful common cases; INSTALL_INTERFACE is intentionally omitted for source analysis.
        token = re.sub(r"\$<BUILD_INTERFACE:([^>]+)>", r"\1", token)
        token = re.sub(r"\$<INSTALL_INTERFACE:[^>]*>", "", token)
        token = re.sub(r"\$<TARGET_NAME_IF_EXISTS:([^>]+)>", r"\1", token)
        token = re.sub(r"\$<LINK_ONLY:([^>]+)>", r"\1", token)
        # For conditional genex, retaining payload after the final ':' is safer than dropping it.
        m = re.fullmatch(r"\$<.*:([^<>]+)>", token)
        if m:
            token = m.group(1)
        return token

    def expand_token(self, token: str, cmd: Command, rounds: int = 8) -> List[str]:
        token = self._normalize_genex(token)
        builtins = self.builtin_vars(cmd)
        values = [token]

        var_pat = re.compile(r"\$\{([^}]+)\}")
        for _ in range(rounds):
            changed = False
            new_values: List[str] = []
            for value in values:
                m = var_pat.search(value)
                if not m:
                    new_values.append(value)
                    continue
                name = m.group(1)
                repls = builtins.get(name)
                if repls is None:
                    repls = sorted(self.variables.get(name, []))
                if not repls:
                    self.unresolved_variables.add(name)
                    new_values.append(value)
                    continue
                changed = True
                for r in repls:
                    new_values.append(value[:m.start()] + r + value[m.end():])
            values = new_values
            if not changed:
                break

        result: List[str] = []
        for v in values:
            # CMake lists are semicolon-separated. For file collection, split conservatively.
            for piece in v.split(';'):
                piece = piece.strip()
                if piece:
                    result.append(piece)
        return result

    def expand_args(self, args: Sequence[str], cmd: Command) -> List[str]:
        out: List[str] = []
        for a in args:
            out.extend(self.expand_token(a, cmd))
        return out

    def resolve_path(self, raw: str, cmd: Command, base: Optional[Path] = None) -> Optional[Path]:
        if not raw or "$" in raw or raw.startswith("-"):
            return None
        raw = self._normalize_genex(raw).strip().strip('"')
        if not raw:
            return None
        # Avoid target/object expressions and obvious linker values.
        if raw.startswith("$<") or raw.startswith("-l"):
            return None
        p = Path(raw)
        if not p.is_absolute():
            p = (base or cmd.file.parent) / p
        try:
            return p.resolve()
        except OSError:
            return p.absolute()

    # ---------- first pass: vars / globs ----------

    def _glob(self, patterns: List[str], recursive: bool, cmd: Command, relative_base: Optional[Path]) -> List[str]:
        out: List[str] = []
        for pat in patterns:
            if "$" in pat:
                continue
            p = Path(pat)
            if not p.is_absolute():
                p = cmd.file.parent / p
            pat_str = str(p)
            wildcard_pos = min([x for x in [pat_str.find('*'), pat_str.find('?'), pat_str.find('[')] if x >= 0], default=-1)
            if wildcard_pos < 0:
                candidates = [p]
            elif not recursive:
                candidates = [Path(x) for x in globlib.glob(pat_str)]
            else:
                # CMake GLOB_RECURSE traverses descendants even for a pattern such as *.cpp.
                prefix_text = pat_str[:wildcard_pos]
                base_text = os.path.dirname(prefix_text.rstrip(os.sep)) if not prefix_text.endswith(os.sep) else prefix_text.rstrip(os.sep)
                base = Path(base_text or os.curdir)
                pattern_rel = os.path.relpath(pat_str, base)
                if not base.exists():
                    candidates = []
                else:
                    candidates = [
                        c for c in base.rglob("*")
                        if fnmatch.fnmatch(os.path.relpath(c, base), pattern_rel)
                           or fnmatch.fnmatch(c.name, Path(pattern_rel).name)
                    ]
            for c in candidates:
                try:
                    c = c.resolve()
                except OSError:
                    pass
                if not c.is_file() or self.is_excluded(c):
                    continue
                if relative_base:
                    try:
                        out.append(c.relative_to(relative_base).as_posix())
                    except Exception:
                        out.append(str(c))
                else:
                    out.append(str(c))
        return out

    def collect_variables(self) -> None:
        for cmd in self.commands:
            a = cmd.args
            if not a:
                continue
            if cmd.name == "set" and len(a) >= 1:
                name = a[0]
                vals = a[1:]
                # Strip CACHE signature tail conservatively.
                if "CACHE" in vals:
                    vals = vals[:vals.index("CACHE")]
                for v in self.expand_args(vals, cmd):
                    self.variables[name].add(v)
            elif cmd.name == "list" and len(a) >= 3 and a[0].upper() in {"APPEND", "PREPEND"}:
                name = a[1]
                for v in self.expand_args(a[2:], cmd):
                    self.variables[name].add(v)
            elif cmd.name == "aux_source_directory" and len(a) >= 2:
                dirs = self.expand_token(a[0], cmd)
                var = a[1]
                for d in dirs:
                    dp = self.resolve_path(d, cmd)
                    if dp and dp.is_dir():
                        for f in dp.iterdir():
                            if f.is_file() and f.suffix.lower() in SOURCE_EXTS:
                                self.variables[var].add(str(f.resolve()))
            elif cmd.name == "file" and len(a) >= 3 and a[0].upper() in {"GLOB", "GLOB_RECURSE"}:
                recursive = a[0].upper() == "GLOB_RECURSE"
                var = a[1]
                rest = list(a[2:])
                relative_base: Optional[Path] = None
                patterns: List[str] = []
                i = 0
                while i < len(rest):
                    kw = rest[i].upper()
                    if kw == "RELATIVE" and i + 1 < len(rest):
                        vals = self.expand_token(rest[i + 1], cmd)
                        if vals:
                            relative_base = self.resolve_path(vals[0], cmd)
                        i += 2
                        continue
                    if kw in {"CONFIGURE_DEPENDS", "LIST_DIRECTORIES"}:
                        if kw == "LIST_DIRECTORIES" and i + 1 < len(rest):
                            i += 2
                        else:
                            i += 1
                        continue
                    patterns.extend(self.expand_token(rest[i], cmd))
                    i += 1
                for v in self._glob(patterns, recursive, cmd, relative_base):
                    self.variables[var].add(v)

    # ---------- discover included CMake scripts ----------

    def load_cmake_commands(self) -> None:
        queue = deque(sorted((self.repo / m.path / "CMakeLists.txt").resolve() if m.path != "." else (self.repo / "CMakeLists.txt").resolve() for m in self.modules.values()))
        queued = set(queue)

        while queue:
            f = queue.popleft()
            if f in self.cmake_files_seen or not f.exists():
                continue
            self.cmake_files_seen.add(f)
            cmds = self.parse_cmake_file(f)
            self.commands.extend(cmds)

            # Collect simple variables immediately so include(${VAR}) has a chance to resolve.
            for cmd in cmds:
                if cmd.name == "set" and cmd.args:
                    for v in cmd.args[1:]:
                        if "${" not in v:
                            self.variables[cmd.args[0]].add(v)

            for cmd in cmds:
                if cmd.name != "include" or not cmd.args:
                    continue
                candidates = self.expand_token(cmd.args[0], cmd)
                for raw in candidates:
                    if raw.upper() in {"OPTIONAL", "RESULT_VARIABLE", "NO_POLICY_SCOPE"}:
                        continue
                    rawp = Path(raw)
                    test_paths: List[Path] = []
                    if rawp.suffix:
                        test_paths.append(rawp if rawp.is_absolute() else cmd.file.parent / rawp)
                    else:
                        test_paths.append((rawp if rawp.is_absolute() else cmd.file.parent / rawp).with_suffix(".cmake"))
                        # Module-style include(Foo): O(1) lookup from the single repository scan.
                        matches = self.cmake_script_name_index.get((rawp.name + ".cmake").lower(), [])
                        if len(matches) == 1:
                            test_paths.append(matches[0])
                    for tp in test_paths:
                        try:
                            tp = tp.resolve()
                        except OSError:
                            pass
                        if self.is_repo_file(tp) and tp not in queued:
                            queue.append(tp)
                            queued.add(tp)

    # ---------- target extraction ----------

    def _target(self, name: str) -> Target:
        if name not in self.targets:
            self.targets[name] = Target(name=name)
        return self.targets[name]

    def _filter_source_tokens(self, tokens: Sequence[str]) -> List[str]:
        out: List[str] = []
        skip_next_type = False
        for t in tokens:
            u = t.upper()
            if u in TARGET_TYPE_KEYWORDS or u in TARGET_SOURCE_KEYWORDS:
                skip_next_type = u in {"FILE_SET", "TYPE"}
                continue
            if skip_next_type:
                skip_next_type = False
                continue
            out.append(t)
        return out

    def _add_source(self, target: Target, raw: str, cmd: Command) -> None:
        if not raw or raw.upper() in TARGET_SOURCE_KEYWORDS or raw.startswith("$<TARGET_OBJECTS:"):
            return
        if raw.startswith("$<") and ">" in raw:
            raw = self._normalize_genex(raw)
        p = self.resolve_path(raw, cmd)
        if p and self.is_repo_file(p) and p.suffix.lower() in CODE_EXTS:
            target.sources.add(self.rel(p))
        elif p and p.exists() and p.is_file():
            # Non-C/C++ file referenced in target; irrelevant to CodeQL C/C++ slice.
            pass
        else:
            if raw and not raw.startswith("$"):
                target.unresolved_sources.add(raw)

    def _add_include_dir(self, target: Target, raw: str, cmd: Command) -> None:
        if raw.upper() in CMAKE_SCOPE_KEYWORDS:
            return
        p = self.resolve_path(raw, cmd)
        if p and p.is_dir():
            rel = self.rel(p)
            if rel is not None:
                target.include_dirs.add(rel)
        elif raw and not raw.startswith("$") and not raw.startswith("$<INSTALL_INTERFACE"):
            target.unresolved_include_dirs.add(raw)

    def extract_targets(self) -> None:
        # Global directory-level settings first.
        for cmd in self.commands:
            rel_dir = self.rel(cmd.file.parent) or "."
            if cmd.name == "include_directories":
                for raw in self.expand_args(cmd.args, cmd):
                    if raw.upper() in CMAKE_SCOPE_KEYWORDS:
                        continue
                    p = self.resolve_path(raw, cmd)
                    if p and p.is_dir():
                        r = self.rel(p)
                        if r is not None:
                            self.dir_global_includes[rel_dir].add(r)
            elif cmd.name == "link_libraries":
                for raw in self.expand_args(cmd.args, cmd):
                    if raw.upper() not in CMAKE_SCOPE_KEYWORDS:
                        self.dir_global_links[rel_dir].add(raw)

        for cmd in self.commands:
            if not cmd.args:
                continue
            expanded = self.expand_args(cmd.args, cmd)
            if not expanded:
                continue

            if cmd.name in {"add_library", "add_executable"}:
                name = expanded[0]
                if not _is_resolved_target_name(name):
                    self.parse_warnings.append(
                        f"{self.rel(cmd.file)}:{cmd.line}: unresolved target name ignored: {name}"
                    )
                    continue
                if len(expanded) >= 3 and expanded[1].upper() == "ALIAS":
                    real = expanded[2]
                    if _is_resolved_target_name(real):
                        self.alias_to_target[name] = real
                        self._target(real).aliases.add(name)
                    continue
                if any(x.upper() == "IMPORTED" for x in expanded[1:]):
                    continue
                t = self._target(name)
                t.kind = "EXECUTABLE" if cmd.name == "add_executable" else next(
                    (x.upper() for x in expanded[1:] if x.upper() in TARGET_TYPE_KEYWORDS), "LIBRARY"
                )
                if t.defined_file is None:
                    t.defined_file = self.rel(cmd.file)
                    t.defined_dir = self.rel(cmd.file.parent) or "."
                for src in self._filter_source_tokens(expanded[1:]):
                    self._add_source(t, src, cmd)

            elif cmd.name == "target_sources" and len(expanded) >= 2:
                name = expanded[0]
                if not _is_resolved_target_name(name):
                    self.parse_warnings.append(
                        f"{self.rel(cmd.file)}:{cmd.line}: unresolved target_sources target ignored: {name}"
                    )
                    continue
                t = self._target(name)
                for src in self._filter_source_tokens(expanded[1:]):
                    self._add_source(t, src, cmd)

            elif cmd.name == "target_include_directories" and len(expanded) >= 2:
                name = expanded[0]
                if not _is_resolved_target_name(name):
                    self.parse_warnings.append(
                        f"{self.rel(cmd.file)}:{cmd.line}: unresolved include target ignored: {name}"
                    )
                    continue
                t = self._target(name)
                for raw in expanded[1:]:
                    self._add_include_dir(t, raw, cmd)

            elif cmd.name == "target_link_libraries" and len(expanded) >= 2:
                name = expanded[0]
                if not _is_resolved_target_name(name):
                    self.parse_warnings.append(
                        f"{self.rel(cmd.file)}:{cmd.line}: unresolved link target ignored: {name}"
                    )
                    continue
                t = self._target(name)
                skip_modifier = False
                for raw in expanded[1:]:
                    u = raw.upper()
                    if u in CMAKE_SCOPE_KEYWORDS:
                        continue
                    if raw.lower() in LINK_MODIFIERS:
                        skip_modifier = True
                        continue
                    if skip_modifier:
                        skip_modifier = False
                    if (not _is_resolved_target_name(raw) or raw.startswith("-") or "/" in raw or "\\" in raw
                            or raw.endswith((".a", ".so", ".lib", ".dll", ".dylib"))):
                        continue
                    t.links.add(raw)

            elif cmd.name == "add_dependencies" and len(expanded) >= 2:
                name = expanded[0]
                if not _is_resolved_target_name(name):
                    self.parse_warnings.append(
                        f"{self.rel(cmd.file)}:{cmd.line}: unresolved dependency target ignored: {name}"
                    )
                    continue
                t = self._target(name)
                t.build_deps.update(x for x in expanded[1:] if _is_resolved_target_name(x))

        # Inherit directory-scope includes/link_libraries from ancestor CMake directories.
        for t in self.targets.values():
            if not t.defined_dir:
                continue
            d = self.repo / t.defined_dir if t.defined_dir != "." else self.repo
            ancestors: List[str] = []
            cur = d.resolve()
            while True:
                r = self.rel(cur)
                if r is not None:
                    ancestors.append(r or ".")
                if cur == self.repo:
                    break
                if self.repo not in cur.parents:
                    break
                cur = cur.parent
            for a in ancestors:
                t.include_dirs.update(self.dir_global_includes.get(a, set()))
                t.links.update(self.dir_global_links.get(a, set()))

        # Resolve aliases in links after all targets are known.
        for t in self.targets.values():
            t.links = {self.alias_to_target.get(x, x) for x in t.links}

    # ---------- code indexing / LOC ----------

    def index_code_files(self) -> None:
        # scan_repository() already builds this index in one filesystem pass.
        self.scan_repository()

    @staticmethod
    def count_loc(path: Path) -> int:
        """Fast physical-line count for large repositories."""
        try:
            total = 0
            last = b""
            with path.open("rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    total += chunk.count(b"\n")
                    last = chunk[-1:]
            if last and last != b"\n":
                total += 1
            return total
        except OSError:
            return 0

    def loc_of(self, rels: Iterable[str]) -> int:
        total = 0
        for r in set(rels):
            if r not in self.rel_to_path:
                continue
            if r not in self._loc_cache:
                self._loc_cache[r] = self.count_loc(self.rel_to_path[r])
            total += self._loc_cache[r]
        return total

    # ---------- module file ownership ----------

    def _is_under(self, rel_file: str, module_path: str) -> bool:
        if module_path == ".":
            return True
        return rel_file == module_path or rel_file.startswith(module_path.rstrip('/') + '/')

    def compute_physical_module_files(self, skip_loc: bool = False) -> None:
        # Assign each repository code file to its nearest CMake module, then roll it up
        # through parent modules. This is O(files * module-depth), not O(files * modules).
        local_sets: Dict[str, Set[str]] = {mp: set() for mp in self.modules}
        subtree_sets: Dict[str, Set[str]] = {mp: set() for mp in self.modules}

        module_dirs = {
            (self.repo if mp == "." else (self.repo / mp)).resolve(): mp
            for mp in self.modules
        }

        total_files = len(self.rel_to_path)
        for idx, (rel, path) in enumerate(self.rel_to_path.items(), 1):
            if idx == 1 or idx % 20000 == 0 or idx == total_files:
                self.log(f"module ownership: {idx:,}/{total_files:,} C/C++ files")
            cur = path.parent.resolve()
            owner: Optional[str] = None
            while True:
                if cur in module_dirs:
                    owner = module_dirs[cur]
                    break
                if cur == self.repo or self.repo not in cur.parents:
                    break
                cur = cur.parent
            if owner is None:
                continue
            local_sets[owner].add(rel)
            mp: Optional[str] = owner
            while mp is not None and mp in self.modules:
                subtree_sets[mp].add(rel)
                mp = self.modules[mp].parent

        if not skip_loc:
            self.log(f"counting LOC: reading {len(self.rel_to_path):,} C/C++ files once ...")
            for idx, (rel, path) in enumerate(self.rel_to_path.items(), 1):
                self._loc_cache[rel] = self.count_loc(path)
                if idx == 1 or idx % 5000 == 0 or idx == len(self.rel_to_path):
                    self.log(f"LOC count: {idx:,}/{len(self.rel_to_path):,} files")

        for mp, m in self.modules.items():
            m.local_code_files = sorted(local_sets[mp])
            m.subtree_code_files = sorted(subtree_sets[mp])
            if skip_loc:
                m.local_loc = 0
                m.subtree_loc = 0
            else:
                m.local_loc = sum(self._loc_cache.get(r, 0) for r in local_sets[mp])
                m.subtree_loc = sum(self._loc_cache.get(r, 0) for r in subtree_sets[mp])

    # ---------- target closure ----------

    def _single_target_dependency_closure(self, seed: str, include_add_dependencies: bool) -> Set[str]:
        seed = self.alias_to_target.get(seed, seed)
        key = (seed, include_add_dependencies)
        cached = self._target_dep_cache.get(key)
        if cached is not None:
            return set(cached)
        out: Set[str] = set()
        q = deque([seed])
        while q:
            raw = q.popleft()
            name = self.alias_to_target.get(raw, raw)
            if name in out or name not in self.targets:
                continue
            out.add(name)
            t = self.targets[name]
            deps = set(t.links)
            if include_add_dependencies:
                deps.update(t.build_deps)
            for dep in deps:
                dep = self.alias_to_target.get(dep, dep)
                if dep in self.targets and dep not in out:
                    q.append(dep)
        self._target_dep_cache[key] = set(out)
        return out

    def target_dependency_closure(self, seeds: Iterable[str], include_add_dependencies: bool) -> Set[str]:
        out: Set[str] = set()
        # Computing and caching each target's closure makes parent-module unions cheap.
        for seed in seeds:
            out.update(self._single_target_dependency_closure(seed, include_add_dependencies))
        return out

    # ---------- include closure ----------

    INCLUDE_RE = re.compile(r"^\s*#\s*include\s*([<\"])([^>\"]+)[>\"]", re.MULTILINE)

    def parse_includes(self, path: Path) -> List[Tuple[str, bool]]:
        rel = self.rel(path) or str(path)
        if rel in self._include_parse_cache:
            return self._include_parse_cache[rel]
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            self._include_parse_cache[rel] = []
            return []
        result = [(m.group(2).strip(), m.group(1) == '"') for m in self.INCLUDE_RE.finditer(text)]
        self._include_parse_cache[rel] = result
        return result

    def resolve_include(
        self,
        include: str,
        quoted: bool,
        current: Path,
        include_dirs_rel: Sequence[str],
        allowed_files: Optional[Set[str]] = None,
    ) -> Tuple[List[Path], bool]:
        """Resolve a repository-local include.

        ``allowed_files`` is used by forced-split to keep include resolution inside
        the semantic universe being partitioned.  This is intentionally applied
        *during* resolution rather than intersecting after traversal, otherwise a
        basename fallback can enqueue thousands of unrelated repository headers.
        """
        include = include.replace('\\', '/').strip()
        current_rel = self.rel(current) or ''
        current_dir_rel = posixpath.dirname(current_rel) or '.'
        dirs_tuple = tuple(include_dirs_rel)

        # Normal target/module closure can use the global cache.  Forced-split has
        # a per-unit allowed set, so do not reuse a cache entry computed against a
        # different universe.
        key = (include, quoted, current_dir_rel, dirs_tuple)
        if allowed_files is None:
            cached = self._include_resolution_cache.get(key)
            if cached is not None:
                rels, ambiguous = cached
                return [self.rel_to_path[r] for r in rels if r in self.rel_to_path], ambiguous

        def permitted(rel: str) -> bool:
            return allowed_files is None or rel in allowed_files

        search_dirs: List[str] = []
        if quoted:
            search_dirs.append(current_dir_rel)
        search_dirs.extend(include_dirs_rel)
        search_dirs.append('.')

        seen_dirs: Set[str] = set()
        for drel in search_dirs:
            drel = drel or '.'
            if drel in seen_dirs:
                continue
            seen_dirs.add(drel)
            candidate = posixpath.normpath(posixpath.join('' if drel == '.' else drel, include))
            if candidate == '..' or candidate.startswith('../') or candidate.startswith('/'):
                continue
            p = self.rel_to_path.get(candidate)
            if p is not None and p.suffix.lower() in CODE_EXTS and permitted(candidate):
                if allowed_files is None:
                    self._include_resolution_cache[key] = ((candidate,), False)
                return [p], False

        # Fallback: basename/suffix lookup.  For forced-split, filter against the
        # allowed universe *before* ambiguity counting.  This both avoids fan-out
        # and allows a globally ambiguous basename to resolve uniquely inside the
        # current semantic unit.
        suffix = '/' + include.lstrip('./')
        basename_candidates = self.basename_index.get(Path(include).name, [])
        candidate_rels: List[str] = []
        for p in basename_candidates:
            r = self.rel(p)
            if not r or not permitted(r):
                continue
            candidate_rels.append(r)

        matches_rel = [r for r in candidate_rels if ('/' + r).endswith(suffix)]
        if not matches_rel and '/' not in include:
            matches_rel = candidate_rels

        matches_rel = sorted(set(matches_rel))
        if len(matches_rel) > self.max_include_ambiguity:
            if allowed_files is None:
                self._include_resolution_cache[key] = (tuple(), True)
            return [], True

        ambiguous = len(matches_rel) > 1
        if allowed_files is None:
            self._include_resolution_cache[key] = (tuple(matches_rel), ambiguous)
        return [self.rel_to_path[r] for r in matches_rel if r in self.rel_to_path], ambiguous

    def include_closure(
        self,
        initial_files: Set[str],
        include_dirs_rel: Set[str],
        label: str = '',
        allowed_files: Optional[Set[str]] = None,
    ) -> Tuple[Set[str], Set[str]]:
        # allowed_files is primarily used by forced-split.  The old implementation
        # traversed arbitrary repository headers first and intersected with the
        # semantic universe only after the closure finished.  On large repositories
        # (especially when include_dirs is empty) basename fallback could therefore
        # fan out to thousands of unrelated headers.  Restrict traversal up front.
        allowed = set(allowed_files) if allowed_files is not None else None
        out = {r for r in initial_files if allowed is None or r in allowed}
        unresolved: Set[str] = set()
        include_dirs: List[str] = []
        for r in sorted(include_dirs_rel):
            # include dirs were normalized to repository-relative directories when CMake was parsed.
            p = self.repo / r if r != '.' else self.repo
            if p.is_dir():
                include_dirs.append(r or '.')

        q = deque(
            r for r in initial_files
            if r in self.rel_to_path and (allowed is None or r in allowed)
        )
        scanned: Set[str] = set()
        started = time.monotonic()
        last_log = started
        while q:
            rel = q.popleft()
            if rel in scanned or rel not in self.rel_to_path:
                continue
            scanned.add(rel)
            path = self.rel_to_path[rel]
            for inc, quoted in self.parse_includes(path):
                matches, too_ambiguous = self.resolve_include(
                    inc, quoted, path, include_dirs, allowed_files=allowed
                )
                if not matches:
                    if too_ambiguous:
                        unresolved.add(f"{rel}: {inc} [ambiguous>{self.max_include_ambiguity}]")
                    else:
                        unresolved.add(f"{rel}: {inc}")
                    continue
                accepted = 0
                for p in matches:
                    r = self.rel(p)
                    if not r:
                        continue
                    if allowed is not None and r not in allowed:
                        continue
                    accepted += 1
                    if r not in out:
                        out.add(r)
                        q.append(r)
                # A resolver match that points only outside the forced-split universe
                # is intentionally treated as unresolved for this partition.
                if matches and accepted == 0 and allowed is not None:
                    unresolved.add(f"{rel}: {inc} [outside-split-universe]")

            now = time.monotonic()
            if self.progress and now - started >= self.slow_include_seconds and now - last_log >= 2.0:
                self.log(
                    f"include closure{(' [' + label + ']') if label else ''}: "
                    f"scanned={len(scanned):,}, queued={len(q):,}, related={len(out):,}, "
                    f"include_dirs={len(include_dirs):,}"
                )
                last_log = now
        return out, unresolved

    # ---------- module slices ----------

    def nearest_module_for_dir(self, d: str) -> Optional[str]:
        p = self.repo / d if d != "." else self.repo
        p = p.resolve()
        while True:
            r = self.rel(p)
            key = r or "."
            if key in self.modules:
                return key
            if p == self.repo or self.repo not in p.parents:
                return None
            p = p.parent

    def _target_related_files(self, target_name: str, include_add_dependencies: bool) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        """Return (related_files, unresolved_includes, include_dirs, unresolved_cmake) for one target.

        The result is cached.  Include directories are conservatively unioned across the target's
        internal dependency closure, then repository-local #include closure is computed once.
        """
        target_name = self.alias_to_target.get(target_name, target_name)
        key = (target_name, include_add_dependencies)
        cached = self._target_related_cache.get(key)
        if cached is not None:
            return tuple(set(x) for x in cached)  # defensive copies

        target_started = time.monotonic()
        closure = self._single_target_dependency_closure(target_name, include_add_dependencies)
        sources: Set[str] = set()
        include_dirs: Set[str] = set()
        unresolved_cmake: Set[str] = set()
        for name in closure:
            t = self.targets.get(name)
            if not t:
                continue
            sources.update(t.sources)
            include_dirs.update(t.include_dirs)
            unresolved_cmake.update(f"{name}: source:{x}" for x in t.unresolved_sources)
            unresolved_cmake.update(f"{name}: include_dir:{x}" for x in t.unresolved_include_dirs)

        if self.progress and (len(sources) >= 1000 or len(include_dirs) >= 200):
            self.log(
                f"target closure START target={target_name} deps={len(closure):,} "
                f"sources={len(sources):,} include_dirs={len(include_dirs):,}"
            )
        related, unresolved_includes = self.include_closure(sources, include_dirs, label=f"target:{target_name}")
        if self.progress and time.monotonic() - target_started >= self.slow_include_seconds:
            self.log(
                f"target closure DONE  target={target_name} elapsed={time.monotonic() - target_started:.2f}s "
                f"related={len(related):,} unresolved={len(unresolved_includes):,}"
            )
        value = (set(related), set(unresolved_includes), set(include_dirs), set(unresolved_cmake))
        self._target_related_cache[key] = value
        n = len(self._target_related_cache)
        if n % 100 == 0:
            self.log(f"target include closures: {n:,} cached")
        return tuple(set(x) for x in value)

    def compute_module_slices(self, include_add_dependencies: bool = False) -> None:
        self.log("mapping targets to modules ...")
        module_seed_targets: Dict[str, Set[str]] = {mp: set() for mp in self.modules}

        # Direct target ownership.
        for t in self.targets.values():
            if t.defined_dir:
                mp = self.nearest_module_for_dir(t.defined_dir)
                if mp:
                    self.modules[mp].direct_targets.append(t.name)

            # A target can be defined in a parent and extended by target_sources() in a child.
            owners: Set[str] = set()
            if t.defined_dir:
                mp = self.nearest_module_for_dir(t.defined_dir)
                if mp:
                    owners.add(mp)
            for src in t.sources:
                p = self.rel_to_path.get(src)
                if not p:
                    continue
                cur = p.parent
                while True:
                    r = self.rel(cur) or "."
                    if r in self.modules:
                        owners.add(r)
                        break
                    if cur == self.repo or self.repo not in cur.parents:
                        break
                    cur = cur.parent

            # Roll target membership up module parents once instead of scanning all targets per module.
            for owner in owners:
                mp: Optional[str] = owner
                while mp is not None and mp in self.modules:
                    module_seed_targets[mp].add(t.name)
                    mp = self.modules[mp].parent

        for m in self.modules.values():
            m.direct_targets = sorted(set(m.direct_targets))

        ordered = sorted(self.modules.items(), key=lambda kv: (kv[1].depth, kv[0]), reverse=True)
        total = len(ordered)
        for idx, (mp, m) in enumerate(ordered, 1):
            module_started = time.monotonic()
            seeds = sorted(module_seed_targets.get(mp, set()))
            self.log(
                f"module slices: {idx:,}/{total:,} START module={mp} "
                f"seed_targets={len(seeds):,} subtree_files={len(m.subtree_code_files):,} "
                f"target_cache={len(self._target_related_cache):,}"
            )
            m.subtree_targets = seeds
            closure = self.target_dependency_closure(seeds, include_add_dependencies)
            m.dependency_targets = sorted(closure - set(seeds))

            direct_sources: Set[str] = set()
            for name in seeds:
                t = self.targets.get(name)
                if t:
                    direct_sources.update(t.sources)

            related: Set[str] = set()
            unresolved_includes: Set[str] = set()
            include_dirs: Set[str] = set()
            unresolved_cmake: Set[str] = set()

            # Crucial optimization: each target's dependency+include closure is calculated once,
            # then modules only union cached target results.
            for name in seeds:
                tr, ui, incs, uc = self._target_related_files(name, include_add_dependencies)
                related.update(tr)
                unresolved_includes.update(ui)
                include_dirs.update(incs)
                unresolved_cmake.update(uc)

            # Fallback for modules with no resolvable CMake target.
            if not related:
                source_set = {r for r in m.subtree_code_files if Path(r).suffix.lower() in SOURCE_EXTS}
                related, unresolved_includes = self.include_closure(source_set, include_dirs, label=f"fallback-module:{mp}")
                if not related:
                    related = set(m.subtree_code_files)
                m.fallback_used = True

            m.direct_cmake_sources = sorted(direct_sources)
            m.include_dirs = sorted(include_dirs)
            m.related_files = sorted(related)
            m.related_loc = 0 if self.skip_loc else self.loc_of(related)
            m.related_source_files = sum(1 for r in related if Path(r).suffix.lower() in SOURCE_EXTS)
            m.related_header_files = sum(1 for r in related if Path(r).suffix.lower() in HEADER_EXTS)
            m.unresolved_includes = sorted(unresolved_includes)
            m.unresolved_cmake_references = sorted(unresolved_cmake)
            self.log(
                f"module slices: {idx:,}/{total:,} DONE  module={mp} "
                f"elapsed={time.monotonic() - module_started:.2f}s "
                f"related={len(related):,} deps={len(m.dependency_targets):,} "
                f"unresolved_includes={len(unresolved_includes):,}"
            )

    # ---------- output ----------

    @staticmethod
    def module_id(module_path: str) -> str:
        if module_path == ".":
            return "root"
        slug = re.sub(r"[^A-Za-z0-9._-]+", "__", module_path.replace('/', '__'))
        digest = hashlib.sha1(module_path.encode()).hexdigest()[:8]
        return f"{slug}__{digest}"

    def write_outputs(self, outdir: Path) -> None:
        outdir.mkdir(parents=True, exist_ok=True)
        lists_dir = outdir / "module_files"
        lists_dir.mkdir(exist_ok=True)

        modules_data = []
        for mp in sorted(self.modules):
            m = self.modules[mp]
            d = asdict(m)
            d["module_id"] = self.module_id(mp)
            d["codeql_suggested_command"] = (
                f"codeql database create <DB_PATH> --language=c-cpp --build-mode=none "
                f"--source-root=<MATERIALIZED_SLICE_FOR:{mp}>"
            )
            modules_data.append(d)
            (lists_dir / f"{self.module_id(mp)}.files.txt").write_text(
                "\n".join(m.related_files) + ("\n" if m.related_files else ""),
                encoding="utf-8",
            )

        targets_data = {}
        for name in sorted(self.targets):
            t = self.targets[name]
            targets_data[name] = {
                "name": t.name,
                "kind": t.kind,
                "defined_file": t.defined_file,
                "defined_dir": t.defined_dir,
                "sources": sorted(t.sources),
                "include_dirs": sorted(t.include_dirs),
                "links": sorted(t.links),
                "build_deps": sorted(t.build_deps),
                "aliases": sorted(t.aliases),
                "unresolved_sources": sorted(t.unresolved_sources),
                "unresolved_include_dirs": sorted(t.unresolved_include_dirs),
            }

        report = {
            "repository": str(self.repo),
            "analysis_mode": "static-cmake-union-no-configure-no-build",
            "module_definition": "every directory containing CMakeLists.txt",
            "slice_definition": "module-subtree target sources + internal linked-target closure + repository-local transitive include closure",
            "modules": modules_data,
            "targets": targets_data,
            "unresolved_variables": sorted(self.unresolved_variables),
            "parse_warnings": self.parse_warnings,
            "limitations": [
                "CMake is a programming language; static parsing cannot perfectly evaluate arbitrary functions/macros, execute_process(), generated files, toolchain logic, or all generator expressions.",
                "Conditional branches are approximated by union semantics to reduce audit false negatives.",
                "Only repository-local files that exist on disk can be included; generated-at-build files are reported only when their references are visible.",
                "Header resolution is heuristic when multiple repository files can satisfy the same #include.",
            ],
        }
        (outdir / "modules.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

        with (outdir / "modules.csv").open("w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow([
                "module_id", "module_path", "parent", "children",
                "local_files", "local_loc", "subtree_files", "subtree_loc",
                "direct_targets", "subtree_targets", "dependency_targets",
                "direct_cmake_sources", "related_files", "related_source_files",
                "related_header_files", "related_loc", "include_dirs",
                "unresolved_includes", "unresolved_cmake_refs", "fallback_used",
            ])
            for mp in sorted(self.modules):
                m = self.modules[mp]
                w.writerow([
                    self.module_id(mp), mp, m.parent or "", ";".join(m.children),
                    len(m.local_code_files), m.local_loc,
                    len(m.subtree_code_files), m.subtree_loc,
                    ";".join(m.direct_targets), ";".join(m.subtree_targets), ";".join(m.dependency_targets),
                    len(m.direct_cmake_sources), len(m.related_files),
                    m.related_source_files, m.related_header_files, m.related_loc,
                    ";".join(m.include_dirs), len(m.unresolved_includes),
                    len(m.unresolved_cmake_references), str(m.fallback_used).lower(),
                ])

        # Simple tree-oriented text report for quick inspection.
        lines = []
        for mp in sorted(self.modules, key=lambda x: (self.modules[x].depth, x)):
            m = self.modules[mp]
            indent = "  " * m.depth
            lines.append(
                f"{indent}- {mp} | local={len(m.local_code_files)} files/{m.local_loc} LOC "
                f"| subtree={len(m.subtree_code_files)} files/{m.subtree_loc} LOC "
                f"| slice={len(m.related_files)} files/{m.related_loc} LOC "
                f"| targets={len(m.subtree_targets)} deps={len(m.dependency_targets)}"
            )
        (outdir / "module_tree.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def materialize_module(self, module_path: str, slice_dir: Path, mode: str = "hardlink") -> None:
        if module_path not in self.modules:
            raise KeyError(f"unknown module: {module_path}")
        m = self.modules[module_path]
        slice_dir = slice_dir.resolve()
        slice_dir.mkdir(parents=True, exist_ok=True)
        for rel in m.related_files:
            src = self.repo / rel
            dst = slice_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                continue
            if mode == "symlink":
                dst.symlink_to(src)
            elif mode == "copy":
                shutil.copy2(src, dst)
            else:
                try:
                    os.link(src, dst)
                except OSError:
                    shutil.copy2(src, dst)

        # Preserve CMake files as metadata for inspection, although CodeQL C/C++ does not require them.
        cur = self.repo / module_path if module_path != "." else self.repo
        while True:
            cm = cur / "CMakeLists.txt"
            if cm.exists():
                rel = self.rel(cm)
                if rel:
                    dst = slice_dir / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    if not dst.exists():
                        shutil.copy2(cm, dst)
            if cur == self.repo:
                break
            cur = cur.parent



# ============================================================================
# Integrated repository -> split CodeQL databases pipeline
# ============================================================================

import subprocess
import tempfile
from dataclasses import dataclass as _dataclass


@_dataclass
class SliceUnit:
    unit_id: str
    modules: List[str]
    targets: List[str]
    files: Set[str]
    loc: int
    source_files: int
    header_files: int
    oversized: bool = False


@_dataclass
class ShardPlan:
    shard_id: str
    modules: List[str]
    targets: List[str]
    unit_ids: List[str]
    files: Set[str]
    loc: int
    source_files: int
    header_files: int
    oversized: bool = False


def _safe_slug(value: str, max_len: int = 56) -> str:
    value = value.replace("\\", "/").strip("/")
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    value = value.strip("._-") or "root"
    if len(value) > max_len:
        digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:8]
        value = value[:max_len - 9] + "_" + digest
    return value


def _resolve_executable(name: str) -> str:
    p = Path(name)
    if p.is_absolute() or p.parent != Path("."):
        if p.is_file() and os.access(p, os.X_OK):
            return str(p.resolve())
        raise FileNotFoundError(f"executable not found or not executable: {name}")
    found = shutil.which(name)
    if not found:
        raise FileNotFoundError(f"executable not found in PATH: {name}")
    return found


def _safe_repo_file(repo: Path, rel: str) -> Path:
    rp = Path(rel)
    if rp.is_absolute() or ".." in rp.parts:
        raise ValueError(f"unsafe repository-relative path: {rel!r}")
    src = (repo / rp).resolve()
    try:
        src.relative_to(repo)
    except ValueError as exc:
        raise ValueError(f"path escapes repository: {rel!r}") from exc
    return src


def _materialize_file(src: Path, dst: Path, mode: str) -> str:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if mode == "copy":
        shutil.copy2(src, dst)
        return "copy"
    if mode == "symlink":
        os.symlink(src, dst)
        return "symlink"
    try:
        os.link(src, dst)
        return "hardlink"
    except OSError:
        shutil.copy2(src, dst)
        return "copy-fallback"


def _loc_of_files(analyzer: CMakeStaticAnalyzer, files: Iterable[str]) -> int:
    # compute_physical_module_files(skip_loc=False) pre-populates _loc_cache for
    # repository C/C++ files, so this is normally just integer summation.
    return sum(analyzer._loc_cache.get(r, 0) for r in set(files))


def _count_kinds(files: Iterable[str]) -> Tuple[int, int]:
    s = h = 0
    for r in set(files):
        ext = Path(r).suffix.lower()
        if ext in SOURCE_EXTS:
            s += 1
        elif ext in HEADER_EXTS:
            h += 1
    return s, h


def _module_direct_targets(analyzer: CMakeStaticAnalyzer) -> Dict[str, List[str]]:
    result: Dict[str, Set[str]] = {mp: set() for mp in analyzer.modules}
    for t in analyzer.targets.values():
        if not t.defined_dir:
            continue
        mp = analyzer.nearest_module_for_dir(t.defined_dir)
        if mp:
            result.setdefault(mp, set()).add(t.name)
    out = {mp: sorted(v) for mp, v in result.items()}
    for mp, vals in out.items():
        analyzer.modules[mp].direct_targets = vals
    return out


def _split_oversized_related_files(
    analyzer: CMakeStaticAnalyzer,
    files: Set[str],
    include_dirs: Set[str],
    module_path: str,
    targets: Sequence[str],
    unit_prefix: str,
    max_loc: int,
) -> List[SliceUnit]:
    """Split an oversized semantic unit while preserving source/include locality.

    The preferred boundaries are CMake modules and targets.  This function is a
    last-resort boundary used only when one such unit still exceeds ``max_loc``.
    It recursively partitions the source-file seeds by repository path and
    recomputes the repository-local include closure for each partition.  Header
    files can therefore be duplicated across chunks when needed, while source
    files are assigned to one chunk.

    A pathological single source file whose transitive include closure alone is
    larger than ``max_loc`` cannot be split without breaking that translation
    unit.  Such a chunk is retained and marked ``oversized``.
    """
    files = set(files)
    source_seeds = sorted(
        (r for r in files if Path(r).suffix.lower() in SOURCE_EXTS),
        key=lambda r: (posixpath.dirname(r), r),
    )

    def make_unit(chunk_files: Set[str], index: int) -> SliceUnit:
        loc = _loc_of_files(analyzer, chunk_files)
        src_n, hdr_n = _count_kinds(chunk_files)
        return SliceUnit(
            unit_id=f"{unit_prefix}:part{index:03d}",
            modules=[module_path],
            targets=list(targets),
            files=set(chunk_files),
            loc=loc,
            source_files=src_n,
            header_files=hdr_n,
            oversized=loc > max_loc,
        )

    # Header-only fallback. This should be rare, but keep the hard-limit planner
    # usable for metadata/header modules as well.
    if not source_seeds:
        ordered = sorted(files, key=lambda r: (posixpath.dirname(r), r))
        units: List[SliceUnit] = []
        cur: Set[str] = set()
        cur_loc = 0
        part = 1
        for r in ordered:
            rloc = analyzer._loc_cache.get(r, 0)
            if cur and cur_loc + rloc > max_loc:
                units.append(make_unit(cur, part))
                part += 1
                cur, cur_loc = set(), 0
            cur.add(r)
            cur_loc += rloc
        if cur:
            units.append(make_unit(cur, part))
        return units

    units_files: List[Set[str]] = []

    # Build the include graph ONCE for this oversized semantic universe.
    # v2 recursively called include_closure() for every binary split.  A 2M+ LOC
    # unit could therefore rescan the same 5k-10k files dozens of times.  Here
    # every file is parsed/resolved once; recursive partitions only do cheap
    # in-memory graph reachability.
    include_dirs_list: List[str] = []
    for r in sorted(include_dirs):
        pp = analyzer.repo / r if r != '.' else analyzer.repo
        if pp.is_dir():
            include_dirs_list.append(r or '.')

    analyzer.log(
        f"forced split graph START: {unit_prefix} universe={len(files):,} "
        f"sources={len(source_seeds):,} include_dirs={len(include_dirs_list):,}"
    )
    graph: Dict[str, Set[str]] = {}
    graph_started = time.monotonic()
    graph_last_log = graph_started
    ordered_universe = sorted(r for r in files if r in analyzer.rel_to_path)
    universe_set = set(files)
    for idx, rel in enumerate(ordered_universe, 1):
        path = analyzer.rel_to_path[rel]
        edges: Set[str] = set()
        for inc, quoted in analyzer.parse_includes(path):
            matches, _amb = analyzer.resolve_include(
                inc, quoted, path, include_dirs_list, allowed_files=universe_set
            )
            for mp in matches:
                rr = analyzer.rel(mp)
                if rr and rr in universe_set:
                    edges.add(rr)
        graph[rel] = edges
        now = time.monotonic()
        if analyzer.progress and now - graph_started >= analyzer.slow_include_seconds and now - graph_last_log >= 2.0:
            analyzer.log(
                f"forced split graph [{unit_prefix}]: indexed={idx:,}/{len(ordered_universe):,} "
                f"edges={sum(len(v) for v in graph.values()):,}"
            )
            graph_last_log = now
    analyzer.log(
        f"forced split graph DONE: {unit_prefix} files={len(graph):,} "
        f"edges={sum(len(v) for v in graph.values()):,} "
        f"elapsed={time.monotonic() - graph_started:.2f}s"
    )

    closure_cache: Dict[Tuple[str, ...], Set[str]] = {}

    def graph_closure(seeds: List[str]) -> Set[str]:
        key = tuple(seeds)
        cached = closure_cache.get(key)
        if cached is not None:
            return set(cached)
        out = set(seeds)
        q = deque(seeds)
        while q:
            cur = q.popleft()
            for nxt in graph.get(cur, ()):
                if nxt not in out:
                    out.add(nxt)
                    q.append(nxt)
        closure_cache[key] = set(out)
        return out

    split_counter = 0
    def recurse(seeds: List[str], depth: int = 0) -> None:
        nonlocal split_counter
        split_counter += 1
        related = graph_closure(seeds)
        loc = _loc_of_files(analyzer, related)
        if analyzer.progress:
            analyzer.log(
                f"forced split part: {unit_prefix} depth={depth} seeds={len(seeds):,} "
                f"related={len(related):,} LOC={loc:,}"
            )
        if loc <= max_loc or len(seeds) <= 1:
            units_files.append(related)
            return

        # Split approximately by source LOC while retaining lexical/path locality.
        total = sum(analyzer._loc_cache.get(r, 0) for r in seeds)
        half = max(1, total // 2)
        acc = 0
        cut = 1
        for i, r in enumerate(seeds[:-1], 1):
            acc += analyzer._loc_cache.get(r, 0)
            cut = i
            if acc >= half:
                break
        recurse(seeds[:cut], depth + 1)
        recurse(seeds[cut:], depth + 1)

    recurse(source_seeds)

    # Preserve any non-header/non-source files that were in the semantic slice
    # by attaching them to the smallest chunk when possible. Normally ``files``
    # contains only C/C++ source/header files.
    covered = set().union(*units_files) if units_files else set()
    leftovers = files - covered
    if leftovers and units_files:
        for r in sorted(leftovers):
            candidates = sorted(
                range(len(units_files)),
                key=lambda i: _loc_of_files(analyzer, units_files[i]),
            )
            placed = False
            for i in candidates:
                cand = set(units_files[i])
                cand.add(r)
                if _loc_of_files(analyzer, cand) <= max_loc:
                    units_files[i] = cand
                    placed = True
                    break
            if not placed:
                units_files.append({r})

    return [make_unit(fs, i + 1) for i, fs in enumerate(units_files) if fs]


def _build_module_unit(
    analyzer: CMakeStaticAnalyzer,
    module_path: str,
    direct_targets: Sequence[str],
    include_add_dependencies: bool,
    max_loc: int,
) -> List[SliceUnit]:
    """Create semantic atomic units without arbitrary source-level hard splitting.

    v4 policy:
      * A leaf CMake module is indivisible, regardless of LOC.
      * For a non-leaf module, only code physically local to that CMake directory
        is represented here; descendant CMake modules are planned separately.
      * Real direct CMake targets are preferred boundaries. A target may exceed
        400K and is then kept intact/marked oversized instead of being split into
        hundreds or thousands of source chunks.
      * Unassigned local files form one residual semantic unit and may also exceed
        400K. 400K is therefore a packing target, not a reason to destroy the last
        meaningful CMake/target boundary.
    """
    m = analyzer.modules[module_path]
    is_leaf = not m.children

    local_sources = {
        r for r in m.local_code_files if Path(r).suffix.lower() in SOURCE_EXTS
    }
    local_headers = {
        r for r in m.local_code_files if Path(r).suffix.lower() in HEADER_EXTS
    }

    # Leaf module: keep the whole semantic module intact. Use direct-target
    # dependency closures when available, plus unassigned local source/include closure.
    if is_leaf:
        related: Set[str] = set()
        include_dirs: Set[str] = set()
        covered_local: Set[str] = set()
        for idx, tname in enumerate(direct_targets, 1):
            analyzer.log(f"atomic leaf: module={module_path} target={tname} ({idx}/{len(direct_targets)})")
            tr, _ui, incs, _uc = analyzer._target_related_files(tname, include_add_dependencies)
            related.update(tr)
            include_dirs.update(incs)
            t = analyzer.targets.get(tname)
            if t:
                covered_local.update(r for r in t.sources if r in m.local_code_files)

        residual_sources = local_sources - covered_local
        if residual_sources:
            rc, _ = analyzer.include_closure(
                residual_sources, include_dirs, label=f"leaf-residual:{module_path}"
            )
            related.update(rc)
        related.update(local_headers)
        if not related:
            related.update(m.local_code_files)
        if not related:
            return []
        loc = _loc_of_files(analyzer, related)
        src_n, hdr_n = _count_kinds(related)
        if loc > max_loc:
            analyzer.log(
                f"semantic oversized leaf kept intact: module={module_path} "
                f"LOC={loc:,} > nominal max={max_loc:,}"
            )
        return [SliceUnit(
            unit_id=f"leaf-module:{module_path}", modules=[module_path],
            targets=list(direct_targets), files=related, loc=loc,
            source_files=src_n, header_files=hdr_n, oversized=loc > max_loc,
        )]

    # Non-leaf: DO NOT build a full parent target/subtree closure. Descendant
    # modules already get their own units. Only preserve parent-local code.
    if not local_sources and not local_headers:
        return []

    units: List[SliceUnit] = []
    covered_local: Set[str] = set()

    for tname in direct_targets:
        t = analyzer.targets.get(tname)
        if not t:
            continue
        target_local_sources = {r for r in t.sources if r in local_sources}
        if not target_local_sources:
            continue
        covered_local.update(target_local_sources)

        # For parent targets, use the target's include directories but deliberately
        # restrict the source seed to files physically local to this module. This
        # avoids re-importing all descendant module sources through a parent target.
        include_dirs = set(t.include_dirs)
        related, _ = analyzer.include_closure(
            target_local_sources, include_dirs, label=f"parent-local-target:{module_path}:{tname}"
        )
        related.update(r for r in local_headers if r in related)
        if not related:
            related = set(target_local_sources)
        loc = _loc_of_files(analyzer, related)
        src_n, hdr_n = _count_kinds(related)
        if loc > max_loc:
            analyzer.log(
                f"semantic oversized target kept intact: module={module_path} "
                f"target={tname} LOC={loc:,} > nominal max={max_loc:,}"
            )
        units.append(SliceUnit(
            unit_id=f"target-local:{module_path}:{tname}", modules=[module_path],
            targets=[tname], files=related, loc=loc,
            source_files=src_n, header_files=hdr_n, oversized=loc > max_loc,
        ))

    residual_sources = local_sources - covered_local
    residual_files: Set[str] = set(local_headers)
    if residual_sources:
        residual_closure, _ = analyzer.include_closure(
            residual_sources, set(), label=f"parent-residual:{module_path}"
        )
        residual_files.update(residual_closure)
    if residual_files:
        loc = _loc_of_files(analyzer, residual_files)
        src_n, hdr_n = _count_kinds(residual_files)
        if loc > max_loc:
            analyzer.log(
                f"semantic oversized parent residual kept intact: module={module_path} "
                f"LOC={loc:,} > nominal max={max_loc:,}"
            )
        units.append(SliceUnit(
            unit_id=f"parent-residual:{module_path}", modules=[module_path],
            targets=[], files=residual_files, loc=loc,
            source_files=src_n, header_files=hdr_n, oversized=loc > max_loc,
        ))

    return units


def _build_atomic_units(
    analyzer: CMakeStaticAnalyzer,
    include_add_dependencies: bool,
    max_loc: int,
) -> Tuple[List[SliceUnit], List[str]]:
    """Build semantic atoms while avoiding parent/child duplication.

    The old planner built full units for every parent and every child CMake
    module. Parent targets often reference child sources, which caused the same
    code to be split repeatedly and could yield thousands of shards. v4 makes
    leaf modules primary atoms and limits non-leaf modules to their physically
    local residual code/targets only.
    """
    direct_map = _module_direct_targets(analyzer)
    units: List[SliceUnit] = []
    empty_modules: List[str] = []

    module_order = sorted(
        analyzer.modules,
        key=lambda mp: (analyzer.modules[mp].depth, mp.replace("\\", "/")),
        reverse=True,
    )
    total = len(module_order)
    for idx, mp in enumerate(module_order, 1):
        m = analyzer.modules[mp]
        kind = "leaf" if not m.children else "parent-local"
        analyzer.log(
            f"atomic modules: {idx:,}/{total:,} START module={mp} kind={kind} "
            f"direct_targets={len(direct_map.get(mp, [])):,} "
            f"local_files={len(m.local_code_files):,}"
        )
        created = _build_module_unit(
            analyzer, mp, direct_map.get(mp, []), include_add_dependencies, max_loc
        )
        if not created:
            empty_modules.append(mp)
        else:
            units.extend(created)
        analyzer.log(
            f"atomic modules: {idx:,}/{total:,} DONE module={mp} units={len(created):,}"
        )
    return units, empty_modules

def _make_shard(
    index: int,
    units: Sequence[SliceUnit],
    analyzer: CMakeStaticAnalyzer,
    max_loc: int,
) -> ShardPlan:
    files: Set[str] = set()
    modules: Set[str] = set()
    targets: Set[str] = set()
    unit_ids: List[str] = []
    oversize = False
    for u in units:
        files.update(u.files)
        modules.update(u.modules)
        targets.update(u.targets)
        unit_ids.append(u.unit_id)
        oversize = oversize or u.oversized
    loc = _loc_of_files(analyzer, files)
    src_n, hdr_n = _count_kinds(files)
    first = sorted(modules)[0] if modules else f"shard-{index}"
    return ShardPlan(
        shard_id=f"shard_{index:04d}_{_safe_slug(first, 42)}",
        modules=sorted(modules),
        targets=sorted(targets),
        unit_ids=unit_ids,
        files=files,
        loc=loc,
        source_files=src_n,
        header_files=hdr_n,
        oversized=oversize or loc > max_loc,
    )


def _pack_units(
    units: Sequence[SliceUnit],
    analyzer: CMakeStaticAnalyzer,
    target_loc: int,
    max_loc: int,
    min_loc: int,
) -> List[ShardPlan]:
    """
    Greedy locality-aware packing with unique-file LOC accounting.

    - Leaf CMake modules are indivisible semantic units and may exceed max_loc.
    - Real CMake targets and parent-local residual units are also never source-split.
    - Adjacent small modules are considered together.
    - The soft objective is target_loc.
    - max_loc is a packing limit; indivisible semantic atoms may exceed it.
    """
    if target_loc <= 0 or max_loc <= 0:
        raise ValueError("target_loc and max_loc must be > 0")
    if target_loc > max_loc:
        raise ValueError("target_loc cannot exceed max_loc")
    if min_loc < 0:
        raise ValueError("min_loc cannot be negative")

    ordered = sorted(
        units,
        key=lambda u: (
            u.modules[0] if u.modules else "",
            u.unit_id,
        ),
    )

    groups: List[List[SliceUnit]] = []
    current: List[SliceUnit] = []
    current_files: Set[str] = set()
    current_loc = 0

    def finalize() -> None:
        nonlocal current, current_files, current_loc
        if current:
            groups.append(current)
            current = []
            current_files = set()
            current_loc = 0

    for u in ordered:
        if not current:
            current = [u]
            current_files = set(u.files)
            current_loc = _loc_of_files(analyzer, current_files)
            if current_loc > max_loc:
                # Pathological single-source closure larger than the hard limit.
                finalize()
            continue

        candidate_files = current_files | u.files
        candidate_loc = _loc_of_files(analyzer, candidate_files)

        # Never cross the hard limit when the current group can be finalized.
        if candidate_loc > max_loc:
            finalize()
            current = [u]
            current_files = set(u.files)
            current_loc = _loc_of_files(analyzer, current_files)
            if current_loc > max_loc:
                finalize()
            continue

        # Soft-target choice: if the current shard is already reasonably sized
        # and adding this unit moves farther away from target_loc, close it.
        current_distance = abs(target_loc - current_loc)
        candidate_distance = abs(target_loc - candidate_loc)
        if (
            current_loc >= min_loc
            and candidate_loc >= target_loc
            and current_distance <= candidate_distance
        ):
            finalize()
            current = [u]
            current_files = set(u.files)
            current_loc = _loc_of_files(analyzer, current_files)
            if current_loc > max_loc:
                finalize()
            continue

        current.append(u)
        current_files = candidate_files
        current_loc = candidate_loc

    finalize()

    # Avoid a tiny tail when it can be merged back without exceeding max_loc.
    if len(groups) >= 2:
        tail_files: Set[str] = set()
        for u in groups[-1]:
            tail_files.update(u.files)
        tail_loc = _loc_of_files(analyzer, tail_files)
        if tail_loc < min_loc:
            prev_files: Set[str] = set()
            for u in groups[-2]:
                prev_files.update(u.files)
            merged_loc = _loc_of_files(analyzer, prev_files | tail_files)
            if merged_loc <= max_loc:
                groups[-2].extend(groups[-1])
                groups.pop()

    return [
        _make_shard(i + 1, g, analyzer, max_loc)
        for i, g in enumerate(groups)
    ]


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def _manifest_from_plan(
    repo: Path,
    output_dir: Path,
    analyzer: CMakeStaticAnalyzer,
    units: Sequence[SliceUnit],
    shards: Sequence[ShardPlan],
    target_loc: int,
    max_loc: int,
    min_loc: int,
    empty_modules: Sequence[str],
) -> dict:
    module_to_shards: Dict[str, List[str]] = defaultdict(list)
    for s in shards:
        for mp in s.modules:
            module_to_shards[mp].append(s.shard_id)

    return {
        "repository": str(repo),
        "output_dir": str(output_dir),
        "analysis_mode": "static-cmake-no-build + target/include closure",
        "codeql_build_mode": "none",
        "sizing_policy": {
            "target_loc": target_loc,
            "max_loc": max_loc,
            "min_loc": min_loc,
            "rationale": (
                "GitHub classifies 100k-1M LOC as medium and >1M LOC as large "
                "for CodeQL hardware planning; the default target keeps shards "
                "comfortably inside the medium range."
            ),
        },
        "repository_stats": {
            "cmake_modules": len(analyzer.modules),
            "cmake_targets": len(analyzer.targets),
            "indexed_cpp_files": len(analyzer.rel_to_path),
            "indexed_cpp_loc": sum(analyzer._loc_cache.values()),
            "atomic_units": len(units),
            "planned_shards": len(shards),
        },
        "empty_or_metadata_only_modules": list(empty_modules),
        "module_to_shards": {k: v for k, v in sorted(module_to_shards.items())},
        "shards": [
            {
                "shard_id": s.shard_id,
                "database": str(output_dir / "databases" / s.shard_id),
                "status": "planned",
                "loc": s.loc,
                "files": len(s.files),
                "source_files": s.source_files,
                "header_files": s.header_files,
                "modules": s.modules,
                "targets": s.targets,
                "unit_ids": s.unit_ids,
                "oversized": s.oversized,
            }
            for s in shards
        ],
        "limitations": [
            "CMake is a programming language; static parsing is conservative and cannot perfectly model arbitrary project logic.",
            "Shared target/include dependencies may intentionally appear in multiple databases.",
            "The planner keeps composite shards at or below max_loc when possible. Leaf modules, real targets, and parent-local residual semantic atoms are never arbitrarily source-split; an indivisible atom may exceed max_loc and is marked oversized.",
            "build-mode=none does not reproduce the precision of a successful instrumented C/C++ build.",
        ],
    }


def _write_plan_csv(path: Path, manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow([
            "shard_id", "status", "loc", "files", "source_files", "header_files",
            "oversized", "modules", "targets", "database",
        ])
        for s in manifest["shards"]:
            w.writerow([
                s["shard_id"], s["status"], s["loc"], s["files"],
                s["source_files"], s["header_files"], str(s["oversized"]).lower(),
                ";".join(s["modules"]), ";".join(s["targets"]), s["database"],
            ])


def _materialize_shard(
    repo: Path,
    shard: ShardPlan,
    temp_root: Path,
    mode: str,
    allow_missing: bool,
    progress: bool,
) -> Tuple[Path, List[str], Dict[str, int]]:
    temp_root.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(
        prefix=f"{shard.shard_id}-",
        dir=str(temp_root),
    )).resolve()
    missing: List[str] = []
    modes: Dict[str, int] = defaultdict(int)
    total = len(shard.files)
    started = time.monotonic()

    for i, rel in enumerate(sorted(shard.files), 1):
        src = _safe_repo_file(repo, rel)
        if not src.is_file():
            missing.append(rel)
            if not allow_missing:
                raise FileNotFoundError(f"repository file is missing: {src}")
            continue
        dst = temp_dir / rel
        actual = _materialize_file(src, dst, mode)
        modes[actual] += 1
        if progress and (i == 1 or i % 5000 == 0 or i == total):
            print(
                f"[materialize] {shard.shard_id}: {i:,}/{total:,} "
                f"({time.monotonic() - started:.1f}s)",
                file=sys.stderr,
                flush=True,
            )
    return temp_dir, missing, dict(modes)


def _is_valid_codeql_db(path: Path) -> bool:
    return path.is_dir() and (
        (path / "codeql-database.yml").is_file()
        or (path / "db-cpp").is_dir()
    )


def _build_one_database(
    codeql: str,
    repo: Path,
    output_dir: Path,
    shard: ShardPlan,
    temp_root: Path,
    materialize_mode: str,
    language: str,
    threads: Optional[int],
    ram_mb: Optional[int],
    allow_missing: bool,
    force: bool,
    resume: bool,
    keep_failed_temp: bool,
    progress: bool,
) -> dict:
    db = (output_dir / "databases" / shard.shard_id).resolve()
    db.parent.mkdir(parents=True, exist_ok=True)

    if _is_valid_codeql_db(db) and resume and not force:
        return {
            "status": "skipped-existing",
            "database": str(db),
            "temp_slice": None,
            "missing_files": [],
            "materialize_modes": {},
            "elapsed_seconds": 0.0,
            "returncode": 0,
        }

    if db.exists():
        if not force:
            raise FileExistsError(
                f"database path already exists: {db}; use force=True/--force "
                "or resume=True with a valid database"
            )
        if db.is_dir():
            shutil.rmtree(db)
        else:
            db.unlink()

    started = time.monotonic()
    temp_dir: Optional[Path] = None
    missing: List[str] = []
    modes: Dict[str, int] = {}
    try:
        temp_dir, missing, modes = _materialize_shard(
            repo,
            shard,
            temp_root,
            materialize_mode,
            allow_missing,
            progress,
        )

        cmd = [
            codeql,
            "database",
            "create",
            str(db),
            f"--language={language}",
            "--build-mode=none",
            f"--source-root={temp_dir}",
        ]
        if threads is not None:
            cmd.append(f"--threads={threads}")
        if ram_mb is not None:
            cmd.append(f"--ram={ram_mb}")

        if progress:
            print(
                "[codeql] " + " ".join(subprocess.list2cmdline([x]) for x in cmd),
                file=sys.stderr,
                flush=True,
            )
        rc = subprocess.run(cmd).returncode
        if rc != 0:
            if db.exists():
                shutil.rmtree(db, ignore_errors=True)
            result = {
                "status": "failed",
                "database": str(db),
                "temp_slice": str(temp_dir) if keep_failed_temp else None,
                "missing_files": missing,
                "materialize_modes": modes,
                "elapsed_seconds": round(time.monotonic() - started, 2),
                "returncode": rc,
            }
            if not keep_failed_temp and temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
            return result

        # User's requested final state: keep only the CodeQL database.
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
        return {
            "status": "built",
            "database": str(db),
            "temp_slice": None,
            "missing_files": missing,
            "materialize_modes": modes,
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "returncode": 0,
        }
    except Exception:
        if db.exists():
            shutil.rmtree(db, ignore_errors=True)
        if temp_dir is not None and temp_dir.exists() and not keep_failed_temp:
            shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def build_split_codeql_databases(
    repo_path: str | Path,
    output_dir: str | Path | None = None,
    *,
    codeql: str = "codeql",
    target_loc: int = 400_000,
    max_loc: int = 400_000,
    min_loc: int = 100_000,
    exclude_dirs: Sequence[str] = (),
    include_add_dependencies: bool = False,
    max_include_ambiguity: int = 20,
    language: str = "c-cpp",
    threads: Optional[int] = 0,
    ram_mb: Optional[int] = None,
    materialize_mode: str = "hardlink",
    allow_missing: bool = True,
    force: bool = False,
    resume: bool = True,
    plan_only: bool = False,
    stop_on_error: bool = False,
    keep_failed_temp: bool = False,
    progress: bool = True,
) -> dict:
    """
    Analyze a CMake C/C++ repository, split it into appropriately-sized semantic
    slices, build one CodeQL database per slice with --build-mode=none, and delete
    temporary source slices after successful creation.

    Only `repo_path` is required. By default the output is created next to the
    repository as `<repo-name>_codeql_dbs`.

    Returns the final manifest dictionary.
    """
    repo = Path(repo_path).resolve()
    if not repo.is_dir():
        raise FileNotFoundError(f"repository does not exist: {repo}")

    if output_dir is None:
        output = repo.parent / f"{repo.name}_codeql_dbs"
    else:
        output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)

    excludes = set(DEFAULT_EXCLUDE_DIRS) | set(exclude_dirs)
    # If the caller deliberately places output under the source tree, make sure
    # a rerun does not scan its own databases.
    try:
        rel_out = output.relative_to(repo)
        if rel_out.parts:
            excludes.add(rel_out.parts[0])
    except ValueError:
        pass

    analyzer = CMakeStaticAnalyzer(
        repo,
        excludes,
        max_include_ambiguity=max_include_ambiguity,
        progress=progress,
    )
    analyzer.scan_repository()
    if not analyzer.modules:
        raise RuntimeError("no CMakeLists.txt found in repository")

    analyzer.log("parsing CMake files and included scripts ...")
    analyzer.load_cmake_commands()
    analyzer.log(
        f"parsed {len(analyzer.cmake_files_seen):,} CMake files / "
        f"{len(analyzer.commands):,} commands"
    )
    analyzer.log("collecting CMake variables ...")
    analyzer.collect_variables()
    analyzer.collect_variables()
    analyzer.log("extracting CMake targets and dependency edges ...")
    analyzer.extract_targets()
    analyzer.log(f"targets extracted: {len(analyzer.targets):,}")

    # LOC is required for sizing. This pass is linear in repository C/C++ files.
    analyzer.skip_loc = False
    analyzer.log("computing physical module ownership and LOC ...")
    analyzer.compute_physical_module_files(skip_loc=False)

    analyzer.log("building atomic module/target slices ...")
    units, empty_modules = _build_atomic_units(
        analyzer,
        include_add_dependencies=include_add_dependencies,
        max_loc=max_loc,
    )
    if not units:
        raise RuntimeError("no C/C++ slice units could be derived")

    analyzer.log(
        f"packing {len(units):,} atomic units into ~{target_loc:,}-LOC shards "
        f"(max {max_loc:,}) ..."
    )
    shards = _pack_units(
        units,
        analyzer,
        target_loc=target_loc,
        max_loc=max_loc,
        min_loc=min_loc,
    )

    manifest = _manifest_from_plan(
        repo,
        output,
        analyzer,
        units,
        shards,
        target_loc,
        max_loc,
        min_loc,
        empty_modules,
    )
    manifest_path = output / "manifest.json"
    _atomic_write_json(manifest_path, manifest)
    _write_plan_csv(output / "split_plan.csv", manifest)

    # Keep per-shard file lists. They are small compared with the DBs and make
    # the split reproducible without retaining temporary source trees.
    filelist_dir = output / "filelists"
    filelist_dir.mkdir(exist_ok=True)
    for shard in shards:
        (filelist_dir / f"{shard.shard_id}.files.txt").write_text(
            "\n".join(sorted(shard.files)) + "\n",
            encoding="utf-8",
        )

    if plan_only:
        analyzer.log(f"plan-only complete: {len(shards):,} shards")
        return manifest

    codeql_exe = _resolve_executable(codeql)
    try:
        ver = subprocess.run(
            [codeql_exe, "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        manifest["codeql_version"] = ver.stdout.strip()
    except Exception:
        manifest["codeql_version"] = "unknown"

    temp_root = output / ".tmp_slices"
    temp_root.mkdir(exist_ok=True)

    shard_by_id = {s.shard_id: s for s in shards}
    failures = 0
    for idx, entry in enumerate(manifest["shards"], 1):
        sid = entry["shard_id"]
        shard = shard_by_id[sid]
        analyzer.log(
            f"database {idx:,}/{len(shards):,}: {sid} "
            f"LOC={shard.loc:,} files={len(shard.files):,} "
            f"modules={len(shard.modules):,}"
        )
        try:
            result = _build_one_database(
                codeql_exe,
                repo,
                output,
                shard,
                temp_root,
                materialize_mode,
                language,
                threads,
                ram_mb,
                allow_missing,
                force,
                resume,
                keep_failed_temp,
                progress,
            )
            entry.update(result)
            if result["status"] == "failed":
                failures += 1
                if stop_on_error:
                    _atomic_write_json(manifest_path, manifest)
                    _write_plan_csv(output / "split_plan.csv", manifest)
                    break
        except Exception as exc:
            failures += 1
            entry.update({
                "status": "failed-exception",
                "error": str(exc),
                "returncode": None,
            })
            _atomic_write_json(manifest_path, manifest)
            _write_plan_csv(output / "split_plan.csv", manifest)
            if stop_on_error:
                break

        _atomic_write_json(manifest_path, manifest)
        _write_plan_csv(output / "split_plan.csv", manifest)

    # Successful builds leave no temporary source slices.
    try:
        if temp_root.is_dir() and not any(temp_root.iterdir()):
            temp_root.rmdir()
    except OSError:
        pass

    manifest["summary"] = {
        "built": sum(1 for s in manifest["shards"] if s.get("status") == "built"),
        "skipped_existing": sum(
            1 for s in manifest["shards"]
            if s.get("status") == "skipped-existing"
        ),
        "failed": sum(
            1 for s in manifest["shards"]
            if str(s.get("status", "")).startswith("failed")
        ),
        "total": len(manifest["shards"]),
    }
    _atomic_write_json(manifest_path, manifest)
    _write_plan_csv(output / "split_plan.csv", manifest)
    return manifest


def _parse_integrated_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Split a large CMake C/C++ repository into semantically-related "
            "CodeQL --build-mode=none databases."
        )
    )
    p.add_argument("repo", type=Path, help="C/C++ repository root")
    p.add_argument(
        "-o", "--output", type=Path,
        help="Output directory (default: sibling <repo>_codeql_dbs)"
    )
    p.add_argument("--codeql", default="codeql", help="CodeQL CLI executable")
    p.add_argument(
        "--target-loc", type=int, default=400_000,
        help="Target LOC per database (default: 400000)"
    )
    p.add_argument(
        "--max-loc", type=int, default=400_000,
        help="Nominal maximum LOC per database (default: 400000); leaf CMake modules may exceed it and remain intact"
    )
    p.add_argument(
        "--min-loc", type=int, default=100_000,
        help="Avoid tiny shards below this LOC when possible (default: 100000)"
    )
    p.add_argument(
        "--exclude-dir", action="append", default=[],
        help="Directory basename to exclude; may be repeated"
    )
    p.add_argument(
        "--include-add-dependencies", action="store_true",
        help="Follow add_dependencies() edges in addition to target_link_libraries()"
    )
    p.add_argument(
        "--max-include-ambiguity", type=int, default=20,
        help="Maximum ambiguous #include candidates before treating it as unresolved"
    )
    p.add_argument("--language", default="c-cpp")
    p.add_argument(
        "--threads", type=int, default=0,
        help="CodeQL database-create threads; 0 means one per core"
    )
    p.add_argument(
        "--ram", dest="ram_mb", type=int,
        help="CodeQL RAM hint in MB"
    )
    p.add_argument(
        "--materialize-mode",
        choices=["hardlink", "copy", "symlink"],
        default="hardlink",
        help="Temporary slice mode (default hardlink, copy fallback)"
    )
    p.add_argument(
        "--strict-missing", action="store_true",
        help="Fail a shard if a referenced repository file is missing"
    )
    p.add_argument(
        "--force", action="store_true",
        help="Delete and rebuild existing database directories"
    )
    p.add_argument(
        "--no-resume", action="store_true",
        help="Do not reuse already-valid CodeQL database shards"
    )
    p.add_argument(
        "--plan-only", action="store_true",
        help="Only analyze and write split plan/file lists; do not invoke CodeQL"
    )
    p.add_argument(
        "--stop-on-error", action="store_true",
        help="Stop after the first failed database"
    )
    p.add_argument(
        "--keep-failed-temp", action="store_true",
        help="Keep a failed shard's temporary source tree for debugging"
    )
    p.add_argument(
        "--quiet", action="store_true",
        help="Reduce progress output"
    )
    return p.parse_args()


def _integrated_main() -> int:
    ns = _parse_integrated_args()
    try:
        manifest = build_split_codeql_databases(
            ns.repo,
            ns.output,
            codeql=ns.codeql,
            target_loc=ns.target_loc,
            max_loc=ns.max_loc,
            min_loc=ns.min_loc,
            exclude_dirs=ns.exclude_dir,
            include_add_dependencies=ns.include_add_dependencies,
            max_include_ambiguity=ns.max_include_ambiguity,
            language=ns.language,
            threads=ns.threads,
            ram_mb=ns.ram_mb,
            materialize_mode=ns.materialize_mode,
            allow_missing=not ns.strict_missing,
            force=ns.force,
            resume=not ns.no_resume,
            plan_only=ns.plan_only,
            stop_on_error=ns.stop_on_error,
            keep_failed_temp=ns.keep_failed_temp,
            progress=not ns.quiet,
        )
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"repository: {manifest['repository']}")
    print(f"output:     {manifest['output_dir']}")
    print(f"shards:     {len(manifest['shards'])}")
    if ns.plan_only:
        print("mode:       plan-only")
    else:
        summary = manifest.get("summary", {})
        print(
            f"built:      {summary.get('built', 0)} "
            f"(skipped={summary.get('skipped_existing', 0)}, "
            f"failed={summary.get('failed', 0)})"
        )
    print(f"manifest:   {Path(manifest['output_dir']) / 'manifest.json'}")
    return 0 if not manifest.get("summary", {}).get("failed", 0) else 1


if __name__ == "__main__":
    raise SystemExit(_integrated_main())
