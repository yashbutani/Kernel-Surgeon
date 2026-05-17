"""
Cscope-based call graph extractor.

Fast extraction method that uses cscope's database to build the kernel
call graph. Lower fidelity than LLVM IR (misses indirect calls, macros)
but produces a workable graph in minutes rather than hours.

Mapping approach
----------------
The extractor operates subsystem-by-subsystem so a live progress display
can show exactly which parts of the kernel have been explored:

  1. Build (or reuse) the cscope database from the full kernel tree.
  2. Parse the cscope.out cross-reference in a single pass to extract
     all caller→callee edges into memory (no per-function subprocess).
  3. Enumerate all function definitions via ctags (or regex fallback).
  4. Group functions by their top-level directory (net/, mm/, fs/, ...).
  5. For each subsystem in the supplied order:
       a. Add all function nodes for that subsystem.
       b. Add call edges from the pre-parsed cross-reference.
       c. Emit progress events to a MappingVisualizer (if provided).
  6. Return the completed KernelGraph.

Usage
-----
    python cscope_extractor.py --kernel-path /path/to/linux --output data/callgraph.json
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Generator, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from kernel_graph import KernelGraph, EdgeType


# ============================================================================
# CscopeDBParser — parse cscope.out cross-reference in a single pass
# ============================================================================

class CscopeDBParser:
    """
    Parse the cscope.out cross-reference file directly to extract all
    caller→callee relationships in one read.  Eliminates the need for
    per-function ``cscope -d -L -2 <symbol>`` subprocess calls.

    cscope.out cross-reference markers (tab-prefixed lines)::

        \\t@<file_path>       — current file marker
        \\t$<func_name>       — function definition (sets current scope)
        \\t`<func_name>       — function call (callee of current function)

    Everything between a ``\\t$`` marker and the next ``\\t$`` or ``\\t@``
    marker belongs to that function's definition scope.
    """

    def __init__(self, cscope_out_path: Path):
        self.calls: dict[str, set[str]] = defaultdict(set)   # caller -> {callees}
        self.func_files: dict[str, str] = {}                  # func -> file_path
        self._parse(cscope_out_path)

    def _parse(self, path: Path) -> None:
        current_file = ""
        current_func = ""

        # Determine trailer offset from the header line so we stop before
        # the binary symbol index appended by ``cscope -q``.
        trailer_offset = 0

        with open(path, "rb") as f:
            header = f.readline()
            header_str = header.decode("utf-8", errors="replace").strip()
            # Header format: cscope <version> <dir> [-c] [-q ...] <trailer_offset>
            for token in reversed(header_str.split()):
                if token.isdigit():
                    trailer_offset = int(token)
                    break

            for raw_line in f:
                # Stop at the trailer (binary symbol index)
                if trailer_offset and f.tell() > trailer_offset:
                    break

                # Fast check: only lines starting with tab have markers
                if not raw_line or raw_line[0] != 0x09:  # 0x09 = '\t'
                    continue

                line = raw_line.decode("utf-8", errors="replace").rstrip("\n\r")

                if len(line) < 2:
                    continue

                marker = line[1]

                if marker == "@":
                    # File marker
                    current_file = line[2:]
                elif marker == "$":
                    # Function definition — sets current scope
                    current_func = line[2:]
                    if current_func and current_file:
                        self.func_files[current_func] = current_file
                elif marker == "`":
                    # Function call — callee of current_func
                    callee = line[2:]
                    if current_func and callee:
                        self.calls[current_func].add(callee)

    def get_callees(self, func_name: str) -> set[str]:
        """Get all functions called by *func_name*."""
        return self.calls.get(func_name, set())

    def get_file(self, func_name: str) -> str:
        """Get the file where *func_name* is defined (or ``""`` if unknown)."""
        return self.func_files.get(func_name, "")


# ============================================================================
# CscopeExtractor
# ============================================================================

class CscopeExtractor:
    """
    Extracts kernel call graph using cscope.

    Workflow:
    1. Build cscope database on the kernel tree (or use existing).
    2. Parse cscope.out cross-reference into memory (CscopeDBParser).
    3. Enumerate all function definitions (ctags, or regex fallback).
    4. Group functions by subsystem, then process each group in order.
    5. For each function: look up callees from the parsed DB and add edges.
    """

    def __init__(
        self,
        kernel_path: str,
        subsystems: list[str] | None = None,
        cache_dir: str | None = None,
    ) -> None:
        self.kernel_path = Path(kernel_path).resolve()
        self.subsystems = subsystems
        self.cscope_db  = self.kernel_path / "cscope.out"
        self.cache_dir  = Path(cache_dir) if cache_dir else None
        self.graph      = KernelGraph()

        self._processed_functions: set[str] = set()

    # ------------------------------------------------------------------
    # Step 1: cscope database
    # ------------------------------------------------------------------

    def build_cscope_db(self) -> None:
        """Build cscope database. Uses kernel's built-in ``make cscope``."""
        print("[*] Building cscope database...")
        if self.cscope_db.exists():
            print("    cscope.out already exists — reusing. Delete it to rebuild.")
            return

        result = subprocess.run(
            ["make", "cscope"],
            cwd=self.kernel_path,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            print("    make cscope failed — building database manually...")
            self._build_cscope_manual()

    def _build_cscope_manual(self) -> None:
        """Build cscope DB manually by finding all C files in the target dirs."""
        file_list = self.kernel_path / "cscope.files"
        patterns = self.subsystems or [
            "kernel/", "mm/", "fs/", "net/", "drivers/",
            "security/", "ipc/", "block/", "crypto/", "lib/",
        ]
        with open(file_list, "w") as fh:
            for pattern in patterns:
                search_dir = self.kernel_path / pattern
                if not search_dir.exists():
                    continue
                for cfile in search_dir.rglob("*.c"):
                    fh.write(str(cfile) + "\n")
                for hfile in search_dir.rglob("*.h"):
                    fh.write(str(hfile) + "\n")

        subprocess.run(
            ["cscope", "-b", "-q", "-k"],
            cwd=self.kernel_path,
            capture_output=True,
            timeout=600,
        )

    # ------------------------------------------------------------------
    # Fallback: query cscope via subprocess (for non-callee queries)
    # ------------------------------------------------------------------

    def _query_cscope(self, query_type: int, symbol: str) -> list[dict]:
        """
        Query cscope database via subprocess (fallback only).

        Query types:
            0 = Find this C symbol
            1 = Find this function definition
            2 = Find functions called by this function
            3 = Find functions calling this function

        NOTE: For type-2 (callee) queries, prefer CscopeDBParser which
        pre-parses the entire cross-reference in a single pass.
        """
        try:
            result = subprocess.run(
                ["cscope", "-d", "-L", f"-{query_type}", symbol],
                cwd=self.kernel_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            return []

        results = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split(maxsplit=3)
            if len(parts) >= 3:
                results.append({
                    "file":     parts[0],
                    "function": parts[1],
                    "line":     int(parts[2]) if parts[2].isdigit() else 0,
                    "context":  parts[3] if len(parts) > 3 else "",
                })
        return results

    def _is_cscope_compressed(self) -> bool:
        """
        Check if cscope.out was built WITHOUT the -c (ASCII) flag.

        The header line looks like::

            cscope 15 /dir [-q <offset1> <offset2>] [-c] <trailer_offset>

        If ``-c`` is absent, cscope used its default compression scheme and
        function names in the cross-reference contain high-byte tokens that
        won't match plain ASCII ctags identifiers.
        """
        try:
            with open(self.cscope_db, "rb") as f:
                header = f.readline().decode("utf-8", errors="replace")
            return "-c" not in header.split()
        except Exception:
            return True  # assume compressed if unreadable

    def _batch_query_callees(
        self,
        func_names: list[str],
        max_workers: int = 16,
    ) -> dict[str, set[str]]:
        """
        Query cscope for callees of every function in *func_names* using a
        thread pool of subprocess calls.

        Used as fallback when cscope.out is compressed and cannot be parsed
        directly.  ThreadPoolExecutor is sufficient here because each worker
        spends most of its time blocked on the cscope subprocess I/O.

        Args:
            func_names:  Functions to query.
            max_workers: Parallel cscope processes (capped at len(func_names)).

        Returns:
            dict mapping caller name → set of callee names.
        """
        calls: dict[str, set[str]] = defaultdict(set)
        workers = min(max_workers, len(func_names)) if func_names else 1

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self._query_cscope, 2, name): name
                for name in func_names
            }
            done = 0
            total = len(futures)
            for future in as_completed(futures):
                name = futures[future]
                try:
                    for r in future.result():
                        calls[name].add(r["function"])
                except Exception:
                    pass
                done += 1
                if done % 500 == 0 or done == total:
                    print(f"    Queried {done:,}/{total:,} functions ...", end="\r")
        print()  # newline after \r progress
        return dict(calls)

    # ------------------------------------------------------------------
    # Per-subsystem extraction cache
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_cache_name(subsys: str) -> str:
        """Convert a subsystem path to a safe filename stem."""
        return re.sub(r"[^a-zA-Z0-9_-]", "_", subsys).strip("_")

    def _subsys_cache_path(self, subsys: str) -> Path:
        return self.cache_dir / f"{self._safe_cache_name(subsys)}.json"

    def _try_load_cache(
        self, subsys: str, cscope_mtime: float
    ) -> Optional[dict]:
        """
        Load cached extraction data for *subsys* if it is still valid.

        A cache entry is valid when:
          - ``mode`` equals ``"cscope"``
          - ``cscope_mtime`` matches the current mtime of ``cscope.out``

        Returns ``None`` on any miss.
        """
        if self.cache_dir is None:
            return None
        path = self._subsys_cache_path(subsys)
        if not path.exists():
            return None
        try:
            with open(path) as f:
                data = json.load(f)
            if data.get("mode") != "cscope":
                return None  # different extraction mode
            if abs(data.get("cscope_mtime", -1) - cscope_mtime) > 1.0:
                return None  # stale
            return data
        except Exception:
            return None

    def _save_cache(
        self,
        subsys: str,
        funcs: list[dict],
        edges: list[tuple[str, str]],
        cscope_mtime: float,
    ) -> None:
        """Persist extraction results for *subsys* to the cache directory."""
        if self.cache_dir is None:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "mode": "cscope",
            "subsystem": subsys,
            "extracted_at": time.time(),
            "cscope_mtime": cscope_mtime,
            "functions": funcs,
            "edges": [[c, e] for c, e in edges],
        }
        path = self._subsys_cache_path(subsys)
        with open(path, "w") as f:
            json.dump(data, f)

    def _replay_cache(self, cached: dict) -> tuple[int, int]:
        """
        Replay a cached subsystem into ``self.graph``.

        Returns ``(n_functions, n_edges)`` for reporting.
        """
        for func in cached["functions"]:
            self.graph.add_function(
                name=func["name"],
                file_path=func["file"],
                line_start=func.get("line", 0),
            )
            self._processed_functions.add(func["name"])

        n_edges = 0
        for caller_name, callee_name in cached["edges"]:
            caller_ids = self.graph.lookup_function(caller_name)
            callee_ids = self.graph.lookup_function(callee_name)
            if not callee_ids:
                callee_id = self.graph.add_function(
                    name=callee_name, file_path="unknown"
                )
                callee_ids = [callee_id]
            for cid in caller_ids:
                for eid in callee_ids:
                    self.graph.add_call_edge(cid, eid, edge_type=EdgeType.CALLS)
                    n_edges += 1
        return len(cached["functions"]), n_edges

    # ------------------------------------------------------------------
    # Step 2: function enumeration
    # ------------------------------------------------------------------

    @staticmethod
    def _find_ctags() -> str | None:
        """Return the first available ctags binary name, or None."""
        import shutil
        for candidate in ("ctags", "universal-ctags", "exuberant-ctags"):
            if shutil.which(candidate):
                return candidate
        return None

    def _get_all_function_defs(self) -> Generator[dict, None, None]:
        """
        Enumerate all function definitions in the kernel tree.

        Tries ctags first (fast), falls back to regex scanning.
        """
        ctags_file = self.kernel_path / "tags"
        if not ctags_file.exists():
            ctags_bin = self._find_ctags()
            if ctags_bin:
                print("[*] Generating ctags index for function enumeration...")
                patterns = self.subsystems or [
                    "kernel/", "mm/", "fs/", "net/", "security/", "ipc/", "block/",
                ]
                dirs = [
                    str(self.kernel_path / p)
                    for p in patterns
                    if (self.kernel_path / p).exists()
                ]
                if dirs:
                    try:
                        subprocess.run(
                            [ctags_bin, "-R", "--c-kinds=f", "--fields=+Sn",
                             "-o", str(ctags_file)] + dirs,
                            capture_output=True,
                            timeout=300,
                        )
                    except (FileNotFoundError, OSError) as e:
                        print(f"[!] ctags failed ({e}), falling back to regex scan")
            else:
                print("[!] ctags not found, falling back to regex scan")

        if ctags_file.exists():
            yield from self._parse_ctags(ctags_file)
        else:
            yield from self._scan_for_functions()

    def _parse_ctags(self, ctags_file: Path) -> Generator[dict, None, None]:
        """Parse ctags output for function definitions."""
        with open(ctags_file, errors="ignore") as fh:
            for line in fh:
                if line.startswith("!"):
                    continue
                parts = line.split("\t")
                if len(parts) < 3:
                    continue
                name     = parts[0]
                filepath = parts[1]

                try:
                    rel_path = str(Path(filepath).relative_to(self.kernel_path))
                except ValueError:
                    rel_path = filepath

                # Apply subsystem filter if requested
                if self.subsystems:
                    if not any(rel_path.startswith(s) for s in self.subsystems):
                        continue

                # Extract line number from tag fields
                line_num = 0
                for part in parts[2:]:
                    part = part.strip()
                    if part.isdigit():
                        line_num = int(part)
                        break
                    m = re.search(r'line:(\d+)', part)
                    if m:
                        line_num = int(m.group(1))
                        break

                yield {"name": name, "file": rel_path, "line": line_num}

    def _scan_for_functions(self) -> Generator[dict, None, None]:
        """Fallback: regex scan C files for function definitions."""
        func_pattern = re.compile(
            r'^(?:static\s+)?(?:inline\s+)?(?:__always_inline\s+)?'
            r'(?:(?:void|int|long|unsigned|bool|struct\s+\w+|enum\s+\w+)\s*\*?\s+)'
            r'(\w+)\s*\(',
            re.MULTILINE,
        )
        patterns = self.subsystems or ["kernel/", "mm/", "fs/", "net/"]
        for pattern in patterns:
            search_dir = self.kernel_path / pattern
            if not search_dir.exists():
                continue
            for cfile in search_dir.rglob("*.c"):
                try:
                    text = cfile.read_text(errors="ignore")
                except Exception:
                    continue
                rel_path = str(cfile.relative_to(self.kernel_path))
                for m in func_pattern.finditer(text):
                    line_num = text[: m.start()].count("\n") + 1
                    yield {"name": m.group(1), "file": rel_path, "line": line_num}

    # ------------------------------------------------------------------
    # Subsystem classification helper
    # ------------------------------------------------------------------

    @staticmethod
    def _get_subsystem_dir(file_path: str) -> str:
        """
        Extract the top-level directory from a relative file path.

        ``net/ipv4/tcp.c``  →  ``net/``
        ``mm/slub.c``       →  ``mm/``
        ``unknown``         →  ``other/``
        """
        parts = file_path.replace("\\", "/").split("/")
        if len(parts) >= 2:
            return parts[0] + "/"
        return "other/"

    # ------------------------------------------------------------------
    # Main extract entry point
    # ------------------------------------------------------------------

    def extract(
        self,
        max_functions: int = 0,
        visualizer=None,
    ) -> KernelGraph:
        """
        Run the full extraction pipeline.

        Parses the cscope cross-reference file once into memory, then
        processes subsystem by subsystem using the pre-built caller→callee
        map.  No per-function subprocess calls.

        Args:
            max_functions: Limit total functions processed (0 = all).
            visualizer:    A :class:`MappingVisualizer` instance.

        Returns:
            The populated :class:`KernelGraph`.
        """
        self.build_cscope_db()

        # cscope.out mtime is used as the cache invalidation key
        try:
            cscope_mtime = self.cscope_db.stat().st_mtime
        except OSError:
            cscope_mtime = 0.0

        # ── Load callee data from cscope ──────────────────────────────────
        # Prefer direct cscope.out parsing (zero subprocesses), but fall back
        # to parallel subprocess queries when the database uses cscope's default
        # compression (no -c flag), which makes function names unreadable.
        if self._is_cscope_compressed():
            print("[*] cscope.out is compressed — callee data will be fetched "
                  "via parallel subprocess queries after function enumeration.")
            db = None  # resolved after we know which functions to query
        else:
            print("[*] Parsing cscope cross-reference into memory...")
            parse_start = time.monotonic()
            db = CscopeDBParser(self.cscope_db)
            parse_elapsed = time.monotonic() - parse_start
            print(f"    Parsed {len(db.calls):,} callers "
                  f"in {parse_elapsed:.1f}s")

        # ── Enumerate all function definitions ──────────────────────────
        print("[*] Enumerating function definitions...")
        all_functions: list[dict] = []
        for func_def in self._get_all_function_defs():
            all_functions.append(func_def)
            if max_functions and len(all_functions) >= max_functions:
                break
        print(f"    Found {len(all_functions):,} function definitions")

        # ── Fetch callee data if we skipped direct parsing ────────────────
        if db is None:
            print(f"[*] Querying cscope for callees of "
                  f"{len(all_functions):,} functions (parallel)...")
            raw_calls = self._batch_query_callees(
                [f["name"] for f in all_functions]
            )
            # Wrap in the same interface CscopeDBParser exposes
            class _DictDB:
                def __init__(self, calls):
                    self.calls = calls
                    self.func_files: dict[str, str] = {}
                def get_callees(self, name):
                    return self.calls.get(name, set())
                def get_file(self, name):
                    return self.func_files.get(name, "")
            db = _DictDB(raw_calls)
            print(f"    Done — {sum(len(v) for v in raw_calls.values()):,} "
                  f"callee relationships found")

        # ── Group functions by subsystem ──────────────────────────────────
        # When self.subsystems is specified (e.g. ['net/netfilter/', 'net/ipv4/']),
        # match each function to the deepest qualifying subsystem path.
        # Without self.subsystems we fall back to top-level directory grouping
        # (net/, mm/, …) which matches detect_subsystems() output.
        groups: dict[str, list[dict]] = defaultdict(list)
        if self.subsystems:
            for func in all_functions:
                fp = func["file"]
                best = ""
                for s in self.subsystems:
                    if fp.startswith(s) and len(s) > len(best):
                        best = s
                if best:
                    groups[best].append(func)
                # else: file outside all specified subsystems — skip
        else:
            for func in all_functions:
                groups[self._get_subsystem_dir(func["file"])].append(func)

        # Determine processing order
        if visualizer is not None:
            ordered = [s for s in visualizer._order if s in groups]
            for s in sorted(groups, key=lambda x: -len(groups[x])):
                if s not in ordered:
                    ordered.append(s)
        else:
            ordered = sorted(groups, key=lambda x: -len(groups[x]))

        # ── Process subsystem by subsystem ───────────────────────────────
        total_processed = 0

        for subsys in ordered:
            funcs = groups[subsys]
            if max_functions and total_processed >= max_functions:
                break
            if not funcs:
                if visualizer:
                    visualizer.skip_subsystem(subsys)
                continue

            if visualizer:
                visualizer.begin_subsystem(subsys)

            subsys_start = time.monotonic()

            # ── Cache check ──────────────────────────────────────────────
            # Only use cache when max_functions is not capping the run, to
            # avoid persisting partial subsystem extractions.
            use_cache = self.cache_dir is not None and not max_functions
            cached = self._try_load_cache(subsys, cscope_mtime) if use_cache else None

            if cached is not None:
                n_funcs, subsys_edges = self._replay_cache(cached)
                files_seen: set[str] = {f["file"] for f in cached["functions"]}
                total_processed += n_funcs

                if visualizer:
                    visualizer.update_subsystem(
                        subsys,
                        files=len(files_seen),
                        functions=n_funcs,
                        edges=subsys_edges,
                    )
                    visualizer.complete_subsystem(subsys)

                elapsed = time.monotonic() - subsys_start
                print(
                    f"    {subsys:<20}  "
                    f"functions={n_funcs:>8,}  "
                    f"edges={subsys_edges:>8,}  "
                    f"{elapsed:.0f}s  [cached]"
                )
                continue

            # ── Live extraction ───────────────────────────────────────────
            # Phase A: add all function nodes for this subsystem
            for func in funcs:
                self.graph.add_function(
                    name=func["name"],
                    file_path=func["file"],
                    line_start=func.get("line", 0),
                )

            # Phase B: add call edges from pre-parsed cross-reference
            subsys_edges = 0
            files_seen = set()
            subsys_edge_list: list[tuple[str, str]] = []  # for cache

            for i, func in enumerate(funcs):
                name = func["name"]
                files_seen.add(func["file"])

                if name not in self._processed_functions:
                    self._processed_functions.add(name)

                    caller_ids = self.graph.lookup_function(name)
                    for callee_name in db.get_callees(name):
                        callee_ids = self.graph.lookup_function(callee_name)

                        if not callee_ids:
                            callee_file = db.get_file(callee_name) or "unknown"

                            # Strict subsystem scoping: when the user
                            # specified --subsystems, do NOT add callee
                            # nodes whose file falls outside those dirs.
                            if self.subsystems and callee_file != "unknown":
                                if not any(
                                    callee_file.startswith(s)
                                    for s in self.subsystems
                                ):
                                    continue  # skip out-of-scope callee

                            callee_id = self.graph.add_function(
                                name=callee_name,
                                file_path=callee_file,
                            )
                            callee_ids = [callee_id]

                        for caller_id in caller_ids:
                            for callee_id in callee_ids:
                                self.graph.add_call_edge(
                                    caller_id, callee_id,
                                    edge_type=EdgeType.CALLS,
                                )
                                subsys_edges += 1

                        if use_cache:
                            subsys_edge_list.append((name, callee_name))

                # Emit progress every 50 functions
                if visualizer and i % 50 == 49:
                    visualizer.update_subsystem(
                        subsys,
                        files=len(files_seen),
                        functions=i + 1,
                        edges=subsys_edges,
                    )

                if max_functions and total_processed + i + 1 >= max_functions:
                    break

            total_processed += len(funcs)

            if visualizer:
                visualizer.update_subsystem(
                    subsys,
                    files=len(files_seen),
                    functions=len(funcs),
                    edges=subsys_edges,
                )
                visualizer.complete_subsystem(subsys)

            # Save to cache after successful full extraction
            if use_cache:
                self._save_cache(subsys, funcs, subsys_edge_list, cscope_mtime)

            elapsed = time.monotonic() - subsys_start
            print(
                f"    {subsys:<20}  "
                f"functions={len(funcs):>8,}  "
                f"edges={subsys_edges:>8,}  "
                f"{elapsed:.0f}s"
            )

        print(
            f"[+] Extraction complete: "
            f"{self.graph.num_nodes:,} nodes, "
            f"{self.graph.num_edges:,} edges"
        )
        return self.graph


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract Linux kernel call graph using cscope"
    )
    parser.add_argument("--kernel-path", required=True,
                        help="Path to Linux kernel source tree")
    parser.add_argument("--output", default="data/callgraph.json",
                        help="Output path for graph JSON")
    parser.add_argument("--subsystems", nargs="+",
                        help="Subsystems to extract, e.g. kernel/ net/ mm/ "
                             "(default: auto-detect from kernel tree)")
    parser.add_argument("--max-functions", type=int, default=0,
                        help="Max functions to process (0=all)")
    parser.add_argument("--no-visualizer", action="store_true",
                        help="Disable live progress display")
    args = parser.parse_args()

    # Auto-detect subsystems if none specified
    subsystems = args.subsystems
    if subsystems is None:
        from map_visualizer import detect_subsystems
        subsystems = detect_subsystems(args.kernel_path)
        print(f"[*] Auto-detected {len(subsystems)} subsystems: "
              f"{', '.join(subsystems[:6])}{'...' if len(subsystems) > 6 else ''}")

    visualizer = None
    if not args.no_visualizer:
        from map_visualizer import MappingVisualizer
        visualizer = MappingVisualizer(
            kernel_path=args.kernel_path,
            subsystems=subsystems,
        )

    extractor = CscopeExtractor(
        kernel_path=args.kernel_path,
        subsystems=subsystems,
    )

    if visualizer:
        with visualizer:
            graph = extractor.extract(
                max_functions=args.max_functions,
                visualizer=visualizer,
            )
        visualizer.print_summary()
    else:
        graph = extractor.extract(max_functions=args.max_functions)

    graph.save(args.output)
    print(f"[+] Graph saved to {args.output}")

    import json
    print(json.dumps(graph.summary(), indent=2))


if __name__ == "__main__":
    main()
