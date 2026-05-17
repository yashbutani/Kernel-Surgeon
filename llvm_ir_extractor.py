"""
LLVM IR-based call graph extractor.

High-fidelity extraction that parses LLVM IR files emitted during
kernel compilation with Clang. Captures direct calls precisely and
uses type-based approximation for indirect (function pointer) calls.

Prerequisites:
    1. Build kernel with Clang, saving IR:
       make CC=clang LLVM=1 defconfig
       # Add to Makefile or KCFLAGS: -save-temps=obj -emit-llvm
       # Or use: scripts/clang-tools/gen_compile_commands.py
       #         then iterate with: clang -S -emit-llvm per TU

    2. Collect all .ll files into a directory

Usage:
    python -m extractors.llvm_ir_extractor --ir-dir /path/to/ir-files --output data/callgraph.json
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from collections import defaultdict
from typing import Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from kernel_graph import KernelGraph, EdgeType


class LLVMIRExtractor:
    """
    Parses LLVM IR (.ll) files to build a precise kernel call graph.
    
    Handles:
    - Direct calls: `call void @function_name(...)`
    - Indirect calls: `call void %func_ptr(...)` — resolved via type matching
    - Function definitions and declarations
    - Source file mapping from IR metadata
    """

    # Pattern for function definitions
    # define [linkage] [visibility] [ret_type] @name(args) ... {
    FUNC_DEF_PATTERN = re.compile(
        r'^define\s+(?:internal\s+|private\s+|linkonce_odr\s+|weak\s+|external\s+)?'
        r'(?:dso_local\s+)?'
        r'(\S+)\s+'           # return type
        r'@(["\w.]+)'         # function name
        r'\(([^)]*)\)',        # arguments
        re.MULTILINE,
    )

    # Pattern for function declarations (external)
    FUNC_DECL_PATTERN = re.compile(
        r'^declare\s+(?:dso_local\s+)?(\S+)\s+@(["\w.]+)\(([^)]*)\)',
        re.MULTILINE,
    )

    # Pattern for direct calls
    # call [ret_type] @function_name(args)
    # invoke [ret_type] @function_name(args)
    DIRECT_CALL_PATTERN = re.compile(
        r'(?:call|invoke)\s+'
        r'(?:fastcc\s+|ccc\s+)?'
        r'(?:zeroext\s+|signext\s+|noalias\s+)?'
        r'(\S+)\s+'           # return type
        r'@(["\w.]+)'         # callee name
        r'\(',
    )

    # Pattern for indirect calls (function pointers)
    # call [ret_type] %reg(args)
    INDIRECT_CALL_PATTERN = re.compile(
        r'(?:call|invoke)\s+'
        r'(?:fastcc\s+|ccc\s+)?'
        r'(?:zeroext\s+|signext\s+|noalias\s+)?'
        r'(\S+)\s+'           # return type  
        r'(%[\w.]+)'          # register (indirect target)
        r'\(([^)]*)\)',        # arguments (for type matching)
    )

    # Source filename from metadata — captures filename and optional directory
    SOURCE_FILE_PATTERN = re.compile(
        r'!DIFile\(filename:\s*"([^"]+)"'
    )
    SOURCE_DIR_PATTERN = re.compile(
        r'!DIFile\([^)]*directory:\s*"([^"]+)"'
    )

    # Debug info for function definitions — captures name and line number
    # !DISubprogram(name: "nf_conntrack_init", ..., line: 2345, ...)
    DI_SUBPROGRAM_PATTERN = re.compile(
        r'!DISubprogram\(name:\s*"([^"]+)"[^)]*line:\s*(\d+)'
    )

    def __init__(self, ir_dir: str, kernel_path: str = "", cache_dir: str | None = None):
        self.ir_dir = Path(ir_dir)
        self.kernel_path = kernel_path
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.graph = KernelGraph()

        # For indirect call resolution: signature -> [function_names]
        self._sig_to_funcs: dict[str, list[str]] = defaultdict(list)
        # Track which function we're currently inside while parsing
        self._current_func: Optional[str] = None
        self._current_file: str = ""

    def _normalize_func_name(self, name: str) -> str:
        """Strip LLVM name mangling artifacts."""
        name = name.strip('"')
        # Remove .llvm.XXXX suffixes
        name = re.sub(r'\.llvm\.\d+', '', name)
        # Remove .constprop / .isra suffixes (compiler optimizations)
        name = re.sub(r'\.(constprop|isra|part)\.\d+', '', name)
        return name

    def _make_signature(self, ret_type: str, args: str) -> str:
        """Create a normalized function signature for type-based matching."""
        # Simplify types for matching
        arg_types = []
        for arg in args.split(","):
            arg = arg.strip()
            if not arg or arg == "...":
                continue
            # Extract just the type (before the %name)
            parts = arg.split()
            if parts:
                arg_types.append(parts[0])
        return f"{ret_type}({','.join(arg_types)})"

    def _parse_ir_file(self, ir_path: Path) -> None:
        """Parse a single .ll file and add nodes/edges to the graph."""
        try:
            content = ir_path.read_text(errors="ignore")
        except Exception as e:
            print(f"    Warning: could not read {ir_path}: {e}")
            return

        # Determine source file from metadata.
        # !DIFile has both filename and directory fields:
        #   !DIFile(filename: "nf_conntrack_core.c", directory: "/home/user/linux/net/netfilter")
        # We need both to reconstruct the full path.
        source_match = self.SOURCE_FILE_PATTERN.search(content)
        dir_match = self.SOURCE_DIR_PATTERN.search(content)
        source_file = source_match.group(1) if source_match else str(ir_path.stem)

        # If filename is just a basename, prepend the directory
        if dir_match and os.sep not in source_file and "/" not in source_file:
            source_file = str(Path(dir_match.group(1)) / source_file)

        # Make relative to kernel path if possible
        if self.kernel_path:
            try:
                source_file = str(Path(source_file).relative_to(self.kernel_path))
            except (ValueError, TypeError):
                # source_file might already be relative or from a different root;
                # try matching by suffix against the kernel path
                p = Path(source_file)
                # Use the last 3 components as a heuristic (e.g. net/netfilter/foo.c)
                for depth in range(min(4, len(p.parts)), 0, -1):
                    candidate = Path(*p.parts[-depth:])
                    if (Path(self.kernel_path) / candidate).exists():
                        source_file = str(candidate)
                        break

        self._current_file = source_file

        # Build func_name → source line number map from !DISubprogram metadata
        di_lines: dict[str, int] = {}
        for di_match in self.DI_SUBPROGRAM_PATTERN.finditer(content):
            di_lines[di_match.group(1)] = int(di_match.group(2))

        # Phase 1: Extract all function definitions
        for match in self.FUNC_DEF_PATTERN.finditer(content):
            ret_type = match.group(1)
            func_name = self._normalize_func_name(match.group(2))
            args = match.group(3)

            # Skip LLVM intrinsics
            if func_name.startswith("llvm."):
                continue

            node_id = self.graph.add_function(
                name=func_name,
                file_path=source_file,
                line_start=di_lines.get(func_name, 0),
                signature=self._make_signature(ret_type, args),
                is_static="internal" in content[:match.start()].split("\n")[-1],
            )

            sig = self._make_signature(ret_type, args)
            self._sig_to_funcs[sig].append(node_id)

        # Phase 2: Extract function declarations (external references)
        for match in self.FUNC_DECL_PATTERN.finditer(content):
            func_name = self._normalize_func_name(match.group(2))
            if func_name.startswith("llvm."):
                continue
            # Only add if not already in graph
            if not self.graph.lookup_function(func_name):
                ret_type = match.group(1)
                args = match.group(3)
                node_id = self.graph.add_function(
                    name=func_name,
                    file_path="external",
                    signature=self._make_signature(ret_type, args),
                )
                sig = self._make_signature(ret_type, args)
                self._sig_to_funcs[sig].append(node_id)

        # Phase 3: Extract call edges
        # We need to track which function body we're in
        lines = content.split("\n")
        current_func_name = None

        for line in lines:
            # Check for function definition start
            def_match = self.FUNC_DEF_PATTERN.match(line)
            if def_match:
                current_func_name = self._normalize_func_name(def_match.group(2))
                continue

            # Check for function end
            if line.strip() == "}":
                current_func_name = None
                continue

            if not current_func_name:
                continue

            # Look for direct calls
            for call_match in self.DIRECT_CALL_PATTERN.finditer(line):
                callee_name = self._normalize_func_name(call_match.group(2))
                if callee_name.startswith("llvm."):
                    continue
                self._add_call_edge(current_func_name, callee_name, EdgeType.CALLS)

            # Look for indirect calls
            for icall_match in self.INDIRECT_CALL_PATTERN.finditer(line):
                ret_type = icall_match.group(1)
                args = icall_match.group(3)
                sig = self._make_signature(ret_type, args)
                # Type-based resolution: find all functions matching signature
                candidates = self._sig_to_funcs.get(sig, [])
                for candidate_id in candidates:
                    caller_ids = self.graph.lookup_function(current_func_name)
                    for caller_id in caller_ids:
                        self.graph.add_call_edge(
                            caller_id,
                            candidate_id,
                            edge_type=EdgeType.INDIRECT_CALL,
                        )

    def _add_call_edge(self, caller_name: str, callee_name: str, edge_type: EdgeType) -> None:
        """Add a call edge, creating callee node if needed."""
        caller_ids = self.graph.lookup_function(caller_name)
        callee_ids = self.graph.lookup_function(callee_name)

        if not callee_ids:
            # External function not yet seen
            callee_id = self.graph.add_function(
                name=callee_name,
                file_path="external",
            )
            callee_ids = [callee_id]

        for caller_id in caller_ids:
            for callee_id in callee_ids:
                self.graph.add_call_edge(caller_id, callee_id, edge_type=edge_type)

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache_path(self) -> Path | None:
        if self.cache_dir is None:
            return None
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", str(self.ir_dir)).strip("_")
        return self.cache_dir / f"llvm_{safe}.json"

    def _ir_max_mtime(self, ir_files: list[Path]) -> float:
        """Return the newest mtime across all .ll files."""
        return max((f.stat().st_mtime for f in ir_files), default=0.0)

    def _try_load_cache(self, ir_mtime: float) -> Optional[dict]:
        path = self._cache_path()
        if path is None or not path.exists():
            return None
        try:
            with open(path) as f:
                data = json.load(f)
            if data.get("mode") != "llvm":
                return None
            if abs(data.get("ir_mtime", -1) - ir_mtime) > 1.0:
                return None
            return data
        except Exception:
            return None

    def _save_cache(self, ir_mtime: float) -> None:
        path = self._cache_path()
        if path is None:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # Serialize graph summary for quick reload detection
        data = {
            "mode": "llvm",
            "ir_dir": str(self.ir_dir),
            "extracted_at": time.time(),
            "ir_mtime": ir_mtime,
            "nodes": self.graph.num_nodes,
            "edges": self.graph.num_edges,
        }
        with open(path, "w") as f:
            json.dump(data, f)

    # ------------------------------------------------------------------
    # Main extraction
    # ------------------------------------------------------------------

    def extract(self) -> KernelGraph:
        """Run extraction over all .ll files in the IR directory."""
        ir_files = list(self.ir_dir.rglob("*.ll"))
        if not ir_files:
            print(f"[!] No .ll files found in {self.ir_dir}")
            print("    Build kernel with: make CC=clang LLVM=1 KCFLAGS='-save-temps=obj'")
            return self.graph

        ir_mtime = self._ir_max_mtime(ir_files)

        # Check cache — note: the graph itself is saved as callgraph.json
        # by run_pipeline.  The LLVM cache file is a sentinel that records
        # whether we've already parsed these exact .ll files, so we can
        # skip the expensive re-parse when callgraph.json already exists.
        cached = self._try_load_cache(ir_mtime)
        if cached is not None:
            print(f"[*] LLVM extraction cache hit ({cached['nodes']} nodes, "
                  f"{cached['edges']} edges) — load callgraph.json instead")

        print(f"[*] Found {len(ir_files)} IR files to parse")

        for i, ir_file in enumerate(ir_files):
            if i % 100 == 0 and i > 0:
                print(f"    Parsed {i}/{len(ir_files)} files, "
                      f"{self.graph.num_nodes} nodes, {self.graph.num_edges} edges")
            self._parse_ir_file(ir_file)

        print(f"[+] Extraction complete: {self.graph.num_nodes} nodes, {self.graph.num_edges} edges")

        # Report indirect call stats
        indirect_edges = sum(
            1 for _, _, _, d in self.graph.graph.edges(data=True, keys=True)
            if d.get("edge_type") == EdgeType.INDIRECT_CALL.value
        )
        print(f"    Direct calls: {self.graph.num_edges - indirect_edges}")
        print(f"    Indirect calls (type-approx): {indirect_edges}")

        # Save cache sentinel
        self._save_cache(ir_mtime)

        return self.graph


def main():
    parser = argparse.ArgumentParser(description="Extract kernel call graph from LLVM IR")
    parser.add_argument("--ir-dir", required=True, help="Directory containing .ll files")
    parser.add_argument("--kernel-path", default="", help="Kernel source path (for relative paths)")
    parser.add_argument("--output", default="data/callgraph.json", help="Output graph JSON")
    args = parser.parse_args()

    extractor = LLVMIRExtractor(
        ir_dir=args.ir_dir,
        kernel_path=args.kernel_path,
    )
    graph = extractor.extract()
    graph.save(args.output)
    print(f"[+] Graph saved to {args.output}")

    import json
    print(json.dumps(graph.summary(), indent=2))


if __name__ == "__main__":
    main()
