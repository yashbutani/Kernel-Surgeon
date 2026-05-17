"""
Context Assembler (Layer 2)

Gathers everything the LLM needs to reason about a candidate function:
- Source code of the function
- Callers and callees (2 hops)
- Graph metrics and structural features
- Matching CVE taxonomy patterns
- Security checks on call paths
- Cross-subsystem boundary info

Produces a focused context package (~2-5k tokens) per candidate.
"""

import os
import sys
import re
from pathlib import Path
from dataclasses import dataclass

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from kernel_graph import KernelGraph, SecurityRole
from graph_analyzer import CandidateFunction
from config import CVE_TAXONOMY, ANALYSIS_CONFIG


@dataclass
class ContextPackage:
    """Everything the LLM needs to analyze a single candidate."""
    candidate: CandidateFunction
    source_code: str
    caller_context: list[dict]       # [{name, file, source_snippet, security_role}]
    callee_context: list[dict]
    unchecked_path_examples: list[list[str]]  # example paths bypassing checks
    cve_pattern_details: list[dict]   # matched patterns with full description
    graph_neighborhood: dict          # structural summary
    prompt: str                       # full assembled prompt (for backwards compat)
    # Prompt caching split: static content (cacheable) + dynamic candidate data
    static_prefix: str = ""           # analysis instructions + CVE taxonomy (~1500 tok, cacheable)
    candidate_body: str = ""          # source code + metrics + neighbors (per-candidate, not cached)


class ContextAssembler:
    """
    Builds context packages for candidate functions.
    
    Bridges the graph analytics (Layer 1) and LLM reasoning (Layer 3)
    by assembling exactly the right context for each candidate.
    """

    def __init__(self, kernel_graph: KernelGraph, kernel_path: str | None):
        self.kg = kernel_graph
        self.kernel_path = Path(kernel_path) if kernel_path else None
        self.config = ANALYSIS_CONFIG

        # Cache for source code reads
        self._source_cache: dict[str, list[str]] = {}

    def _read_source_lines(self, file_path: str) -> list[str]:
        """Read and cache source file lines.

        Attempts the direct path first (``kernel_path / file_path``), then
        falls back to a recursive search if the path is a bare filename
        (e.g. ``nfnetlink`` from LLVM IR metadata that lost its directory).
        """
        if file_path in self._source_cache:
            return self._source_cache[file_path]

        if not self.kernel_path:
            return []

        if file_path in ("external", "unknown", ""):
            return []

        full_path = self.kernel_path / file_path
        try:
            lines = full_path.read_text(errors="ignore").split("\n")
            self._source_cache[file_path] = lines
            return lines
        except Exception:
            pass

        # Fallback: bare basename without extension (common with LLVM IR)
        # Try adding .c and searching the kernel tree
        basename = Path(file_path).name
        if "." not in basename:
            basename += ".c"

        # Search within the kernel tree (limit depth to avoid scanning everything)
        try:
            matches = list(self.kernel_path.rglob(basename))
            if matches:
                # Prefer shorter paths (closer to the subsystem root)
                matches.sort(key=lambda p: len(p.parts))
                lines = matches[0].read_text(errors="ignore").split("\n")
                self._source_cache[file_path] = lines
                return lines
        except Exception:
            pass

        return []

    def _ctags_lookup(self, func_name: str, file_path: str) -> int:
        """
        Look up a function's line number via ctags.

        Checks the kernel tree's ``tags`` file first (fast index lookup).
        Falls back to running ctags on the single source file.
        Returns 0 on failure.
        """
        if not self.kernel_path:
            return 0

        # 1. Try existing tags index in the kernel tree
        tags_file = self.kernel_path / "tags"
        if tags_file.exists():
            try:
                with open(tags_file, errors="ignore") as fh:
                    for line in fh:
                        if line.startswith("!"):
                            continue
                        parts = line.split("\t")
                        if len(parts) >= 3 and parts[0] == func_name:
                            # Match against file path suffix
                            tag_file = parts[1]
                            if tag_file.endswith(file_path) or file_path.endswith(
                                Path(tag_file).name
                            ):
                                for part in parts[2:]:
                                    part = part.strip()
                                    if part.isdigit():
                                        return int(part)
                                    m = re.search(r"line:(\d+)", part)
                                    if m:
                                        return int(m.group(1))
            except Exception:
                pass

        # 2. Run ctags on the single file (fast, one file only)
        import shutil
        import subprocess
        ctags_bin = shutil.which("ctags") or shutil.which("universal-ctags")
        if not ctags_bin:
            return 0

        full_path = self.kernel_path / file_path
        if not full_path.exists():
            return 0

        try:
            result = subprocess.run(
                [ctags_bin, "-x", "--c-kinds=f", str(full_path)],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 3 and parts[0] == func_name:
                    if parts[2].isdigit():
                        return int(parts[2])
        except Exception:
            pass

        return 0

    def _extract_function_source(self, file_path: str, func_name: str,
                                  line_start: int = 0) -> str:
        """
        Extract a function's source code from the kernel tree.

        Resolution order:
          1. ``line_start`` hint (from graph node / debug metadata)
          2. ctags index lookup (``tags`` file or single-file ctags run)
          3. Regex scan as last resort
        """
        lines = self._read_source_lines(file_path)
        if not lines:
            return f"// Source not available: {file_path}::{func_name}"

        # Find function start
        start_idx = None

        # Strategy 1: line_start hint from graph metadata
        if line_start > 0 and line_start <= len(lines):
            # Verify the hint is correct (function name should be nearby)
            search_start = max(0, line_start - 5)
            search_end = min(len(lines), line_start + 5)
            for idx in range(search_start, search_end):
                if func_name in lines[idx]:
                    start_idx = idx
                    break

        # Strategy 2: ctags lookup
        if start_idx is None:
            ctags_line = self._ctags_lookup(func_name, file_path)
            if ctags_line > 0 and ctags_line <= len(lines):
                search_start = max(0, ctags_line - 3)
                search_end = min(len(lines), ctags_line + 3)
                for idx in range(search_start, search_end):
                    if func_name in lines[idx]:
                        start_idx = idx
                        break
                if start_idx is None:
                    # Trust ctags even if name isn't on the exact line
                    start_idx = ctags_line - 1

        # Strategy 3: regex scan
        if start_idx is None:
            func_pattern = re.compile(
                rf'(?:^|\s)(?:static\s+)?(?:inline\s+)?'
                rf'(?:\w+[\s*]+)*{re.escape(func_name)}\s*\(',
            )
            for idx, line in enumerate(lines):
                if func_pattern.search(line):
                    start_idx = idx
                    break

        if start_idx is None:
            return f"// Function {func_name} not found in {file_path}"

        # Find function end (matching braces)
        brace_depth = 0
        end_idx = start_idx
        found_open = False

        for idx in range(start_idx, min(len(lines), start_idx + 500)):
            line = lines[idx]
            for char in line:
                if char == '{':
                    brace_depth += 1
                    found_open = True
                elif char == '}':
                    brace_depth -= 1

            if found_open and brace_depth <= 0:
                end_idx = idx
                break
        else:
            # Truncate if function is too long
            end_idx = min(start_idx + 100, len(lines) - 1)

        # Limit to ~200 lines to stay within token budget
        if end_idx - start_idx > 200:
            source_lines = lines[start_idx:start_idx + 100]
            source_lines.append("    // ... truncated ...")
            source_lines.extend(lines[end_idx - 50:end_idx + 1])
        else:
            source_lines = lines[start_idx:end_idx + 1]

        return "\n".join(f"{start_idx + i + 1:5d} | {l}" for i, l in enumerate(source_lines))

    def _get_neighbor_context(self, node_id: str, direction: str = "callers",
                               hops: int = 2, max_items: int = 10) -> list[dict]:
        """Get context for callers or callees of a node."""
        if direction == "callers":
            neighbors = self.kg.get_callers(node_id, hops=hops)
        else:
            neighbors = self.kg.get_callees(node_id, hops=hops)

        context = []
        for neighbor_id in list(neighbors)[:max_items]:
            data = self.kg.get_node(neighbor_id)
            if not data:
                continue

            # Get first ~10 lines of the function as a snippet
            snippet = self._extract_function_source(
                data.get("file_path", ""),
                data.get("name", ""),
                data.get("line_start", 0),
            )
            # Truncate snippet for context budget
            snippet_lines = snippet.split("\n")[:15]
            if len(snippet.split("\n")) > 15:
                snippet_lines.append("    // ...")

            context.append({
                "node_id": neighbor_id,
                "name": data.get("name", ""),
                "file_path": data.get("file_path", ""),
                "subsystem": data.get("subsystem", ""),
                "security_role": data.get("security_role", "none"),
                "snippet": "\n".join(snippet_lines),
            })

        return context

    def _get_cve_pattern_details(self, pattern_ids: list[str]) -> list[dict]:
        """Get full CVE pattern details for matched patterns."""
        details = []
        for pid in pattern_ids:
            for name, pattern in CVE_TAXONOMY.items():
                if pattern["id"] == pid:
                    details.append({
                        "id": pid,
                        "name": name,
                        "description": pattern["description"],
                        "graph_signature": pattern.get("graph_signature", ""),
                        "sink_functions": pattern.get("sink_functions", []),
                        "missing_checks": pattern.get("missing_checks", []),
                    })
                    break
        return details

    def _build_graph_neighborhood(self, node_id: str) -> dict:
        """Summarize the graph neighborhood of a node."""
        simple = self.kg.to_simple_graph()
        data = self.kg.get_node(node_id)
        if not data:
            return {}

        predecessors = list(simple.predecessors(node_id))
        successors = list(simple.successors(node_id))

        # Classify callers/callees by subsystem
        caller_subsystems = {}
        for p in predecessors:
            pdata = self.kg.get_node(p)
            if pdata:
                sub = pdata.get("subsystem", "other")
                caller_subsystems[sub] = caller_subsystems.get(sub, 0) + 1

        callee_subsystems = {}
        for s in successors:
            sdata = self.kg.get_node(s)
            if sdata:
                sub = sdata.get("subsystem", "other")
                callee_subsystems[sub] = callee_subsystems.get(sub, 0) + 1

        # Check nodes on paths to this function
        check_nodes_nearby = []
        for p in predecessors:
            pdata = self.kg.get_node(p)
            if pdata and pdata.get("security_role") in [
                SecurityRole.VALIDATION.value, SecurityRole.LSM_HOOK.value
            ]:
                check_nodes_nearby.append(pdata.get("name", ""))

        return {
            "in_degree": len(predecessors),
            "out_degree": len(successors),
            "caller_subsystems": caller_subsystems,
            "callee_subsystems": callee_subsystems,
            "nearby_check_functions": check_nodes_nearby,
            "betweenness": data.get("betweenness", 0),
            "pagerank": data.get("pagerank", 0),
            "fiedler_value": data.get("fiedler_value", 0),
            "community_id": data.get("community_id", -1),
        }

    def assemble(self, candidate: CandidateFunction) -> ContextPackage:
        """
        Assemble a complete context package for a candidate function.
        This is what gets sent to the LLM.
        """
        # 1. Source code of the candidate function
        source_code = self._extract_function_source(
            candidate.file_path,
            candidate.name,
            getattr(candidate, "line_start", 0),
        )

        # 2. Caller context
        caller_context = self._get_neighbor_context(
            candidate.node_id, "callers",
            hops=self.config.get("context_hops", 2),
        )

        # 3. Callee context
        callee_context = self._get_neighbor_context(
            candidate.node_id, "callees",
            hops=1,  # 1 hop for callees is usually enough
        )

        # 4. CVE pattern details
        cve_details = self._get_cve_pattern_details(candidate.matching_cve_patterns)

        # 5. Graph neighborhood summary
        neighborhood = self._build_graph_neighborhood(candidate.node_id)

        # 6. Build the LLM prompt (split into static + dynamic for caching)
        static_prefix, candidate_body = self._build_prompt_parts(
            candidate, source_code, caller_context,
            callee_context, cve_details, neighborhood,
        )
        prompt = static_prefix + candidate_body

        return ContextPackage(
            candidate=candidate,
            source_code=source_code,
            caller_context=caller_context,
            callee_context=callee_context,
            unchecked_path_examples=[],  # populated by analyzer if needed
            cve_pattern_details=cve_details,
            graph_neighborhood=neighborhood,
            prompt=prompt,
            static_prefix=static_prefix,
            candidate_body=candidate_body,
        )

    # ------------------------------------------------------------------
    # Static prefix: analysis instructions + CVE taxonomy reference.
    # Identical across ALL candidate analyses → prime candidate for caching.
    # ------------------------------------------------------------------
    _STATIC_PREFIX = """\
## Vulnerability Analysis Session

You are part of a hybrid kernel vulnerability analysis system.  Graph analytics
has pre-selected structurally suspicious functions; your role is deep semantic
reasoning that only a human expert could perform.

### CVE Pattern Reference

The following vulnerability patterns guide this analysis session.  Each candidate
will be matched against these patterns based on its call-graph position.

| ID | Pattern | Key sinks | Missing checks |
|----|---------|-----------|----------------|
| P1 | stack_buffer_overflow | strcpy, strcat, sprintf | strlcpy, snprintf bounds |
| P2 | heap_buffer_overflow  | kmalloc, kzalloc | integer-overflow size guard |
| P3 | off_by_one            | loop/boundary conditions | strict < vs <= |
| P4 | missing_bounds_check  | cross-subsystem calls | copy_from_user, access_ok |
| P5 | toctou_race           | shared buffer read-modify-write | mutex, seqlock |
| P6 | type_confusion        | union dereference, unsafe cast | type tag checks |
| P7 | use_after_free        | async callback, deferred work | refcount, RCU |

### Analysis Instructions

For each candidate function you receive, you MUST:

1. **Vulnerability Assessment** — Does the function contain or enable a real
   security vulnerability?  Consider: buffer overflows, integer overflows,
   off-by-one, missing/bypassable permission checks, TOCTOU races, UAF,
   type confusion, null-pointer dereference.

2. **Check-Bypass Analysis** — Are there call paths where security checks are
   missing or can be bypassed?  Note which callers DO and DON'T validate before
   reaching this function.

3. **Exploitability** — If vulnerable, how does an attacker reach this code
   from userspace?  Which syscalls or ioctls lead here?

4. **Confidence** — Rate HIGH / MEDIUM / LOW.  Explain your reasoning briefly.

5. **Next Steps** — What additional context would help?  List specific:
   - Function names to examine (the agent fetches their source)
   - Graph queries: Python scripts to run against the live kernel call graph
   - Codebase patterns to search for

### Sandbox — Live Graph Scripting

The `graph_scripts` field accepts Python code executed in a persistent REPL
with the full kernel call graph loaded in memory.  Available objects:

| Name | Type | Description |
|------|------|-------------|
| `G` | nx.MultiDiGraph | Raw NetworkX kernel call graph |
| `kernel_graph` | KernelGraph | Wrapper with `.get_node()`, `.get_callers()`, etc. |
| `nx` | module | NetworkX — full API available |
| `find_callers(name)` | fn | grep-based call site finder |
| `kgrep(pattern)` | fn | grep against kernel source tree |

Example scripts:
```python
# Shortest call path between two functions
path = nx.shortest_path(G, 'sys_bpf', 'kmalloc')
print(' -> '.join(path))

# All syscall-reachable ancestors of a function
syscall_ancestors = [n for n in nx.ancestors(G, 'copy_from_user') if n.startswith('sys_')]
print(syscall_ancestors[:20])

# Callers with no bounds check in their call neighborhood
risky = [n for n in G.predecessors('memcpy') if not any('check' in s or 'valid' in s for s in G.successors(n))]
print(risky)
```

### Required JSON Response Format

Respond ONLY with valid JSON (no prose outside the block):

```json
{
    "is_vulnerable": true,
    "confidence": "HIGH",
    "vulnerability_type": "buffer_overflow",
    "description": "...",
    "attack_path": "syscall → vfs_write → mydriver_write → overflow at line N",
    "check_bypass_analysis": "...",
    "vulnerable_line": 47,
    "next_steps": {
        "examine_functions": ["func1", "func2"],
        "graph_scripts": [
            "path = nx.shortest_path(G, 'sys_bpf', 'target_fn'); print(' -> '.join(path))",
            "print(list(G.predecessors('target_fn'))[:15])"
        ],
        "graph_queries": ["natural language fallback description"],
        "pattern_searches": ["pattern description"]
    }
}
```

---
## Candidate Function Analysis

"""

    def _build_prompt_parts(
        self,
        candidate: CandidateFunction,
        source_code: str,
        callers: list[dict],
        callees: list[dict],
        cve_patterns: list[dict],
        neighborhood: dict,
    ) -> tuple[str, str]:
        """
        Build the structured prompt split into (static_prefix, candidate_body).

        static_prefix  — identical for every candidate → cache_control eligible
        candidate_body — unique per candidate → never cached
        """
        body = f"""### Target Function
- **Name**: `{candidate.name}`
- **File**: `{candidate.file_path}`
- **Subsystem**: `{candidate.subsystem}`
- **Security Role**: `{candidate.security_role}`
- **Vulnerability Score**: {candidate.vulnerability_score:.1f}

### Why This Was Flagged
{candidate.reasoning}

### Graph Structural Properties
- In-degree (callers): {neighborhood.get('in_degree', 0)}
- Out-degree (callees): {neighborhood.get('out_degree', 0)}
- Betweenness centrality: {candidate.betweenness:.6f} (p{candidate.betweenness_percentile:.0f})
- PageRank: {candidate.pagerank:.6f} (p{candidate.pagerank_percentile:.0f})
- Fiedler value: {candidate.fiedler_value:.3f} ({'BOUNDARY NODE' if candidate.is_boundary_node else 'interior'})
- Cross-subsystem callers: {candidate.cross_subsystem_callers}
- Cross-subsystem callees: {candidate.cross_subsystem_callees}
- Callers by subsystem: {neighborhood.get('caller_subsystems', {})}
- Callees by subsystem: {neighborhood.get('callee_subsystems', {})}
- Nearby security checks: {neighborhood.get('nearby_check_functions', [])}

### Source Code
```c
{source_code}
```

"""
        # Caller context
        if callers:
            body += "### Callers (functions that call this)\n"
            for c in callers[:5]:
                role_tag = f" [{c['security_role']}]" if c['security_role'] != 'none' else ""
                body += f"\n**{c['name']}** ({c['file_path']}, {c['subsystem']}{role_tag}):\n"
                body += f"```c\n{c['snippet']}\n```\n"

        # Callee context
        if callees:
            body += "\n### Callees (functions this calls)\n"
            for c in callees[:5]:
                role_tag = f" [{c['security_role']}]" if c['security_role'] != 'none' else ""
                body += f"\n**{c['name']}** ({c['file_path']}, {c['subsystem']}{role_tag}):\n"
                body += f"```c\n{c['snippet']}\n```\n"

        # Matching CVE patterns
        if cve_patterns:
            body += "\n### Matching CVE Patterns\n"
            for p in cve_patterns:
                body += f"\n**{p['id']}: {p['name']}**\n"
                body += f"Description: {p['description']}\n"
                body += f"Graph signature: {p['graph_signature']}\n"
                body += f"Sink functions: {p.get('sink_functions', [])}\n"

        return self._STATIC_PREFIX, body

    # Keep old name as alias for any legacy callers
    def _build_prompt(self, candidate, source_code, callers, callees,
                      cve_patterns, neighborhood) -> str:
        static, body = self._build_prompt_parts(
            candidate, source_code, callers, callees, cve_patterns, neighborhood
        )
        return static + body
