"""
RLM Sandbox — Persistent Python REPL for LLM-driven kernel analysis.

Provides a stateful Python interpreter that an LLM can interact with
by submitting string-based scripts.  Execution state (variables, imports,
and defined functions) persists across calls — enabling iterative analysis
workflows where each call builds on prior results.

Pre-populated namespace
-----------------------
Standard library:
    os, sys, re, json, subprocess, pathlib (Path), textwrap,
    collections, itertools, functools, math, time, datetime

Scientific / graph:
    nx    — networkx
    np    — numpy   (if installed)
    scipy — scipy   (if installed)

Kernel graph (injected via constructor or inject()):
    kernel_graph  — KernelGraph wrapper object
    G             — raw nx.MultiDiGraph for direct NetworkX API calls

Kernel source helpers (requires kernel_path):
    audit         — KernelAudit instance
    kgrep(pat)    — grep -rn against kernel source
    kcscope(t,s)  — cscope symbol lookup
    kctags(sym)   — ctags symbol lookup
    find_function(name)  — locate a C function definition
    find_callers(name)   — find all call sites of a function

Thread safety
-------------
run() is serialized via an internal lock.  Only one script executes at
a time, which prevents interleaved output capture.
"""

import code
import io
import os
import sys
import textwrap
import threading
import time
from typing import Optional

# Capture stdout/stderr at import time so we can always restore them after a
# timed-out sandbox thread leaves sys.stdout pointing at a dead buffer.
_REAL_STDOUT = sys.stdout
_REAL_STDERR = sys.stderr


# ---------------------------------------------------------------------------
# Kernel source auditing helpers
# ---------------------------------------------------------------------------

class KernelAudit:
    """
    Thin wrappers around common Linux kernel auditing CLI tools.

    All methods return their output as a plain string.  On error or timeout
    the error text is returned instead of raising.
    """

    def __init__(self, kernel_path: str) -> None:
        self.kernel_path = os.path.realpath(kernel_path)

    # ------------------------------------------------------------------ grep

    def grep(
        self,
        pattern: str,
        path: str = ".",
        flags: str = "-rn",
        include: str = "*.c *.h",
    ) -> str:
        """
        Run grep against the kernel source tree.

        Args:
            pattern: Regular expression to search for.
            path:    Relative sub-path within kernel_path to search.
            flags:   grep flags (default: recursive, show line numbers).
            include: Glob patterns for --include (space-separated).

        Returns:
            grep stdout; stderr on failure.
        """
        import subprocess
        target = os.path.join(self.kernel_path, path)
        cmd = ["grep"] + flags.split()
        for pat in include.split():
            cmd += [f"--include={pat}"]
        cmd += [pattern, target]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return r.stdout or r.stderr or "(no matches)"
        except subprocess.TimeoutExpired:
            return "[grep] Timed out after 60 s"
        except FileNotFoundError:
            return "[grep] grep not found on PATH"

    # --------------------------------------------------------------- cscope

    def cscope_find(self, query_type: str, symbol: str) -> str:
        """
        Run a cscope line-oriented query.

        Args:
            query_type: One of:
                's'  symbol references
                'g'  global definition
                'c'  functions calling this function
                'd'  functions called by this function
                'f'  file name
                'e'  egrep pattern
            symbol: Symbol or pattern to query.

        Returns:
            cscope output (one result per line); error string on failure.
        """
        import subprocess
        flag_map = {
            "s": "-0", "g": "-1", "c": "-3",
            "d": "-2", "f": "-7", "e": "-6",
        }
        cscope_db = os.path.join(self.kernel_path, "cscope.out")
        if not os.path.exists(cscope_db):
            return (
                f"[cscope] No cscope.out found at {cscope_db}.\n"
                "Build it with:  cscope -Rb  inside the kernel tree."
            )
        flag = flag_map.get(query_type, "-0")
        cmd = ["cscope", "-d", "-f", cscope_db, "-L", flag, symbol]
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=30, cwd=self.kernel_path,
            )
            return r.stdout or r.stderr or "(no results)"
        except subprocess.TimeoutExpired:
            return "[cscope] Timed out after 30 s"
        except FileNotFoundError:
            return "[cscope] cscope not found on PATH"

    # --------------------------------------------------------------- ctags

    def ctags_find(self, symbol: str) -> str:
        """
        Look up a symbol in a ctags tags file (must exist in kernel root).

        Returns:
            Matching tag lines; error string if tags file missing.
        """
        import subprocess
        tags_file = os.path.join(self.kernel_path, "tags")
        if not os.path.exists(tags_file):
            return (
                f"[ctags] No tags file at {tags_file}.\n"
                "Build it with:  ctags -R  inside the kernel tree."
            )
        cmd = ["grep", f"^{symbol}\t", tags_file]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return r.stdout or "(no match)"
        except subprocess.TimeoutExpired:
            return "[ctags] Timed out after 10 s"

    # ----------------------------------------------------------- convenience

    def find_function(self, name: str) -> str:
        """Grep for a C function definition (handles pointer/void return types)."""
        return self.grep(
            rf"^[\w\s\*]+\b{name}\s*\(",
            flags="-rn",
            include="*.c",
        )

    def find_callers(self, name: str) -> str:
        """Grep for all call sites of a function."""
        return self.grep(
            rf"\b{name}\s*\(",
            flags="-rn",
            include="*.c *.h",
        )

    def __repr__(self) -> str:
        return f"<KernelAudit kernel={self.kernel_path!r}>"


# ---------------------------------------------------------------------------
# Capturing interpreter wrapper
# ---------------------------------------------------------------------------

class _CapturingInterpreter(code.InteractiveInterpreter):
    """
    Subclass of InteractiveInterpreter that routes internal write() calls
    (used by the interpreter for tracebacks) into the active capture buffer.
    """

    def __init__(self, locals: dict) -> None:
        super().__init__(locals=locals)
        self._buf: Optional[io.StringIO] = None

    def write(self, data: str) -> None:
        if self._buf is not None:
            self._buf.write(data)
        else:
            sys.stderr.write(data)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_raw_graph(obj):
    """
    Return the raw nx.Graph object from either a KernelGraph wrapper or a
    bare nx.Graph.

    NetworkX graphs have a `.graph` attribute that is a plain dict of
    graph-level metadata, NOT the graph itself.  KernelGraph wrappers store
    their underlying nx.MultiDiGraph in `.graph`.  We tell them apart by
    checking whether the extracted attribute has graph-like methods.
    """
    candidate = getattr(obj, "graph", None)
    if candidate is not None and hasattr(candidate, "nodes") and hasattr(candidate, "add_edge"):
        return candidate   # KernelGraph wrapper → return the inner nx graph
    return obj             # already a raw nx.Graph (or unknown — return as-is)


# ---------------------------------------------------------------------------
# RLM Sandbox
# ---------------------------------------------------------------------------

class RLMSandbox:
    """
    Persistent Python REPL sandbox for LLM-driven kernel analysis.

    State persists across run() calls — variables, imports, and defined
    functions from one call are available in the next.
    """

    def __init__(
        self,
        kernel_path: Optional[str] = None,
        graph=None,
    ) -> None:
        """
        Args:
            kernel_path: Path to the Linux kernel source tree.  When provided,
                         audit helpers (kgrep, kcscope, …) are pre-loaded.
            graph:       A KernelGraph or raw nx.DiGraph to expose as
                         ``kernel_graph`` and ``G`` in the namespace.
        """
        self._lock = threading.Lock()
        self._kernel_path = kernel_path
        self._namespace = self._build_namespace(kernel_path, graph)
        self._interp = _CapturingInterpreter(locals=self._namespace)

    # ------------------------------------------------------------------
    # Namespace construction
    # ------------------------------------------------------------------

    def _build_namespace(
        self,
        kernel_path: Optional[str],
        graph,
    ) -> dict:
        import importlib

        ns: dict = {}

        # ── Standard library ──────────────────────────────────────────
        import collections, itertools, functools, math, time, datetime
        import pathlib, textwrap

        ns.update({
            "os":           os,
            "sys":          sys,
            "re":           __import__("re"),
            "json":         __import__("json"),
            "subprocess":   __import__("subprocess"),
            "pathlib":      pathlib,
            "Path":         pathlib.Path,
            "textwrap":     textwrap,
            "collections":  collections,
            "itertools":    itertools,
            "functools":    functools,
            "math":         math,
            "time":         time,
            "datetime":     datetime,
        })

        # ── NetworkX ──────────────────────────────────────────────────
        try:
            import networkx as _nx
            ns["nx"] = _nx
            ns["networkx"] = _nx
        except ImportError:
            pass

        # ── NumPy / SciPy ─────────────────────────────────────────────
        for _mod, _alias in [("numpy", "np"), ("scipy", "scipy")]:
            try:
                ns[_alias] = importlib.import_module(_mod)
            except ImportError:
                pass

        # ── Kernel audit helpers ───────────────────────────────────────
        if kernel_path:
            audit = KernelAudit(kernel_path)
            ns["audit"]          = audit
            ns["kernel_path"]    = kernel_path
            ns["kgrep"]          = audit.grep
            ns["kcscope"]        = audit.cscope_find
            ns["kctags"]         = audit.ctags_find
            ns["find_function"]  = audit.find_function
            ns["find_callers"]   = audit.find_callers

        # ── Graph ─────────────────────────────────────────────────────
        if graph is not None:
            ns["kernel_graph"] = graph
            # Expose raw nx graph as G for direct NetworkX API use
            ns["G"] = _extract_raw_graph(graph)

        # ── Sandbox self-reference ─────────────────────────────────────
        ns["__name__"]    = "__rlm_sandbox__"
        ns["__builtins__"] = __builtins__
        ns["_sandbox"]    = self

        return ns

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, script: str, *, timeout: float = 30.0) -> str:
        """
        Execute a Python script string and return all captured output.

        Both stdout and stderr (including exception tracebacks) are merged
        into the returned string in the order they were written.

        Args:
            script: Arbitrary Python source (single expression, multi-line
                    script, or function/class definitions).
            timeout: Wall-clock limit in seconds.  If exceeded the call
                     returns immediately with a timeout notice; the
                     interpreter state may be inconsistent after a timeout.

        Returns:
            A plain string containing all output.  Never raises — all
            errors (syntax errors, runtime exceptions, timeouts) appear
            as text in the returned string.

        Example:
            >>> sandbox.run("print(list(G.nodes)[:5])")
            "['sys_read', 'sys_write', 'vfs_read', 'copy_from_user', ...]\n"
        """
        buf = io.StringIO()
        result: list = []

        def _execute() -> None:
            # Route interpreter.write() into our buffer
            self._interp._buf = buf

            old_stdout, old_stderr = sys.stdout, sys.stderr
            sys.stdout = buf
            sys.stderr = buf
            try:
                try:
                    compiled = compile(script, "<llm_script>", "exec")
                except SyntaxError:
                    import traceback
                    buf.write(traceback.format_exc())
                    return

                self._interp.runcode(compiled)
            except SystemExit as exc:
                buf.write(f"\n[SystemExit({exc.code})]\n")
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
                self._interp._buf = None

        with self._lock:
            t = threading.Thread(target=_execute, daemon=True)
            t.start()
            t.join(timeout)
            if t.is_alive():
                # The daemon thread is still running with sys.stdout redirected to
                # buf.  Restore the real streams so that subsequent calls (and the
                # main thread's own print statements) are not swallowed into a dead
                # buffer.  The daemon thread is left to run to completion or die
                # naturally when the process exits.
                sys.stdout = _REAL_STDOUT
                sys.stderr = _REAL_STDERR
                self._interp._buf = None
                return (
                    f"[TIMEOUT] Script exceeded {timeout:.1f} s wall-clock limit.\n"
                    "The interpreter state may be inconsistent. "
                    "Call sandbox.reset() to restore a clean environment.\n"
                )

        return buf.getvalue()

    def inject(self, name: str, value) -> None:
        """
        Inject a named value into the live REPL namespace.

        Use this to load a freshly built graph after Phase 1 completes:

            sandbox.inject("kernel_graph", kg)
            # G is automatically set to kg.graph if kg is a KernelGraph
        """
        self._namespace[name] = value
        if name == "kernel_graph":
            self._namespace["G"] = _extract_raw_graph(value)

    def reset(self) -> None:
        """
        Wipe interpreter state and rebuild the namespace from scratch.

        Preserves the kernel_path and any previously injected graph.
        """
        with self._lock:
            graph = self._namespace.get("kernel_graph")
            self._namespace = self._build_namespace(self._kernel_path, graph)
            self._interp = _CapturingInterpreter(locals=self._namespace)

    def namespace_keys(self) -> list[str]:
        """Return the public names currently defined in the sandbox namespace."""
        return sorted(k for k in self._namespace if not k.startswith("_"))

    def __repr__(self) -> str:
        keys = self.namespace_keys()
        return f"<RLMSandbox [{', '.join(keys)}]>"


# ---------------------------------------------------------------------------
# ScriptResult — structured result returned by the supervisor
# ---------------------------------------------------------------------------

def _timeout_backtrack_for(script: str) -> str:
    """
    Analyse a timed-out script and return targeted Markdown guidance
    suggesting bounded alternatives the LLM should use instead.
    """
    lower = script.lower()
    hints: list[str] = []

    if "all_simple_paths" in lower:
        hints.append(
            "- `nx.all_simple_paths` is exponential on dense graphs.  "
            "Replace with `nx.shortest_path(G, src, dst)` to find one path, "
            "or `nx.shortest_path_length(G, src, dst, cutoff=10)` to cap depth."
        )
    if "shortest_path" in lower and "has_path" not in lower:
        hints.append(
            "- Guard with a reachability check before computing the path:\n"
            "  `if nx.has_path(G, src, dst): path = nx.shortest_path(G, src, dst)`\n"
            "  Or use `nx.shortest_path_length(G, src, dst, cutoff=15)` — "
            "it raises `nx.NetworkXNoPath` if no path exists within 15 hops."
        )
    if "ancestors" in lower or "descendants" in lower:
        hints.append(
            "- `nx.ancestors` / `nx.descendants` visits the entire reachable "
            "set, which can be millions of nodes in the kernel graph.  "
            "Replace with a bounded BFS:\n"
            "  `subg = nx.ego_graph(G, node, radius=3)`\n"
            "  `nearby = list(subg.nodes)`"
        )
    if "all_pairs" in lower:
        hints.append(
            "- `nx.all_pairs_*` algorithms are O(n²) or worse on large graphs.  "
            "Pick a specific source node and use single-source variants instead."
        )
    if "pagerank" in lower and "max_iter" not in lower:
        hints.append(
            "- Add `max_iter=50, tol=1e-3` to `nx.pagerank()` to bound "
            "the number of power-iteration steps."
        )
    # Detect unbounded loops
    if any(kw in lower for kw in ("while true", "while 1", "while(1)")):
        hints.append(
            "- Infinite loop detected.  Add an explicit break condition:\n"
            "  `count = 0\n  while condition:\n      count += 1\n      if count > 500: break`"
        )
    if not hints:
        hints.append(
            "- Work on a local subgraph instead of the full graph:\n"
            "  `subg = nx.ego_graph(G, target_node, radius=2)`\n"
            "  `print(list(subg.predecessors(target_node))[:20])`\n"
            "- Prefer direct neighbour access over full traversals:\n"
            "  `list(G.predecessors(node))[:20]` instead of `nx.ancestors(G, node)`"
        )

    return (
        "**Backtrack**: The kernel graph has hundreds of thousands of nodes.  "
        "Avoid algorithms that traverse the full graph.\n\n"
        "Bounded alternatives:\n" + "\n".join(hints)
    )


class ScriptResult:
    """
    Structured result returned by RLMSupervisor.run_supervised().

    Attributes
    ----------
    output         : Captured stdout + stderr from the script.
    status         : "ok" | "timeout" | "max_depth_reached"
    script         : The Python source that was submitted.
    iteration      : 1-based execution count for this candidate.
    elapsed        : Wall-clock seconds (0.0 for max_depth_reached).
    candidate_name : Candidate function this script was analysing.
    backtrack_hint : Non-empty when status != "ok"; LLM-facing Markdown guidance.
    """

    __slots__ = ("output", "status", "script", "iteration",
                 "elapsed", "candidate_name", "backtrack_hint")

    def __init__(
        self,
        output: str,
        status: str,
        script: str,
        iteration: int,
        elapsed: float,
        candidate_name: str,
        backtrack_hint: str = "",
    ) -> None:
        self.output = output
        self.status = status
        self.script = script
        self.iteration = iteration
        self.elapsed = elapsed
        self.candidate_name = candidate_name
        self.backtrack_hint = backtrack_hint

    @property
    def is_ok(self) -> bool:
        return self.status == "ok"

    def to_llm_context(self, max_scripts: int = 10) -> str:
        """
        Format the result as a Markdown block suitable for inclusion in the
        LLM follow-up context message.

        For "timeout" and "max_depth_reached" statuses the block contains
        explicit instructions telling the LLM what to do next, so the model
        is forced to attempt a different algorithmic path.
        """
        budget_note = f"iteration {self.iteration}/{max_scripts}"
        header = f"### Sandbox Script ({budget_note}, {self.elapsed:.1f}s)"
        code_block = f"```python\n{self.script}\n```"

        if self.status == "ok":
            out = self.output.rstrip() or "(no output)"
            return f"{header}\n{code_block}\nOutput:\n```\n{out}\n```\n"

        if self.status == "timeout":
            return (
                f"{header} — **TIMEOUT**\n"
                f"{code_block}\n"
                f"**Error**: Script exceeded the time limit ({self.elapsed:.0f} s).  "
                f"The kernel call graph is too large for this traversal strategy.\n\n"
                f"{self.backtrack_hint}\n\n"
                f"**ACTION REQUIRED**: In your next `graph_scripts` entry write a "
                f"*bounded* script using the alternatives above.  "
                f"Do not repeat the same algorithm."
            )

        if self.status == "max_depth_reached":
            return (
                f"{header} — **MAX_DEPTH_REACHED**\n"
                f"{code_block}\n"
                f"**Error**: You have used all {self.iteration - 1} allowed graph "
                f"scripts for `{self.candidate_name}`.  "
                f"No further scripts will be executed.\n\n"
                f"{self.backtrack_hint}\n\n"
                f"**ACTION REQUIRED**: Write your final JSON assessment now, "
                f"using only the information already gathered above.  "
                f"Set `next_steps.graph_scripts` to `[]`."
            )

        # Unexpected status — pass output through
        out = self.output.rstrip() or "(no output)"
        return (
            f"{header} — **{self.status.upper()}**\n"
            f"{code_block}\n"
            f"Output:\n```\n{out}\n```\n"
        )

    def __repr__(self) -> str:
        return (
            f"<ScriptResult status={self.status!r} "
            f"iter={self.iteration} elapsed={self.elapsed:.1f}s "
            f"candidate={self.candidate_name!r}>"
        )


# ---------------------------------------------------------------------------
# RLMSupervisor — per-candidate budget enforcement
# ---------------------------------------------------------------------------

class RLMSupervisor:
    """
    Supervises RLMSandbox script execution per vulnerability candidate.

    Enforces two independent hard limits:

    script_timeout (default 45 s)
        Each script runs inside a daemon thread inside sandbox.run().  If the
        thread has not returned within ``script_timeout`` seconds, the call
        returns the "[TIMEOUT]" sentinel and the supervisor records the event,
        attaches a targeted backtrack hint, and returns status="timeout".

    max_scripts_per_candidate (default 10)
        Every call to run_supervised() for the same candidate_name consumes
        one slot.  When the budget is exhausted the script is *never submitted*
        to the sandbox and status="max_depth_reached" is returned immediately
        with instructions forcing the LLM to produce a final verdict.

    Usage (from VulnAgent)
    ----------------------
        supervisor.begin_candidate(candidate.name)   # reset per-candidate counters
        result = supervisor.run_supervised(script, candidate.name)
        follow_up_context += result.to_llm_context(supervisor.max_scripts_per_candidate)
        if result.status == "max_depth_reached":
            break   # stop sending scripts for this candidate
    """

    _MAX_DEPTH_HINT = (
        "You have consumed all available graph-script slots for this candidate.  "
        "Synthesise your final vulnerability assessment from the information "
        "already gathered and produce the JSON response now."
    )

    def __init__(
        self,
        sandbox: RLMSandbox,
        script_timeout: float = 45.0,
        max_scripts_per_candidate: int = 10,
    ) -> None:
        """
        Args:
            sandbox:                   The underlying RLMSandbox to execute scripts in.
            script_timeout:            Per-script wall-clock limit in seconds.
            max_scripts_per_candidate: Maximum number of graph_scripts the LLM
                                       may request per candidate function.
        """
        self.sandbox = sandbox
        self.script_timeout = script_timeout
        self.max_scripts_per_candidate = max_scripts_per_candidate

        # Counters keyed by candidate_name
        self._script_counts: dict[str, int] = {}
        self._timeout_counts: dict[str, int] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def begin_candidate(self, candidate_name: str) -> None:
        """
        Reset per-candidate counters.

        Must be called at the start of each new candidate analysis so that
        the script budget starts fresh.
        """
        with self._lock:
            self._script_counts[candidate_name] = 0
            self._timeout_counts[candidate_name] = 0

    def reset_candidate(self, candidate_name: str) -> None:
        """Remove a candidate's counters entirely (alias for begin_candidate)."""
        self.begin_candidate(candidate_name)

    # ------------------------------------------------------------------
    # Core execution
    # ------------------------------------------------------------------

    def run_supervised(self, script: str, candidate_name: str) -> ScriptResult:
        """
        Execute a script under supervision.

        Returns a ScriptResult whose ``status`` is one of:

        "ok"
            Script completed within timeout and iteration limits.
        "timeout"
            Script exceeded ``script_timeout`` seconds.  The backtrack_hint
            field contains algorithm-specific suggestions.
        "max_depth_reached"
            Candidate has exhausted its ``max_scripts_per_candidate`` budget.
            The script was not executed.  backtrack_hint instructs the LLM
            to produce a final verdict without further scripts.
        """
        with self._lock:
            used = self._script_counts.get(candidate_name, 0)
            if used >= self.max_scripts_per_candidate:
                return ScriptResult(
                    output="",
                    status="max_depth_reached",
                    script=script,
                    iteration=used + 1,
                    elapsed=0.0,
                    candidate_name=candidate_name,
                    backtrack_hint=self._MAX_DEPTH_HINT,
                )
            self._script_counts[candidate_name] = used + 1
            iteration = used + 1

        start = time.monotonic()
        output = self.sandbox.run(script, timeout=self.script_timeout)
        elapsed = time.monotonic() - start

        if output.startswith("[TIMEOUT]"):
            with self._lock:
                self._timeout_counts[candidate_name] = (
                    self._timeout_counts.get(candidate_name, 0) + 1
                )
            # Reset the interpreter: the timed-out daemon thread left the
            # namespace in an unknown state.  reset() preserves the graph
            # injection (kernel_graph / G) but gives us a fresh interpreter.
            self.sandbox.reset()
            return ScriptResult(
                output=output,
                status="timeout",
                script=script,
                iteration=iteration,
                elapsed=elapsed,
                candidate_name=candidate_name,
                backtrack_hint=_timeout_backtrack_for(script),
            )

        return ScriptResult(
            output=output,
            status="ok",
            script=script,
            iteration=iteration,
            elapsed=elapsed,
            candidate_name=candidate_name,
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def stats(self, candidate_name: str) -> dict:
        """Return budget-usage statistics for a single candidate."""
        with self._lock:
            used = self._script_counts.get(candidate_name, 0)
            timeouts = self._timeout_counts.get(candidate_name, 0)
        return {
            "candidate": candidate_name,
            "scripts_used": used,
            "scripts_remaining": max(0, self.max_scripts_per_candidate - used),
            "timeouts": timeouts,
        }

    def all_stats(self) -> list[dict]:
        """Return budget-usage statistics for every candidate seen so far."""
        with self._lock:
            names = sorted(set(self._script_counts) | set(self._timeout_counts))
        return [self.stats(n) for n in names]

    def __repr__(self) -> str:
        with self._lock:
            total = sum(self._script_counts.values())
            timed_out = sum(self._timeout_counts.values())
        return (
            f"<RLMSupervisor timeout={self.script_timeout}s "
            f"max_per_candidate={self.max_scripts_per_candidate} "
            f"total_scripts={total} timeouts={timed_out}>"
        )


# ---------------------------------------------------------------------------
# CLI — quick smoke-test / interactive mode
# ---------------------------------------------------------------------------

def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="RLM Sandbox — interactive kernel analysis REPL",
    )
    parser.add_argument("--kernel-path", metavar="DIR",
                        help="Path to Linux kernel source tree")
    parser.add_argument("--graph", metavar="JSON",
                        help="Path to callgraph.json or callgraph_enriched.json")
    parser.add_argument("--exec", metavar="SCRIPT",
                        dest="script",
                        help="Execute a script string and print output, then exit")
    args = parser.parse_args()

    graph = None
    if args.graph:
        _here = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, os.path.join(_here, "kernelsurgeon"))
        from kernel_graph import KernelGraph
        print(f"[rlm_sandbox] Loading graph from {args.graph} …", file=sys.stderr)
        graph = KernelGraph.load(args.graph)
        print(f"[rlm_sandbox] Loaded {graph.graph.number_of_nodes()} nodes, "
              f"{graph.graph.number_of_edges()} edges", file=sys.stderr)

    sandbox = RLMSandbox(kernel_path=args.kernel_path, graph=graph)

    if args.script:
        output = sandbox.run(args.script)
        print(output, end="")
        return

    # Interactive mode
    print("RLM Sandbox — persistent kernel analysis REPL")
    print(f"Namespace: {sandbox.namespace_keys()}")
    print("Type Python code. Empty line executes. 'exit' to quit.\n")

    lines: list[str] = []
    while True:
        try:
            prompt = "... " if lines else ">>> "
            line = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if line.strip() == "exit":
            break

        if line == "" and lines:
            script = "\n".join(lines)
            output = sandbox.run(script)
            if output:
                print(output, end="")
            lines = []
        elif line:
            lines.append(line)


if __name__ == "__main__":
    _main()
