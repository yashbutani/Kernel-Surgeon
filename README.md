# KernelSurgeon

An agentic vulnerability-discovery system for the Linux kernel. A graph-analytics
layer ranks suspicious functions; an LLM agent loop walks the call graph by
writing Python that executes in a persistent sandbox, reads kernel source on
demand, and produces verified findings with CVSS scores and compilable crash
reproducers.

> **Status:** This was developed solely by me as a research project on nights and weekends. Output is a
> prioritized list of candidates for human review, not ground truth. False
> positives may be exepected and human verification is still needed.

---

## Headline result — CVE-2022-32250 rediscovered from cold start

Pointed at an unmodified Linux **v5.10** source tree — a point release
predating the upstream backport of the fix — KernelSurgeon rediscovered
**[CVE-2022-32250](https://nvd.nist.gov/vuln/detail/CVE-2022-32250)**, a
use-after-free in `__nf_tables_abort`
([`net/netfilter/nf_tables_api.c`](https://elixir.bootlin.com/linux/v5.10/source/net/netfilter/nf_tables_api.c)).
The bug had a public weaponized LPE exploit and a CVSS v3.1 base score of 7.8.

The generated report — attack path, CVSS vector, CWE classification, and a
compilable crash reproducer — is at
[data/reports/run_20260306_035313/HIGH/report___nf_tables_abort_dada1b00.md](data/reports/run_20260306_035313/HIGH/report___nf_tables_abort_dada1b00.md).

The tool was **not** seeded with knowledge of this CVE: no CVE database, no
patch corpus, no hand-targeted hints toward netfilter. Candidate ranking comes
from graph topology and LLM-evaluated structural patterns; the verdict comes
from an agent loop that explored the function plus its callers/callees in the
call graph and then read the relevant source.

---

## Methodology grounding

The 7-pattern `CVE_TAXONOMY` in [config.py](config.py) is not ad-hoc — it
was derived from a manual analysis of **19 Linux kernel
security patch diffs**, abstracting the call-graph signature each bug
class leaves behind. The full analysis is in
[docs/Linux Kernel CVE Analysis v2.pdf](docs/Linux%20Kernel%20CVE%20Analysis%20v2.pdf).

This manual corpus is the seed for the planned **patch-derived
vulnerability prior** (see Roadmap), which scales the same methodology to
thousands of historical security-fix commits mined from the kernel's git
log — replacing centrality as the primary ranking signal.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 6: Report Generator                                          │
│  Severity-categorized JSON + Markdown reports (CRITICAL -> INFO)    │
│  Consolidated index.json sorted by severity and CVSS score          │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 5: Crash-Reproducer Generator + Compile Loop                 │
│  Compilable C trigger for CONFIRMED vulnerabilities only            │
│  gcc -Wall in sandbox; LLM fixes compilation errors iteratively     │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 4: Verifier Agent                                            │
│  Independent second opinion -- evaluates evidence objectively       │
│  Validates attack path, assigns CVSS v3.1 score + CWE ID            │
├─────────────────────────────────────────────────────────────────────┤
│  Layers 2+3: VulnAgent (while True agentic loop)                    │
│  LLM writes Python scripts -> sandbox executes -> reads output      │
│  Work-stealing parallel analysis across top-N candidates            │
│  RLMSupervisor enforces timeout (45s) + budget (10 scripts/cand)    │
├─────────────────────────────────────────────────────────────────────┤
│  RLM Sandbox + Supervisor                                           │
│  Persistent Python REPL with live nx.DiGraph in memory              │
│  Thread-based timeout, stdout/stderr capture, state reset           │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 1: Graph Analytics Engine                                    │
│  Betweenness / PageRank / eigenvector centrality                    │
│  Spectral analysis (Fiedler vector), Louvain community detection    │
│  Unchecked-path enumeration from syscall entry points               │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 0b: Function Pointer Resolver                                │
│  Resolves indirect calls through 51 kernel ops struct types         │
│  Injects resolved edges back into the call graph                    │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 0: Call Graph Extraction                                     │
│  cscope parser (fast, no build required)                            │
│  LLVM IR parser (high fidelity, requires clang build)               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Two-Phase Pipeline

The pipeline is split into two independent phases so you can map the kernel
once and run LLM analysis repeatedly with different parameters.

```
Phase 1 -- map       Layers 0 + 0b + 1   No API key needed
Phase 2 -- research  Layers 2-6          Requires ANTHROPIC_API_KEY
```

Artifacts written by **map** are loaded directly by **research** — no kernel
source tree needed in Phase 2.

---

## Quick Start

Tested on Ubuntu 22.04 and WSL2. Phase 1 requires a Linux environment;
Phase 2 is pure Python and runs on Windows / macOS / Linux.

```bash
# 1. Install Python deps
git clone <this-repo>
cd kernelsurgeon
pip install -r requirements.txt

# 2. Install system tools (Linux / WSL)
sudo apt install cscope exuberant-ctags

# 3. Get a kernel source tree (any version; v5.10 is the one used for the
#    headline result above)
git clone --depth 1 --branch v5.10 \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git ~/linux

# 4. Build the cscope database in the kernel tree. The -c flag is important:
#    it produces an uncompressed cross-reference, which lets KernelSurgeon
#    parse the database in a single pass (seconds) instead of falling back
#    to per-symbol subprocess queries.
(cd ~/linux && cscope -b -c -q -k)

# 5. Set the Anthropic API key — never commit it to a file
export ANTHROPIC_API_KEY='your-key-here'         # bash / zsh
# $env:ANTHROPIC_API_KEY = 'your-key-here'       # PowerShell

# 6. Map the kernel (Phase 1). One-time, no API calls.
#    Wall-clock: ~5–30 min depending on kernel size and `--subsystems`.
python run_pipeline.py --phase map --kernel-path ~/linux

# 7. Run vulnerability research (Phase 2). Re-runnable.
#    API spend: ~$5–15 per run at the defaults (top-n=20, sonnet).
python run_pipeline.py --phase research --top-n 20 --workers 4

# 8. View results
ls data/reports/run_*/HIGH/         # confirmed high-severity findings
cat data/reports/run_*/index.json   # full sorted summary
```

---

## Common workflows

Copy-paste recipes for the most frequent cases. All paths assume you are in
the repo root with the venv active.

### A. Just inspect the headline finding (zero install, zero API cost)

```bash
git clone <this-repo>
cd kernelsurgeon
# Then open in your editor:
#   data/reports/run_20260306_035313/HIGH/report___nf_tables_abort_dada1b00.md
```

### B. Reproduce CVE-2022-32250 from scratch

```bash
# v5.10.0 (Dec 2020) — predates the stable backport of the fix (v5.10.120,
# May 2022). NFT_CHAIN_BINDING is consumed in net/netfilter/nf_tables_api.c
# at lines 2010 and 2062 of this tree, confirming the vulnerable code path
# is present.
git clone --depth 1 --branch v5.10 \
    https://github.com/torvalds/linux.git ~/linux
(cd ~/linux && cscope -b -c -q -k)

export ANTHROPIC_API_KEY='<your-key>'

# Scope to net/netfilter to keep the run small and cheap (~$1, ~5 min)
python run_pipeline.py \
    --kernel-path ~/linux \
    --subsystems net/netfilter \
    --top-n 20

# __nf_tables_abort should appear in:
ls data/reports/run_*/HIGH/
```

### C. Quick taste — one small subsystem, minimum spend

```bash
python run_pipeline.py \
    --kernel-path <kernel-tree> \
    --subsystems <subsystem-path>/ \    # e.g. net/netfilter/ , fs/ext4/ , drivers/usb/
    --top-n 5 \
    --no-fptr                             # skip function-pointer resolution for speed
```

Approximate cost: ~$0.50–$2.00, ~3–10 min wall-clock.

### D. Iterate on Phase 2 without remapping the kernel

```bash
# Map once (slow, no API cost)
python run_pipeline.py --phase map --kernel-path <kernel-tree>

# Then run Phase 2 repeatedly with different parameters — Layer 1 results
# are cached and reused, so this is just LLM + verifier + reporter cost.
python run_pipeline.py --phase research --top-n 20
python run_pipeline.py --phase research --top-n 50 --workers 6
python run_pipeline.py --phase research --top-n 20 --model claude-opus-4-7
```

Each Phase 2 run writes to a fresh `data/reports/run_<timestamp>/` so prior
results are preserved for comparison.

### E. Focus on a specific subsystem or set of subsystems

```bash
# Single
python run_pipeline.py --kernel-path <kernel-tree> --subsystems net/

# Multiple (space-separated)
python run_pipeline.py --kernel-path <kernel-tree> --subsystems net/ mm/ fs/

# Drilling deeper — sub-subsystem
python run_pipeline.py --kernel-path <kernel-tree> --subsystems drivers/net/wireless/
```

### F. Different kernel version

```bash
KVER=v6.6
git clone --depth 1 --branch $KVER \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git ~/linux-$KVER
(cd ~/linux-$KVER && cscope -b -c -q -k)

python run_pipeline.py \
    --kernel-path ~/linux-$KVER \
    --output-dir data-$KVER/        # keep artifacts separate per kernel
```

### G. Graph analytics only — no LLM calls, no API key needed

```bash
python run_pipeline.py --phase map --kernel-path <kernel-tree> --no-agent

# Then inspect ranked candidates by graph score alone:
python -c "import json; \
    cs=json.load(open('data/candidates.json')); \
    [print(f\"{c['vulnerability_score']:.3f}  {c['subsystem']:20s} {c['name']}\") \
     for c in cs[:30]]"
```

Useful for sanity-checking the ranker output before spending on LLM analysis.

### H. Regenerate the crash-reproducer for one existing finding

```bash
# After editing poc_generator.py, its prompts, or _clean_code()
python regenerate_poc.py data/reports/run_*/HIGH/report_<fn>_<id>.json
# Re-renders both the .json and the .md in place. ~1 API call, ~10 sec.
```

### I. Run with a smaller / cheaper model for experimentation

```bash
export ANTHROPIC_API_KEY='<your-key>'
python run_pipeline.py \
    --kernel-path <kernel-tree> \
    --subsystems net/netfilter \
    --top-n 10 \
    --model claude-haiku-4-5-20251001       # cheaper, faster, lower verdict quality
```

Useful for prompt iteration; not recommended for the final run.

### J. Stop / resume

The pipeline writes reports incrementally as each candidate's analysis
completes. **`Ctrl+C` is safe** — any candidates that finished are already
on disk under `data/reports/run_<timestamp>/`. A re-run starts from the top
of the candidate list (not where it stopped); scope it with `--subsystems` if
you want to skip already-covered ground.

---

**Optional — LLVM IR mode** (higher fidelity, recovers inlined calls). Build
the kernel with clang first:

```bash
(cd ~/linux && make CC=clang LLVM=1 KCFLAGS='-save-temps=obj' -j$(nproc))
python run_pipeline.py --kernel-path ~/linux --mode llvm --ir-dir ~/linux
```

**Optional — graph analytics only, no LLM**: pass `--no-agent` or run with
only `--phase map`.

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--phase` | `all` | `map`, `research`, or `all` |
| `--kernel-path` | — | Kernel source tree (required for map/all; optional for research — omitting it skips source-code snippets in LLM context) |
| `--mode` | `cscope` | Extraction backend: `cscope` or `llvm` |
| `--ir-dir` | — | LLVM IR directory (llvm mode only) |
| `--graph` | — | Load existing `callgraph.json`, skip extraction |
| `--subsystems` | auto | Limit to specific subsystems, e.g. `net/ mm/`. Default: auto-detect all code directories from the kernel tree, sorted largest first. |
| `--max-functions` | 0 (all) | Cap extracted functions |
| `--output-dir` | `data` | Directory for all artifacts |
| `--top-n` | 10 | Candidates to analyse with LLM |
| `--workers` | 4 | Work-stealing threads |
| `--rate-limit` | 2.0 | Max API calls/sec across all workers |
| `--model` | `claude-sonnet-4-20250514` | Claude model for all agents |
| `--max-iter` | 5 | Max agent iterations per candidate |
| `--no-agent` | — | Skip LLM (graph analytics only) |
| `--no-cache` | — | Disable per-subsystem extraction cache |
| `--no-fptr` | — | Skip function pointer resolution |
| `--no-verify` | — | Skip verifier, crash-reproducer generation, reports |
| `--no-visualizer` | — | Disable live mapping progress display |

---

## Output Directory Layout

After a full `--phase map` run, `--output-dir` (default `data/`) contains:

```
data/
  callgraph.json              — raw call graph (before fptr resolution)
  callgraph_enriched.json     — graph with fptr edges + analytics annotations
  fptr_edges.json             — function pointer edges from Layer 0b
  candidates.json             — all candidates, ranked by vulnerability score
  map_report.json             — per-subsystem mapping statistics
  analysis_summary.json       — top-50 candidates + per-subsystem summary
  cache/                      — extraction + metrics cache (Layers 0-1)
  subsystems/                 — per-subsystem candidate lists (Layer 1)
  reports/                    — written by --phase research (Layers 4-6)
    run_20260306_035313/        — timestamped per-run folder
      CRITICAL/
      HIGH/
        report___nf_tables_abort_dada1b00.json
        report___nf_tables_abort_dada1b00.md
      MEDIUM/ ...
      LOW/ ...
      INFORMATIONAL/ ...
      index.json                — sorted summary for this run
```

### Caching (Layers 0 + 1)

**Layer 0 — Extraction cache.** Per-subsystem function/edge data is cached in
`data/cache/`. Each cache file is tagged with its extraction mode (`"cscope"`
or `"llvm"`), so switching modes automatically invalidates stale entries.

- **cscope mode**: invalidated when `cscope.out` mtime changes
- **LLVM mode**: invalidated when any `.ll` file's mtime changes
- Cache is not written when `--max-functions` is set (partial extractions)

**Layer 1 — Metrics cache.** Betweenness, PageRank, eigenvector, Fiedler, and
community metrics are saved to `data/cache/metrics_cache.json`. On re-runs the
cache is loaded if the graph fingerprint (`nodes:edges`) matches, skipping the
most expensive computations entirely.

**Strict subsystem scoping.** When `--subsystems` is specified, only functions
and edges *within* those directories are extracted.

```bash
# Force full re-extraction + re-analysis (ignore all caches)
python run_pipeline.py --phase map --kernel-path /linux --no-cache

# Clear the cache manually
rm -rf data/cache/
```

### Timestamped Reports

Each `--phase research` run writes its reports into a timestamped subdirectory
under `data/reports/`. Previous runs are never overwritten, so you can compare
results across parameter / model / `--top-n` variations.

---

## Features

### Layer 0 — Call Graph Extraction + Live Mapping Visualization

The extractor points at a Linux kernel top-level directory and maps it
**subsystem by subsystem**. It auto-detects all code directories (anything
under the kernel root that contains `.c` files, excluding `Documentation/`,
`scripts/`, `tools/`, etc.), sorts them largest-first, and builds the call
graph incrementally.

For each subsystem in sequence:
1. All function definitions in that directory are added as graph nodes (via ctags).
2. cscope is queried for the callees of each function and edges are added.
3. The live display updates in real time.

**Live progress display** (`rich` required — `pip install rich`):

```
KernelSurgeon — Code Mapping Phase
[=============                       ] 33%  3/9 subsystems  |  142,847 functions  |  891,234 edges  |  214s

  Subsystem           Status          Files    Functions       Edges     Time
  drivers/            [x] done        18,243     87,412      612,847    142s
  fs/                 [x] done         3,102     22,847      184,231     38s
  net/                [~] scanning  1,024/1,891   8,342       61,234     34s
  ...
```

A JSON summary is saved to `data/map_report.json` after each mapping run.

**Two extraction backends:**

**cscope** (default) — fast, no kernel build required. Recovers direct call
edges and function definitions. Extraction behaviour depends on how the cscope
database was built:

- **Uncompressed** (`cscope -c`): cross-reference parsed in a single pass,
  zero subprocess calls, full-kernel graphs in seconds.
- **Compressed** (default `make cscope`): binary names can't be matched
  against ctags. KernelSurgeon detects this from the database header and falls
  back to parallel subprocess queries (`ThreadPoolExecutor`, 16 workers).

To get the fast path on a fresh database:
```bash
cscope -b -c -q -k          # -c = uncompressed ASCII cross-reference
```

**LLVM IR** — high-fidelity. Parses `.ll` files produced by
`clang -save-temps=obj` to recover precise call edges including inlined calls.
Build with:
```bash
make CC=clang LLVM=1 KCFLAGS='-save-temps=obj'
```

The extracted graph is a **NetworkX MultiDiGraph** with per-node metadata:
file path, subsystem, security role (syscall entry / memory sink / lock
acquirer / etc.).

---

### Layer 0b — Function Pointer Resolution

Resolves indirect dispatch through 51 kernel ops struct types, injecting
resolved edges back into the call graph as `INDIRECT` typed edges.

| Category | Structs |
|---|---|
| File / VFS | `file_operations`, `inode_operations`, `super_operations`, `address_space_operations`, `dentry_operations`, `seq_operations`, `proc_ops`, `xattr_handler`, `export_operations`, `file_lock_operations`, `quota_format_ops` |
| Network | `net_device_ops`, `proto_ops`, `proto`, `net_proto_family`, `neigh_ops`, `dst_ops`, `packet_type` |
| Device model | `bus_type`, `device_driver`, `platform_driver` |
| Char / TTY | `tty_operations`, `uart_ops`, `tty_ldisc_ops` |
| Graphics | `fb_ops`, `drm_driver` |
| Video / media | `v4l2_subdev_ops`, `media_entity_operations` |
| Sound | `snd_pcm_ops`, `snd_soc_dai_ops` |
| Crypto | `crypto_alg`, `shash_alg`, `skcipher_alg` |
| Storage | `scsi_host_template`, `ata_port_operations` |
| Hardware | `irq_chip`, `dma_map_ops`, `i2c_driver`, `spi_driver`, `rtc_class_ops`, `watchdog_ops` |
| Input | `input_dev` |
| Memory | `mmu_notifier_ops`, `vm_operations_struct` |
| Kobject / sysfs | `kobj_type`, `sysfs_ops` |

The resolver builds a ctags line→function index once and uses `bisect` for
O(log N) enclosing-function lookups. All C files in scope are scanned in a
single pass via `ThreadPoolExecutor`.

---

### Layer 1 — Graph Analytics Engine

Ranks candidate functions using a composite **vulnerability score** built
from:

- **Betweenness centrality** — functions on many shortest paths (high
  information flow).
- **PageRank** — functions reachable from many entry points. Computed via
  SciPy sparse matrix power iteration (releases the GIL — real parallelism
  with ThreadPoolExecutor).
- **Eigenvector centrality** — proximity to other high-scoring nodes.
  Computed via SciPy ARPACK `eigs()` on the largest SCC adjacency matrix.
- **Fiedler vector** (spectral analysis) — near-zero values flag subsystem
  boundary nodes. Computed via SciPy `eigsh()` on the graph Laplacian.
- **Louvain community detection** — cross-community callers indicate
  trust-boundary crossings.
- **Unchecked path count** — paths from syscall entry points that reach
  this function without passing through known check functions. BFS is
  parallelised across syscall entry points.
- **CVE pattern match count** — how many of the 7 taxonomy patterns the
  function's neighborhood exhibits.

All five algorithms (betweenness, PageRank, eigenvector, Fiedler, Louvain)
run concurrently in a `ThreadPoolExecutor(max_workers=5)`.

> **Note on the ranking signal.** Centrality is a weak proxy for vulnerability
> likelihood — high-betweenness functions tend to be well-connected
> (`do_syscall_64`, `kmalloc`) rather than buggy. A patch-derived prior built
> from the kernel's own security-fix history is on the roadmap and is expected
> to replace centrality as the dominant signal.

---

### RLM Sandbox — Persistent Python REPL

The **RLM Sandbox** ([rlm_sandbox.py](rlm_sandbox.py)) provides a stateful
Python interpreter that the LLM interacts with by submitting string-based
scripts. Execution state (variables, imports, defined functions) persists
across calls, enabling iterative analysis where each script builds on prior
results.

**Pre-populated namespace:**

| Name | Description |
|---|---|
| `G` | Raw `nx.MultiDiGraph` — the kernel call graph |
| `kernel_graph` | `KernelGraph` wrapper object |
| `nx` | NetworkX library |
| `audit` | `KernelAudit` instance with kernel source helpers |
| `kgrep(pat)` | `grep -rn` against kernel source tree |
| `kcscope(t, s)` | cscope symbol lookup |
| `kctags(sym)` | ctags symbol lookup |
| `find_function(name)` | Locate a C function definition |
| `find_callers(name)` | Find all call sites of a function |
| `os`, `sys`, `re`, `json`, `subprocess`, `pathlib` | Standard library |
| `np`, `scipy` | NumPy / SciPy (if installed) |

**Key design decisions:**

- `code.InteractiveInterpreter` for persistent state across `run()` calls.
- Thread-based timeout via daemon threads.
- `sys.stdout` / `sys.stderr` redirection with module-level
  `_REAL_STDOUT` / `_REAL_STDERR` saves to restore after timeout.
- `self._lock` ensures only one script executes at a time.
- `_extract_raw_graph()` distinguishes `KernelGraph.graph` (an
  `nx.MultiDiGraph`) from `nx.Graph.graph` (a metadata dict) by checking for
  graph-like methods.

**CLI smoke-test:**

```bash
# Execute a script against a loaded graph
python rlm_sandbox.py --graph data/callgraph_enriched.json \
    --exec "print(list(G.nodes)[:5])"

# Interactive REPL mode
python rlm_sandbox.py --kernel-path /path/to/linux --graph data/callgraph_enriched.json
```

---

### RLM Supervisor — Timeout + Budget Enforcement

The **RLMSupervisor** wraps the sandbox with two hard limits per candidate:

| Limit | Default | Behavior |
|---|---|---|
| `script_timeout` | 45 s | Per-script wall-clock limit. On timeout: returns `status="timeout"` with a targeted backtrack hint, resets the interpreter. |
| `max_scripts_per_candidate` | 10 | Total scripts allowed per candidate. On exhaustion: returns `status="max_depth_reached"` without executing, forces the LLM to produce a final verdict. |

**Backtrack hints** (`_timeout_backtrack_for()`): when a script times out, the
supervisor pattern-matches the source to identify the algorithmic issue and
suggests bounded alternatives:

- `nx.all_simple_paths` → replace with `nx.shortest_path` or `cutoff`
- `nx.ancestors` / `nx.descendants` → replace with `nx.ego_graph(G, node, radius=3)`
- `nx.all_pairs_*` → replace with single-source variants
- `nx.pagerank` without `max_iter` → add `max_iter=50, tol=1e-3`
- Infinite loops (`while True` / `while 1`) → add explicit break condition
- Unbounded `shortest_path` without `has_path` guard → add reachability check

Results are formatted as Markdown blocks via `to_llm_context()` with explicit
`ACTION REQUIRED` directives that force the LLM to change strategy on timeout
or budget exhaustion.

---

### Layers 2+3 — Agentic LLM Vulnerability Analysis

**`while True` execution loop** (`VulnAgent.analyze_candidate()`):

1. Assemble initial context (source code, graph metrics, CVE patterns) and
   send to LLM.
2. LLM returns a JSON assessment with optional `graph_scripts` (Python
   scripts to explore the call graph), `examine_functions` (source code
   requests), and `graph_queries` (natural-language queries).
3. Python scripts execute in the RLM Sandbox via the supervisor (timeout +
   budget enforced).
4. Results are fed back as a follow-up prompt.
5. Loop continues until:
   - LLM declares the candidate analyzed (empty `next_steps`).
   - `--max-iter` iterations are reached.
   - RLMSupervisor triggers a hard stop (script budget exhausted).

**Best-iteration tracking.** VulnAgent preserves the highest-confidence
`is_vulnerable=true` finding across iterations instead of using the last
response. Prevents malformed later iterations from overwriting correct
earlier results.

**Work-stealing parallel execution** (`WorkStealingPool`):
- Chase-Lev style: each worker holds a `deque`; idle workers steal tasks
  from the back of random victims' deques.
- Shared token-bucket rate limiter keeps total API calls/sec within
  `--rate-limit`.
- Progress printed per completion: `[done/total] function_name -> vuln=True conf=HIGH`.

**Anthropic prompt caching:**
- System prompt cached across all candidates in a session.
- Static CVE taxonomy + analysis instructions cached as a second block.
- Per-candidate source code + graph neighborhood NOT cached (unique per
  function).
- Typically >80% cache hit ratio after the first candidate.

---

### Layer 4 — Verifier Agent

An independent Claude agent that evaluates the primary finding's evidence
objectively. Originally adversarial; rebalanced after the adversarial framing
caused real vulnerabilities to be rejected.

Verification checklist applied to every finding:
1. Attack path reachability — is every hop actually present in the code?
2. Preconditions — required capabilities, namespaces, race window feasibility.
3. Existing mitigations — KASAN, hardened usercopy, fortified string
   functions.
4. Impact — confidentiality / integrity / availability / privilege escalation.

Output: **CVSS v3.1 score**, **CWE ID**, verifier confidence (HIGH/MEDIUM/LOW),
and an `is_confirmed` flag. Only confirmed findings proceed to Layer 5.

---

### Layer 5 — Crash-Reproducer Generator + Compile Loop

Generates a minimal, compilable **C trigger** for confirmed vulnerabilities.
Output is intended to crash a vulnerable kernel under the right conditions —
not a weaponized LPE.

- Written against standard Linux userspace headers only (no kernel headers).
- Template-guided by vulnerability type:

| Type | Template approach |
|---|---|
| `stack_buffer_overflow` / `heap_buffer_overflow` | Oversized `write()` / `ioctl()` payload |
| `missing_bounds_check` | Out-of-range index via ioctl |
| `toctou_race` | Two-thread racing with userfaultfd timing |
| `use_after_free` | Allocate → concurrent close → reclaim → access |
| `type_confusion` | Crafted `sockaddr` / union payload |

Every generated file:
- Carries an `/* AUTHORIZED SECURITY RESEARCH ONLY */` disclaimer.
- Has a `main()` with setup → trigger → detection → cleanup phases.
- Ends with a `// Build: gcc -o trigger trigger.c -lpthread` comment block.

**Compile-and-fix loop** (`_compile_and_fix_loop()`):

When an RLMSupervisor is available, the generated C is compiled inside the
sandbox:

1. Code is injected into the sandbox namespace (avoids string escaping issues
   with C backslashes and quotes).
2. A compile script writes the code to a temp file and runs `gcc -Wall`.
3. If compilation fails, gcc stderr is fed back to the LLM which produces a
   corrected version.
4. The loop repeats up to `max_fix_attempts` (default 3).
5. The `ProofOfConcept` dataclass tracks `compilation_status`
   (`success` / `failed` / `untested`) and `fix_iterations`.

---

### Layer 6 — Severity-Categorized Reports

Reports are organized by severity under `<output-dir>/reports/<run_id>/`:

```
reports/
└── run_20260306_035313/
    ├── CRITICAL/
    │   └── report_<fn>_<uuid>.{json,md}
    ├── HIGH/
    ├── MEDIUM/
    ├── LOW/
    ├── INFORMATIONAL/
    └── index.json              — consolidated summary
```

Each report contains:
- File path, function name, subsystem, vulnerable line number.
- CVSS v3.1 score and vector components.
- CWE ID and vulnerability type.
- Full attack path and check-bypass analysis.
- Verification notes and false-positive reasoning (if rejected).
- Crash-reproducer code, compilation status, trigger steps, expected kernel
  output, and limitations.
- Remediation advice.
- Raw graph metrics (betweenness, PageRank, vulnerability score).

**CVSS severity bands:**

| Score | Severity |
|---|---|
| ≥ 9.0 | CRITICAL |
| ≥ 7.0 | HIGH |
| ≥ 4.0 | MEDIUM |
| ≥ 0.1 | LOW |
| 0.0 | INFORMATIONAL |

---

## CVE Taxonomy Patterns

Seven structural patterns guide candidate prioritization and LLM prompting:

| ID | Pattern | Typical indicators |
|---|---|---|
| P1 | Stack buffer overflow | `strcpy`, `strcat`, `sprintf` without length |
| P2 | Heap buffer overflow | Integer overflow in `kmalloc` size calculation |
| P3 | Off-by-one | Boundary check uses `<` instead of `<=` (or vice versa) |
| P4 | Missing bounds check | Cross-subsystem call with no validation of user-supplied size |
| P5 | TOCTOU race | Check and use of shared buffer separated by preemption point |
| P6 | Type confusion | Union or pointer cast without discriminant check |
| P7 | Use-after-free | Object accessed on async callback after `kfree` |

---

## File Structure

```
(repo root)/
├── run_pipeline.py             — main entry point (two-phase CLI)
├── rlm_sandbox.py              — RLMSandbox + RLMSupervisor + ScriptResult
├── regenerate_poc.py           — re-run crash-reproducer generation on an existing report
├── kernel_graph.py             — KernelGraph (NetworkX MultiDiGraph wrapper)
├── cscope_extractor.py         — Layer 0: cscope-based extraction
├── llvm_ir_extractor.py        — Layer 0: LLVM IR-based extraction
├── map_visualizer.py           — Live terminal visualization + detect_subsystems()
├── fptr_resolver.py            — Layer 0b: function pointer resolution
├── graph_analyzer.py           — Layer 1: graph analytics + candidate ranking
├── context_assembler.py        — Layer 2: LLM context assembly
├── vuln_agent.py               — Layer 3: agentic vulnerability analysis
├── verifier_agent.py           — Layer 4: verification
├── poc_generator.py            — Layer 5: crash-reproducer generation + compile loop
├── report_generator.py         — Layer 6: severity-categorized reports
├── work_stealing_pool.py       — Work-stealing thread pool
├── config.py                   — CVE taxonomy, security roles, analysis config
├── test_fptr.py                — Function pointer resolver test suite
├── requirements.txt
└── data/
    └── reports/
        └── run_20260306_035313/HIGH/
            └── report___nf_tables_abort_dada1b00.{json,md}
```

**Running the test suite:**

```bash
python test_fptr.py
```

---

## Requirements

```
python >= 3.11           # tested on 3.13
networkx
numpy
scipy
anthropic
rich                     # optional — enables live mapping display
```

**Platform notes:**

- **Phase 2 (`research`)** is pure Python. Runs on Windows (PowerShell or
  CMD), macOS, or Linux.
- **Phase 1 (`map`)** requires `cscope` and `ctags` on `PATH`. On Windows,
  use WSL.
- **LLVM IR mode** additionally requires a kernel built with
  `make CC=clang LLVM=1 KCFLAGS='-save-temps=obj'`. Linux / WSL only.

---

## Roadmap

- **Patch-derived vulnerability prior.** Replace centrality as the primary
  ranking signal with a count of how many security-fix commits in the
  kernel's git history have touched each function. Centrality flags
  well-connected functions; patch history flags empirically bug-prone ones.
- **Bug-pattern matching from extracted fix fingerprints.** For each
  security-fix commit, extract a structured "what was wrong / what was added"
  pair via a cheap LLM, then match current functions against the pre-fix
  pattern.
- **Embedding-based CVE-anchored retrieval.** For each current function,
  retrieve K-nearest neighbors among pre-fix functions; high similarity
  raises the prior.

---

## License

[Add a license file before publishing. MIT or Apache-2.0 are conventional for
research code; the kernel's GPL does not extend to tools that merely *analyze*
kernel source without linking against it.]
