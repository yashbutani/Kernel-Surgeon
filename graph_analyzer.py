"""
Graph Analytics Engine (Layer 1)

Runs structural analysis on the kernel call graph to surface
statistically interesting candidate functions for vulnerability review.

Implements:
- Centrality metrics (betweenness, PageRank, eigenvector)
- Spectral analysis (Fiedler vector for boundary detection)
- Community detection (Louvain)
- Security-aware path analysis (unchecked path enumeration)
- Composite scoring and candidate ranking
"""

import json
import os
import re
import sys
import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Optional

import networkx as nx
import numpy as np
from scipy.sparse import csr_matrix, diags as sparse_diags
from scipy.sparse.linalg import eigsh, eigs

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from kernel_graph import KernelGraph, SecurityRole
from config import ANALYSIS_CONFIG, CVE_TAXONOMY


@dataclass
class CandidateFunction:
    """A function flagged as interesting by graph analytics."""
    node_id: str
    name: str
    file_path: str
    subsystem: str
    security_role: str
    line_start: int = 0

    # Centrality scores
    betweenness: float = 0.0
    betweenness_percentile: float = 0.0
    pagerank: float = 0.0
    pagerank_percentile: float = 0.0
    eigenvector: float = 0.0

    # Structural features
    fiedler_value: float = 0.0          # near zero = subsystem boundary
    is_boundary_node: bool = False
    community_id: int = -1
    cross_subsystem_callers: int = 0
    cross_subsystem_callees: int = 0

    # Security-specific
    unchecked_paths_from_syscall: int = 0
    reachable_from_syscalls: int = 0
    reaches_sinks: int = 0
    matching_cve_patterns: list[str] = None

    # Composite score (weighted combination)
    vulnerability_score: float = 0.0
    reasoning: str = ""

    def __post_init__(self):
        if self.matching_cve_patterns is None:
            self.matching_cve_patterns = []


class GraphAnalyzer:
    """
    Runs graph analytics to find vulnerability candidates.
    
    Two modes:
    1. Full analysis: compute all metrics, rank everything
    2. Targeted query: given a hypothesis, find matching subgraph
    """

    def __init__(
        self,
        kernel_graph: KernelGraph,
        config: dict = None,
        metrics_dir: str | None = None,
    ):
        self.kg = kernel_graph
        self.config = config or ANALYSIS_CONFIG
        self.simple_graph = kernel_graph.to_simple_graph()
        self.candidates: list[CandidateFunction] = []
        self.metrics_dir = metrics_dir

        # Cache computed metrics
        self._betweenness: dict[str, float] = {}
        self._pagerank: dict[str, float] = {}
        self._eigenvector: dict[str, float] = {}
        self._fiedler: dict[str, float] = {}
        self._communities: dict[str, int] = {}

        # Graph fingerprint for cache invalidation
        self._graph_fingerprint = f"{self.kg.num_nodes}:{self.kg.num_edges}"

    # ------------------------------------------------------------------
    # Metrics cache: save/load intermediate calculations
    # ------------------------------------------------------------------

    def _metrics_cache_path(self) -> str | None:
        if self.metrics_dir is None:
            return None
        return os.path.join(self.metrics_dir, "metrics_cache.json")

    def _try_load_metrics(self) -> bool:
        """
        Load cached metric dictionaries if the graph fingerprint matches.

        Returns ``True`` if all five metric caches were loaded successfully.
        """
        path = self._metrics_cache_path()
        if path is None or not os.path.exists(path):
            return False
        try:
            with open(path) as f:
                data = json.load(f)
            if data.get("fingerprint") != self._graph_fingerprint:
                return False
            self._betweenness = data.get("betweenness", {})
            self._pagerank    = data.get("pagerank", {})
            self._eigenvector = data.get("eigenvector", {})
            self._fiedler     = data.get("fiedler", {})
            self._communities = {k: int(v) for k, v in data.get("communities", {}).items()}
            return bool(self._betweenness or self._pagerank)
        except Exception:
            return False

    def _save_metrics(self) -> None:
        """Persist all computed metrics to disk."""
        path = self._metrics_cache_path()
        if path is None:
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = {
            "fingerprint": self._graph_fingerprint,
            "betweenness": self._betweenness,
            "pagerank": self._pagerank,
            "eigenvector": self._eigenvector,
            "fiedler": self._fiedler,
            "communities": self._communities,
        }
        with open(path, "w") as f:
            json.dump(data, f)
        print(f"    Metrics cached → {path}")

    # ------------------------------------------------------------------
    # Full analysis pipeline
    # ------------------------------------------------------------------

    def run_full_analysis(self) -> list[CandidateFunction]:
        """Run all analyses and produce ranked candidate list.

        Betweenness, PageRank, eigenvector, Fiedler, and Louvain are
        independent read-only computations — run them concurrently.
        SciPy-based algorithms (PageRank, eigenvector, Fiedler) release
        the GIL during compiled C/Fortran work, so ThreadPoolExecutor
        achieves real parallelism without pickling overhead.

        If a metrics cache exists (matching graph fingerprint), the five
        metric computations are skipped entirely.
        """
        print("[*] Running full graph analysis...")
        print(f"    Graph: {self.kg.num_nodes} nodes, {self.kg.num_edges} edges")

        # Try loading cached metrics first
        if self._try_load_metrics():
            print("    Loaded cached metrics (betweenness, pagerank, "
                  "eigenvector, fiedler, communities)")
        else:
            # Step 1-3: Independent algorithms in parallel
            with ThreadPoolExecutor(max_workers=5) as pool:
                f_bc = pool.submit(self._compute_betweenness)
                f_pr = pool.submit(self._compute_pagerank)
                f_ev = pool.submit(self._compute_eigenvector)
                f_fi = pool.submit(self._compute_fiedler_vector)
                f_lo = pool.submit(self._detect_communities)

                # Collect results (each method stores results in self._*)
                for future in as_completed([f_bc, f_pr, f_ev, f_fi, f_lo]):
                    exc = future.exception()
                    if exc:
                        print(f"    Warning: algorithm failed: {exc}")

            # Persist for future runs
            self._save_metrics()

        # Step 4: Security-aware path analysis (depends on graph, not metrics)
        self._analyze_unchecked_paths()

        # Step 5: Score and rank (depends on all metrics above)
        self._score_candidates()

        # Step 6: Write metrics back to graph nodes
        self._write_metrics_to_graph()

        print(f"[+] Analysis complete: {len(self.candidates)} candidates flagged")
        return self.candidates

    # ========================================================================
    # CENTRALITY METRICS
    # ========================================================================

    def _compute_betweenness(self) -> None:
        """
        Betweenness centrality: nodes on many shortest paths.
        High betweenness = chokepoint function that many call chains pass through.
        """
        print("    Computing betweenness centrality...")
        n = self.simple_graph.number_of_nodes()

        if n > 50000:
            # Approximate for large graphs
            k = min(1000, n // 10)
            print(f"    (approximating with k={k} samples)")
            self._betweenness = nx.betweenness_centrality(self.simple_graph, k=k)
        else:
            self._betweenness = nx.betweenness_centrality(self.simple_graph)

        print(f"    Max betweenness: {max(self._betweenness.values()):.6f}")

    def _compute_pagerank(self) -> None:
        """
        PageRank via SciPy sparse matrix power iteration.

        Pushes the entire computation into compiled C/Fortran via
        scipy sparse matrix–vector products, bypassing Python loop
        overhead.  Personalization biases toward syscall entry points.
        """
        print("    Computing PageRank (scipy sparse)...")
        nodes = list(self.simple_graph.nodes())
        node_to_idx = {n: i for i, n in enumerate(nodes)}
        n = len(nodes)

        if n == 0:
            self._pagerank = {}
            return

        try:
            # Build sparse adjacency (CSC for efficient column slicing)
            A = nx.to_scipy_sparse_array(self.simple_graph, nodelist=nodes, format="csc", dtype=float)

            # Column-normalize → stochastic transition matrix
            out_degree = np.array(A.sum(axis=0)).flatten()
            dangling = out_degree == 0
            out_degree[dangling] = 1.0  # avoid division by zero
            D_inv = sparse_diags(1.0 / out_degree)
            M = A @ D_inv

            # Personalization vector biased toward syscall entries
            v = np.ones(n) / n
            syscall_set = set(self.kg.get_syscall_nodes())
            if syscall_set:
                for sc_node in syscall_set:
                    if sc_node in node_to_idx:
                        v[node_to_idx[sc_node]] = 10.0
                v /= v.sum()

            # Dangling node correction
            dangling_vec = dangling.astype(float)

            # Power iteration
            alpha = 0.85
            pr = np.ones(n) / n
            for _ in range(200):
                dangling_contrib = pr[dangling].sum() * v
                pr_new = alpha * (M @ pr + dangling_contrib) + (1 - alpha) * v
                if np.linalg.norm(pr_new - pr, 1) < 1e-6:
                    break
                pr = pr_new

            self._pagerank = {nodes[i]: float(pr[i]) for i in range(n)}
            print(f"    Max PageRank: {max(self._pagerank.values()):.6f}")

        except Exception as e:
            print(f"    Warning: scipy PageRank failed ({e}), falling back to NetworkX")
            try:
                self._pagerank = nx.pagerank(self.simple_graph, alpha=0.85, max_iter=200)
            except nx.PowerIterationFailedConvergence:
                self._pagerank = nx.pagerank(self.simple_graph, alpha=0.85)
            print(f"    Max PageRank: {max(self._pagerank.values()):.6f}")

    def _compute_eigenvector(self) -> None:
        """
        Eigenvector centrality on the largest SCC via SciPy ARPACK.

        Uses ``scipy.sparse.linalg.eigs`` to find the dominant eigenvector
        of the adjacency matrix, replacing NetworkX's pure-Python power
        iteration with compiled ARPACK Fortran routines.
        """
        print("    Computing eigenvector centrality (scipy ARPACK)...")
        self._eigenvector = {n: 0.0 for n in self.simple_graph.nodes()}

        try:
            sccs = list(nx.strongly_connected_components(self.simple_graph))
            if not sccs:
                return

            largest_scc = max(sccs, key=len)
            if len(largest_scc) < 3:
                return

            subgraph = self.simple_graph.subgraph(largest_scc)
            scc_nodes = list(subgraph.nodes())

            A = nx.to_scipy_sparse_array(subgraph, nodelist=scc_nodes, format="csr", dtype=float)
            eigenvalues, eigenvectors = eigs(A, k=1, which="LM")

            ev = np.abs(eigenvectors[:, 0].real)
            ev_max = ev.max()
            if ev_max > 0:
                ev /= ev_max

            for i, node in enumerate(scc_nodes):
                self._eigenvector[node] = float(ev[i])

            print(f"    SCC size: {len(largest_scc)}, max eigenvector: {ev_max:.6f}")

        except Exception as e:
            print(f"    Warning: eigenvector centrality failed: {e}")
            # Fall back to NetworkX
            try:
                sccs = list(nx.strongly_connected_components(self.simple_graph))
                if sccs:
                    largest_scc = max(sccs, key=len)
                    subgraph = self.simple_graph.subgraph(largest_scc)
                    eig = nx.eigenvector_centrality(subgraph, max_iter=500, tol=1e-4)
                    self._eigenvector.update(eig)
            except Exception:
                pass

    # ========================================================================
    # SPECTRAL ANALYSIS
    # ========================================================================

    def _compute_fiedler_vector(self) -> None:
        """
        Fiedler vector: second smallest eigenvector of the graph Laplacian.
        Nodes near zero sit on the boundary between clusters.
        
        These boundary nodes are functions that bridge subsystems -
        exactly where check-bypass vulnerabilities hide.
        """
        print("    Computing Fiedler vector...")
        self._fiedler = {n: 0.0 for n in self.simple_graph.nodes()}

        # Fiedler vector requires connected graph — use largest WCC
        undirected = self.simple_graph.to_undirected()
        wccs = list(nx.connected_components(undirected))
        if not wccs:
            return

        largest_wcc = max(wccs, key=len)
        if len(largest_wcc) < 3:
            return

        subgraph = undirected.subgraph(largest_wcc)
        nodes = list(subgraph.nodes())
        node_to_idx = {n: i for i, n in enumerate(nodes)}

        try:
            # Build sparse Laplacian
            L = nx.laplacian_matrix(subgraph).astype(float)

            # Get second smallest eigenvector
            # k=2 gets the two smallest eigenvalues; we want the second one
            eigenvalues, eigenvectors = eigsh(L, k=2, which='SM', tol=1e-4)

            fiedler_vec = eigenvectors[:, 1]  # second eigenvector

            # Normalize
            fiedler_vec = fiedler_vec / (np.max(np.abs(fiedler_vec)) + 1e-10)

            for node, idx in node_to_idx.items():
                self._fiedler[node] = float(fiedler_vec[idx])

            threshold = self.config.get("fiedler_boundary_threshold", 0.1)
            boundary_count = sum(1 for v in fiedler_vec if abs(v) < threshold)
            print(f"    Boundary nodes (|fiedler| < {threshold}): {boundary_count}")

        except Exception as e:
            print(f"    Warning: Fiedler computation failed: {e}")

    # ========================================================================
    # COMMUNITY DETECTION
    # ========================================================================

    def _detect_communities(self) -> None:
        """
        Louvain community detection.
        Communities that don't align with directory structure indicate
        unexpected coupling — prime territory for confused-deputy bugs.
        """
        print("    Running community detection (Louvain)...")
        undirected = self.simple_graph.to_undirected()

        try:
            communities = nx.community.louvain_communities(
                undirected,
                resolution=self.config.get("community_resolution", 1.0),
            )
            for comm_id, community in enumerate(communities):
                for node in community:
                    self._communities[node] = comm_id

            print(f"    Found {len(communities)} communities")

            # Analyze community-subsystem alignment
            self._analyze_community_alignment(communities)

        except Exception as e:
            print(f"    Warning: community detection failed: {e}")
            self._communities = {n: 0 for n in self.simple_graph.nodes()}

    def _analyze_community_alignment(self, communities: list[set]) -> None:
        """Check how well graph communities align with directory-based subsystems."""
        misaligned = 0
        for comm_id, community in enumerate(communities):
            subsystems_in_comm = set()
            for node in community:
                data = self.kg.get_node(node)
                if data:
                    subsystems_in_comm.add(data.get("subsystem", "other"))
            if len(subsystems_in_comm) > 1:
                misaligned += 1
        print(f"    Communities spanning multiple subsystems: {misaligned}/{len(communities)}")

    # ========================================================================
    # SECURITY-AWARE PATH ANALYSIS
    # ========================================================================

    def _analyze_unchecked_paths(self) -> None:
        """
        Find paths from syscall entry points to sensitive sinks that
        do NOT pass through any validation/check node.

        Pre-builds adjacency dicts and parallelises per-entry-point BFS
        across threads.
        """
        print("    Analyzing unchecked paths from syscalls to sinks...")

        syscall_nodes = self.kg.get_syscall_nodes()
        validation_nodes = set(self.kg.get_nodes_by_role(SecurityRole.VALIDATION))
        lsm_nodes = set(self.kg.get_nodes_by_role(SecurityRole.LSM_HOOK))
        check_nodes = validation_nodes | lsm_nodes

        sink_nodes = set()
        for role in [SecurityRole.ALLOC_SINK, SecurityRole.FREE_SINK]:
            sink_nodes |= set(self.kg.get_nodes_by_role(role))

        if not syscall_nodes:
            print("    Warning: no syscall entry points found")
            return
        if not sink_nodes:
            print("    Warning: no sink nodes found")
            return

        print(f"    Syscall entries: {len(syscall_nodes)}, "
              f"Check nodes: {len(check_nodes)}, Sinks: {len(sink_nodes)}")

        max_path_len = self.config.get("max_path_length", 10)

        # Pre-build adjacency dicts (avoids repeated .successors() overhead)
        fwd_adj: dict[str, set[str]] = {
            n: set(self.simple_graph.successors(n))
            for n in self.simple_graph.nodes()
        }
        rev_adj: dict[str, set[str]] = {
            n: set(self.simple_graph.predecessors(n))
            for n in self.simple_graph.nodes()
        }

        def _bfs_from(source: str, adj: dict, max_depth: int) -> set[str]:
            visited: set[str] = set()
            frontier = {source}
            for _ in range(max_depth):
                if not frontier:
                    break
                next_frontier: set[str] = set()
                for node in frontier:
                    if node in visited:
                        continue
                    visited.add(node)
                    next_frontier |= adj.get(node, set()) - visited
                frontier = next_frontier
            return visited

        def _tainted_bfs(source: str, adj: dict, blockers: set, max_depth: int) -> set[str]:
            """BFS that stops propagation at blocker nodes."""
            visited: set[str] = set()
            frontier = {source}
            for _ in range(max_depth):
                if not frontier:
                    break
                next_frontier: set[str] = set()
                for node in frontier:
                    if node in visited:
                        continue
                    visited.add(node)
                    if node not in blockers:
                        next_frontier |= adj.get(node, set()) - visited
                frontier = next_frontier
            return visited

        # --- Forward reachability from syscalls (parallel) ---
        print("    Computing forward reachability from syscalls...")
        reachable_from_syscall: dict[str, int] = {}

        with ThreadPoolExecutor(max_workers=min(len(syscall_nodes), 8)) as pool:
            futures = {
                pool.submit(_bfs_from, sc, fwd_adj, max_path_len): sc
                for sc in syscall_nodes
            }
            for future in as_completed(futures):
                for node in future.result():
                    reachable_from_syscall[node] = reachable_from_syscall.get(node, 0) + 1

        # --- Backward reachability to sinks (parallel) ---
        print("    Computing backward reachability to sinks...")
        reaches_sink: dict[str, int] = {}

        with ThreadPoolExecutor(max_workers=min(len(sink_nodes), 8)) as pool:
            futures = {
                pool.submit(_bfs_from, sink, rev_adj, max_path_len): sink
                for sink in sink_nodes
            }
            for future in as_completed(futures):
                for node in future.result():
                    reaches_sink[node] = reaches_sink.get(node, 0) + 1

        # --- Tainted reachability: BFS stops at check nodes (parallel) ---
        print("    Computing tainted (check-free) reachability...")
        unchecked_reachable: set[str] = set()

        with ThreadPoolExecutor(max_workers=min(len(syscall_nodes), 8)) as pool:
            futures = [
                pool.submit(_tainted_bfs, sc, fwd_adj, check_nodes, max_path_len)
                for sc in syscall_nodes
            ]
            for future in as_completed(futures):
                unchecked_reachable |= future.result()

        # Final: unchecked AND reaches sink
        truly_unchecked = unchecked_reachable & set(reaches_sink.keys()) - check_nodes
        print(f"    Nodes on unchecked syscall→sink paths: {len(truly_unchecked)}")

        self._unchecked_nodes = truly_unchecked
        self._reachable_from_syscall = reachable_from_syscall
        self._reaches_sink = reaches_sink

    # ========================================================================
    # SCORING AND RANKING
    # ========================================================================

    def _score_candidates(self) -> None:
        """
        Compute composite vulnerability score and build ranked candidate list.
        
        Scoring combines:
        - Centrality metrics (structural importance)
        - Boundary position (Fiedler value near zero)
        - Unchecked path exposure
        - Cross-subsystem call count
        - CVE pattern matching
        """
        print("    Scoring and ranking candidates...")

        # Compute percentiles for normalization
        bc_values = sorted(self._betweenness.values())
        pr_values = sorted(self._pagerank.values())

        def percentile(value, sorted_values):
            if not sorted_values:
                return 0.0
            idx = np.searchsorted(sorted_values, value)
            return idx / len(sorted_values) * 100

        threshold = self.config.get("fiedler_boundary_threshold", 0.1)

        for node_id in self.simple_graph.nodes():
            data = self.kg.get_node(node_id)
            if not data:
                continue

            bc = self._betweenness.get(node_id, 0.0)
            pr = self._pagerank.get(node_id, 0.0)
            ev = self._eigenvector.get(node_id, 0.0)
            fv = self._fiedler.get(node_id, 0.0)
            comm = self._communities.get(node_id, -1)

            bc_pct = percentile(bc, bc_values)
            pr_pct = percentile(pr, pr_values)

            is_boundary = abs(fv) < threshold
            is_unchecked = hasattr(self, '_unchecked_nodes') and node_id in self._unchecked_nodes
            syscall_reach = getattr(self, '_reachable_from_syscall', {}).get(node_id, 0)
            sink_reach = getattr(self, '_reaches_sink', {}).get(node_id, 0)

            # Cross-subsystem connections
            node_subsystem = data.get("subsystem", "other")
            cross_callers = sum(
                1 for pred in self.simple_graph.predecessors(node_id)
                if self.kg.get_node(pred) and
                self.kg.get_node(pred).get("subsystem") != node_subsystem
            )
            cross_callees = sum(
                1 for succ in self.simple_graph.successors(node_id)
                if self.kg.get_node(succ) and
                self.kg.get_node(succ).get("subsystem") != node_subsystem
            )

            # CVE pattern matching
            matching_patterns = self._match_cve_patterns(node_id, data)

            # ================================================================
            # COMPOSITE SCORE
            # Weights are tunable — these are initial values
            # ================================================================
            score = 0.0

            # High betweenness = structural chokepoint
            if bc_pct >= 90:
                score += 3.0 * (bc_pct / 100)

            # High PageRank from syscall-biased walk = attack-reachable
            if pr_pct >= 90:
                score += 2.0 * (pr_pct / 100)

            # Boundary node = bridges subsystems
            if is_boundary:
                score += 2.5

            # On unchecked path from syscall to sink = direct bypass candidate
            if is_unchecked:
                score += 4.0

            # Cross-subsystem exposure
            if cross_callers + cross_callees > 3:
                score += 1.5

            # Reachable from many syscalls
            if syscall_reach > 5:
                score += 1.0

            # Matches known CVE patterns
            score += len(matching_patterns) * 2.0

            # Only keep candidates above threshold
            if score < 3.0:
                continue

            # Build reasoning string
            reasons = []
            if bc_pct >= 90:
                reasons.append(f"betweenness={bc:.4f} (p{bc_pct:.0f})")
            if pr_pct >= 90:
                reasons.append(f"pagerank={pr:.6f} (p{pr_pct:.0f})")
            if is_boundary:
                reasons.append(f"boundary_node (fiedler={fv:.3f})")
            if is_unchecked:
                reasons.append("on_unchecked_syscall_to_sink_path")
            if cross_callers + cross_callees > 3:
                reasons.append(f"cross_subsystem ({cross_callers} callers, {cross_callees} callees)")
            if matching_patterns:
                reasons.append(f"matches_patterns: {matching_patterns}")

            candidate = CandidateFunction(
                node_id=node_id,
                name=data.get("name", ""),
                file_path=data.get("file_path", ""),
                subsystem=node_subsystem,
                security_role=data.get("security_role", "none"),
                line_start=data.get("line_start", 0),
                betweenness=bc,
                betweenness_percentile=bc_pct,
                pagerank=pr,
                pagerank_percentile=pr_pct,
                eigenvector=ev,
                fiedler_value=fv,
                is_boundary_node=is_boundary,
                community_id=comm,
                cross_subsystem_callers=cross_callers,
                cross_subsystem_callees=cross_callees,
                unchecked_paths_from_syscall=1 if is_unchecked else 0,
                reachable_from_syscalls=syscall_reach,
                reaches_sinks=sink_reach,
                matching_cve_patterns=matching_patterns,
                vulnerability_score=score,
                reasoning="; ".join(reasons),
            )
            self.candidates.append(candidate)

        # Sort by score descending
        self.candidates.sort(key=lambda c: c.vulnerability_score, reverse=True)

    def _match_cve_patterns(self, node_id: str, data: dict) -> list[str]:
        """Check if a node's structural position matches known CVE patterns."""
        matches = []
        name = data.get("name", "")

        for pattern_name, pattern in CVE_TAXONOMY.items():
            # Check if node calls known sink functions for this pattern
            callees = set(self.simple_graph.successors(node_id))
            callee_names = set()
            for c in callees:
                cdata = self.kg.get_node(c)
                if cdata:
                    callee_names.add(cdata.get("name", ""))

            sinks = set(pattern.get("sink_functions", []) +
                       pattern.get("free_functions", []))
            if sinks & callee_names:
                matches.append(pattern["id"])
                continue

            # Check async mechanism patterns (UAF)
            async_mechs = set(pattern.get("async_mechanisms", []))
            if async_mechs & callee_names:
                matches.append(pattern["id"])

        return matches

    def _write_metrics_to_graph(self) -> None:
        """Write computed metrics back to graph node attributes."""
        for node_id in self.simple_graph.nodes():
            attrs = {
                "betweenness": self._betweenness.get(node_id, 0.0),
                "pagerank": self._pagerank.get(node_id, 0.0),
                "eigenvector": self._eigenvector.get(node_id, 0.0),
                "fiedler_value": self._fiedler.get(node_id, 0.0),
                "community_id": self._communities.get(node_id, -1),
            }
            if hasattr(self, '_unchecked_nodes') and node_id in self._unchecked_nodes:
                attrs["unchecked_path_count"] = 1
            nx.set_node_attributes(self.kg.graph, {node_id: attrs})

    # ========================================================================
    # TARGETED QUERIES (for agent feedback loop)
    # ========================================================================

    def query_unchecked_paths(
        self,
        source_role: SecurityRole = SecurityRole.SYSCALL_ENTRY,
        sink_role: SecurityRole = SecurityRole.ALLOC_SINK,
        max_paths: int = 50,
        max_length: int = 8,
    ) -> list[list[str]]:
        """
        Find specific paths from source to sink that bypass checks.
        Used by the agent to investigate specific hypotheses.
        """
        sources = self.kg.get_nodes_by_role(source_role)
        sinks = self.kg.get_nodes_by_role(sink_role)
        check_nodes = set(self.kg.get_nodes_by_role(SecurityRole.VALIDATION))
        check_nodes |= set(self.kg.get_nodes_by_role(SecurityRole.LSM_HOOK))

        unchecked_paths = []
        for source in sources:
            for sink in sinks:
                try:
                    for path in nx.all_simple_paths(
                        self.simple_graph, source, sink, cutoff=max_length
                    ):
                        # Check if any node on path is a validation node
                        if not any(n in check_nodes for n in path[1:-1]):
                            unchecked_paths.append(path)
                            if len(unchecked_paths) >= max_paths:
                                return unchecked_paths
                except nx.NodeNotFound:
                    continue

        return unchecked_paths

    def find_similar_nodes(self, node_id: str, top_k: int = 10) -> list[str]:
        """
        Find nodes with similar structural properties to a given node.
        Useful for variant analysis: "find other functions like this CVE function."
        """
        if node_id not in self.simple_graph:
            return []

        target_bc = self._betweenness.get(node_id, 0)
        target_pr = self._pagerank.get(node_id, 0)
        target_fv = self._fiedler.get(node_id, 0)
        target_in = self.simple_graph.in_degree(node_id)
        target_out = self.simple_graph.out_degree(node_id)

        similarities = []
        for other in self.simple_graph.nodes():
            if other == node_id:
                continue
            bc = self._betweenness.get(other, 0)
            pr = self._pagerank.get(other, 0)
            fv = self._fiedler.get(other, 0)
            in_d = self.simple_graph.in_degree(other)
            out_d = self.simple_graph.out_degree(other)

            # Euclidean distance in metric space (normalized)
            dist = np.sqrt(
                (bc - target_bc) ** 2 * 1000 +
                (pr - target_pr) ** 2 * 10000 +
                (fv - target_fv) ** 2 +
                ((in_d - target_in) / (target_in + 1)) ** 2 +
                ((out_d - target_out) / (target_out + 1)) ** 2
            )
            similarities.append((other, dist))

        similarities.sort(key=lambda x: x[1])
        return [n for n, _ in similarities[:top_k]]

    def save_candidates(self, path: str) -> None:
        """Save candidate list to JSON."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        data = [asdict(c) for c in self.candidates]
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Saved {len(self.candidates)} candidates to {path}")

    def save_subsystem_reports(self, base_dir: str) -> None:
        """
        Save per-subsystem candidate reports and a consolidated analysis summary.

        Output layout::

            {base_dir}/
              analysis_summary.json          — top-50 ranked + per-subsystem counts
              subsystems/
                net__netfilter__candidates.json
                mm__candidates.json
                ...
        """
        subsys_dir = os.path.join(base_dir, "subsystems")
        os.makedirs(subsys_dir, exist_ok=True)

        # Group candidates by subsystem
        by_subsystem: dict[str, list[CandidateFunction]] = defaultdict(list)
        for c in self.candidates:
            by_subsystem[c.subsystem].append(c)

        # Write one JSON file per subsystem (sorted by score descending)
        for subsys, cands in sorted(by_subsystem.items()):
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", subsys).strip("_")
            path = os.path.join(subsys_dir, f"{safe}_candidates.json")
            with open(path, "w") as f:
                json.dump([asdict(c) for c in cands], f, indent=2)

        # Consolidated summary
        summary: dict = {
            "total_candidates": len(self.candidates),
            "subsystems_with_candidates": len(by_subsystem),
            "top_candidates": [
                {
                    "rank": i + 1,
                    "name": c.name,
                    "file_path": c.file_path,
                    "subsystem": c.subsystem,
                    "score": round(c.vulnerability_score, 2),
                    "reasoning": c.reasoning,
                }
                for i, c in enumerate(self.candidates[:50])
            ],
            "by_subsystem": {
                subsys: {
                    "candidates": len(cands),
                    "max_score": round(
                        max(c.vulnerability_score for c in cands), 2
                    ),
                    "top_function": cands[0].name,
                }
                for subsys, cands in sorted(
                    by_subsystem.items(),
                    key=lambda kv: -max(c.vulnerability_score for c in kv[1]),
                )
            },
        }

        summary_path = os.path.join(base_dir, "analysis_summary.json")
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"[+] Per-subsystem reports → {subsys_dir}/")
        print(f"[+] Analysis summary      → {summary_path}")


def main():
    parser = argparse.ArgumentParser(description="Run graph analytics on kernel call graph")
    parser.add_argument("--input", required=True, help="Path to callgraph.json")
    parser.add_argument("--output", default="data/candidates.json", help="Output candidates JSON")
    args = parser.parse_args()

    print(f"[*] Loading graph from {args.input}...")
    kg = KernelGraph.load(args.input)
    print(f"    Loaded: {kg.num_nodes} nodes, {kg.num_edges} edges")

    analyzer = GraphAnalyzer(kg)
    candidates = analyzer.run_full_analysis()

    # Print top candidates
    print("\n" + "=" * 80)
    print("TOP VULNERABILITY CANDIDATES")
    print("=" * 80)
    for i, c in enumerate(candidates[:20]):
        print(f"\n#{i+1} [{c.vulnerability_score:.1f}] {c.name}")
        print(f"   File: {c.file_path} | Subsystem: {c.subsystem}")
        print(f"   Reason: {c.reasoning}")

    # Save
    analyzer.save_candidates(args.output)

    # Also save the enriched graph
    enriched_path = args.input.replace(".json", "_enriched.json")
    kg.save(enriched_path)
    print(f"[+] Enriched graph saved to {enriched_path}")


if __name__ == "__main__":
    main()
