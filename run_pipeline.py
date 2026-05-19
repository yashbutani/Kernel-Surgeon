#!/usr/bin/env python3
"""
KernelSurgeon: Topology-Guided Vulnerability Discovery Pipeline

Two-phase architecture:

  Phase 'map'      — Code mapping (no LLM needed)
                     Extract call graph + function pointer resolution + graph analytics
                     Saves: callgraph.json, fptr_edges.json, callgraph_enriched.json, candidates.json

  Phase 'research' — Vulnerability research (loads saved artifacts, requires ANTHROPIC_API_KEY)
                     Agentic LLM analysis → independent verification → PoC generation → reports

  Phase 'all'      — Full pipeline (default): map then research in one shot

Usage:
    # Phase 1: map the kernel (run once, no API key needed)
    python run_pipeline.py --phase map --kernel-path /path/to/linux --output-dir data/

    # Phase 2: vulnerability research (reads saved data/, needs API key)
    python run_pipeline.py --phase research --output-dir data/ --top-n 20 --workers 4

    # Full pipeline in one shot
    python run_pipeline.py --kernel-path /path/to/linux

    # Skip LLM analysis (graph only, same as --phase map)
    python run_pipeline.py --kernel-path /path/to/linux --no-agent

    # Skip verification / PoC (faster, analysis only)
    python run_pipeline.py --kernel-path /linux --no-verify
"""

import argparse
import json
import os
import queue as _queue
import sys
import threading
import time

# Root-level files live alongside the kernelsurgeon/ package.
# Add the package directory to sys.path so all imports resolve correctly.
_ROOT = os.path.dirname(os.path.abspath(__file__))
_PKG = os.path.join(_ROOT, "kernelsurgeon")
sys.path.insert(0, _PKG)
sys.path.insert(0, _ROOT)

from kernel_graph import KernelGraph
from cscope_extractor import CscopeExtractor
from llvm_ir_extractor import LLVMIRExtractor
from graph_analyzer import GraphAnalyzer, CandidateFunction
from context_assembler import ContextAssembler
from vuln_agent import VulnAgent, VulnerabilityFinding
from config import ANALYSIS_CONFIG
from map_visualizer import MappingVisualizer, detect_subsystems

# Root-level modules
from fptr_resolver import FunctionPointerResolver
from work_stealing_pool import WorkStealingPool
from verifier_agent import VerifierAgent, VerifiedFinding
from poc_generator import PoCGenerator
from report_generator import ReportGenerator, VulnerabilityReport
from rlm_sandbox import RLMSandbox, RLMSupervisor


# ============================================================================
# Layer 0: Call Graph Extraction
# ============================================================================

def run_extraction(args) -> KernelGraph:
    """
    Extract or load the kernel call graph, then run fptr resolution.

    When using cscope mode with no ``--subsystems`` flag, subsystems are
    auto-detected from the kernel tree and displayed in a live progress table.
    """
    if args.graph:
        print(f"[*] Loading existing graph from {args.graph}")
        return KernelGraph.load(args.graph)

    if args.mode == "cscope":
        # ── Auto-detect subsystems if not specified ──────────────────
        subsystems = args.subsystems
        if subsystems is None:
            subsystems = detect_subsystems(args.kernel_path)
            print(
                f"[*] Auto-detected {len(subsystems)} subsystems: "
                f"{', '.join(subsystems[:6])}"
                f"{'...' if len(subsystems) > 6 else ''}"
            )
        else:
            print(f"[*] Subsystems: {', '.join(subsystems)}")

        cache_dir = (
            None if getattr(args, "no_cache", False)
            else os.path.join(args.output_dir, "cache")
        )
        extractor = CscopeExtractor(
            kernel_path=args.kernel_path,
            subsystems=subsystems,
            cache_dir=cache_dir,
        )

        if args.no_visualizer:
            graph = extractor.extract(max_functions=args.max_functions)
        else:
            visualizer = MappingVisualizer(
                kernel_path=args.kernel_path,
                subsystems=subsystems,
            )
            with visualizer:
                graph = extractor.extract(
                    max_functions=args.max_functions,
                    visualizer=visualizer,
                )
            visualizer.print_summary()
            vis_report = os.path.join(args.output_dir, "map_report.json")
            visualizer.save_report(vis_report)

    elif args.mode == "llvm":
        if not args.ir_dir:
            print("[!] LLVM mode requires --ir-dir pointing to a directory of .ll files")
            print("    Build with: make CC=clang LLVM=1 KCFLAGS='-save-temps=obj'")
            sys.exit(1)
        llvm_cache_dir = (
            None if getattr(args, "no_cache", False)
            else os.path.join(args.output_dir, "cache")
        )
        extractor = LLVMIRExtractor(
            ir_dir=args.ir_dir,
            kernel_path=args.kernel_path,
            cache_dir=llvm_cache_dir,
        )
        graph = extractor.extract()

    else:
        print(f"[!] Unknown extraction mode: {args.mode}")
        sys.exit(1)

    graph_path = os.path.join(args.output_dir, "callgraph.json")
    graph.save(graph_path)
    print(f"[+] Graph saved to {graph_path}")

    # Function pointer resolution pass
    if not args.no_fptr:
        print("\n[*] Running function pointer resolution...")
        fptr_resolver = FunctionPointerResolver(
            kernel_path=args.kernel_path,
            subsystems=args.subsystems,
        )
        fptr_resolver.run(discover_new=True)
        added = fptr_resolver.integrate_into_graph(graph)
        print(f"    Added {added} indirect call edges via function pointer resolution")

        fptr_path = os.path.join(args.output_dir, "fptr_edges.json")
        fptr_resolver.save_edges(fptr_path)

        # Re-save graph with fptr edges included
        graph.save(graph_path)

    return graph


# ============================================================================
# Layer 1: Graph Analytics
# ============================================================================

def run_analysis(graph: KernelGraph, args) -> list[CandidateFunction]:
    """Run graph analytics and return ranked candidates."""
    metrics_dir = (
        None if getattr(args, "no_cache", False)
        else os.path.join(args.output_dir, "cache")
    )
    analyzer = GraphAnalyzer(graph, metrics_dir=metrics_dir)
    candidates = analyzer.run_full_analysis()

    candidates_path = os.path.join(args.output_dir, "candidates.json")
    analyzer.save_candidates(candidates_path)

    # Per-subsystem candidate reports + consolidated summary
    analyzer.save_subsystem_reports(args.output_dir)

    enriched_path = os.path.join(args.output_dir, "callgraph_enriched.json")
    graph.save(enriched_path)

    return candidates


# ============================================================================
# Phase 'research': load artifacts saved by Phase 'map'
# ============================================================================

def load_artifacts(args) -> tuple[KernelGraph, list[CandidateFunction]]:
    """
    Load the call graph and candidate list written by a previous --phase map run.

    Prefers callgraph_enriched.json (graph + fptr edges + analytics annotations)
    and falls back to callgraph.json if the enriched version is absent.
    """
    enriched_path = os.path.join(args.output_dir, "callgraph_enriched.json")
    plain_path    = os.path.join(args.output_dir, "callgraph.json")

    if os.path.exists(enriched_path):
        graph_path = enriched_path
    elif os.path.exists(plain_path):
        graph_path = plain_path
    else:
        print(f"[!] No call graph found in {args.output_dir}/")
        print("    Run '--phase map' first to build the graph.")
        sys.exit(1)

    print(f"[*] Loading graph from {graph_path}")
    graph = KernelGraph.load(graph_path)

    cands_path = os.path.join(args.output_dir, "candidates.json")
    if not os.path.exists(cands_path):
        print(f"[!] No candidates.json found in {args.output_dir}/")
        print("    Run '--phase map' first to generate candidates.")
        sys.exit(1)

    with open(cands_path) as f:
        data = json.load(f)
    candidates = [CandidateFunction(**d) for d in data]
    candidates.sort(key=lambda c: c.vulnerability_score, reverse=True)

    summary = graph.summary()
    print(f"[+] Loaded graph: {summary['nodes']} nodes, {summary['edges']} edges")
    print(f"[+] Loaded {len(candidates)} candidates")
    return graph, candidates


# ============================================================================
# Layers 2+3: Agentic LLM Analysis (work-stealing parallel)
# ============================================================================

def run_agent(
    graph: KernelGraph,
    candidates: list[CandidateFunction],
    args,
    supervisor: "RLMSupervisor | None" = None,
) -> tuple[list[VulnerabilityFinding], dict]:
    """
    Run the vulnerability agent on top-N candidates using a work-stealing pool.

    Returns (findings, context_pkg_map) where context_pkg_map maps
    candidate_name -> ContextPackage for downstream stages.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[!] ANTHROPIC_API_KEY not set. Skipping agent analysis.")
        print("    Set it with: export ANTHROPIC_API_KEY='your-key-here'")
        return [], {}

    analyzer = GraphAnalyzer(graph)
    agent = VulnAgent(
        kernel_graph=graph,
        kernel_path=args.kernel_path,
        analyzer=analyzer,
        model=args.model,
        max_iterations=args.max_iter,
        supervisor=supervisor,
    )

    top_candidates = candidates[: args.top_n]

    # Pre-assemble context packages so we can pass them to the verifier
    # later without re-reading source files.
    assembler = agent.assembler
    context_pkgs = {}
    print("[*] Assembling context packages...")
    for c in top_candidates:
        context_pkgs[c.name] = assembler.assemble(c)

    print(f"\n[*] Analysing {len(top_candidates)} candidates "
          f"with {args.workers} worker(s), rate limit {args.rate_limit} RPS...")

    pool = WorkStealingPool(
        n_workers=args.workers,
        tasks=top_candidates,
        rate_limit_rps=args.rate_limit,
    )
    findings: list[VulnerabilityFinding] = pool.run(agent.analyze_candidate)

    # Summary
    vulnerable = [f for f in findings if f.is_vulnerable]
    high_conf = [f for f in vulnerable if f.confidence == "HIGH"]
    print(f"\n  Candidates analysed  : {len(findings)}")
    print(f"  Potentially vulnerable: {len(vulnerable)}")
    print(f"  High confidence      : {len(high_conf)}")
    print(f"  Total API calls      : {agent.state.total_api_calls}")

    # Supervisor execution summary
    if supervisor is not None:
        sv_stats = supervisor.all_stats()
        if sv_stats:
            total_scripts = sum(s["scripts_used"] for s in sv_stats)
            total_timeouts = sum(s["timeouts"] for s in sv_stats)
            print(f"  Sandbox scripts run  : {total_scripts} "
                  f"({total_timeouts} timeout{'s' if total_timeouts != 1 else ''})")
            for s in sv_stats:
                if s["timeouts"] or s["scripts_used"] >= supervisor.max_scripts_per_candidate:
                    print(f"    {s['candidate']}: {s['scripts_used']} scripts, "
                          f"{s['timeouts']} timeouts")

    # Save raw findings
    findings_path = os.path.join(args.output_dir, "findings.json")
    agent.save_findings(findings_path)
    agent.save_generated_queries(
        findings_path.replace(".json", "_queries.json")
    )

    return findings, context_pkgs


# ============================================================================
# Layers 4-6: Verify -> PoC -> Report
# ============================================================================

def run_post_analysis(
    findings: list[VulnerabilityFinding],
    context_pkgs: dict,
    args,
    supervisor: "RLMSupervisor | None" = None,
) -> tuple[list[VulnerabilityReport], str]:
    """
    For each finding:
      Layer 4 — Independent verification (VerifierAgent)
      Layer 5 — PoC generation if confirmed (PoCGenerator)
      Layer 6 — Report writing (ReportGenerator, severity-categorised)

    Returns (reports, reports_dir) — all VulnerabilityReport objects
    (including rejected ones) and the timestamped output directory.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[!] No API key — skipping verification and PoC generation.")
        return [], ""

    # Timestamped reports directory so each run is preserved
    run_ts = time.strftime("%Y%m%d_%H%M%S")
    reports_dir = os.path.join(args.output_dir, "reports", f"run_{run_ts}")
    verifier = VerifierAgent(model=args.model)
    poc_gen = PoCGenerator(model=args.model)
    report_gen = ReportGenerator(output_dir=reports_dir)

    all_reports: list[VulnerabilityReport] = []

    # Only send findings the primary agent flagged as vulnerable to
    # the verifier.  Findings with is_vulnerable=False are documented
    # but skip the expensive verification + PoC pipeline.
    positive_findings = [f for f in findings if f.is_vulnerable]
    negative_findings = [f for f in findings if not f.is_vulnerable]

    if positive_findings:
        print(f"\n[*] {len(positive_findings)} positive findings → verifier")
    if negative_findings:
        print(f"    {len(negative_findings)} negative findings → report only (skipping verifier)")

    for finding in positive_findings:
        pkg = context_pkgs.get(finding.candidate_name)
        if pkg is None:
            print(f"  [skip] No context package for {finding.candidate_name}")
            continue

        print(f"\n--- Post-analysis: {finding.candidate_name} ---")

        # Layer 4: Verify
        verified = verifier.verify(finding, pkg)
        time.sleep(1)   # rate-limit between verifier calls

        # Layer 5: PoC (confirmed findings only)
        poc = None
        if verified.is_confirmed:
            poc = poc_gen.generate(verified, pkg, supervisor=supervisor)
            time.sleep(1)

        # Layer 6: Report
        report = report_gen.generate(verified, poc, pkg, finding)
        report_gen.save(report)
        all_reports.append(report)

    # Document negative findings without verification overhead.
    # Create a stub VerifiedFinding so the report generator works unchanged.
    for finding in negative_findings:
        pkg = context_pkgs.get(finding.candidate_name)
        if pkg is None:
            continue
        stub_verified = VerifiedFinding(
            candidate_name=finding.candidate_name,
            candidate_file=finding.candidate_file,
            candidate_subsystem=finding.candidate_subsystem,
            is_confirmed=False,
            false_positive_reason="Primary agent did not flag as vulnerable",
            severity="INFORMATIONAL",
            cvss_score=0.0,
            cwe_id="unknown",
            attack_vector="LOCAL",
            attack_complexity="HIGH",
            privileges_required="HIGH",
            user_interaction="NONE",
            exploitability="LOW",
            impact="",
            verification_notes="Skipped verification (primary agent: not vulnerable)",
            verifier_confidence="LOW",
            remediation="",
        )
        report = report_gen.generate(stub_verified, None, pkg, finding)
        report_gen.save(report)
        all_reports.append(report)

    # Write the consolidated index
    report_gen.generate_index(all_reports)
    return all_reports, reports_dir


# ============================================================================
# Streaming pipeline: Layers 2-6 concurrently
# ============================================================================

def run_streaming_pipeline(
    graph: KernelGraph,
    candidates: list[CandidateFunction],
    args,
    supervisor: "RLMSupervisor | None" = None,
) -> tuple[list[VulnerabilityFinding], dict, list[VulnerabilityReport], str]:
    """
    Streaming Layers 2-6: as each candidate is analysed, positive findings
    are immediately forwarded to the verifier → PoC → report pipeline via a
    background consumer thread.  This overlaps analysis of later candidates
    with verification of earlier ones instead of waiting for all N candidates
    to finish before post-processing begins.

    Returns (all_findings, context_pkgs, all_reports, reports_dir).
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[!] No API key — skipping agent analysis.")
        return [], {}, [], ""

    run_ts = time.strftime("%Y%m%d_%H%M%S")
    reports_dir = os.path.join(args.output_dir, "reports", f"run_{run_ts}")

    analyzer = GraphAnalyzer(graph)
    agent = VulnAgent(
        kernel_graph=graph,
        kernel_path=args.kernel_path,
        analyzer=analyzer,
        model=args.model,
        max_iterations=args.max_iter,
        supervisor=supervisor,
    )
    verifier = VerifierAgent(model=args.model)
    poc_gen   = PoCGenerator(model=args.model)
    report_gen = ReportGenerator(output_dir=reports_dir)

    top_candidates = candidates[: args.top_n]

    # Pre-assemble context packages
    assembler = agent.assembler
    context_pkgs: dict = {}
    print("[*] Assembling context packages...")
    for c in top_candidates:
        context_pkgs[c.name] = assembler.assemble(c)

    # Shared state (all_findings written by pool workers; all_reports by consumer)
    all_findings: list[VulnerabilityFinding] = []
    all_reports:  list[VulnerabilityReport]  = []
    findings_lock = threading.Lock()
    _DONE = object()   # sentinel

    # Queue of (VulnerabilityFinding, ContextPackage) tuples for the consumer
    work_q: _queue.Queue = _queue.Queue()

    def on_finding(finding: VulnerabilityFinding) -> None:
        """Called by each pool worker immediately when a result is ready."""
        with findings_lock:
            all_findings.append(finding)
        if finding.is_vulnerable:
            pkg = context_pkgs.get(finding.candidate_name)
            if pkg:
                work_q.put((finding, pkg))

    def consumer() -> None:
        """
        Single background thread: verify → PoC → report as findings arrive.
        Runs concurrently with the WorkStealingPool producers.
        """
        while True:
            item = work_q.get()
            if item is _DONE:
                break
            finding, pkg = item

            print(f"\n--- Post-analysis: {finding.candidate_name} ---")

            # Layer 4: Verify
            verified = verifier.verify(finding, pkg)
            time.sleep(1)

            # Layer 5: PoC (confirmed only)
            poc = None
            if verified.is_confirmed:
                poc = poc_gen.generate(verified, pkg, supervisor=supervisor)
                time.sleep(1)

            # Layer 6: Report
            report = report_gen.generate(verified, poc, pkg, finding)
            report_gen.save(report)
            all_reports.append(report)

    # Start consumer before producers so it's ready immediately
    consumer_thread = threading.Thread(target=consumer, daemon=True, name="post-analysis")
    consumer_thread.start()

    print(f"\n[*] Streaming pipeline: {len(top_candidates)} candidates "
          f"with {args.workers} worker(s) — verify+PoC starts as findings arrive")

    pool = WorkStealingPool(
        n_workers=args.workers,
        tasks=top_candidates,
        rate_limit_rps=args.rate_limit,
    )
    pool.run(agent.analyze_candidate, result_callback=on_finding)

    # Drain the queue: let consumer finish any in-flight post-analysis
    work_q.put(_DONE)
    consumer_thread.join()

    # Save raw findings (same as run_agent does)
    findings_path = os.path.join(args.output_dir, "findings.json")
    agent.save_findings(findings_path)
    agent.save_generated_queries(findings_path.replace(".json", "_queries.json"))

    # Document negative findings with stub reports
    negative_findings = [f for f in all_findings if not f.is_vulnerable]
    if negative_findings:
        print(f"\n    {len(negative_findings)} negative findings → report only")
    for finding in negative_findings:
        pkg = context_pkgs.get(finding.candidate_name)
        if pkg is None:
            continue
        stub_verified = VerifiedFinding(
            candidate_name=finding.candidate_name,
            candidate_file=finding.candidate_file,
            candidate_subsystem=finding.candidate_subsystem,
            is_confirmed=False,
            false_positive_reason="Primary agent did not flag as vulnerable",
            severity="INFORMATIONAL",
            cvss_score=0.0,
            cwe_id="unknown",
            attack_vector="LOCAL",
            attack_complexity="HIGH",
            privileges_required="HIGH",
            user_interaction="NONE",
            exploitability="LOW",
            impact="",
            verification_notes="Skipped verification (primary agent: not vulnerable)",
            verifier_confidence="LOW",
            remediation="",
        )
        report = report_gen.generate(stub_verified, None, pkg, finding)
        report_gen.save(report)
        all_reports.append(report)

    report_gen.generate_index(all_reports)

    positive = [f for f in all_findings if f.is_vulnerable]
    confirmed = [r for r in all_reports if r.is_verified]
    sv_stats = agent.state.total_api_calls if hasattr(agent, "state") else "?"
    print(f"\n  Candidates analysed  : {len(all_findings)}")
    print(f"  Potentially vulnerable: {len(positive)}")
    print(f"  Confirmed vulns      : {len(confirmed)}")
    print(f"  Total API calls      : {sv_stats}")

    return all_findings, context_pkgs, all_reports, reports_dir


# ============================================================================
# Summary printer
# ============================================================================

def print_summary(graph: KernelGraph, candidates: list[CandidateFunction]) -> None:
    summary = graph.summary()

    print(f"\n{'='*60}")
    print("PIPELINE SUMMARY")
    print(f"{'='*60}")
    print(f"\nGraph:")
    print(f"  Nodes: {summary['nodes']}")
    print(f"  Edges: {summary['edges']}")
    print(f"  Cross-subsystem edges: {summary['cross_subsystem_edges']}")

    print(f"\nSubsystems:")
    for sub, count in sorted(summary["subsystems"].items(), key=lambda x: -x[1]):
        print(f"  {sub}: {count} functions")

    print(f"\nSecurity roles:")
    for role, count in sorted(summary["security_roles"].items(), key=lambda x: -x[1]):
        if count > 0:
            print(f"  {role}: {count}")

    print(f"\nCandidates flagged: {len(candidates)}")
    if candidates:
        print(f"  Top score: {candidates[0].vulnerability_score:.1f} ({candidates[0].name})")
        print(f"  On unchecked paths: "
              f"{sum(1 for c in candidates if c.unchecked_paths_from_syscall > 0)}")
        print(f"  Boundary nodes: {sum(1 for c in candidates if c.is_boundary_node)}")

        pattern_counts: dict[str, int] = {}
        for c in candidates:
            for p in c.matching_cve_patterns:
                pattern_counts[p] = pattern_counts.get(p, 0) + 1
        if pattern_counts:
            print("  CVE pattern matches:")
            for p, count in sorted(pattern_counts.items(), key=lambda x: -x[1]):
                print(f"    {p}: {count} candidates")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="KernelSurgeon: Topology-Guided Vulnerability Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Phases:
  map       Build and save the call graph + analytics (no LLM needed).
            Produces: callgraph_enriched.json, candidates.json in --output-dir.

  research  Load saved artifacts and run LLM vulnerability analysis.
            Requires ANTHROPIC_API_KEY.  --kernel-path not needed.

  all       Run both phases end-to-end (default).

Examples:
  # Map once
  python run_pipeline.py --phase map --kernel-path /linux --output-dir data/

  # Research later (or with different parameters)
  python run_pipeline.py --phase research --output-dir data/ --top-n 20

  # Full pipeline
  python run_pipeline.py --kernel-path /linux
""",
    )

    # Phase control
    parser.add_argument(
        "--phase", choices=["map", "research", "all"], default="all",
        help="Pipeline phase to run (default: all)",
    )

    # Kernel source (required for map/all, optional for research)
    parser.add_argument("--kernel-path", default=None,
                        help="Path to Linux kernel source tree "
                             "(required for --phase map/all)")

    # Extraction
    parser.add_argument("--mode", choices=["cscope", "llvm"], default="cscope",
                        help="Extraction mode (default: cscope)")
    parser.add_argument("--graph",
                        help="Skip extraction — load existing callgraph.json")
    parser.add_argument("--ir-dir",
                        help="LLVM IR directory (for llvm mode)")
    parser.add_argument("--subsystems", nargs="+",
                        help="Subsystems to analyse (e.g. net/ mm/ kernel/)")
    parser.add_argument("--max-functions", type=int, default=0,
                        help="Max functions to extract (0=all)")

    # Analysis control
    parser.add_argument("--no-agent", action="store_true",
                        help="Skip LLM agent (graph analytics only)")
    parser.add_argument("--no-cache", action="store_true",
                        help="Disable per-subsystem extraction cache (force re-extract)")
    parser.add_argument("--no-fptr", action="store_true",
                        help="Skip function pointer resolution")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip verifier, PoC generation, and report writing")
    parser.add_argument("--no-visualizer", action="store_true",
                        help="Disable live mapping progress display")
    parser.add_argument("--top-n", type=int, default=10,
                        help="Top candidates to analyse with LLM (default: 10)")
    parser.add_argument("--workers", type=int, default=4,
                        help="Work-stealing worker threads (default: 4)")
    parser.add_argument("--rate-limit", type=float, default=2.0,
                        help="Max API calls/sec across all workers (default: 2.0)")

    # Model settings
    parser.add_argument("--model", default="claude-sonnet-4-20250514",
                        help="Claude model for all agents")
    parser.add_argument("--max-iter", type=int, default=5,
                        help="Max agent iterations per candidate (default: 5)")

    # Output
    parser.add_argument("--output-dir", default="data",
                        help="Output directory (default: data)")

    args = parser.parse_args()

    # Validate: kernel-path is required when extraction runs
    if args.phase in ("map", "all") and not args.kernel_path and not args.graph:
        parser.error("--kernel-path is required for --phase map/all "
                     "(or provide --graph to skip extraction)")

    os.makedirs(args.output_dir, exist_ok=True)

    start_time = time.time()
    sandbox = None      # populated after graph is built (map or research phase)
    supervisor = None   # wraps sandbox with timeout + iteration-budget enforcement

    # ------------------------------------------------------------------
    # Phase 'map': Layers 0-1 only
    # ------------------------------------------------------------------
    if args.phase in ("map", "all"):
        print("\n" + "=" * 60)
        print("PHASE: CODE MAPPING")
        print("=" * 60)

        print("\n" + "=" * 60)
        print("LAYER 0: CALL GRAPH EXTRACTION")
        print("=" * 60)
        graph = run_extraction(args)

        print("\n" + "=" * 60)
        print("LAYER 1: GRAPH ANALYTICS")
        print("=" * 60)
        candidates = run_analysis(graph, args)
        print_summary(graph, candidates)

        # Build sandbox with the live graph loaded into its namespace
        sandbox = RLMSandbox(kernel_path=args.kernel_path, graph=graph)
        supervisor = RLMSupervisor(sandbox)
        print(f"\n[*] RLM sandbox ready — namespace: {sandbox.namespace_keys()}")
        print(f"[*] Supervisor: timeout={supervisor.script_timeout}s, "
              f"max_scripts/candidate={supervisor.max_scripts_per_candidate}")

        if args.phase == "map":
            elapsed = time.time() - start_time
            print(f"\n[+] Phase 'map' complete in {elapsed:.1f}s")
            print(f"    Artifacts in: {args.output_dir}/")
            print(f"      {args.output_dir}/callgraph_enriched.json")
            print(f"      {args.output_dir}/candidates.json")
            print(f"\n    To run vulnerability research:")
            print(f"      python run_pipeline.py --phase research --output-dir {args.output_dir}/")
            return

    # ------------------------------------------------------------------
    # Phase 'research': load artifacts from disk
    # ------------------------------------------------------------------
    if args.phase == "research":
        print("\n" + "=" * 60)
        print("PHASE: VULNERABILITY RESEARCH")
        print("=" * 60)
        graph, candidates = load_artifacts(args)

        # Build sandbox with the graph deserialized from disk
        sandbox = RLMSandbox(kernel_path=args.kernel_path, graph=graph)
        supervisor = RLMSupervisor(sandbox)
        print(f"[*] RLM sandbox ready — namespace: {sandbox.namespace_keys()}")
        print(f"[*] Supervisor: timeout={supervisor.script_timeout}s, "
              f"max_scripts/candidate={supervisor.max_scripts_per_candidate}")

    # ------------------------------------------------------------------
    # Layers 2-6: Streaming pipeline (analysis + verify + PoC + report)
    # ------------------------------------------------------------------
    findings: list[VulnerabilityFinding] = []
    context_pkgs: dict = {}
    reports: list = []
    reports_dir = ""

    if not args.no_agent and candidates:
        if args.no_verify:
            # Verification/PoC disabled — run analysis only (original sequential path)
            print("\n" + "=" * 60)
            print("LAYERS 2+3: AGENTIC VULNERABILITY ANALYSIS")
            print("=" * 60)
            findings, context_pkgs = run_agent(graph, candidates, args, supervisor=supervisor)
        else:
            # Streaming: verify+PoC fires as each finding arrives
            print("\n" + "=" * 60)
            print("LAYERS 2-6: STREAMING ANALYSIS → VERIFY → POC → REPORT")
            print("=" * 60)
            findings, context_pkgs, reports, reports_dir = run_streaming_pipeline(
                graph, candidates, args, supervisor=supervisor
            )
            confirmed = [r for r in reports if r.is_verified]
            print(f"\n  Reports written : {len(reports)}")
            print(f"  Confirmed vulns : {len(confirmed)}")
            if reports_dir:
                print(f"  Reports dir     : {reports_dir}")

    elapsed = time.time() - start_time
    print(f"\n[+] Pipeline complete in {elapsed:.1f}s")
    print(f"    Results in: {args.output_dir}/")


if __name__ == "__main__":
    main()
