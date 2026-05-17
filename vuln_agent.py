"""
Vulnerability Discovery Agent (Layer 3)

The agentic loop that:
1. Takes candidates from the graph analyzer
2. Assembles context for each via the context assembler
3. Sends to Claude for semantic vulnerability reasoning
4. Parses the model's response for:
   - Vulnerability assessments
   - Requests for additional context (functions to examine)
   - New graph query hypotheses
5. Executes follow-up queries and feeds results back
6. Produces a final vulnerability report

This is where the novel hybrid approach lives: the model both
analyzes candidates AND generates new detection heuristics.
"""

import json
import os
import sys
import argparse
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

import anthropic

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from kernel_graph import KernelGraph, SecurityRole
from graph_analyzer import GraphAnalyzer, CandidateFunction
from context_assembler import ContextAssembler, ContextPackage
from config import ANALYSIS_CONFIG


@dataclass
class VulnerabilityFinding:
    """A potential vulnerability identified by the agent."""
    candidate_name: str
    candidate_file: str
    candidate_subsystem: str
    vulnerability_score: float
    is_vulnerable: bool
    confidence: str
    vulnerability_type: str
    description: str
    attack_path: str
    check_bypass_analysis: str
    iterations: int
    raw_responses: list[str] = field(default_factory=list)


@dataclass
class AgentState:
    """Tracks the state of the agentic analysis loop."""
    current_candidate: Optional[CandidateFunction] = None
    iteration: int = 0
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    examined_functions: set = field(default_factory=set)
    generated_queries: list[dict] = field(default_factory=list)
    total_api_calls: int = 0


class VulnAgent:
    """
    Agentic vulnerability discovery system.
    
    Architecture:
    - Graph Analyzer: provides structural candidates and metric queries
    - Context Assembler: builds LLM-ready context packages
    - Claude API: semantic reasoning over enriched candidates
    - Feedback loop: model requests drive further graph/code exploration
    """

#     SYSTEM_PROMPT = """You are an expert Linux kernel vulnerability researcher. 
# You are part of a hybrid analysis system where:
# - Graph analytics has already identified structurally interesting candidate functions
# - You receive enriched context: source code, callers/callees, graph metrics, CVE patterns
# - Your job is to perform deep semantic analysis that only an expert can do

# You excel at:
# - Identifying logic bugs including buffer overflows, race conditions, use-after-free bugs
# - Reasoning about trust boundaries between kernel subsystems
# - Tracing attack paths from userspace entry points to vulnerable code
# - Recognizing when security checks can be bypassed via alternative call paths

# Be precise and technical. If you're not sure, say so. If you need more context, 
# request specific functions or graph queries — the system will fetch them for you.

# Always respond in the JSON format specified in the analysis instructions."""

    SYSTEM_PROMPT = """You are an elite Linux kernel vulnerability researcher and exploit developer. 
You are part of a hybrid analysis system where graph analytics has already flagged the provided function as highly central and probabilistically vulnerable. 

Do NOT analyze this function in isolation. Assume this function is a reachable sink in a larger state-machine sequence. Verify its reachability and trace the path to the vulnerability using line level precesion to highlight the vulnerability and the larger function it is a part of. 

You are looking for vulnerabilities in the kernel that include but are not limited to the following:
1. Cross-Function State: Complex logic bugs (like UAFs, Race Conditions etc) span multiple functions. If this function frees, uses, or allocates a struct, tell me exactly what state the *caller* or *concurrent threads* must be in to trigger a Use-After-Free (UAF), Double-Free, or Out-Of-Bounds (OOB) access.
2. Pointer & Memory Layout: You cannot verify safety without struct layouts. If you see structs (e.g., netfilter rules, routing tables) being accessed, and you don't have the memory layout, you MUST factor that blind spot into your analysis and request the struct definition.
3. Bypass Logic: Do not mark this as safe just because local bounds checks look correct. Identify how a malicious userspace caller could bypass these checks by manipulating input lengths, namespaces, or race windows before the execution reaches this function. Also consider incorrect bounds checking, off by one errors and validate A-Use-B patterns. 
4. Actionable Context Requests: If you need the definition of a struct, a macro, or the source code of a specific caller/callee to definitively prove exploitability, explicitly request it in your output.
5. Identify protential cryptographic vulnerabilities, weak authentication schemes, hardcoded credentials
6. If you find something that is not vulnerable itself, mark that as an exploit primitive. 

Be precise, highly technical, and ruthless in your assumptions of caller input. Always respond in the JSON format specified in the analysis instructions."""


    def __init__(
        self,
        kernel_graph: KernelGraph,
        kernel_path: str,
        analyzer: GraphAnalyzer,
        model: str = "claude-sonnet-4-20250514",
        max_iterations: int = 5,
        supervisor=None,
    ):
        self.kg = kernel_graph
        self.kernel_path = kernel_path
        self.analyzer = analyzer
        self.assembler = ContextAssembler(kernel_graph, kernel_path)
        self.model = model
        self.max_iterations = max_iterations
        self.state = AgentState()
        self.supervisor = supervisor  # RLMSupervisor instance (or None)

        # Initialize Anthropic client
        self.client = anthropic.Anthropic()

    def _call_llm(self, prompt: str, context_pkg: "ContextPackage | None" = None) -> str:
        """Call Claude API with prompt caching applied where possible.

        Caching strategy:
        - System prompt: cached (identical across all candidate analyses)
        - static_prefix from context_pkg: cached (analysis instructions + CVE taxonomy)
        - candidate_body / follow-up text: NOT cached (unique per candidate/iteration)
        """
        self.state.total_api_calls += 1

        # Build cached system message
        system = [{"type": "text", "text": self.SYSTEM_PROMPT,
                   "cache_control": {"type": "ephemeral"}}]

        # Build user content blocks
        if context_pkg is not None and context_pkg.static_prefix:
            user_content = [
                # Static analysis instructions + CVE taxonomy → cacheable
                {"type": "text", "text": context_pkg.static_prefix,
                 "cache_control": {"type": "ephemeral"}},
                # Candidate-specific data → not cached
                {"type": "text", "text": context_pkg.candidate_body or prompt},
            ]
        else:
            # Follow-up iterations or missing context_pkg — single non-cached block
            user_content = [{"type": "text", "text": prompt}]

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system,
                messages=[{"role": "user", "content": user_content}],
            )
            # Log cache performance when available
            usage = getattr(response, "usage", None)
            if usage and getattr(usage, "cache_read_input_tokens", 0):
                print(f"    [cache] read={usage.cache_read_input_tokens} "
                      f"created={getattr(usage, 'cache_creation_input_tokens', 0)}")
            return response.content[0].text
        except anthropic.APIError as e:
            print(f"    API error: {e}")
            return json.dumps({
                "is_vulnerable": False,
                "confidence": "LOW",
                "vulnerability_type": "error",
                "description": f"API error: {str(e)}",
                "attack_path": "",
                "check_bypass_analysis": "",
                "next_steps": {"examine_functions": [], "graph_queries": [], "pattern_searches": []}
            })

    @staticmethod
    def _normalize_parsed(d: dict) -> dict:
        """Unwrap nested response formats and normalize key names.

        LLMs sometimes wrap results in ``{"answer": {...}}``,
        ``{"findings": {...}}``, or ``{"result": {...}}``.  They also
        use ``"vulnerable"`` instead of ``"is_vulnerable"``.  This method
        flattens such variations into the canonical schema.
        """
        # Unwrap known nesting patterns
        for wrapper_key in ("answer", "findings", "result"):
            if wrapper_key in d and isinstance(d[wrapper_key], dict):
                inner = d[wrapper_key]
                # Merge inner keys into top level (inner wins on conflict)
                merged = {k: v for k, v in d.items() if k != wrapper_key}
                merged.update(inner)
                d = merged
                break  # only unwrap one level

        # Normalize key name: "vulnerable" → "is_vulnerable"
        if "vulnerable" in d and "is_vulnerable" not in d:
            d["is_vulnerable"] = d.pop("vulnerable")

        return d

    def _parse_llm_response(self, response: str) -> dict:
        """Parse JSON response from LLM, handling markdown code blocks."""
        # Strip markdown code blocks if present
        if "```json" in response:
            start = response.index("```json") + 7
            end = response.find("```", start)
            response = response[start:end] if end != -1 else response[start:]
        elif "```" in response:
            start = response.index("```") + 3
            end = response.find("```", start)
            response = response[start:end] if end != -1 else response[start:]

        try:
            parsed = json.loads(response.strip())
            return self._normalize_parsed(parsed)
        except json.JSONDecodeError:
            # Try to extract JSON from mixed text
            import re
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                try:
                    parsed = json.loads(json_match.group())
                    return self._normalize_parsed(parsed)
                except json.JSONDecodeError:
                    pass
            return {
                "is_vulnerable": False,
                "confidence": "LOW",
                "vulnerability_type": "parse_error",
                "description": response[:500],
                "attack_path": "",
                "check_bypass_analysis": "",
                "next_steps": {"examine_functions": [], "graph_queries": [], "pattern_searches": []}
            }

    def _handle_next_steps(self, next_steps: dict, candidate: CandidateFunction) -> str:
        """
        Process the model's follow-up requests and build additional context.
        
        This is the feedback loop: the model tells us what it needs,
        we fetch it from the graph/source, and send it back.
        """
        follow_up_context = ""

        # 1. Examine additional functions
        functions_to_examine = next_steps.get("examine_functions", [])
        for func_name in functions_to_examine[:5]:  # Limit to prevent runaway
            if func_name in self.state.examined_functions:
                continue
            self.state.examined_functions.add(func_name)

            node_ids = self.kg.lookup_function(func_name)
            if not node_ids:
                follow_up_context += f"\n### {func_name}\nNot found in call graph.\n"
                continue

            for node_id in node_ids[:2]:
                data = self.kg.get_node(node_id)
                if not data:
                    continue
                source = self.assembler._extract_function_source(
                    data.get("file_path", ""), func_name, data.get("line_start", 0)
                )
                role = data.get("security_role", "none")
                sub = data.get("subsystem", "unknown")

                # Get its callers too
                callers = list(self.kg.graph.predecessors(node_id))[:10]
                caller_names = []
                for c in callers:
                    cdata = self.kg.get_node(c)
                    if cdata:
                        caller_names.append(f"{cdata['name']} ({cdata.get('subsystem', '?')})")

                follow_up_context += f"""
### {func_name} ({data.get('file_path', '?')}, {sub}, role: {role})
Callers: {', '.join(caller_names[:5]) if caller_names else 'none found'}
```c
{source}
```
"""

        # 2. Execute sandbox scripts via the supervisor (timeout + budget enforced)
        graph_scripts = next_steps.get("graph_scripts", [])
        for script in graph_scripts[:3]:
            self.state.generated_queries.append({
                "from_candidate": candidate.name,
                "type": "sandbox_script",
                "script": script,
                "iteration": self.state.iteration,
            })
            if self.supervisor is not None:
                result = self.supervisor.run_supervised(script, candidate.name)
                budget = self.supervisor.max_scripts_per_candidate
                print(
                    f"    [supervisor] {result.status} in {result.elapsed:.1f}s "
                    f"({result.iteration}/{budget} scripts for {candidate.name})"
                )
                follow_up_context += "\n" + result.to_llm_context(budget)
                if result.status == "max_depth_reached":
                    # Budget exhausted — stop sending scripts for this candidate
                    break
            else:
                follow_up_context += (
                    f"\n### Graph Script (no supervisor attached)\n"
                    f"```python\n{script}\n```\n"
                )

        # 3. Execute natural-language graph queries (fallback pattern matcher)
        graph_queries = next_steps.get("graph_queries", [])
        for query_desc in graph_queries[:3]:
            self.state.generated_queries.append({
                "from_candidate": candidate.name,
                "type": "nl_query",
                "description": query_desc,
                "iteration": self.state.iteration,
            })

            # Try to interpret and execute common query patterns
            query_result = self._execute_model_query(query_desc, candidate)
            if query_result:
                follow_up_context += f"\n### Graph Query: {query_desc}\n{query_result}\n"

        return follow_up_context

    def _execute_model_query(self, query_desc: str, candidate: CandidateFunction) -> str:
        """
        Attempt to interpret and execute a natural language graph query.
        
        This is intentionally limited — it handles common patterns.
        Complex queries get logged for manual investigation.
        """
        query_lower = query_desc.lower()
        result_lines = []

        # Pattern: "find all callers that don't hold lock X"
        if "caller" in query_lower and ("lock" in query_lower or "check" in query_lower):
            callers = self.kg.get_callers(candidate.node_id, hops=1)
            for caller_id in callers:
                cdata = self.kg.get_node(caller_id)
                if not cdata:
                    continue
                callees = set(self.kg.graph.successors(caller_id))
                callee_names = set()
                for c in callees:
                    cd = self.kg.get_node(c)
                    if cd:
                        callee_names.add(cd.get("name", ""))

                # Check if caller calls any lock functions
                from config import LOCK_FUNCTIONS
                holds_lock = bool(set(LOCK_FUNCTIONS) & callee_names)
                result_lines.append(
                    f"  {cdata['name']} ({cdata.get('subsystem', '?')}): "
                    f"{'holds lock' if holds_lock else 'NO LOCK'}"
                )

        # Pattern: "find paths from X to Y"
        elif "path" in query_lower:
            # Log it — too complex for automated execution
            result_lines.append(f"Complex path query logged for manual investigation.")

        # Pattern: "find similar functions" / "other functions with same pattern"
        elif "similar" in query_lower or "other" in query_lower or "same pattern" in query_lower:
            similar = self.analyzer.find_similar_nodes(candidate.node_id, top_k=5)
            for node_id in similar:
                data = self.kg.get_node(node_id)
                if data:
                    result_lines.append(
                        f"  {data['name']} ({data.get('file_path', '?')}, "
                        f"{data.get('subsystem', '?')}) - "
                        f"bc={data.get('betweenness', 0):.4f}"
                    )

        # Pattern: "check if X is reachable from userspace"
        elif "reachable" in query_lower and ("user" in query_lower or "syscall" in query_lower):
            syscalls = self.kg.get_syscall_nodes()
            simple = self.kg.to_simple_graph()
            reachable_from = []
            for sc in syscalls:
                try:
                    if candidate.node_id in simple and sc in simple:
                        if nx.has_path(simple, sc, candidate.node_id):
                            scdata = self.kg.get_node(sc)
                            if scdata:
                                reachable_from.append(scdata.get("name", sc))
                except Exception:
                    continue
            result_lines.append(f"Reachable from {len(reachable_from)} syscalls: "
                              f"{', '.join(reachable_from[:10])}")

        if result_lines:
            return "\n".join(result_lines)
        return f"Query type not automatically executable. Logged for manual review."

    def analyze_candidate(self, candidate: CandidateFunction) -> VulnerabilityFinding:
        """
        Run the full agentic analysis loop on a single candidate.

        Architecture (while True loop):
        1. Assemble initial context and send to LLM.
        2. LLM returns a JSON response with its assessment and
           optional ``graph_scripts`` / ``examine_functions`` / ``graph_queries``
           requesting further exploration.
        3. Execute sandbox scripts via the supervisor (timeout + budget enforced).
        4. Feed results back to the LLM as a follow-up prompt.
        5. Repeat until:
           - The LLM declares the candidate analyzed (no follow-ups).
           - ``max_iterations`` is reached.
           - The RLMSupervisor triggers a hard stop (``max_depth_reached``).
        """
        self.state.current_candidate = candidate
        self.state.iteration = 0
        self.state.examined_functions = {candidate.name}

        # Reset per-candidate script budget in the supervisor
        if self.supervisor is not None:
            self.supervisor.begin_candidate(candidate.name)

        print(f"\n{'='*60}")
        print(f"Analyzing: {candidate.name} (score: {candidate.vulnerability_score:.1f})")
        print(f"File: {candidate.file_path} | Subsystem: {candidate.subsystem}")
        print(f"{'='*60}")

        # Step 1: Assemble initial context
        context_pkg = self.assembler.assemble(candidate)
        current_prompt = context_pkg.prompt
        all_responses = []
        parsed = {}
        best_parsed = {}          # best is_vulnerable=true response across iterations
        supervisor_hard_stop = False

        # Confidence ranking for best-iteration selection
        _CONF_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

        # Step 2-5: while True execution loop
        while True:
            self.state.iteration += 1
            iteration = self.state.iteration
            print(f"\n  Iteration {iteration}/{self.max_iterations}...")

            # Pass context_pkg on first iteration so caching applies to static prefix;
            # follow-up iterations use plain prompt (candidate-specific continuation)
            response_text = self._call_llm(
                current_prompt,
                context_pkg=context_pkg if iteration == 1 else None,
            )
            all_responses.append(response_text)
            parsed = self._parse_llm_response(response_text)

            print(f"  Verdict: vulnerable={parsed.get('is_vulnerable', '?')}, "
                  f"confidence={parsed.get('confidence', '?')}, "
                  f"type={parsed.get('vulnerability_type', '?')}")

            # Track best positive finding across iterations.
            # If the LLM says is_vulnerable=true with higher confidence than
            # what we've seen before, keep it — don't let a later iteration
            # with a broken format overwrite a good result.
            if parsed.get("is_vulnerable"):
                cur_rank = _CONF_RANK.get(str(parsed.get("confidence", "")).upper(), 0)
                best_rank = _CONF_RANK.get(str(best_parsed.get("confidence", "")).upper(), 0)
                if not best_parsed or cur_rank >= best_rank:
                    best_parsed = dict(parsed)

            # ── Check termination conditions ─────────────────────────
            next_steps = parsed.get("next_steps", {})
            has_scripts = bool(next_steps.get("graph_scripts", []))
            has_functions = bool(next_steps.get("examine_functions", []))
            has_queries = bool(next_steps.get("graph_queries", []))
            has_follow_ups = has_scripts or has_functions or has_queries

            if not has_follow_ups:
                # LLM has converged — no more exploration requested
                print(f"  Converged: no follow-up requests.")
                break

            if iteration >= self.max_iterations:
                # Exhausted iteration budget
                print(f"  Max iterations reached ({self.max_iterations}).")
                break

            # ── Execute follow-ups ───────────────────────────────────
            print(f"  Model requested additional context...")
            additional_context = self._handle_next_steps(next_steps, candidate)

            # Check if the supervisor forced a hard stop during script execution
            if self.supervisor is not None:
                sv_stats = self.supervisor.stats(candidate.name)
                if sv_stats["scripts_remaining"] <= 0:
                    supervisor_hard_stop = True
                    print(f"  Supervisor hard stop — script budget exhausted.")
                    break

            if not additional_context.strip():
                # No useful context was gathered — stop to avoid spinning
                print(f"  No additional context returned — stopping.")
                break

            # Build follow-up prompt with exploration results
            current_prompt = f"""## Follow-up Analysis (iteration {iteration + 1})

Based on your previous analysis of `{candidate.name}`, here are the results
of the exploration scripts and queries you requested:

{additional_context}

### Previous Assessment
- Vulnerable: {parsed.get('is_vulnerable', '?')}
- Confidence: {parsed.get('confidence', '?')}
- Type: {parsed.get('vulnerability_type', '?')}
- Description: {parsed.get('description', '')}

### Instructions
Analyze the new information above.
- If you have found the vulnerability, provide your final assessment with
  high confidence.  Set `next_steps.graph_scripts` to `[]`.
- If you need more information, write your next exploration script in
  `next_steps.graph_scripts`.  Use bounded algorithms only.
- If you cannot determine the vulnerability from the data so far,
  lower your confidence and provide your best assessment.

Respond in the same JSON format as before."""

        # Use best positive finding if available; fall back to last response
        final = best_parsed if best_parsed else parsed
        if best_parsed and not parsed.get("is_vulnerable"):
            print(f"  Using best-iteration result (last iteration lost the finding)")

        # Build final finding
        finding = VulnerabilityFinding(
            candidate_name=candidate.name,
            candidate_file=candidate.file_path,
            candidate_subsystem=candidate.subsystem,
            vulnerability_score=candidate.vulnerability_score,
            is_vulnerable=final.get("is_vulnerable", False),
            confidence=final.get("confidence", "LOW"),
            vulnerability_type=final.get("vulnerability_type", "unknown"),
            description=final.get("description", ""),
            attack_path=final.get("attack_path", ""),
            check_bypass_analysis=final.get("check_bypass_analysis", ""),
            iterations=self.state.iteration,
            raw_responses=all_responses,
        )
        self.state.findings.append(finding)
        return finding

    def run(self, candidates: list[CandidateFunction], top_n: int = 10) -> list[VulnerabilityFinding]:
        """Run the agent on the top N candidates."""
        print(f"\n[*] Starting agentic vulnerability analysis")
        print(f"    Candidates: {len(candidates)}, analyzing top {top_n}")
        print(f"    Model: {self.model}")
        print(f"    Max iterations per candidate: {self.max_iterations}")

        findings = []
        for i, candidate in enumerate(candidates[:top_n]):
            print(f"\n[{i+1}/{top_n}]", end="")
            finding = self.analyze_candidate(candidate)
            findings.append(finding)

            # Rate limiting
            time.sleep(1)

        # Summary
        vulnerable = [f for f in findings if f.is_vulnerable]
        high_conf = [f for f in vulnerable if f.confidence == "HIGH"]

        print(f"\n{'='*60}")
        print(f"ANALYSIS COMPLETE")
        print(f"{'='*60}")
        print(f"Candidates analyzed: {len(findings)}")
        print(f"Potentially vulnerable: {len(vulnerable)}")
        print(f"High confidence: {len(high_conf)}")
        print(f"Total API calls: {self.state.total_api_calls}")
        print(f"Model-generated queries: {len(self.state.generated_queries)}")

        return findings

    def save_findings(self, path: str) -> None:
        """Save all findings to JSON."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        data = {
            "findings": [asdict(f) for f in self.state.findings],
            "generated_queries": self.state.generated_queries,
            "stats": {
                "total_candidates": len(self.state.findings),
                "vulnerable": sum(1 for f in self.state.findings if f.is_vulnerable),
                "high_confidence": sum(1 for f in self.state.findings
                                      if f.is_vulnerable and f.confidence == "HIGH"),
                "api_calls": self.state.total_api_calls,
            }
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Findings saved to {path}")

    def save_generated_queries(self, path: str) -> None:
        """
        Save model-generated graph queries for manual review.
        These are hypotheses the model came up with — potentially novel detection heuristics.
        """
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.state.generated_queries, f, indent=2)
        print(f"[+] Generated queries saved to {path}")


def main():
    parser = argparse.ArgumentParser(description="Run agentic vulnerability analysis")
    parser.add_argument("--graph", required=True, help="Path to callgraph.json")
    parser.add_argument("--candidates", required=True, help="Path to candidates.json")
    parser.add_argument("--kernel-path", required=True, help="Path to kernel source")
    parser.add_argument("--output", default="data/findings.json", help="Output findings")
    parser.add_argument("--top-n", type=int, default=10, help="Number of candidates to analyze")
    parser.add_argument("--model", default="claude-sonnet-4-20250514", help="Claude model to use")
    parser.add_argument("--max-iter", type=int, default=5, help="Max iterations per candidate")
    args = parser.parse_args()

    # Load graph
    print(f"[*] Loading graph from {args.graph}...")
    kg = KernelGraph.load(args.graph)

    # Load candidates
    print(f"[*] Loading candidates from {args.candidates}...")
    with open(args.candidates) as f:
        candidate_data = json.load(f)
    candidates = [CandidateFunction(**c) for c in candidate_data]
    print(f"    {len(candidates)} candidates loaded")

    # Initialize analyzer (for follow-up queries)
    analyzer = GraphAnalyzer(kg)

    # Run agent
    agent = VulnAgent(
        kernel_graph=kg,
        kernel_path=args.kernel_path,
        analyzer=analyzer,
        model=args.model,
        max_iterations=args.max_iter,
    )
    findings = agent.run(candidates, top_n=args.top_n)

    # Save results
    agent.save_findings(args.output)
    agent.save_generated_queries(args.output.replace(".json", "_queries.json"))


if __name__ == "__main__":
    main()
