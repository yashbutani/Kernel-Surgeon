"""
regenerate_poc.py

Re-runs only the PoC generator against an existing report JSON.  Avoids the
full extraction/analysis/verification pipeline.  Cost: one Anthropic API call
(plus up to 3 fix-attempt calls if a supervisor is wired in).

Usage:
    python regenerate_poc.py <path/to/report_*.json>

The script:
  1. Loads the report JSON.
  2. Reconstructs a VerifiedFinding from its fields.
  3. Builds a minimal ContextPackage stub carrying source_code + neighborhood.
  4. Calls PoCGenerator.generate(supervisor=None) -- skips the gcc loop.
  5. Splices the new PoC fields back into the JSON and re-renders the .md.
"""

import json
import os
import sys
import types
from pathlib import Path

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from verifier_agent import VerifiedFinding
from poc_generator import PoCGenerator
from report_generator import ReportGenerator, VulnerabilityReport


def main(report_json_path: str) -> int:
    report_path = Path(report_json_path)
    if not report_path.exists():
        print(f"error: {report_path} does not exist", file=sys.stderr)
        return 1

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: ANTHROPIC_API_KEY not set in environment", file=sys.stderr)
        return 1

    data = json.loads(report_path.read_text(encoding="utf-8"))

    verified = VerifiedFinding(
        candidate_name=data["function_name"],
        candidate_file=data["file_path"],
        candidate_subsystem=data["subsystem"],
        is_confirmed=bool(data.get("is_verified", True)),
        false_positive_reason=data.get("false_positive_reason", ""),
        severity=data["severity"],
        cvss_score=float(data["cvss_score"]),
        cwe_id=data["cwe_id"],
        attack_vector=data["attack_vector"],
        attack_complexity=data["attack_complexity"],
        privileges_required=data["privileges_required"],
        user_interaction=data["user_interaction"],
        exploitability=data["exploitability"],
        impact=data["impact"],
        verification_notes=data["verification_notes"],
        verifier_confidence=data["verifier_confidence"],
        remediation=data["remediation"],
    )

    ctx = types.SimpleNamespace(
        candidate=types.SimpleNamespace(
            line_start=data.get("line_number", 0),
            vulnerability_score=data.get("vulnerability_score", 0.0),
            betweenness=data.get("betweenness", 0.0),
            pagerank=data.get("pagerank", 0.0),
        ),
        source_code=data.get("source_code", ""),
        caller_context=[],
        callee_context=[],
        unchecked_path_examples=[],
        cve_pattern_details=[],
        graph_neighborhood={"caller_subsystems": {}, "nearby_check_functions": []},
        prompt="",
        static_prefix="",
        candidate_body="",
    )

    print(f"[+] Regenerating PoC for {verified.candidate_name}...")
    gen = PoCGenerator(model="claude-sonnet-4-20250514")
    poc = gen.generate(verified, ctx, supervisor=None)

    print(
        f"[+] PoC generated: {len(poc.code)} bytes, "
        f"{len(poc.trigger_steps)} trigger steps"
    )

    data["poc_code"] = poc.code
    data["poc_description"] = poc.description
    data["poc_trigger_steps"] = poc.trigger_steps
    data["poc_expected_output"] = poc.expected_kernel_output
    data["poc_limitations"] = poc.limitations

    report = VulnerabilityReport(**data)
    md = ReportGenerator()._render_markdown(report)

    md_path = report_path.with_suffix(".md")
    report_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    md_path.write_text(md, encoding="utf-8")

    print(f"[+] Updated {report_path}")
    print(f"[+] Updated {md_path}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path/to/report_*.json>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
