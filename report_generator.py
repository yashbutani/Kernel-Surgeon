"""
Report Generator

Assembles VerifiedFinding + ProofOfConcept into structured vulnerability reports.

Output layout:
    reports/
        CRITICAL/
            report_<id>.json
            report_<id>.md
        HIGH/ ...
        MEDIUM/ ...
        LOW/ ...
        INFORMATIONAL/ ...
        index.json          ← sorted summary of all reports

Reports are keyed by the function name + a short UUID fragment to stay unique.
"""

import json
import os
import re
import sys
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "kernelsurgeon"))
from context_assembler import ContextPackage
from verifier_agent import VerifiedFinding
from poc_generator import ProofOfConcept

# Canonical severity ordering (highest first)
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


@dataclass
class VulnerabilityReport:
    """Full structured report for one confirmed (or candidate) vulnerability."""
    report_id: str

    # Timing
    generated_at: str               # ISO-8601 UTC timestamp

    # Location in kernel source
    file_path: str
    function_name: str
    line_number: int                # best-guess vulnerable line (0 if unknown)
    subsystem: str

    # Classification
    title: str
    severity: str                   # CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
    cvss_score: float
    cwe_id: str
    vulnerability_type: str         # buffer_overflow / uaf / race / etc.

    # Narrative
    description: str
    attack_path: str                # full attack path string
    check_bypass_analysis: str

    # Verification
    is_verified: bool
    verification_notes: str
    verifier_confidence: str
    false_positive_reason: str      # non-empty if rejected

    # CVSS components
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    exploitability: str
    impact: str

    # Proof of concept (only populated when is_verified=True)
    poc_code: str
    poc_description: str
    poc_trigger_steps: list[str]
    poc_expected_output: str
    poc_limitations: str

    # Remediation
    remediation: str

    # Graph metrics (informational)
    vulnerability_score: float      # raw graph score
    betweenness: float
    pagerank: float

    # Source context (default so existing serialized reports stay compatible)
    source_code: str = ""           # extracted function source (with line numbers)


class ReportGenerator:
    """
    Builds, saves, and indexes vulnerability reports.

    Usage:
        gen = ReportGenerator(output_dir="reports")
        report = gen.generate(verified, poc, context_pkg, primary_finding)
        gen.save(report)
        gen.generate_index(all_reports)
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate(
        self,
        verified: VerifiedFinding,
        poc: Optional[ProofOfConcept],
        context_pkg: ContextPackage,
        primary_finding=None,       # VulnerabilityFinding from vuln_agent
    ) -> VulnerabilityReport:
        """Assemble a VulnerabilityReport from all available data sources."""

        report_id = f"{verified.candidate_name}_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()

        # Extract line number from candidate graph data
        candidate = context_pkg.candidate
        line_number = getattr(candidate, "line_start", 0)
        vuln_type = "unknown"
        description = ""
        attack_path = ""
        check_bypass = ""

        if primary_finding is not None:
            vuln_type = getattr(primary_finding, "vulnerability_type", "unknown")
            description = getattr(primary_finding, "description", "")
            attack_path = getattr(primary_finding, "attack_path", "")
            check_bypass = getattr(primary_finding, "check_bypass_analysis", "")

        vuln_score = getattr(candidate, "vulnerability_score", 0.0)
        betweenness = getattr(candidate, "betweenness", 0.0)
        pagerank = getattr(candidate, "pagerank", 0.0)

        # Build a human-readable title
        severity = verified.severity
        cwe = verified.cwe_id
        title = f"[{severity}] {vuln_type.replace('_', ' ').title()} in {verified.candidate_name} ({cwe})"

        report = VulnerabilityReport(
            report_id=report_id,
            generated_at=now,
            file_path=verified.candidate_file,
            function_name=verified.candidate_name,
            line_number=line_number,
            subsystem=verified.candidate_subsystem,
            title=title,
            severity=severity,
            cvss_score=verified.cvss_score,
            cwe_id=cwe,
            vulnerability_type=vuln_type,
            description=description,
            attack_path=attack_path,
            check_bypass_analysis=check_bypass,
            is_verified=verified.is_confirmed,
            verification_notes=verified.verification_notes,
            verifier_confidence=verified.verifier_confidence,
            false_positive_reason=verified.false_positive_reason,
            attack_vector=verified.attack_vector,
            attack_complexity=verified.attack_complexity,
            privileges_required=verified.privileges_required,
            user_interaction=verified.user_interaction,
            exploitability=verified.exploitability,
            impact=verified.impact,
            poc_code=poc.code if poc else "",
            poc_description=poc.description if poc else "",
            poc_trigger_steps=poc.trigger_steps if poc else [],
            poc_expected_output=poc.expected_kernel_output if poc else "",
            poc_limitations=poc.limitations if poc else "",
            remediation=verified.remediation,
            source_code=context_pkg.source_code,
            vulnerability_score=vuln_score,
            betweenness=betweenness,
            pagerank=pagerank,
        )
        return report

    # ------------------------------------------------------------------
    # Saving
    # ------------------------------------------------------------------

    def save(self, report: VulnerabilityReport) -> str:
        """Save a report as both JSON and Markdown. Returns the directory path."""
        severity_dir = self.output_dir / report.severity
        severity_dir.mkdir(parents=True, exist_ok=True)

        base = f"report_{report.report_id}"

        json_path = severity_dir / f"{base}.json"
        md_path = severity_dir / f"{base}.md"

        # JSON — full machine-readable record
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, default=str)

        # Markdown — human-readable report
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(self._render_markdown(report))

        print(f"  [report] {report.severity}: {json_path}")
        return str(severity_dir)

    def generate_index(self, reports: list[VulnerabilityReport]) -> None:
        """Write reports/index.json sorted by severity then CVSS score."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        def sort_key(r: VulnerabilityReport):
            sev_rank = SEVERITY_ORDER.index(r.severity) if r.severity in SEVERITY_ORDER else 99
            return (sev_rank, -r.cvss_score)

        sorted_reports = sorted(reports, key=sort_key)

        index = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total": len(reports),
            "confirmed": sum(1 for r in reports if r.is_verified),
            "by_severity": {
                sev: sum(1 for r in reports if r.severity == sev)
                for sev in SEVERITY_ORDER
            },
            "reports": [
                {
                    "report_id": r.report_id,
                    "title": r.title,
                    "severity": r.severity,
                    "cvss_score": r.cvss_score,
                    "cwe_id": r.cwe_id,
                    "function_name": r.function_name,
                    "file_path": r.file_path,
                    "is_verified": r.is_verified,
                    "path": str(
                        self.output_dir / r.severity / f"report_{r.report_id}.json"
                    ),
                }
                for r in sorted_reports
            ],
        }

        index_path = self.output_dir / "index.json"
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2, default=str)

        print(f"\n[+] Report index: {index_path}")
        print(f"    Total: {index['total']}  Confirmed: {index['confirmed']}")
        for sev in SEVERITY_ORDER:
            count = index["by_severity"][sev]
            if count:
                print(f"    {sev}: {count}")

    # ------------------------------------------------------------------
    # Markdown rendering
    # ------------------------------------------------------------------

    def _render_markdown(self, r: VulnerabilityReport) -> str:
        lines = []

        # Title block
        lines.append(f"# {r.title}\n")
        lines.append(f"**Generated:** {r.generated_at}  ")
        lines.append(f"**Report ID:** `{r.report_id}`\n")

        # Location table
        lines.append("## Location\n")
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        lines.append(f"| File | `{r.file_path}` |")
        lines.append(f"| Function | `{r.function_name}` |")
        if r.line_number:
            lines.append(f"| Line | {r.line_number} |")
        lines.append(f"| Subsystem | {r.subsystem} |")
        lines.append("")

        # Source code
        if r.source_code and not r.source_code.startswith("//"):
            lines.append("## Source Code\n")
            lines.append("```c")
            lines.append(r.source_code)
            lines.append("```")
            lines.append("")

        # Classification
        lines.append("## Classification\n")
        lines.append("| Metric | Value |")
        lines.append("|---|---|")
        lines.append(f"| Severity | **{r.severity}** |")
        lines.append(f"| CVSS Score | {r.cvss_score:.1f} |")
        lines.append(f"| CWE | {r.cwe_id} |")
        lines.append(f"| Type | {r.vulnerability_type} |")
        lines.append(f"| Attack Vector | {r.attack_vector} |")
        lines.append(f"| Attack Complexity | {r.attack_complexity} |")
        lines.append(f"| Privileges Required | {r.privileges_required} |")
        lines.append(f"| User Interaction | {r.user_interaction} |")
        lines.append(f"| Exploitability | {r.exploitability} |")
        lines.append("")

        # Description
        if r.description:
            lines.append("## Description\n")
            lines.append(r.description)
            lines.append("")

        # Impact
        if r.impact:
            lines.append("## Impact\n")
            lines.append(r.impact)
            lines.append("")

        # Attack path
        if r.attack_path:
            lines.append("## Attack Path\n")
            lines.append("```")
            lines.append(r.attack_path)
            lines.append("```")
            lines.append("")

        # Check bypass
        if r.check_bypass_analysis:
            lines.append("## Check-Bypass Analysis\n")
            lines.append(r.check_bypass_analysis)
            lines.append("")

        # Verification
        lines.append("## Verification\n")
        status = "✓ CONFIRMED" if r.is_verified else "✗ NOT CONFIRMED"
        lines.append(f"**Status:** {status}  ")
        lines.append(f"**Verifier Confidence:** {r.verifier_confidence}\n")
        if r.verification_notes:
            lines.append(r.verification_notes)
        if r.false_positive_reason:
            lines.append(f"\n**False-positive reason:** {r.false_positive_reason}")
        lines.append("")

        # PoC
        if r.poc_code:
            lines.append("## Proof of Concept\n")
            if r.poc_description:
                lines.append(r.poc_description)
                lines.append("")
            if r.poc_trigger_steps:
                lines.append("**Trigger steps:**\n")
                for i, step in enumerate(r.poc_trigger_steps, 1):
                    lines.append(f"{i}. {step}")
                lines.append("")
            # Strip any markdown code fences that may have been left in the
            # poc_code field (e.g. from a parse-error fallback in PoCGenerator)
            # before wrapping in our own ```c fence, to avoid nesting fences.
            poc_code = re.sub(r'```[a-zA-Z]*\n?', '', r.poc_code)
            poc_code = re.sub(r'\n```', '', poc_code).strip()
            lines.append("```c")
            lines.append(poc_code)
            lines.append("```")
            if r.poc_expected_output:
                lines.append(f"\n**Expected kernel output:**")
                lines.append(f"```\n{r.poc_expected_output}\n```")
            if r.poc_limitations:
                lines.append(f"\n**Limitations:** {r.poc_limitations}")
            lines.append("")

        # Remediation
        if r.remediation:
            lines.append("## Remediation\n")
            lines.append(r.remediation)
            lines.append("")

        # Graph metrics footer
        lines.append("---")
        lines.append(f"*Graph vulnerability score: {r.vulnerability_score:.2f} | "
                     f"Betweenness: {r.betweenness:.4f} | PageRank: {r.pagerank:.6f}*")

        return "\n".join(lines) + "\n"
