"""
Proof-of-Concept Generator

Generates kernel exploit scaffolding for CONFIRMED, VERIFIED vulnerabilities.
Only invoked when VerifiedFinding.is_confirmed == True.

The PoC is a *research scaffold* — a compilable C program that sets up the
conditions needed to trigger the vulnerability in a controlled test environment.
It is intentionally incomplete (no heap spray tuning, no KASLR bypass) and
clearly labelled for authorized security research only.

Prompt caching strategy:
  - System prompt                  → cached
  - PoC template instructions      → cached  (static per vuln type)
  - Finding-specific data          → NOT cached
"""

import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import anthropic

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "kernelsurgeon"))
from context_assembler import ContextPackage
from verifier_agent import VerifiedFinding


DISCLAIMER = (
    "/* This proof-of-concept is generated for AUTHORIZED SECURITY RESEARCH ONLY.\n"
    " * Do NOT use this code on any system without explicit written permission.\n"
    " * Handle responsibly: report findings via coordinated disclosure.\n"
    " */"
)


@dataclass
class ProofOfConcept:
    """Exploit scaffold for a verified kernel vulnerability."""
    finding_id: str                     # candidate_name from VerifiedFinding
    language: str = "C"                 # always C for kernel exploits
    code: str = ""                      # full PoC source (C code)
    description: str = ""               # plain-English explanation
    trigger_steps: list[str] = field(default_factory=list)
    expected_kernel_output: str = ""    # dmesg/oops pattern to watch for
    limitations: str = ""               # required kernel config / privileges
    disclaimer: str = DISCLAIMER
    compilation_status: str = "untested"  # "success", "failed", "untested"
    fix_iterations: int = 0               # number of LLM fix attempts made


class PoCGenerator:
    """
    Generates a kernel exploit proof-of-concept for a verified vulnerability.

    The generator is template-guided by vulnerability type so the model
    produces structurally correct syscall sequences rather than generic prose.
    """

    SYSTEM_PROMPT = """\
You are a Linux kernel exploit developer writing proof-of-concept code for
authorized security research and vulnerability disclosure.

Your PoCs are:
- Written in C using standard Linux userspace headers
- Minimal and focused: they trigger the vulnerability, not weaponize it
- Well-commented so a reviewer can understand each step
- Realistic: they use actual syscalls / ioctls that reach the vulnerable path
- Safe by default: they crash the kernel or print a warning, not escalate silently

You understand the Linux kernel exploit primitives:
- Heap spray via userfaultfd, pipe_buffer, msg_msg, shm, mmap
- Race condition triggering via pthread, userfaultfd page faults
- Stack overflow detection via KASAN / slab poisoning patterns
- Type confusion via setsockopt polymorphism
- UAF via concurrent open/close/ioctl sequences
"""

    # Static per-session template instructions → cached
    _TEMPLATE_INSTRUCTIONS = """\
## PoC Generation Session

You will generate a minimal C proof-of-concept that triggers the described
Linux kernel vulnerability in a test environment.

### Structural Requirements

1. **Headers**: Include all necessary headers (unistd.h, fcntl.h, sys/ioctl.h,
   pthread.h, etc.).  Do NOT use kernel headers — only userspace headers.

2. **main() entrypoint**: The program must compile and run as a normal unprivileged
   process (unless the vulnerability requires specific capabilities).

3. **Setup phase**: Open the device/socket/file that leads to the vulnerable code.

4. **Trigger phase**: Execute the syscall sequence that reaches the vulnerable
   function with crafted input.  Comment each step.

5. **Detection**: Print "TRIGGERED" after the triggering call, or catch the
   expected kernel WARN / BUG via a signal handler on SIGBUS/SIGSEGV.

6. **Cleanup**: Close file descriptors, free memory.

7. **Makefile stub**: End with a comment block:
   ```
   // Build: gcc -o poc poc.c -lpthread
   // Run:   ./poc
   // Watch: dmesg | tail -20
   ```

### Type-Specific Templates

**stack_buffer_overflow / heap_buffer_overflow**
```c
// Write oversized payload through the interface that reaches the overflow
// Example: write(fd, payload, sizeof(buf) + OVERFLOW_BYTES);
```

**missing_bounds_check**
```c
// Pass an out-of-range index / size parameter via ioctl or write
// struct crafted_req req = { .size = SIZE_MAX };
// ioctl(fd, VULN_IOCTL, &req);
```

**toctou_race**
```c
// Thread 1: repeatedly perform the check (e.g. stat / access)
// Thread 2: swap the resource between check and use (e.g. symlink swap)
// Use userfaultfd or mmap tricks to control timing
```

**use_after_free**
```c
// 1. Allocate object (open device, create socket)
// 2. Trigger async deallocation (close in a racing thread)
// 3. Reclaim the freed slot with a different object type
// 4. Access the original reference → type confusion / UAF
```

**type_confusion**
```c
// Pass a crafted sockaddr / union payload with wrong type tag
// setsockopt(fd, SOL_SOCKET, SO_TYPE, &crafted, sizeof(crafted));
```

### Required JSON Response

```json
{
    "description": "One paragraph explaining what the PoC does and why it triggers the bug",
    "code": "/* full C source code here */",
    "trigger_steps": [
        "Step 1: Open /dev/target",
        "Step 2: Send oversized ioctl payload",
        "Step 3: Observe kernel WARN_ON in dmesg"
    ],
    "expected_kernel_output": "BUG: KASAN: heap-out-of-bounds in target_func+0x...",
    "limitations": "Requires /dev/target to be accessible (udev rule or group membership).  Kernel must be built with CONFIG_KASAN=y for reliable detection."
}
```

---
## Vulnerability to Exploit

"""

    # Script executed in the RLMSandbox to write + compile the PoC.
    # The variable _poc_code is injected into the sandbox namespace before
    # this script runs.  _poc_id is also injected for unique filenames.
    _COMPILE_SCRIPT = '''\
import subprocess, os, tempfile

poc_dir = tempfile.gettempdir()
poc_path = os.path.join(poc_dir, f"poc_{_poc_id}.c")
bin_path = os.path.join(poc_dir, f"poc_{_poc_id}")

with open(poc_path, "w") as f:
    f.write(_poc_code)

result = subprocess.run(
    ["gcc", "-Wall", poc_path, "-o", bin_path, "-lpthread"],
    capture_output=True, text=True, timeout=30,
)
print(f"EXIT_CODE:{result.returncode}")
if result.stderr:
    print(f"STDERR:{result.stderr}")
if result.stdout:
    print(f"STDOUT:{result.stdout}")
if result.returncode == 0:
    print(f"BINARY:{bin_path}")
'''

    # Prompt sent to the LLM when gcc reports errors, asking it to fix the code.
    _FIX_PROMPT_TEMPLATE = """\
## Compilation Fix Required

The C proof-of-concept you generated for `{candidate_name}` ({vuln_type}) failed
to compile with `gcc -Wall`.

### gcc stderr

```
{gcc_stderr}
```

### Current Code

```c
{current_code}
```

### Instructions

Fix every compilation error reported above.  Common issues:
- Missing `#include` headers (add them)
- Implicit function declarations (add correct prototype or header)
- Pointer type mismatches (add explicit casts)
- Undeclared identifiers (check spelling or add declarations)
- Strict aliasing violations (use memcpy or unions)
- Missing struct field initializers

Return ONLY the **complete, corrected C source** as a JSON object:

```json
{{
    "code": "/* full corrected C source */"
}}
```

Do NOT explain the changes in prose — just return the fixed JSON.
"""

    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        self.model = model
        self.client = anthropic.Anthropic()
        self._total_api_calls = 0

    def _call_llm(self, finding_context: str) -> str:
        """Call Claude with prompt caching on system + template instructions."""
        self._total_api_calls += 1

        system = [{"type": "text", "text": self.SYSTEM_PROMPT,
                   "cache_control": {"type": "ephemeral"}}]

        user_content = [
            # Static PoC template instructions → cached
            {"type": "text", "text": self._TEMPLATE_INSTRUCTIONS,
             "cache_control": {"type": "ephemeral"}},
            # Finding-specific data → not cached
            {"type": "text", "text": finding_context},
        ]

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system,
                messages=[{"role": "user", "content": user_content}],
            )
            usage = getattr(response, "usage", None)
            if usage and getattr(usage, "cache_read_input_tokens", 0):
                print(f"    [poc cache] read={usage.cache_read_input_tokens} "
                      f"created={getattr(usage, 'cache_creation_input_tokens', 0)}")
            return response.content[0].text
        except anthropic.APIError as e:
            print(f"    [poc] API error: {e}")
            return json.dumps({
                "description": f"PoC generation failed: {e}",
                "code": f"/* PoC generation failed: {e} */",
                "trigger_steps": ["Manual PoC required"],
                "expected_kernel_output": "unknown",
                "limitations": "API error — manual PoC required",
            })

    def _parse_response(self, raw: str) -> dict:
        """Parse JSON from LLM response."""
        text = raw
        if "```json" in text:
            start = text.index("```json") + 7
            # Search for "\n```" rather than bare "```" so we match only the
            # closing fence (on its own line).  Backtick sequences inside a
            # JSON string value are always mid-line; literal newlines are
            # illegal in JSON strings, so "\n```" can only be the fence close.
            end = text.find("\n```", start)
            text = text[start:end] if end != -1 else text[start:]
        elif "```" in text:
            start = text.index("```") + 3
            end = text.find("\n```", start)
            text = text[start:end] if end != -1 else text[start:]

        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            import re
            m = re.search(r'\{[\s\S]*\}', text)
            if m:
                try:
                    return json.loads(m.group())
                except json.JSONDecodeError:
                    pass
            # Fallback: return the raw text as the "code" field
            return {
                "description": "See raw code below",
                "code": raw,
                "trigger_steps": [],
                "expected_kernel_output": "unknown",
                "limitations": "Parse error — review raw output",
            }

    def _build_finding_context(
        self, verified: VerifiedFinding, context_pkg: ContextPackage
    ) -> str:
        """Build the finding-specific section (not cached)."""
        return f"""\
**Function**: `{verified.candidate_name}`
**File**: `{verified.candidate_file}`
**Vulnerability Type**: {verified.cwe_id} — inferred from primary analysis
**CVSS Score**: {verified.cvss_score:.1f} ({verified.severity})
**Attack Vector**: {verified.attack_vector}
**Exploitability**: {verified.exploitability}

### Verified Attack Path

{verified.verification_notes}

### Impact

{verified.impact}

### Source Code of Vulnerable Function

```c
{context_pkg.source_code}
```

### Graph Context (for syscall entry points)

- Callers by subsystem: {context_pkg.graph_neighborhood.get('caller_subsystems', {})}
- Nearby security checks (may be missing): {context_pkg.graph_neighborhood.get('nearby_check_functions', [])}

Generate a minimal, compilable C PoC for this vulnerability.
"""

    @staticmethod
    def _clean_code(code: str) -> str:
        """Strip markdown fences and leading prose from LLM-generated C code.

        Two common failure modes:
        1. The ``code`` JSON field value itself contains ``` ```c ... ``` ```
           fences (the LLM double-wrapped the code).
        2. The field starts with prose text ("Looking at this vulnerability...")
           before the actual C code begins.
        """
        import re

        # 1. Strip leading/trailing markdown code fences if present
        # Handles: ```c, ```C, ```cpp, or plain ```
        fence_match = re.search(r'```(?:c|C|cpp)?\n([\s\S]*?)(?:```|$)', code)
        if fence_match:
            code = fence_match.group(1)

        # 2. Strip leading prose: find the first line that looks like C code.
        # Valid C start lines: preprocessor directives, comments, or blank lines
        # followed by a C construct.
        c_start = re.search(
            r'^(#\s*(?:include|define|pragma|ifndef|ifdef|if)\b|/\*|//|typedef\b|struct\b|enum\b|int\b|void\b|static\b|extern\b)',
            code, re.MULTILINE,
        )
        if c_start and c_start.start() > 0:
            code = code[c_start.start():]

        return code.strip()

    def generate(
        self,
        verified: VerifiedFinding,
        context_pkg: ContextPackage,
        supervisor=None,
        max_fix_attempts: int = 3,
    ) -> ProofOfConcept:
        """
        Generate a PoC for a CONFIRMED vulnerability, then compile-test it.

        If a supervisor (RLMSupervisor) is provided, the generated C code is
        written to a temp file and compiled with ``gcc -Wall`` inside the
        sandbox.  On compilation failure the gcc stderr is fed back to the
        LLM which fixes the code; this repeats up to ``max_fix_attempts``
        times.

        Callers MUST check verified.is_confirmed before calling this method.
        """
        if not verified.is_confirmed:
            raise ValueError(
                f"PoCGenerator.generate() called on unconfirmed finding: "
                f"{verified.candidate_name}"
            )

        print(f"  [poc] Generating exploit scaffold for {verified.candidate_name}...")

        finding_context = self._build_finding_context(verified, context_pkg)
        raw = self._call_llm(finding_context)
        parsed = self._parse_response(raw)

        code = self._clean_code(parsed.get("code", raw))
        # Ensure disclaimer is prepended
        if DISCLAIMER not in code:
            code = DISCLAIMER + "\n\n" + code

        poc = ProofOfConcept(
            finding_id=verified.candidate_name,
            language="C",
            code=code,
            description=parsed.get("description", ""),
            trigger_steps=parsed.get("trigger_steps", []),
            expected_kernel_output=parsed.get("expected_kernel_output", ""),
            limitations=parsed.get("limitations", ""),
            disclaimer=DISCLAIMER,
        )

        print(f"  [poc] Generated {len(poc.code)} bytes of C code")

        # ── Compile-and-fix loop ──────────────────────────────────────
        if supervisor is not None:
            poc = self._compile_and_fix_loop(
                poc, verified, supervisor, max_fix_attempts,
            )

        return poc

    # ------------------------------------------------------------------
    # Compile-and-fix loop
    # ------------------------------------------------------------------

    def _try_compile(self, poc: ProofOfConcept, supervisor) -> tuple[bool, str]:
        """
        Write the PoC to a temp file and compile it with gcc inside the
        sandbox.  Returns (success, gcc_stderr).
        """
        # Inject the C code and a unique ID into the sandbox namespace
        # so the compile script can reference them without string escaping.
        sandbox = supervisor.sandbox
        poc_id = poc.finding_id.replace("/", "_").replace(" ", "_")
        sandbox.inject("_poc_code", poc.code)
        sandbox.inject("_poc_id", poc_id)

        result = supervisor.run_supervised(self._COMPILE_SCRIPT, poc.finding_id)

        if result.status == "timeout":
            return False, "gcc compilation timed out."

        if result.status == "max_depth_reached":
            return False, "Script budget exhausted — could not compile."

        output = result.output

        # Parse structured output from the compile script
        exit_code = -1
        stderr_text = ""
        for line in output.split("\n"):
            if line.startswith("EXIT_CODE:"):
                try:
                    exit_code = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("STDERR:"):
                stderr_text += line.split(":", 1)[1]
            elif stderr_text:
                # Continuation of multi-line stderr
                stderr_text += "\n" + line

        return exit_code == 0, stderr_text.strip()

    def _call_llm_fix(
        self, current_code: str, gcc_stderr: str, verified: VerifiedFinding
    ) -> str:
        """Ask the LLM to fix a PoC that failed to compile."""
        self._total_api_calls += 1

        fix_prompt = self._FIX_PROMPT_TEMPLATE.format(
            candidate_name=verified.candidate_name,
            vuln_type=verified.cwe_id,
            gcc_stderr=gcc_stderr,
            current_code=current_code,
        )

        system = [{"type": "text", "text": self.SYSTEM_PROMPT,
                   "cache_control": {"type": "ephemeral"}}]

        user_content = [{"type": "text", "text": fix_prompt}]

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system,
                messages=[{"role": "user", "content": user_content}],
            )
            return response.content[0].text
        except anthropic.APIError as e:
            print(f"    [poc-fix] API error: {e}")
            return ""

    def _compile_and_fix_loop(
        self,
        poc: ProofOfConcept,
        verified: VerifiedFinding,
        supervisor,
        max_fix_attempts: int,
    ) -> ProofOfConcept:
        """
        Compile the PoC in the sandbox.  On failure, feed gcc stderr back
        to the LLM and iterate until compilation succeeds or the fix budget
        is exhausted.
        """
        for attempt in range(max_fix_attempts + 1):
            label = "initial" if attempt == 0 else f"fix #{attempt}"
            print(f"  [poc-compile] Attempt {attempt + 1}/{max_fix_attempts + 1} "
                  f"({label})...")

            success, gcc_stderr = self._try_compile(poc, supervisor)

            if success:
                print(f"  [poc-compile] Compilation SUCCEEDED after "
                      f"{attempt} fix(es)")
                poc.compilation_status = "success"
                poc.fix_iterations = attempt
                return poc

            # Log the failure
            short_err = gcc_stderr[:300].replace("\n", " | ")
            print(f"  [poc-compile] FAILED: {short_err}")

            if attempt >= max_fix_attempts:
                # Budget exhausted — return the last version as-is
                break

            # Ask the LLM to fix the code
            print(f"  [poc-fix] Feeding gcc stderr to LLM for fix "
                  f"(attempt {attempt + 1}/{max_fix_attempts})...")
            raw_fix = self._call_llm_fix(poc.code, gcc_stderr, verified)
            time.sleep(1)  # rate-limit

            if not raw_fix:
                print(f"  [poc-fix] LLM returned empty response — aborting fix loop")
                break

            parsed_fix = self._parse_response(raw_fix)
            fixed_code = self._clean_code(parsed_fix.get("code", ""))

            if not fixed_code or fixed_code == poc.code:
                print(f"  [poc-fix] LLM did not produce a changed fix — aborting")
                break

            # Ensure disclaimer is preserved
            if DISCLAIMER not in fixed_code:
                fixed_code = DISCLAIMER + "\n\n" + fixed_code

            poc.code = fixed_code
            print(f"  [poc-fix] Updated code ({len(poc.code)} bytes)")

        poc.compilation_status = "failed"
        poc.fix_iterations = max_fix_attempts
        print(f"  [poc-compile] Could not achieve clean compilation after "
              f"{max_fix_attempts} fix attempts")
        return poc
