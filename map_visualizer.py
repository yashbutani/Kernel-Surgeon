"""
Map Visualizer — Live terminal visualization for the code mapping phase.

Shows which kernel subsystems have been explored vs. not, updating in real
time as CscopeExtractor processes each directory.

Requires the ``rich`` package for the live display (``pip install rich``).
Falls back to plain printed progress lines if ``rich`` is not installed.

Usage
-----
    from map_visualizer import MappingVisualizer, detect_subsystems

    subsystems = detect_subsystems("/path/to/linux")
    vis = MappingVisualizer(kernel_path="/path/to/linux", subsystems=subsystems)

    with vis:                                   # starts live display
        for sub in subsystems:
            vis.begin_subsystem(sub)            # marks subsystem as scanning
            # ... extraction work ...
            vis.update_subsystem(sub, files=12, functions=300, edges=2400)
            vis.complete_subsystem(sub)         # marks subsystem as done

    vis.save_report("data/map_report.json")     # write JSON summary
"""

import json
import os
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

# Rich is optional — fall back to plain output if not installed
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box as _box

    _RICH = True
except ImportError:
    _RICH = False


# ---------------------------------------------------------------------------
# Subsystem status model
# ---------------------------------------------------------------------------

class SubsystemStatus(str, Enum):
    PENDING  = "pending"
    SCANNING = "scanning"
    DONE     = "done"
    SKIPPED  = "skipped"


@dataclass
class SubsystemProgress:
    """Per-subsystem tracking state."""
    name: str
    status: SubsystemStatus = SubsystemStatus.PENDING
    files_total: int = 0       # total .c files in this directory (pre-counted)
    files_scanned: int = 0     # .c files processed so far
    functions_found: int = 0
    edges_found: int = 0
    start_time: float = 0.0
    elapsed: float = 0.0       # seconds (set on completion)


# ---------------------------------------------------------------------------
# Auto-detection of kernel subsystems
# ---------------------------------------------------------------------------

# Top-level kernel directories that should be skipped (non-code content)
_SKIP_DIRS: frozenset[str] = frozenset({
    "Documentation", "scripts", "tools", "samples", "include",
    "usr", "certs", "rust", "LICENSES", ".git",
})


def detect_subsystems(kernel_path: str) -> list[str]:
    """
    Auto-detect kernel code subsystems from the top-level directory.

    Scans every top-level subdirectory, counts its ``.c`` files, and returns
    the non-empty code directories sorted **largest first** — so the mapping
    starts with the subsystems that contribute the most nodes (drivers, fs,
    net, ...) and the graph grows as fast as possible.

    Returns a list of directory names **with a trailing slash** to match the
    format expected by ``CscopeExtractor.subsystems``.

    Example::

        >>> detect_subsystems("/usr/src/linux")
        ['drivers/', 'fs/', 'net/', 'arch/', 'kernel/', 'mm/', ...]
    """
    root = Path(kernel_path)
    candidates: list[tuple[int, str]] = []

    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        name = entry.name
        if name in _SKIP_DIRS or name.startswith("."):
            continue

        # Count C files as a size proxy — rglob is fast enough at this stage
        c_count = sum(1 for _ in entry.rglob("*.c"))
        if c_count == 0:
            continue

        candidates.append((c_count, name + "/"))

    # Largest first so the most important subsystems are mapped early
    candidates.sort(reverse=True)
    return [name for _, name in candidates]


# ---------------------------------------------------------------------------
# MappingVisualizer
# ---------------------------------------------------------------------------

class MappingVisualizer:
    """
    Live terminal display for the kernel code mapping phase.

    Thread-safe — ``begin_subsystem()``, ``update_subsystem()``, and
    ``complete_subsystem()`` may be called from any thread.

    Parameters
    ----------
    kernel_path:
        Root of the Linux kernel source tree.
    subsystems:
        Ordered list of subsystem directory names (e.g. ``['drivers/', 'fs/']``).
        Use :func:`detect_subsystems` to generate this list automatically.
    """

    _STATUS_ICON = {
        SubsystemStatus.PENDING:  "[ ]",
        SubsystemStatus.SCANNING: "[~]",
        SubsystemStatus.DONE:     "[x]",
        SubsystemStatus.SKIPPED:  "[-]",
    }
    _STATUS_STYLE = {
        SubsystemStatus.PENDING:  "dim",
        SubsystemStatus.SCANNING: "bold yellow",
        SubsystemStatus.DONE:     "bold green",
        SubsystemStatus.SKIPPED:  "dim red",
    }

    def __init__(self, kernel_path: str, subsystems: list[str]) -> None:
        self.kernel_path = Path(kernel_path)
        self._order: list[str] = list(subsystems)

        # Pre-count C files per subsystem so the table shows totals immediately
        self._progress: dict[str, SubsystemProgress] = {
            s: SubsystemProgress(name=s, files_total=self._count_c_files(s))
            for s in subsystems
        }

        self._lock = threading.Lock()
        self._live: Optional["Live"] = None
        self._console: Optional["Console"] = Console() if _RICH else None
        self._start_time = time.monotonic()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "MappingVisualizer":
        if _RICH and self._console:
            self._live = Live(
                self._render(),
                console=self._console,
                refresh_per_second=4,
                transient=False,
            )
            self._live.__enter__()
        else:
            print("[*] Code mapping started.")
        return self

    def __exit__(self, *args) -> None:
        if self._live:
            self._live.update(self._render())
            self._live.__exit__(*args)

    # ------------------------------------------------------------------
    # Public API — thread-safe
    # ------------------------------------------------------------------

    def begin_subsystem(self, name: str) -> None:
        """Mark a subsystem as actively being scanned."""
        with self._lock:
            if name in self._progress:
                p = self._progress[name]
                p.status = SubsystemStatus.SCANNING
                p.start_time = time.monotonic()
        self._refresh()
        if not _RICH:
            print(f"  [~] Scanning {name} ...")

    def update_subsystem(
        self,
        name: str,
        *,
        files: int = 0,
        functions: int = 0,
        edges: int = 0,
    ) -> None:
        """Update progress counters for a subsystem that is still scanning."""
        with self._lock:
            if name in self._progress:
                p = self._progress[name]
                p.files_scanned = files
                p.functions_found = functions
                p.edges_found = edges
        self._refresh()

    def complete_subsystem(self, name: str) -> None:
        """Mark a subsystem as fully mapped."""
        with self._lock:
            if name in self._progress:
                p = self._progress[name]
                p.status = SubsystemStatus.DONE
                p.elapsed = (
                    time.monotonic() - p.start_time
                    if p.start_time else 0.0
                )
                p.files_scanned = p.files_total  # ensure 100%
        self._refresh()
        if not _RICH:
            p = self._progress.get(name)
            if p:
                print(
                    f"  [x] {name:<20}  "
                    f"functions={p.functions_found:>8,}  "
                    f"edges={p.edges_found:>8,}  "
                    f"{p.elapsed:.0f}s"
                )

    def skip_subsystem(self, name: str) -> None:
        """Mark a subsystem as skipped (e.g. no C files found)."""
        with self._lock:
            if name in self._progress:
                self._progress[name].status = SubsystemStatus.SKIPPED
        self._refresh()

    def totals(self) -> dict:
        """Return aggregate counts across all subsystems."""
        with self._lock:
            fns = sum(p.functions_found for p in self._progress.values())
            eds = sum(p.edges_found     for p in self._progress.values())
            done = sum(
                1 for p in self._progress.values()
                if p.status == SubsystemStatus.DONE
            )
        return {
            "functions": fns,
            "edges": eds,
            "subsystems_done": done,
            "subsystems_total": len(self._progress),
            "elapsed_s": round(time.monotonic() - self._start_time, 1),
        }

    # ------------------------------------------------------------------
    # Rendering (rich)
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._render())

    def _render(self):
        """Build the rich Panel to display."""
        if not _RICH:
            return None

        t = self.totals()
        done  = t["subsystems_done"]
        total = t["subsystems_total"]
        pct   = int(100 * done / total) if total else 0

        bar_len    = 36
        bar_filled = int(bar_len * done / total) if total else 0
        bar        = "[" + "=" * bar_filled + " " * (bar_len - bar_filled) + "]"

        header = Text.assemble(
            ("KernelSurgeon — Code Mapping Phase\n", "bold cyan"),
            (bar,         "bold white"),
            (f" {pct}%  ", "bold white"),
            (f"{done}/{total} subsystems  |  ", "white"),
            (f"{t['functions']:,}", "bold green"),
            (" functions  |  ", "white"),
            (f"{t['edges']:,}", "bold green"),
            (" edges  |  ", "white"),
            (f"{t['elapsed_s']:.0f}s", "dim"),
        )

        table = Table(
            box=_box.SIMPLE,
            show_header=True,
            header_style="bold blue",
            expand=True,
        )
        table.add_column("Subsystem",  style="cyan", min_width=16, no_wrap=True)
        table.add_column("Status",     justify="center", min_width=14)
        table.add_column("Files",      justify="right",  min_width=10)
        table.add_column("Functions",  justify="right",  min_width=11)
        table.add_column("Edges",      justify="right",  min_width=10)
        table.add_column("Time",       justify="right",  min_width=7, style="dim")

        with self._lock:
            for name in self._order:
                p = self._progress[name]
                status = p.status
                style  = self._STATUS_STYLE[status]
                icon   = self._STATUS_ICON[status]

                if status == SubsystemStatus.SCANNING:
                    file_str = f"{p.files_scanned}/{p.files_total}"
                elif status == SubsystemStatus.DONE:
                    file_str = str(p.files_total)
                else:
                    file_str = str(p.files_total) if p.files_total else "-"

                func_str = f"{p.functions_found:,}" if p.functions_found else "-"
                edge_str = f"{p.edges_found:,}"     if p.edges_found     else "-"
                time_str = f"{p.elapsed:.0f}s"      if p.elapsed         else "-"

                table.add_row(
                    name,
                    Text(f"{icon} {status.value}", style=style),
                    file_str,
                    func_str,
                    edge_str,
                    time_str,
                )

        return Panel(table, title=header, border_style="blue", padding=(0, 1))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _count_c_files(self, subsystem: str) -> int:
        d = self.kernel_path / subsystem
        if not d.exists():
            return 0
        return sum(1 for _ in d.rglob("*.c"))

    # ------------------------------------------------------------------
    # Post-run output
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        """Print a plain-text summary (always shown, regardless of rich)."""
        t = self.totals()
        print(f"\n{'='*60}")
        print("MAPPING SUMMARY")
        print(f"{'='*60}")
        with self._lock:
            for name in self._order:
                p = self._progress[name]
                icon = self._STATUS_ICON[p.status]
                print(
                    f"  {icon} {name:<20}  "
                    f"files={p.files_total:<6}  "
                    f"functions={p.functions_found:<8,}  "
                    f"edges={p.edges_found:<8,}  "
                    f"{p.elapsed:.0f}s"
                )
        print(f"\n  Total functions : {t['functions']:,}")
        print(f"  Total edges     : {t['edges']:,}")
        print(f"  Subsystems done : {t['subsystems_done']}/{t['subsystems_total']}")
        print(f"  Elapsed         : {t['elapsed_s']:.0f}s")

    def save_report(self, path: str) -> None:
        """Persist a JSON summary of the mapping run."""
        t = self.totals()
        with self._lock:
            data = {
                "summary": t,
                "subsystems": [
                    {
                        "name":             p.name,
                        "status":           p.status.value,
                        "files_total":      p.files_total,
                        "files_scanned":    p.files_scanned,
                        "functions_found":  p.functions_found,
                        "edges_found":      p.edges_found,
                        "elapsed_s":        round(p.elapsed, 1),
                    }
                    for p in (self._progress[n] for n in self._order)
                ],
            }
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Mapping report saved to {path}")
