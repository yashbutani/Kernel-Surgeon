"""
Work-Stealing Thread Pool for parallel candidate analysis.

Each worker holds a deque of tasks.  When its deque is empty it tries to
steal one task from the *back* of a randomly chosen victim's deque (classic
Chase-Lev style).  A shared rate-limiter keeps total API calls/sec across all
threads within the Anthropic rate limit.

Usage:
    pool = WorkStealingPool(n_workers=4, tasks=candidates, rate_limit_rps=2.0)
    results = pool.run(agent.analyze_candidate)
"""

import random
import time
import threading
from collections import deque
from typing import Any, Callable


class WorkStealingPool:
    """
    Thread pool with work-stealing scheduling.

    Args:
        n_workers:       Number of worker threads.
        tasks:           Flat list of tasks to distribute.
        rate_limit_rps:  Maximum API calls per second across ALL workers combined.
                         Set to 0 to disable rate limiting.
    """

    def __init__(
        self,
        n_workers: int,
        tasks: list,
        rate_limit_rps: float = 2.0,
    ):
        self.n_workers = min(n_workers, len(tasks)) if tasks else 1
        self._rate_limit_rps = rate_limit_rps

        # Distribute tasks across workers (round-robin for even initial load)
        self._queues: list[deque] = [deque() for _ in range(self.n_workers)]
        for i, task in enumerate(tasks):
            self._queues[i % self.n_workers].append(task)

        self._locks: list[threading.Lock] = [threading.Lock() for _ in range(self.n_workers)]

        # Shared results
        self._results: list[Any] = []
        self._results_lock = threading.Lock()

        # Progress tracking
        self._done = 0
        self._total = len(tasks)
        self._progress_lock = threading.Lock()

        # Rate limiting: allow at most rate_limit_rps tokens per second
        self._rate_lock = threading.Lock()
        self._last_call_time: float = 0.0
        self._min_interval = (1.0 / rate_limit_rps) if rate_limit_rps > 0 else 0.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _rate_limit(self) -> None:
        """Block until enough time has passed since the last API call."""
        if self._min_interval <= 0:
            return
        with self._rate_lock:
            elapsed = time.monotonic() - self._last_call_time
            wait = self._min_interval - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_call_time = time.monotonic()

    def _steal(self, thief_id: int) -> Any | None:
        """Try to steal one task from another worker's deque (from the back)."""
        # Randomise victim order to avoid hotspots
        victims = list(range(self.n_workers))
        random.shuffle(victims)
        for victim_id in victims:
            if victim_id == thief_id:
                continue
            with self._locks[victim_id]:
                if self._queues[victim_id]:
                    return self._queues[victim_id].pop()   # steal from back
        return None

    def _worker(self, worker_id: int, fn: Callable, result_callback=None) -> None:
        """Worker loop: process own queue, then steal, then exit."""
        while True:
            # Try own queue first (from front — FIFO within worker)
            task = None
            with self._locks[worker_id]:
                if self._queues[worker_id]:
                    task = self._queues[worker_id].popleft()

            # If own queue empty, try stealing
            if task is None:
                task = self._steal(worker_id)

            # Nothing left anywhere — exit
            if task is None:
                return

            # Rate-limit before calling the (potentially API-bound) function
            self._rate_limit()

            result = fn(task)

            # Record result and update progress
            with self._results_lock:
                self._results.append(result)

            # Fire callback immediately so callers can stream results
            if result_callback is not None:
                result_callback(result)

            with self._progress_lock:
                self._done += 1
                done = self._done
                total = self._total

            # Extract a display name for progress output
            name = getattr(task, "name", repr(task)[:40])
            verdict = ""
            if hasattr(result, "is_vulnerable"):
                verdict = f"vuln={result.is_vulnerable} conf={result.confidence}"
            print(f"  [{done}/{total}] {name} → {verdict}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, fn: Callable, result_callback=None) -> list[Any]:
        """
        Execute *fn* on every task using work-stealing parallelism.

        If *result_callback* is provided it is called immediately in the
        worker thread each time a result is produced, before the next task
        is picked up.  This enables streaming pipelines where downstream
        stages (verification, PoC generation) can start on the first
        finding while other candidates are still being analysed.

        Returns results in completion order (NOT necessarily task order).
        """
        print(f"[*] Work-stealing pool: {self.n_workers} workers, "
              f"{self._total} tasks, rate={self._rate_limit_rps:.1f} RPS")

        threads = [
            threading.Thread(
                target=self._worker, args=(i, fn, result_callback), daemon=True
            )
            for i in range(self.n_workers)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        return self._results
