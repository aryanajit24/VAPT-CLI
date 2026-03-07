"""Parallel execution engine for concurrent scanning."""

from __future__ import annotations

import time
import threading
from concurrent.futures import (
    ThreadPoolExecutor,
    Future,
    as_completed,
)
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar

from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    SpinnerColumn,
    MofNCompleteColumn,
)

T = TypeVar("T")


# Task definitions


@dataclass
class ScanTask:
    """A single unit of work for the parallel engine."""
    task_id: str
    func: Callable[..., Any]
    args: tuple = ()
    kwargs: dict[str, Any] = field(default_factory=dict)
    label: str = ""


@dataclass
class ScanResult:
    """Result from a completed scan task."""
    task_id: str
    success: bool = True
    data: Any = None
    error: str | None = None
    duration: float = 0.0


# Parallel Engine


class ParallelEngine:
    """
    Executes scan tasks in parallel using a thread pool.

    Features:
      - Configurable worker count (auto-scales based on task count)
      - Built-in rate limiting (min delay between task starts)
      - Rich progress bar integration
      - Error isolation (one failing task doesn't kill others)

    Usage:
        engine = ParallelEngine(max_workers=20, rate_limit=0.1)
        tasks = [ScanTask("url-1", scan_func, args=(url,)) for url in urls]
        results = engine.run(tasks, label="Scanning URLs")
    """

    def __init__(
        self,
        max_workers: int = 20,
        rate_limit: float = 0.0,
        show_progress: bool = True,
    ) -> None:
        self.max_workers = max_workers
        self.rate_limit = rate_limit  # Min seconds between task starts
        self.show_progress = show_progress
        self._lock = threading.Lock()
        self._last_start = 0.0

    def _rate_wait(self) -> None:
        """Enforce rate limiting between task starts."""
        if self.rate_limit <= 0:
            return
        with self._lock:
            now = time.time()
            elapsed = now - self._last_start
            if elapsed < self.rate_limit:
                time.sleep(self.rate_limit - elapsed)
            self._last_start = time.time()

    def _execute_task(self, task: ScanTask) -> ScanResult:
        """Execute a single task with timing and error handling."""
        self._rate_wait()
        start = time.time()
        try:
            data = task.func(*task.args, **task.kwargs)
            return ScanResult(
                task_id=task.task_id,
                success=True,
                data=data,
                duration=time.time() - start,
            )
        except Exception as exc:
            return ScanResult(
                task_id=task.task_id,
                success=False,
                error=str(exc),
                duration=time.time() - start,
            )

    def run(
        self,
        tasks: list[ScanTask],
        label: str = "Scanning",
    ) -> list[ScanResult]:
        """
        Run all tasks in parallel and return results.

        Args:
            tasks: List of ScanTask objects to execute.
            label: Label for the progress bar.

        Returns:
            List of ScanResult objects (same order as tasks).
        """
        if not tasks:
            return []

        # Scale workers to task count but don't exceed max
        workers = min(self.max_workers, len(tasks))
        results: dict[str, ScanResult] = {}

        if self.show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=40),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task_bar = progress.add_task(label, total=len(tasks))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    future_map: dict[Future, ScanTask] = {}
                    for task in tasks:
                        f = pool.submit(self._execute_task, task)
                        future_map[f] = task

                    for future in as_completed(future_map):
                        result = future.result()
                        results[result.task_id] = result
                        progress.advance(task_bar)
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                future_map = {
                    pool.submit(self._execute_task, task): task
                    for task in tasks
                }
                for future in as_completed(future_map):
                    result = future.result()
                    results[result.task_id] = result

        # Preserve original task order
        return [results[task.task_id] for task in tasks if task.task_id in results]


# Convenience wrappers for common scanner patterns


def parallel_url_scan(
    urls: list[str],
    scan_func: Callable[[str], Any],
    max_workers: int = 15,
    rate_limit: float = 0.05,
    label: str = "URL Scanning",
    show_progress: bool = True,
) -> list[ScanResult]:
    """
    Scan a list of URLs in parallel.

    Args:
        urls: URLs to scan.
        scan_func: Function that takes a URL string and returns findings.
        max_workers: Max concurrent threads.
        rate_limit: Min seconds between request starts.
        label: Progress bar label.

    Returns:
        List of ScanResult objects.
    """
    tasks = [
        ScanTask(task_id=f"url-{i}", func=scan_func, args=(url,), label=url)
        for i, url in enumerate(urls)
    ]
    engine = ParallelEngine(
        max_workers=max_workers,
        rate_limit=rate_limit,
        show_progress=show_progress,
    )
    return engine.run(tasks, label=label)


def parallel_payload_test(
    url: str,
    payloads: list[str],
    test_func: Callable[[str, str], Any],
    max_workers: int = 10,
    rate_limit: float = 0.1,
    label: str = "Testing payloads",
    show_progress: bool = True,
) -> list[ScanResult]:
    """
    Test multiple payloads against a URL in parallel.

    Args:
        url: Target URL.
        payloads: Payload strings to test.
        test_func: Function(url, payload) → finding or None.
        max_workers: Max concurrent threads.
        rate_limit: Min seconds between requests.

    Returns:
        List of ScanResult objects.
    """
    tasks = [
        ScanTask(
            task_id=f"payload-{i}",
            func=test_func,
            args=(url, payload),
            label=payload[:40],
        )
        for i, payload in enumerate(payloads)
    ]
    engine = ParallelEngine(
        max_workers=max_workers,
        rate_limit=rate_limit,
        show_progress=show_progress,
    )
    return engine.run(tasks, label=label)


def parallel_port_scan(
    host: str,
    ports: list[int],
    scan_func: Callable[[str, int], Any],
    max_workers: int = 50,
    rate_limit: float = 0.0,
    label: str = "Port Scanning",
    show_progress: bool = True,
) -> list[ScanResult]:
    """
    Scan ports on a host in parallel.
    """
    tasks = [
        ScanTask(
            task_id=f"port-{port}",
            func=scan_func,
            args=(host, port),
            label=f"Port {port}",
        )
        for port in ports
    ]
    engine = ParallelEngine(
        max_workers=max_workers,
        rate_limit=rate_limit,
        show_progress=show_progress,
    )
    return engine.run(tasks, label=label)


def collect_findings(results: list[ScanResult]) -> list[dict]:
    """
    Flatten findings from parallel scan results.

    Each ScanResult.data can be:
      - A dict (single finding)
      - A list of dicts (multiple findings)
      - None / empty (no finding)

    Returns a deduplicated list of finding dicts.
    """
    findings: list[dict] = []
    seen: set[str] = set()

    for result in results:
        if not result.success or result.data is None:
            continue

        items = result.data if isinstance(result.data, list) else [result.data]
        for item in items:
            if not isinstance(item, dict):
                continue
            # Deduplicate by vuln_id + evidence (first 100 chars)
            key = f"{item.get('vuln_id', '')}-{str(item.get('evidence', ''))[:100]}"
            if key not in seen:
                seen.add(key)
                findings.append(item)

    return findings
