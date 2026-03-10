
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


@dataclass
class ScanTask:
    task_id: str
    func: Callable[..., Any]
    args: tuple = ()
    kwargs: dict[str, Any] = field(default_factory=dict)
    label: str = ""


@dataclass
class ScanResult:
    task_id: str
    success: bool = True
    data: Any = None
    error: str | None = None
    duration: float = 0.0


class ParallelEngine:

    def __init__(
        self,
        max_workers: int = 20,
        rate_limit: float = 0.0,
        show_progress: bool = True,
    ) -> None:
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.show_progress = show_progress
        self._lock = threading.Lock()
        self._last_start = 0.0

    def _rate_wait(self) -> None:
        if self.rate_limit <= 0:
            return
        with self._lock:
            now = time.time()
            elapsed = now - self._last_start
            if elapsed < self.rate_limit:
                time.sleep(self.rate_limit - elapsed)
            self._last_start = time.time()

    def _execute_task(self, task: ScanTask) -> ScanResult:
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
        if not tasks:
            return []

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

        return [results[task.task_id] for task in tasks if task.task_id in results]


def parallel_url_scan(
    urls: list[str],
    scan_func: Callable[[str], Any],
    max_workers: int = 15,
    rate_limit: float = 0.05,
    label: str = "URL Scanning",
    show_progress: bool = True,
) -> list[ScanResult]:
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
    findings: list[dict] = []
    seen: set[str] = set()

    for result in results:
        if not result.success or result.data is None:
            continue

        items = result.data if isinstance(result.data, list) else [result.data]
        for item in items:
            if not isinstance(item, dict):
                continue
            key = f"{item.get('vuln_id', '')}-{str(item.get('evidence', ''))[:100]}"
            if key not in seen:
                seen.add(key)
                findings.append(item)

    return findings
