"""Send tasks to Claude from the review page: a queue worked through a few at a time.

Investigations only read code, so several run at once, up to a limit. Each run claims its task
when it starts (see store.start_run), a failure is recorded without stopping the rest, and a
Claude usage or rate limit makes that task wait and retry instead of failing the audit.
"""

from __future__ import annotations

import re
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from audit_agent import credentials, fix, pull_requests, reproduce, review, store
from audit_agent import investigate as investigation

MAX_PARALLEL = 8
RATE_LIMITED = re.compile(r"rate.?limit|usage limit|\b429\b|overloaded|\b529\b", re.I)
RETRY_WAITS_S = (60, 300, 900)
KEEP_FINISHED = 100


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def print_log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


class Runner:
    def __init__(self, db_path: Path, settings: investigation.AgentSettings, parallel: int = 2, investigate_fn=None,
                 log=print_log):
        self.db_path = db_path
        self.settings = settings
        self.parallel = max(1, min(parallel, MAX_PARALLEL))
        self.investigate_fn = investigate_fn or investigation.investigate
        self.log = log
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._queue: deque[int] = deque()
        self._titles: dict[int, str] = {}
        self._running: dict[int, str] = {}
        self._waiting: dict[int, str] = {}
        self._finished: deque[dict] = deque(maxlen=KEEP_FINISHED)
        self._workers = 0

    def set_parallel(self, parallel: int) -> None:
        if not 1 <= parallel <= MAX_PARALLEL:
            raise ValueError(f"parallel must be between 1 and {MAX_PARALLEL}")
        with self._lock:
            self.parallel = parallel
        self._spawn()

    def submit(self, task_ids: list[int]) -> dict:
        """Queue tasks that can run (pending, failed, or blocked). Returns what was queued and
        why the others were skipped."""
        queued, skipped = [], []
        conn = store.connect(self.db_path)
        try:
            for task_id in dict.fromkeys(task_ids):
                try:
                    task = store.get_task(conn, task_id)
                except store.StoreError:
                    skipped.append({"id": task_id, "reason": "no such task"})
                    continue
                in_batch = store.task_in_open_batch(conn, task_id)
                with self._lock:
                    if task_id in self._running or task_id in self._waiting or task_id in self._queue:
                        skipped.append({"id": task_id, "reason": "already sent"})
                    elif in_batch:
                        skipped.append({"id": task_id, "reason": "waiting in a batch"})
                    elif task["status"] not in investigation.RUNNABLE_STATUSES:
                        skipped.append({"id": task_id, "reason": f"task is {task['status']}"})
                    else:
                        self._queue.append(task_id)
                        self._titles[task_id] = task["title"]
                        queued.append(task_id)
        finally:
            conn.close()
        if queued or skipped:
            self.log(
                f"Queued {len(queued)} task(s) for Claude ({investigation.runner_label(self.settings)}, "
                f"{self.parallel} at a time)" + (f"; skipped {len(skipped)}: " + ", ".join(
                    f"#{s['id']} {s['reason']}" for s in skipped[:10]) if skipped else "")
            )
        if queued:
            self._stop.clear()
            self._spawn()
        return {"queued": queued, "skipped": skipped}

    def submit_matching(self, audit_id: int, task_filter: review.TaskFilter) -> dict:
        """Queue every pending task that matches the filter."""
        conn = store.connect(self.db_path)
        try:
            ids = [t["id"] for t in review.find_tasks(conn, audit_id, task_filter) if t["status"] == "pending"]
        finally:
            conn.close()
        return self.submit(ids)

    def busy_ids(self) -> set[int]:
        with self._lock:
            return set(self._queue) | set(self._running) | set(self._waiting)

    def stop(self) -> int:
        """Drop queued tasks and stop waiting retries. Investigations already running finish."""
        with self._lock:
            dropped = len(self._queue)
            self._queue.clear()
        self._stop.set()
        self.log(f"Stopped the queue: dropped {dropped} queued task(s); running ones will finish")
        return dropped

    def status(self) -> dict:
        with self._lock:
            return {
                "runner": investigation.runner_label(self.settings),
                "parallel": self.parallel,
                "active": bool(self._queue or self._running or self._waiting),
                "queued": [{"id": i, "title": self._titles.get(i, "")} for i in self._queue],
                "running": [{"id": i, "title": t} for i, t in self._running.items()],
                "waiting": [{"id": i, "title": self._titles.get(i, ""), "reason": r} for i, r in self._waiting.items()],
                "finished": list(reversed(self._finished)),
            }

    def wait_idle(self, timeout: float) -> bool:
        """Wait until nothing is queued, running, or waiting, and every worker has exited."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if not (self._queue or self._running or self._waiting or self._workers):
                    return True
            time.sleep(0.05)
        return False

    def _spawn(self) -> None:
        with self._lock:
            starting = max(0, min(self.parallel - self._workers, len(self._queue)))
            self._workers += starting
        for _ in range(starting):
            threading.Thread(target=self._work, daemon=True).start()

    def _work(self) -> None:
        conn = store.connect(self.db_path)
        try:
            while True:
                with self._lock:
                    if not self._queue or self._workers > self.parallel:
                        self._workers -= 1
                        return
                    task_id = self._queue.popleft()
                    self._running[task_id] = self._titles.get(task_id, "")
                self._run_one(conn, task_id)
        except BaseException:
            with self._lock:
                self._workers -= 1
            raise
        finally:
            conn.close()

    def _run_one(self, conn, task_id: int) -> None:
        started = _now()
        for attempt in range(len(RETRY_WAITS_S) + 1):
            self.log(f"Task #{task_id} started: {self._titles.get(task_id, '')}")
            try:
                summary = self.investigate_fn(conn, task_id, self.settings)
            except Exception as exc:
                message = str(exc)
                if RATE_LIMITED.search(message) and attempt < len(RETRY_WAITS_S) and not self._stop.is_set():
                    wait = RETRY_WAITS_S[attempt]
                    self.log(f"Task #{task_id} hit a Claude rate limit; retrying in {wait}s: {message[:200]}")
                    with self._lock:
                        self._running.pop(task_id, None)
                        self._waiting[task_id] = f"Claude is rate limited; retrying in {wait // 60} min"
                    stopped = self._stop.wait(wait)
                    with self._lock:
                        self._waiting.pop(task_id, None)
                        if not stopped:
                            self._running[task_id] = self._titles.get(task_id, "")
                    if stopped:
                        self._finish(task_id, started, "failed", f"Stopped while waiting to retry. {message}")
                        return
                    continue
                self._finish(task_id, started, "failed", message)
                return
            self._finish(task_id, started, "done", None, summary)
            return

    def _finish(self, task_id: int, started: str, status: str, error: str | None, summary: dict | None = None) -> None:
        if status == "done":
            cost = (summary or {}).get("cost_usd")
            duplicates = (summary or {}).get("duplicates") or 0
            self.log(f"Task #{task_id} done: {(summary or {}).get('findings', 0)} findings, "
                     f"{(summary or {}).get('needs_review', 0)} to review"
                     + (f", {duplicates} already known" if duplicates else "")
                     + (f", ${cost:.2f}" if cost is not None else ""))
        else:
            self.log(f"Task #{task_id} failed: {(error or '')[:500]}")
        with self._lock:
            self._running.pop(task_id, None)
            self._finished.append({
                "id": task_id,
                "title": self._titles.get(task_id, ""),
                "status": status,
                "error": error,
                "findings": (summary or {}).get("findings"),
                "needs_review": (summary or {}).get("needs_review"),
                "cost_usd": (summary or {}).get("cost_usd"),
                "started_at": started,
                "finished_at": _now(),
            })


MAX_REPRODUCE_PARALLEL = 4
LOG_LINES = 6


class ReproductionRunner:
    """Reproduce findings picked on the review page, a few at a time. Only findings that have a GitHub
    issue are accepted. A test run of a large backend can use about 3 GB of memory, so at most
    MAX_REPRODUCE_PARALLEL run at once."""

    def __init__(self, db_path: Path, settings: reproduce.ReproduceSettings | None = None, parallel: int = 2,
                 reproduce_fn=None, log=print_log):
        self.db_path = db_path
        self.settings = settings or reproduce.ReproduceSettings()
        self.parallel = max(1, min(parallel, MAX_REPRODUCE_PARALLEL))
        self.reproduce_fn = reproduce_fn or reproduce.reproduce
        self.log = log
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._queue: deque[int] = deque()
        self._titles: dict[int, str] = {}
        self._running: dict[int, str] = {}
        self._waiting: dict[int, str] = {}
        self._notes: dict[int, deque] = {}
        self._finished: deque[dict] = deque(maxlen=KEEP_FINISHED)
        self._workers = 0

    verb, past_tense, result_key = "reproduce", "reproduced", "verdict"

    def _running_elsewhere(self, conn, finding_id: int) -> bool:
        return any(v["status"] == "running" for v in store.list_verifications(conn, finding_id=finding_id))

    def set_parallel(self, parallel: int) -> None:
        if not 1 <= parallel <= MAX_REPRODUCE_PARALLEL:
            raise ValueError(f"at a time must be between 1 and {MAX_REPRODUCE_PARALLEL} for reproductions")
        with self._lock:
            self.parallel = parallel
        self._spawn()

    def runner_label(self) -> str:
        return "Anthropic API (saved key)" if credentials.get_api_key() else "no Anthropic API key (run audit-agent set-api-key)"

    def submit(self, finding_ids: list[int]) -> dict:
        queued, skipped = [], []
        if finding_ids and not credentials.get_api_key():
            return {"queued": [], "skipped": [{"id": i, "reason": "no Anthropic API key (audit-agent set-api-key)"}
                                              for i in finding_ids]}
        conn = store.connect(self.db_path)
        try:
            for finding_id in dict.fromkeys(finding_ids):
                try:
                    finding = store.get_finding(conn, finding_id)
                except store.StoreError:
                    skipped.append({"id": finding_id, "reason": "no such finding"})
                    continue
                elsewhere = self._running_elsewhere(conn, finding_id)
                with self._lock:
                    if finding_id in self._running or finding_id in self._waiting or finding_id in self._queue:
                        skipped.append({"id": finding_id, "reason": "already sent"})
                    elif finding["kind"] != "finding":
                        skipped.append({"id": finding_id, "reason": "needs-review items aren't reproduced"})
                    elif not finding["issue_url"]:
                        skipped.append({"id": finding_id, "reason": "needs a GitHub issue first"})
                    elif elsewhere:
                        skipped.append({"id": finding_id, "reason": f"already being {self.past_tense}"})
                    else:
                        self._queue.append(finding_id)
                        self._titles[finding_id] = finding["title"]
                        queued.append(finding_id)
        finally:
            conn.close()
        if queued or skipped:
            self.log(f"Queued {len(queued)} finding(s) to {self.verb} ({self.parallel} at a time)" + (
                f"; skipped {len(skipped)}: " + ", ".join(f"#{s['id']} {s['reason']}" for s in skipped[:10])
                if skipped else ""))
        if queued:
            self._stop.clear()
            self._spawn()
        return {"queued": queued, "skipped": skipped}

    def stop(self) -> int:
        """Drop queued findings and stop waiting retries. Reproductions already running finish."""
        with self._lock:
            dropped = len(self._queue)
            self._queue.clear()
        self._stop.set()
        self.log(f"Stopped the reproduction queue: dropped {dropped} queued finding(s); running ones will finish")
        return dropped

    def status(self) -> dict:
        s = self.settings
        with self._lock:
            return {
                "runner": self.runner_label(),
                "model": s.model or reproduce.api_runner.DEFAULT_MODEL,
                "limits": {"max_turns": s.max_turns, "max_cost_usd": s.max_cost_usd, "timeout_s": s.timeout_s},
                "parallel": self.parallel,
                "max_parallel": MAX_REPRODUCE_PARALLEL,
                "active": bool(self._queue or self._running or self._waiting),
                "queued": [{"id": i, "title": self._titles.get(i, "")} for i in self._queue],
                "running": [{"id": i, "title": t, "log": list(self._notes.get(i, []))} for i, t in self._running.items()],
                "waiting": [{"id": i, "title": self._titles.get(i, ""), "reason": r} for i, r in self._waiting.items()],
                "finished": list(reversed(self._finished)),
            }

    def wait_idle(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if not (self._queue or self._running or self._waiting or self._workers):
                    return True
            time.sleep(0.05)
        return False

    def _spawn(self) -> None:
        with self._lock:
            starting = max(0, min(self.parallel - self._workers, len(self._queue)))
            self._workers += starting
        for _ in range(starting):
            threading.Thread(target=self._work, daemon=True).start()

    def _work(self) -> None:
        conn = store.connect(self.db_path)
        try:
            while True:
                with self._lock:
                    if not self._queue or self._workers > self.parallel:
                        self._workers -= 1
                        return
                    finding_id = self._queue.popleft()
                    self._running[finding_id] = self._titles.get(finding_id, "")
                    self._notes[finding_id] = deque(maxlen=LOG_LINES)
                self._run_one(conn, finding_id)
        except BaseException:
            with self._lock:
                self._workers -= 1
            raise
        finally:
            conn.close()

    def _note(self, finding_id: int, message: str) -> None:
        self.log(f"Finding #{finding_id}: {message.strip()}")
        with self._lock:
            if finding_id in self._notes:
                self._notes[finding_id].append(message.strip())

    def _run_one(self, conn, finding_id: int) -> None:
        for attempt in range(len(RETRY_WAITS_S) + 1):
            self.log(f"Finding #{finding_id} started: {self._titles.get(finding_id, '')}")
            try:
                result = self.reproduce_fn(conn, finding_id, self.settings, log=lambda m: self._note(finding_id, m))
            except Exception as exc:
                message = str(exc)
                if RATE_LIMITED.search(message) and attempt < len(RETRY_WAITS_S) and not self._stop.is_set():
                    wait = RETRY_WAITS_S[attempt]
                    self.log(f"Finding #{finding_id} hit a Claude rate limit; retrying in {wait}s: {message[:200]}")
                    with self._lock:
                        self._running.pop(finding_id, None)
                        self._waiting[finding_id] = f"Claude is rate limited; retrying in {wait // 60} min"
                    stopped = self._stop.wait(wait)
                    with self._lock:
                        self._waiting.pop(finding_id, None)
                        if not stopped:
                            self._running[finding_id] = self._titles.get(finding_id, "")
                    if stopped:
                        return self._finish(finding_id, {"status": "failed", "error": f"Stopped while waiting to retry. {message}"})
                    continue
                return self._finish(finding_id, {"status": "failed", "error": message})
            return self._finish(finding_id, result)

    def _finish(self, finding_id: int, result: dict | None) -> None:
        result = result or {"status": "failed", "error": "The reproduction returned no result."}
        verdict, cost = result.get(self.result_key), result.get("cost_usd")
        if result.get("status") == "done":
            self.log(f"Finding #{finding_id} {verdict.replace('_', ' ')}" + (f", ${cost:.2f}" if cost is not None else "")
                     + f": {(result.get('reason') or '').splitlines()[0][:200] if result.get('reason') else ''}")
        else:
            self.log(f"Finding #{finding_id} failed: {(result.get('error') or '')[:500]}")
        with self._lock:
            self._running.pop(finding_id, None)
            self._notes.pop(finding_id, None)
            self._finished.append({
                "id": finding_id,
                "title": self._titles.get(finding_id, ""),
                "status": result.get("status"),
                "verdict": verdict,
                "reason": result.get("reason"),
                "error": result.get("error"),
                "cost_usd": cost,
                "verification_id": result.get("id"),
                "finished_at": _now(),
            })


class FixRunner(ReproductionRunner):
    """The "Reproduce + fix" queue: the same rules as reproductions (GitHub issue required, a few at a time),
    running fix.fix instead. Pull requests are never opened from here; the engineer opens each one. When an
    attempt ends rejected or unable, its issue gets a comment saying why there is no fix."""

    verb, past_tense, result_key = "reproduce and fix", "fixed", "outcome"

    def __init__(self, db_path: Path, settings: "fix.FixSettings | None" = None, parallel: int = 1, fix_fn=None,
                 log=print_log, comment_fn=None):
        super().__init__(db_path, settings or fix.FixSettings(), parallel, fix_fn or fix.fix, log)
        self.comment_fn = comment_fn or pull_requests.post_comment

    def _running_elsewhere(self, conn, finding_id: int) -> bool:
        return any(a["status"] == "running" for a in store.list_fixes(conn, finding_id))

    def _finish(self, finding_id: int, result: dict | None) -> None:
        super()._finish(finding_id, result)
        if not result or result.get("status") != "done" or result.get("outcome") not in ("fix_rejected", "unable"):
            return
        conn = store.connect(self.db_path)
        try:
            self.comment_fn(conn, result["id"], self.log)
        except Exception as exc:
            self.log(f"Finding #{finding_id}: commenting on its issue failed ({exc}); "
                     "post it later with: audit-agent fix-comments --post")
        finally:
            conn.close()
