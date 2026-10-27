"""Reviewing an audit's tasks before they run: filtering, cancelling, and restoring."""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from audit_agent import store
from audit_agent.inventory.languages import is_test_path

CANCELLABLE_STATUSES = ("pending", "blocked", "failed")
TEST_FILTERS = ("only", "hide")
# File tasks by how many of their files a finished API-call task already looked at.
API_FILTERS = ("all", "some", "none")


@dataclass(frozen=True)
class TaskFilter:
    status: str | None = None
    folder: str | None = None
    tests: str | None = None
    search: str | None = None
    app: str | None = None
    kind: str | None = None
    api: str | None = None

    def __post_init__(self) -> None:
        if self.status and self.status not in store.TASK_STATUSES:
            raise ValueError(f"unknown status {self.status!r}")
        if self.kind and self.kind not in store.TASK_KINDS:
            raise ValueError(f"kind must be one of {store.TASK_KINDS}")
        if self.tests and self.tests not in TEST_FILTERS:
            raise ValueError(f"tests must be one of {TEST_FILTERS}")
        if self.api and self.api not in API_FILTERS:
            raise ValueError(f"api must be one of {API_FILTERS}")


def api_coverage(conn: sqlite3.Connection, audit_id: int) -> dict[int, dict]:
    """For each file task of the audit, which of its files a finished API-call task already looked at (from any
    app of the project), and which API tasks those were. An API task reads a file to check one call, so this
    means "looked at for that call", not that the whole file was audited."""
    coverage: dict[int, dict] = {}
    for row in conn.execute(
        """SELECT tf.task_id, tf.path, af.task_id AS api_task_id
           FROM audit_task_files tf
           JOIN api_task_files af ON af.audit_id = tf.audit_id AND af.path = tf.path
           JOIN audit_tasks t ON t.id = af.task_id AND t.kind = 'api' AND t.status = 'done'
           WHERE tf.audit_id = ?""",
        (audit_id,),
    ):
        entry = coverage.setdefault(row["task_id"], {"paths": set(), "api_task_ids": set()})
        entry["paths"].add(row["path"])
        entry["api_task_ids"].add(row["api_task_id"])
    return coverage


def _task_files(conn: sqlite3.Connection, audit_id: int) -> dict[int, list[str]]:
    files: dict[int, list[str]] = defaultdict(list)
    for row in conn.execute(
        """SELECT task_id, path FROM audit_task_files WHERE audit_id = ?
           UNION ALL
           SELECT af.task_id, af.path FROM api_task_files af JOIN audit_tasks t ON t.id = af.task_id
           WHERE t.audit_id = ? AND af.audit_id = t.audit_id
           ORDER BY path""",
        (audit_id, audit_id),
    ):
        files[row["task_id"]].append(row["path"])
    return files


def task_apps(conn: sqlite3.Connection, audit_id: int) -> dict[int, str | None]:
    """The app root each task belongs to: the app holding most of its files (planning keeps a
    task's files inside one package, so in practice all of them). None for audits without apps."""
    best: dict[int, tuple[int, str | None]] = {}
    for row in conn.execute(
        """SELECT tf.task_id, f.app_root, COUNT(*) AS n FROM audit_task_files tf
           JOIN inventory_files f ON f.audit_id = tf.audit_id AND f.path = tf.path
           WHERE tf.audit_id = ? GROUP BY tf.task_id, f.app_root""",
        (audit_id,),
    ):
        if row["task_id"] not in best or row["n"] > best[row["task_id"]][0]:
            best[row["task_id"]] = (row["n"], row["app_root"])
    apps = {task_id: root for task_id, (_, root) in best.items()}
    for row in conn.execute("SELECT id, app_root FROM audit_tasks WHERE audit_id = ? AND kind = 'api'", (audit_id,)):
        apps[row["id"]] = row["app_root"]
    return apps


def _matches(task: dict, files: list[str], f: TaskFilter) -> bool:
    if f.app and task["app_root"] != f.app:
        return False
    if f.kind and task["kind"] != f.kind:
        return False
    if f.status and task["status"] != f.status:
        return False
    if f.folder:
        prefix = f.folder.strip("/") + "/"
        # Every file must be under the folder, so a bulk cancel never catches code outside it.
        if not files or not all(p.startswith(prefix) for p in files):
            return False
    if f.tests == "only" and not task["test_only"]:
        return False
    if f.tests == "hide" and task["test_only"]:
        return False
    if f.search:
        needle = f.search.lower()
        if needle not in task["title"].lower() and not any(needle in p.lower() for p in files):
            return False
    if f.api:
        if task["kind"] != "files":
            return False
        seen, total = task["api_covered"], len(files)
        if (f.api == "all" and not (total and seen == total)) or (f.api == "some" and not 0 < seen < total) \
                or (f.api == "none" and seen):
            return False
    return True


def find_tasks(conn: sqlite3.Connection, audit_id: int, f: TaskFilter = TaskFilter()) -> list[dict]:
    """Tasks matching the filter, highest priority first, each with its files and a test-only flag."""
    store.get_audit(conn, audit_id)
    files = _task_files(conn, audit_id)
    apps = task_apps(conn, audit_id)
    coverage = api_coverage(conn, audit_id)
    found = []
    for row in store.list_tasks(conn, audit_id):
        task = dict(row)
        task_paths = files.get(task["id"], [])
        task["files"] = task_paths
        task["app_root"] = apps.get(task["id"])
        task["test_only"] = bool(task_paths) and all(is_test_path(p) for p in task_paths)
        seen = coverage.get(task["id"]) if task["kind"] == "files" else None
        task["api_covered"] = len(seen["paths"]) if seen else 0
        task["api_task_ids"] = sorted(seen["api_task_ids"]) if seen else []
        if _matches(task, task_paths, f):
            found.append(task)
    return found


def _set_status(conn: sqlite3.Connection, task_ids: list[int], new: str, allowed: tuple[str, ...]) -> int:
    if not task_ids:
        return 0
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    marks = ",".join("?" * len(task_ids))
    allowed_marks = ",".join("?" * len(allowed))
    with conn:
        cursor = conn.execute(
            f"UPDATE audit_tasks SET status = ?, updated_at = ? "
            f"WHERE id IN ({marks}) AND status IN ({allowed_marks})",
            (new, now, *task_ids, *allowed),
        )
    return cursor.rowcount


def cancel_tasks(conn: sqlite3.Connection, task_ids: list[int]) -> int:
    """Cancel tasks so they are never sent to Claude. Done and running tasks are left alone.
    Returns how many tasks changed."""
    return _set_status(conn, task_ids, "cancelled", CANCELLABLE_STATUSES)


def restore_tasks(conn: sqlite3.Connection, task_ids: list[int]) -> int:
    """Put cancelled tasks back in the queue as pending. Returns how many tasks changed."""
    return _set_status(conn, task_ids, "pending", ("cancelled",))


def cancel_matching(conn: sqlite3.Connection, audit_id: int, f: TaskFilter) -> int:
    return cancel_tasks(conn, [t["id"] for t in find_tasks(conn, audit_id, f)])


def restore_matching(conn: sqlite3.Connection, audit_id: int, f: TaskFilter) -> int:
    return restore_tasks(conn, [t["id"] for t in find_tasks(conn, audit_id, f)])
