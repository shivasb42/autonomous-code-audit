"""Local review page: `audit-agent ui` serves projects, their apps and task queues, and each
project's API map on 127.0.0.1 only. Everything shown is read from the audit database. The page
can also send tasks to Claude (see runner), which investigates them with read-only tools, and send
findings that have a GitHub issue to be reproduced with a test (see reproduce).

Write requests must send the `X-Audit-Agent` header and a JSON body. Browsers will not send a
custom header cross-origin without a CORS preflight, which this server never approves, so other
websites cannot change tasks. The Host header is checked to block DNS-rebinding attacks.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import traceback
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from audit_agent import batches, credentials, github_issues, pull_requests, review, store, views
from audit_agent.fix import FixSettings
from audit_agent.investigate import AgentSettings, InvestigationError
from audit_agent.reproduce import ReproduceSettings
from audit_agent.runner import FixRunner, ReproductionRunner, Runner, print_log

PAGE = Path(__file__).with_name("web") / "index.html"
WRITE_HEADER = "X-Audit-Agent"
MAX_BODY_BYTES = 1_000_000


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status


def _filter_from(params: dict) -> review.TaskFilter:
    def one(name: str) -> str | None:
        value = params.get(name)
        if isinstance(value, list):
            value = value[0] if value else None
        return value or None

    try:
        return review.TaskFilter(one("status"), one("folder"), one("tests"), one("search"), one("app"), one("kind"),
                                 one("api"))
    except ValueError as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc


def _ids(body: dict) -> list[int]:
    ids = body.get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids):
        raise ApiError(HTTPStatus.BAD_REQUEST, "body must include 'ids', a list of task ids")
    return ids


def _audits(conn: sqlite3.Connection) -> list[dict]:
    rows = []
    for audit in store.list_audits(conn):
        counts = dict(
            conn.execute(
                "SELECT status, COUNT(*) FROM audit_tasks WHERE audit_id = ? GROUP BY status", (audit["id"],)
            ).fetchall()
        )
        rows.append(
            {
                "id": audit["id"],
                "repo_name": audit["repo_name"],
                "repo_path": audit["repo_path"],
                "status": audit["status"],
                "commit": (audit["head_commit"] or "")[:12],
                "task_counts": {s: counts.get(s, 0) for s in store.TASK_STATUSES},
            }
        )
    return rows


def _audit_tasks(conn: sqlite3.Connection, audit_id: int, params: dict) -> dict:
    tasks = review.find_tasks(conn, audit_id, _filter_from(params))
    everything = review.find_tasks(conn, audit_id, review.TaskFilter(app=_filter_from(params).app))
    counts = {s: 0 for s in store.TASK_STATUSES}
    for task in everything:
        counts[task["status"]] += 1
    in_batch = store.batched_task_ids(conn)
    found = {
        r["task_id"]: (r["n"], r["without_issue"])
        for r in conn.execute(
            """SELECT f.task_id, COUNT(*) AS n, SUM(f.issue_url IS NULL) AS without_issue
               FROM findings f JOIN audit_tasks t ON t.id = f.task_id
               WHERE t.audit_id = ? AND f.duplicate_of IS NULL GROUP BY f.task_id""",
            (audit_id,),
        )
    }
    return {
        "audit_id": audit_id,
        "total": len(everything),
        "counts": counts,
        "tasks": [
            {**{k: t[k] for k in ("id", "title", "status", "priority", "priority_reason", "line_count", "file_count",
                                  "test_only", "app_root", "kind", "api_covered", "api_task_ids")},
             "in_batch": t["id"] in in_batch,
             "findings": found.get(t["id"], (0, 0))[0],
             "findings_without_issue": found.get(t["id"], (0, 0))[1]}
            for t in tasks
        ],
        "not_covered": [dict(r) for r in store.not_covered(conn, audit_id)],
    }


def _send_to_claude(server: "ReviewServer", body: dict) -> dict:
    """Queue tasks for Claude: the given ids, or every pending task in an audit matching a filter."""
    if "parallel" in body:
        try:
            server.runner.set_parallel(int(body["parallel"]))
        except (TypeError, ValueError) as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc
    if isinstance(body.get("audit_id"), int):
        result = server.runner.submit_matching(body["audit_id"], _filter_from(body.get("filter") or {}))
    else:
        result = server.runner.submit(_ids(body))
    return {**result, "status": server.runner.status()}


def _batch_status(server: "ReviewServer", conn: sqlite3.Connection) -> dict:
    return {
        "available": credentials.get_api_key() is not None,
        "batches": batches.batch_rows(conn),
        "last_checked": server.poller.last_checked,
        "last_error": server.poller.last_error,
    }


def _batch_call(server: "ReviewServer", conn: sqlite3.Connection, action) -> dict:
    try:
        result = action()
    except batches.BatchError as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc
    except InvestigationError as exc:
        raise ApiError(HTTPStatus.BAD_GATEWAY, str(exc)) from exc
    return {"result": result, **_batch_status(server, conn)}


def _send_batch(server: "ReviewServer", conn: sqlite3.Connection, body: dict) -> dict:
    if isinstance(body.get("audit_id"), int):
        found = review.find_tasks(conn, body["audit_id"], _filter_from(body.get("filter") or {}))
        ids = [t["id"] for t in found if t["status"] == "pending"]
    else:
        ids = _ids(body)
    return _batch_call(server, conn, lambda: batches.submit(
        conn, ids, server.runner.settings.model, exclude=server.runner.busy_ids(), log=server.runner.log
    ))


def _create_issues(server: "ReviewServer", conn: sqlite3.Connection, task_id: int, body: dict) -> dict:
    finding_ids = body.get("finding_ids")
    if finding_ids is not None and (not isinstance(finding_ids, list) or not all(isinstance(i, int) for i in finding_ids)):
        raise ApiError(HTTPStatus.BAD_REQUEST, "finding_ids must be a list of finding ids")
    try:
        result = github_issues.create(conn, task_id, finding_ids, log=server.runner.log)
    except github_issues.IssueError as exc:
        raise ApiError(HTTPStatus.BAD_GATEWAY, str(exc)) from exc
    return {**result, "preview": github_issues.preview(conn, task_id)}


def _reproduce(queue: ReproductionRunner, body: dict) -> dict:
    if "parallel" in body:
        try:
            queue.set_parallel(int(body["parallel"]))
        except (TypeError, ValueError) as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc
    ids = body.get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids):
        raise ApiError(HTTPStatus.BAD_REQUEST, "body must include 'ids', a list of finding ids")
    return {**queue.submit(ids), "status": queue.status()}


def _open_all_prs(server: "ReviewServer", conn: sqlite3.Connection) -> dict:
    return {**pull_requests.open_all(conn, log=server.runner.log), "preview": pull_requests.preview_all(conn)}


def _open_pr(server: "ReviewServer", conn: sqlite3.Connection, attempt_id: int) -> dict:
    try:
        return pull_requests.open_pr(conn, attempt_id, log=server.runner.log)
    except pull_requests.PullRequestError as exc:
        raise ApiError(HTTPStatus.BAD_GATEWAY, str(exc)) from exc


def _create_all_issues(server: "ReviewServer", conn: sqlite3.Connection) -> dict:
    result = github_issues.create_all(conn, log=server.runner.log)
    return {**result, "preview": github_issues.preview_all(conn)}


ROUTES_GET = [
    (re.compile(r"^/api/issues$"), lambda s, conn, m, q: github_issues.preview_all(conn)),
    (re.compile(r"^/api/tasks/(\d+)/issues$"), lambda s, conn, m, q: github_issues.preview(conn, int(m[1]))),
    (re.compile(r"^/api/batches$"), lambda s, conn, m, q: _batch_status(s, conn)),
    (re.compile(r"^/api/projects$"), lambda s, conn, m, q: views.project_overview(conn)),
    (re.compile(r"^/api/projects/(\d+)/api-map$"), lambda s, conn, m, q: views.api_map_view(conn, int(m[1]))),
    (re.compile(r"^/api/audits$"), lambda s, conn, m, q: _audits(conn)),
    (re.compile(r"^/api/audits/(\d+)/tasks$"), lambda s, conn, m, q: _audit_tasks(conn, int(m[1]), q)),
    (re.compile(r"^/api/tasks/(\d+)$"), lambda s, conn, m, q: views.task_detail(conn, int(m[1]))),
    (re.compile(r"^/api/run$"), lambda s, conn, m, q: s.runner.status()),
    (re.compile(r"^/api/findings$"), lambda s, conn, m, q: views.findings_overview(conn)),
    (re.compile(r"^/api/findings/(\d+)$"), lambda s, conn, m, q: views.finding_detail(conn, int(m[1]))),
    (re.compile(r"^/api/reproduce$"), lambda s, conn, m, q: s.reproducer.status()),
    (re.compile(r"^/api/fix$"), lambda s, conn, m, q: s.fixer.status()),
    (re.compile(r"^/api/fixes/(\d+)/pr$"), lambda s, conn, m, q: pull_requests.preview(conn, int(m[1]))),
    (re.compile(r"^/api/prs$"), lambda s, conn, m, q: pull_requests.preview_all(conn)),
]

ROUTES_POST = [
    (re.compile(r"^/api/tasks/cancel$"), lambda s, conn, m, b: {"changed": review.cancel_tasks(conn, _ids(b))}),
    (re.compile(r"^/api/tasks/restore$"), lambda s, conn, m, b: {"changed": review.restore_tasks(conn, _ids(b))}),
    (
        re.compile(r"^/api/audits/(\d+)/cancel$"),
        lambda s, conn, m, b: {"changed": review.cancel_matching(conn, int(m[1]), _filter_from(b.get("filter") or {}))},
    ),
    (
        re.compile(r"^/api/audits/(\d+)/restore$"),
        lambda s, conn, m, b: {"changed": review.restore_matching(conn, int(m[1]), _filter_from(b.get("filter") or {}))},
    ),
    (re.compile(r"^/api/run$"), lambda s, conn, m, b: _send_to_claude(s, b)),
    (re.compile(r"^/api/run/stop$"), lambda s, conn, m, b: {"dropped": s.runner.stop(), "status": s.runner.status()}),
    (re.compile(r"^/api/reproduce$"), lambda s, conn, m, b: _reproduce(s.reproducer, b)),
    (re.compile(r"^/api/reproduce/stop$"),
     lambda s, conn, m, b: {"dropped": s.reproducer.stop(), "status": s.reproducer.status()}),
    (re.compile(r"^/api/fix$"), lambda s, conn, m, b: _reproduce(s.fixer, b)),
    (re.compile(r"^/api/fix/stop$"), lambda s, conn, m, b: {"dropped": s.fixer.stop(), "status": s.fixer.status()}),
    (re.compile(r"^/api/fixes/(\d+)/pr$"), lambda s, conn, m, b: _open_pr(s, conn, int(m[1]))),
    (re.compile(r"^/api/prs$"), lambda s, conn, m, b: _open_all_prs(s, conn)),
    (re.compile(r"^/api/issues$"), lambda s, conn, m, b: _create_all_issues(s, conn)),
    (re.compile(r"^/api/tasks/(\d+)/issues$"), lambda s, conn, m, b: _create_issues(s, conn, int(m[1]), b)),
    (re.compile(r"^/api/batches$"), lambda s, conn, m, b: _send_batch(s, conn, b)),
    (re.compile(r"^/api/batches/check$"), lambda s, conn, m, b: _batch_call(s, conn, s.poller.check_now)),
    (re.compile(r"^/api/batches/recover$"),
     lambda s, conn, m, b: _batch_call(s, conn, lambda: batches.recover(conn, log=s.runner.log))),
    (re.compile(r"^/api/batches/(\d+)/cancel$"),
     lambda s, conn, m, b: _batch_call(s, conn, lambda: batches.cancel(conn, int(m[1]), log=s.runner.log))),
]


class ReviewHandler(BaseHTTPRequestHandler):
    server: "ReviewServer"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, data: object) -> None:
        self._send(status, json.dumps(data).encode(), "application/json")

    def _host_allowed(self) -> bool:
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _fail(self, status: HTTPStatus, message: str) -> None:
        print_log(f"{self.command} {self.path} -> {status.value}: {message}")
        self._json(status, {"error": message})

    def _dispatch(self, routes, path: str, payload) -> None:
        for pattern, handler in routes:
            if match := pattern.match(path):
                conn = store.connect(self.server.db_path)
                try:
                    self._json(HTTPStatus.OK, handler(self.server, conn, match, payload))
                except ApiError as exc:
                    self._fail(exc.status, str(exc))
                except store.StoreError as exc:
                    self._fail(HTTPStatus.NOT_FOUND, str(exc))
                except Exception as exc:
                    traceback.print_exc()
                    self._fail(HTTPStatus.INTERNAL_SERVER_ERROR, f"{exc.__class__.__name__}: {exc}")
                finally:
                    conn.close()
                return
        self._fail(HTTPStatus.NOT_FOUND, f"no route for {path}")

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_allowed():
            return self._json(HTTPStatus.FORBIDDEN, {"error": "unexpected Host header"})
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            return self._send(HTTPStatus.OK, PAGE.read_bytes(), "text/html; charset=utf-8")
        self._dispatch(ROUTES_GET, url.path, parse_qs(url.query))

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_allowed():
            return self._json(HTTPStatus.FORBIDDEN, {"error": "unexpected Host header"})
        if self.headers.get(WRITE_HEADER) != "1" or not self.headers.get("Content-Type", "").startswith(
            "application/json"
        ):
            return self._json(HTTPStatus.FORBIDDEN, {"error": f"write requests need {WRITE_HEADER}: 1 and a JSON body"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "body is not valid JSON"})
        if not isinstance(body, dict):
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "body must be a JSON object"})
        self._dispatch(ROUTES_POST, urlparse(self.path).path, body)


class ReviewServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, db_path: Path, port: int = 8765, runner: Runner | None = None,
                 reproducer: ReproductionRunner | None = None, fixer: FixRunner | None = None):
        self.db_path = db_path
        self.runner = runner or Runner(db_path, AgentSettings())
        self.reproducer = reproducer or ReproductionRunner(
            db_path, ReproduceSettings(model=self.runner.settings.model), log=self.runner.log)
        self.fixer = fixer or FixRunner(db_path, FixSettings(model=self.runner.settings.model), log=self.runner.log)
        self.poller = batches.Poller(db_path, log=self.runner.log)
        super().__init__(("127.0.0.1", port), ReviewHandler)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/"


def _safe_check(server: "ReviewServer") -> None:
    try:
        server.poller.check_now()
    except Exception as exc:
        print_log(f"Checking batches failed: {exc}")


def serve(db_path: Path, port: int, open_browser: bool, settings: AgentSettings | None = None, parallel: int = 2) -> None:
    conn = store.connect(db_path)
    try:
        if interrupted := store.fail_interrupted_runs(conn):
            print(f"Marked {interrupted} interrupted investigation(s) as failed; they can be sent to Claude again.",
                  flush=True)
        if interrupted := store.fail_interrupted_verifications(conn):
            print(f"Marked {interrupted} interrupted reproduction(s) as failed; they can be started again.", flush=True)
        if interrupted := store.fail_interrupted_fixes(conn):
            print(f"Marked {interrupted} interrupted fix attempt(s) as failed; they can be started again.", flush=True)
    finally:
        conn.close()
    server = ReviewServer(db_path, port, Runner(db_path, settings or AgentSettings(), parallel))
    print(f"Task review page: {server.url}  (Ctrl+C to stop)", flush=True)
    print(f"Tasks sent to Claude run {server.runner.parallel} at a time using {server.runner.status()['runner']}.",
          flush=True)
    print(f"Findings sent to reproduce (Findings tab) run {server.reproducer.parallel} at a time using "
          f"{server.reproducer.runner_label()}.", flush=True)
    server.poller.start()
    conn = store.connect(db_path)
    try:
        open_batches = store.list_batches(conn, store.OPEN_BATCH_STATUSES)
    finally:
        conn.close()
    if open_batches:
        print(f"{len(open_batches)} Claude batch(es) still open; checking them every minute.", flush=True)
        if credentials.get_api_key():
            threading.Thread(target=lambda: _safe_check(server), daemon=True).start()
    if open_browser:
        webbrowser.open(server.url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
