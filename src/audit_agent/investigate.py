"""Run a Claude agent on one audit task and save what it finds.

The agent runs either through the Anthropic API (see api_runner) or through the `claude` CLI in
print mode, inside the task's repository, with read-only tools only. Its answer is validated
before anything is saved: a finding must cite a file and line that exist and quote code that is
actually there; otherwise it is downgraded to "needs review" or rejected.
"""

from __future__ import annotations


from typing import Literal



import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from audit_agent import store
from audit_agent.repo import open_repository

GENERAL_AGENT = "general"
READ_ONLY_TOOLS = "Read,Grep,Glob"
SECRET_PATTERNS = ("**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.jks", "**/*.keystore")
RUNNABLE_STATUSES = ("pending", "failed", "blocked")
BUG_TYPE_ALIASES = {"concurrency and reliability": "concurrency", "reliability": "concurrency", "race": "concurrency"}

CHECKLIST = """\
Security
- Missing or bypassable authentication/authorization (routes or screens reachable without the right checks, IDOR: acting on another user's resource by id)
- Trusting user input: injection (NoSQL/SQL/command/path), unvalidated redirects, mass assignment of request bodies into database writes
- Secrets or tokens exposed in code, logs, responses, or client bundles; insecure token storage
- Unsafe defaults: permissive CORS, missing rate limits on sensitive actions, webhook handlers that don't verify signatures

Logic
- Wrong conditions, inverted checks, off-by-one, wrong comparison or units
- Unhandled null/undefined/empty cases and missing error handling that leaves bad state
- Calls whose method, path, or payload don't match what the other side expects (use the API information below)
- State updates that can leave data inconsistent (partial writes, missing rollback, double counting)

Concurrency and reliability
- Race conditions on shared state or database documents (read-modify-write without atomic operations or locks)
- Missing await, fire-and-forget promises, unhandled rejections, async work in loops without limits
- Jobs, queues, cron, or sockets that can process the same item twice, never retry, or retry forever
- Timeouts, retries, and cleanup missing around network calls and external services
"""

RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "bug_type": {"type": "string", "enum": list[Literal['logic', 'security', 'concurrency']](store.BUG_TYPES)},
                    "severity": {"type": "string", "enum": list[Literal['low', 'medium', 'high', 'critical']](store.SEVERITIES)},
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "evidence": {"type": "string"},
                    "explanation": {"type": "string"},
                    "duplicate_of": {"type": "integer", "description": "Number of the already known finding this "
                                                                       "is the same bug as, if any"},
                },
                "required": ["title", "bug_type", "severity", "file", "line", "evidence", "explanation"],
            },
        },
        "needs_review": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "suspicion": {"type": "string"},
                    "files_examined": {"type": "array", "items": {"type": "string"}},
                    "why_unconfirmed": {"type": "string"},
                    "duplicate_of": {"type": "integer"},
                },
                "required": ["title", "suspicion", "why_unconfirmed"],
            },
        },
    },
    "required": ["findings", "needs_review"],
}


class InvestigationError(Exception):
    pass


RUNNERS = ("auto", "api", "cli")


@dataclass
class AgentSettings:
    executable: str = "claude"
    model: str | None = None
    max_turns: int = 40
    timeout_s: int = 900
    max_budget_usd: float | None = None
    runner: str = "auto"


@dataclass
class AgentResult:
    report: dict
    cost_usd: float | None
    duration_ms: int | None
    num_turns: int | None
    session_id: str | None
    raw: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def find_claude(settings: AgentSettings) -> str:
    executable = os.environ.get("AUDIT_AGENT_CLAUDE") or settings.executable
    resolved = shutil.which(executable) or (executable if Path(executable).is_file() else None)
    if not resolved:
        raise InvestigationError(
            "The `claude` command was not found. Install Claude Code (npm install -g @anthropic-ai/claude-code), "
            "run `claude` once to log in, or point AUDIT_AGENT_CLAUDE at it. "
            "Or save an Anthropic API key with `audit-agent set-api-key` to call the API directly."
        )
    return resolved


def claude_command(executable: str, settings: AgentSettings, secret_paths: list[Path], extra_dirs: list[Path]) -> list[str]:
    deny = ["mcp__*", "Bash", "Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch"]
    deny += [f"Read({pattern})" for pattern in SECRET_PATTERNS]
    deny += [f"Read(/{path})" for path in secret_paths]
    command = [
        executable,
        "-p",
        "--output-format", "json",
        "--json-schema", json.dumps(RESULT_SCHEMA),
        "--tools", READ_ONLY_TOOLS,
        "--allowedTools", READ_ONLY_TOOLS,
        "--disallowedTools", *deny,
        "--permission-mode", "dontAsk",
        "--strict-mcp-config",
        "--no-session-persistence",
        "--max-turns", str(settings.max_turns),
    ]
    for directory in extra_dirs:
        command += ["--add-dir", str(directory)]
    if settings.model:
        command += ["--model", settings.model]
    if settings.max_budget_usd:
        command += ["--max-budget-usd", str(settings.max_budget_usd)]
    return command


def _extract_report(data: dict) -> dict:
    report = data.get("structured_output")
    if isinstance(report, dict):
        return report
    text = data.get("result") or ""
    block = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    candidate = block.group(1) if block else text[text.find("{") : text.rfind("}") + 1]
    try:
        report = json.loads(candidate)
    except (json.JSONDecodeError, ValueError) as exc:
        raise InvestigationError(f"Claude's answer was not valid JSON: {text[:300]!r}") from exc
    if not isinstance(report, dict):
        raise InvestigationError("Claude's answer was not a JSON object")
    return report


def run_claude(prompt: str, repo_root: Path, settings: AgentSettings, secret_paths: list[Path], extra_dirs: list[Path]) -> AgentResult:
    command = claude_command(find_claude(settings), settings, secret_paths, extra_dirs)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command, input=prompt, cwd=repo_root, capture_output=True, text=True, timeout=settings.timeout_s
        )
    except subprocess.TimeoutExpired as exc:
        raise InvestigationError(f"Claude did not finish within {settings.timeout_s} seconds") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()[-800:]
        raise InvestigationError(f"claude exited with code {proc.returncode}: {detail}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise InvestigationError(f"claude did not return JSON output: {proc.stdout[:300]!r}") from exc
    if data.get("is_error"):
        raise InvestigationError(f"claude reported an error: {str(data.get('result'))[:500]}")
    return AgentResult(
        report=_extract_report(data),
        cost_usd=data.get("total_cost_usd"),
        duration_ms=data.get("duration_ms") or int((time.monotonic() - started) * 1000),
        num_turns=data.get("num_turns"),
        session_id=data.get("session_id"),
        raw=proc.stdout[-200_000:],
    )


API_CHECKLIST = """\
- Method and path: the caller's method and path, including path parameters (names, order, types), match the route
- Request: the body fields, query parameters, and headers the caller sends match what the handler reads and validates
  (names, types, required vs optional); nothing the handler needs is missing
- Authentication and authorization: whether the route requires a logged-in user or a role, whether the caller sends
  the token, and whether the handler checks that the user may act on the resource it receives by id
- Response: the fields and shapes the caller uses exist in what the handler returns, including on error; status codes
  the handler returns are handled by the caller
- Failure handling on the caller side: network errors, non-2xx responses, timeouts, and retries that could repeat a
  write
"""

RULES = """
Rules:
- Report only problems you can show in the code. For each finding, quote the exact code (1-10 lines, copied
  verbatim) from the file at the line you cite, and explain what goes wrong and when.
- If you suspect a problem but can't show it in the code (it depends on configuration, runtime data, or code you
  can't see), put it under "needs_review" with what you suspect and why you couldn't confirm it.
- Don't report style, formatting, naming, performance, missing tests, or TODO comments.
- If you find nothing, return empty lists. Don't invent problems to have something to report.
"""


def known_section(conn: sqlite3.Connection, task_id: int) -> str:
    """The findings already known in the task's files, so they aren't reported again."""
    known = store.known_findings(conn, task_id)
    if not known:
        return ""
    lines = []
    for k in known:
        label = f"{k['severity']} {k['bug_type']}" if k["kind"] == "finding" else "to review"
        lines.append(f"  - #{k['id']} [{label}] {k['title']} ({k['repo_name']}: {k['file_path']}:{k['line'] or '?'})")
    return (
        "\nAlready known in these files (found earlier, possibly by another task). Don't report these again. Report "
        "only problems that are not on this list, including a different bug at the same place. If something you "
        "report is the same bug as one of these, set its duplicate_of to that number:\n" + "\n".join(lines)
    )


def _api_prompt(conn: sqlite3.Connection, task: sqlite3.Row, audit: sqlite3.Row, secrets: list[str]) -> str:
    detail = json.loads(task["detail"] or "{}")
    files = store.api_task_files(conn, task["id"])
    calls = [f"{c['file']}:{c['line']} {c['method']} {c['url']}" + (f" (through {c['via']})" if c.get("via") else "")
             for c in detail.get("calls", [])]
    route, closest = detail.get("route"), detail.get("closest")
    if route:
        reaches = (f"It reaches {route['method']} {route['path']} in {route['repo']}, declared in {route['file']}"
                   + (f" and handled in {route['handler']}." if route.get("handler") else "."))
    elif detail.get("status") == "wrong_method":
        reaches = (f"No route accepts this method. The path exists as {closest['method']} {closest['path']} in "
                   f"{closest['repo']}: {closest['handler'] or closest['file']}." if closest else "No route accepts this method.")
    else:
        reaches = (f"No backend route matches this call. The closest route is {closest['method']} {closest['path']} in "
                   f"{closest['repo']}: {closest['handler'] or closest['file']}." if closest
                   else "No backend route matches this call, and no route is similar.")
    file_lines = [
        f"[{f['role']}] {f['repo_name']}: {f['path']} ({f['line_count'] or '?'} lines) at {Path(f['repo_path']) / f['path']}"
        for f in files
    ]
    other_repos = sorted({(f["repo_name"], f["repo_path"]) for f in files if f["audit_id"] != audit["id"]})
    problem = ""
    if detail.get("status") in ("broken", "wrong_method"):
        problem = (
            "\nThis call reaches no route. Decide whether it is a real bug (the screen or feature fails at runtime) "
            "or dead code nothing reaches, and what route was intended. Report it as a finding only if you can show "
            "in the code that the call runs and fails."
        )
    parts = [
        f"You are checking one API call between apps of the same project for real bugs. You can only read files; "
        f"you cannot run or change anything. The main repository is \"{audit['repo_name']}\" ({audit['repo_path']}).",
        f"\nTask #{task['id']}: {task['title']}",
        f"\nThe {detail.get('caller_type', 'unknown')} app \"{detail.get('caller_app', audit['repo_name'])}\" makes this call "
        f"from {len(calls)} place{'s' if len(calls) != 1 else ''}:\n" + "\n".join(f"  - {c}" for c in calls),
        f"\n{reaches}",
        "\nFiles to read (all of them; open others whenever you need context):\n" + "\n".join(f"  - {f}" for f in file_lines),
        ("\nOther repositories you can read:\n" + "\n".join(f"  - {name}: {path}" for name, path in other_repos))
        if other_repos else "",
        f"\nNever open these files in {audit['repo_name']}; they may contain secrets:\n"
        + "\n".join(f"  - {s}" for s in secrets[:50]) if secrets else "",
        "\nCheck that both sides agree:\n" + API_CHECKLIST,
        problem,
        known_section(conn, task["id"]),
        RULES.rstrip("\n")
        + "\n- Cite files in the main repository by their path relative to its root, and files in other repositories "
        "by their absolute path.\n\nReturn your result as JSON with \"findings\" and \"needs_review\" lists.",
    ]
    return "\n".join(p for p in parts if p)


def build_prompt(conn: sqlite3.Connection, task: sqlite3.Row, audit: sqlite3.Row, secrets: list[str]) -> str:
    if task["kind"] == "api":
        return _api_prompt(conn, task, audit, secrets)
    context = store.task_context(conn, task["id"])

    def section(title: str, rows: list[str], limit: int = 25) -> str:
        if not rows:
            return ""
        more = f"\n  ... and {len(rows) - limit} more" if len(rows) > limit else ""
        return f"\n{title}:\n" + "\n".join(f"  - {r}" for r in rows[:limit]) + more

    api_calls = []
    for c in context["api_calls"]:
        where = f"{c['path']}:{c['line']} {c['method']} {c['url']}"
        if c["status"] == "matched":
            api_calls.append(f"{where} -> handled by {c['route_repo']}: {c['handler_path']} ({c['route_method']} {c['route_path']})")
        elif c["status"] == "wrong_method":
            api_calls.append(f"{where} -> NO route with this method; closest is {c['route_method']} {c['route_path']}")
        elif c["status"] == "broken":
            api_calls.append(f"{where} -> NO backend route matches this path")
        else:
            api_calls.append(f"{where} -> URL built at runtime, not resolved")

    parts = [
        f"You are auditing part of the repository \"{audit['repo_name']}\" for real bugs. "
        "You can only read files; you cannot run or change anything.",
        f"\nTask #{task['id']}: {task['title']}",
        section(
            "Files to audit (start here; open other files in the repository whenever you need context)",
            [f"{f['path']} ({f['line_count']} lines)" for f in context["files"]],
            100,
        ),
        section("Entry points in these files", [f"{e['path']}: {e['kind']} ({e['detail']})" for e in context["entry_points"]]),
        section("Files these import from elsewhere in the repo", [r["path"] for r in context["imports"]]),
        section("Files that import these", [r["path"] for r in context["imported_by"]], 15),
        section("Imports of files that don't exist", [f"{u['path']}:{u['line']} {u['specifier']}" for u in context["unresolved"]]),
        section("API calls made from these files (from static analysis)", api_calls, 40),
        section(
            "Backend routes handled in these files",
            [f"{r['method']} {r['path']} ({r['callers']} frontend callers found)" for r in context["api_routes"]],
            40,
        ),
        section(
            "Other repositories in the same project that you can also read (for example, the backend these calls reach)",
            [f"{a['repo_name']}: {a['repo_path']}" for a in store.related_audits(conn, audit["id"])],
        ),
        section("Never open these files; they may contain secrets", secrets, 50),
        "\nLook for these kinds of bugs:\n" + CHECKLIST,
        known_section(conn, task["id"]),
        """
Rules:
- Report only problems you can show in the code. For each finding, quote the exact code (1-10 lines, copied
  verbatim) from the file at the line you cite, and explain what goes wrong and when.
- If you suspect a problem but can't show it in the code (it depends on configuration, runtime data, or code you
  can't see), put it under "needs_review" with what you suspect and why you couldn't confirm it.
- Don't report style, formatting, naming, performance, missing tests, or TODO comments.
- Use file paths relative to the repository root.
- If you find nothing, return empty lists. Don't invent problems to have something to report.

Return your result as JSON with "findings" and "needs_review" lists.""",
    ]
    return "\n".join(p for p in parts if p)


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _locate_evidence(lines: list[str], line: int, evidence: str) -> int | None:
    """Line number where the quoted code appears, preferring the cited line's neighborhood."""
    quoted = [_normalize(q) for q in evidence.splitlines() if len(_normalize(q)) >= 6]
    if not quoted:
        return None
    probe = quoted[0]
    normalized = [_normalize(text) for text in lines]
    start, end = max(0, line - 16), min(len(lines), line + 15)
    for index in range(start, end):
        if probe in normalized[index]:
            return index + 1
    for index, text in enumerate(normalized):
        if probe in text:
            return index + 1
    return None


def _relative(path: str, roots: dict[str, Path]) -> tuple[Path, str] | None:
    """Resolve a reported path to (repo root, relative path) inside one of the allowed repos."""
    candidate = Path(path.strip())
    for root in roots.values():
        absolute = candidate if candidate.is_absolute() else root / candidate.as_posix().removeprefix("./")
        try:
            resolved = absolute.resolve()
        except OSError:
            continue
        if resolved.is_relative_to(root) and resolved.is_file():
            return root, resolved.relative_to(root).as_posix()
    return None


def validate_report(report: dict, roots: dict[str, Path], secrets: set[Path]) -> tuple[list[dict], list[dict], list[dict]]:
    """Split an agent report into (findings, needs_review, rejected) after checking every citation."""
    findings, needs_review, rejected = [], [], []
    for item in report.get("findings") or []:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip() or "Untitled finding"
        bug_type = str(item.get("bug_type") or "").strip().lower()
        bug_type = BUG_TYPE_ALIASES.get(bug_type, bug_type)
        severity = str(item.get("severity") or "medium").strip().lower()
        try:
            line = int(item.get("line"))
        except (TypeError, ValueError):
            line = 0
        located = _relative(str(item.get("file") or ""), roots)
        if bug_type not in store.BUG_TYPES:
            rejected.append({"title": title, "reason": f"unknown bug type {bug_type!r}"})
            continue
        if located is None:
            rejected.append({"title": title, "reason": f"cited file {item.get('file')!r} does not exist in the repository"})
            continue
        root, rel = located
        if (root / rel).resolve() in secrets:
            rejected.append({"title": title, "reason": f"cites a secret file {rel}"})
            continue
        lines = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        if not 1 <= line <= len(lines):
            rejected.append({"title": title, "reason": f"line {line} is outside {rel} ({len(lines)} lines)"})
            continue
        evidence = str(item.get("evidence") or "")
        actual = _locate_evidence(lines, line, evidence)
        explanation = str(item.get("explanation") or "").strip()
        if actual is None:
            needs_review.append(
                {
                    "title": title,
                    "bug_type": bug_type,
                    "file_path": rel,
                    "repo_root": root,
                    "line": line,
                    "evidence": evidence,
                    "explanation": explanation,
                    "why_unconfirmed": "The quoted code was not found in the cited file, so the claim couldn't be checked against the code.",
                    "files_examined": [rel],
                    "duplicate_of": _number(item.get("duplicate_of")),
                }
            )
            continue
        findings.append(
            {
                "title": title,
                "bug_type": bug_type,
                "severity": severity if severity in store.SEVERITIES else "medium",
                "file_path": rel,
                "repo_root": root,
                "line": actual,
                "evidence": evidence,
                "explanation": explanation,
                "duplicate_of": _number(item.get("duplicate_of")),
            }
        )
    for item in report.get("needs_review") or []:
        if not isinstance(item, dict):
            continue
        needs_review.append(
            {
                "title": str(item.get("title") or "Unconfirmed suspicion").strip(),
                "explanation": str(item.get("suspicion") or item.get("explanation") or "").strip(),
                "why_unconfirmed": str(item.get("why_unconfirmed") or "").strip(),
                "files_examined": [str(f) for f in item.get("files_examined") or []],
                "duplicate_of": _number(item.get("duplicate_of")),
            }
        )
    return findings, needs_review, rejected


def _number(value) -> int | None:
    try:
        return int(str(value).lstrip("#")) if value not in (None, "") else None
    except ValueError:
        return None


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(w) > 2}


def mark_duplicates(conn: sqlite3.Connection, task_id: int, items: list[dict]) -> None:
    """Keep Claude's duplicate_of only when it names a finding the prompt listed for this task. Otherwise, add the
    app's own hint (possible_duplicate_of) when a known finding is in the same file, within 3 lines, with a similar
    title. The hint never hides anything; it is a label for the engineer."""
    known = {k["id"]: k for k in store.known_findings(conn, task_id, limit=1000)}
    for item in items:
        if item.get("duplicate_of") not in known:
            item["duplicate_of"] = None
        if item["duplicate_of"] or not item.get("file_path"):
            continue
        words = _words(item["title"])
        for k in known.values():
            if (k["file_path"] == item["file_path"] and k["file_audit_id"] == item.get("file_audit_id")
                    and abs((k["line"] or 0) - (item.get("line") or 0)) <= 3):
                other = _words(k["title"])
                if words and other and len(words & other) / len(words | other) >= 0.5:
                    item["possible_duplicate_of"] = k["id"]
                    break


def _repo_state(root: Path) -> str:
    repo = open_repository(root)
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "-uall"],
        capture_output=True, text=True, env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"),
    ).stdout
    return f"{repo.head_commit}\n{status}"


def choose_runner(settings: AgentSettings):
    """Pick how to call Claude: the Anthropic API with a saved key, or the Claude Code CLI.
    `auto` uses the API when a key is available and the CLI otherwise."""
    from audit_agent import api_runner, credentials

    if settings.runner not in RUNNERS:
        raise InvestigationError(f"Unknown runner {settings.runner!r}; use one of {', '.join(RUNNERS)}.")
    key = credentials.get_api_key()
    if settings.runner == "api" or (settings.runner == "auto" and key):
        if not key:
            raise InvestigationError(
                "No Anthropic API key found. Save one with `audit-agent set-api-key` or set ANTHROPIC_API_KEY."
            )
        return lambda prompt, root, s, secrets, dirs: api_runner.run_api(prompt, root, s, secrets, dirs, key)
    return run_claude


def runner_label(settings: AgentSettings) -> str:
    """Which way `choose_runner` will call Claude, without calling it."""
    from audit_agent import credentials

    if settings.runner == "api" or (settings.runner == "auto" and credentials.get_api_key()):
        return "Anthropic API (saved key)"
    return "Claude Code (claude command)"


@dataclass
class TaskScope:
    """The repositories a task's agent may read and the secret files it must never see."""
    task: sqlite3.Row
    audit: sqlite3.Row
    root: Path
    audit_roots: dict[int, Path]
    roots: dict[str, Path]
    secret_paths: list[Path]
    own_secrets: list[str]


def check_runnable(conn: sqlite3.Connection, task: sqlite3.Row, again: bool = False) -> None:
    task_id = task["id"]
    if task["status"] == "cancelled":
        raise InvestigationError(f"Task {task_id} is cancelled. Restore it before sending it to Claude.")
    if task["status"] == "running":
        raise InvestigationError(f"Task {task_id} is already running.")
    if task["status"] == "done" and not again:
        raise InvestigationError(f"Task {task_id} is already done. Pass --again to investigate it again.")
    if store.task_in_open_batch(conn, task_id):
        raise InvestigationError(f"Task {task_id} is waiting in a Claude batch; its result will be imported from there.")


def task_scope(conn: sqlite3.Connection, task_id: int) -> TaskScope:
    task = store.get_task(conn, task_id)
    audit = store.get_audit(conn, task["audit_id"])
    root = Path(audit["repo_path"])
    if not root.is_dir():
        raise InvestigationError(f"The repository {root} no longer exists.")
    # The agent may also read the other repositories in the same project (for example the backend
    # a mobile app calls), so their secret files are denied too.
    audits = [audit, *store.related_audits(conn, audit["id"])]
    audit_roots = {a["id"]: Path(a["repo_path"]) for a in audits if Path(a["repo_path"]).is_dir()}
    roots = {a["repo_name"]: audit_roots[a["id"]] for a in audits if a["id"] in audit_roots}
    marks = ",".join("?" * len(audit_roots))
    secret_rows = conn.execute(
        f"SELECT audit_id, path FROM inventory_files WHERE category = 'secret' AND audit_id IN ({marks})",
        list(audit_roots),
    ).fetchall()
    return TaskScope(
        task=task,
        audit=audit,
        root=root,
        audit_roots=audit_roots,
        roots=roots,
        secret_paths=[audit_roots[r["audit_id"]] / r["path"] for r in secret_rows],
        own_secrets=sorted({r["path"] for r in secret_rows if r["audit_id"] == audit["id"]}),
    )


def record_result(conn: sqlite3.Connection, run_id: int, scope: TaskScope, result: AgentResult) -> dict:
    """Check every citation in the agent's report, save what holds up, and close the run."""
    task_id = scope.task["id"]
    findings, needs_review, rejected = validate_report(
        result.report, scope.roots, {p.resolve() for p in scope.secret_paths}
    )
    audit_of_root = {path: audit_id for audit_id, path in scope.audit_roots.items()}
    for item in findings + needs_review:
        if "repo_root" in item:
            item["file_audit_id"] = audit_of_root.get(item.pop("repo_root"))
    mark_duplicates(conn, task_id, findings + needs_review)
    store.save_findings(conn, run_id, task_id, scope.audit["id"], GENERAL_AGENT, findings, needs_review)
    store.finish_run(
        conn, run_id, task_id, "done",
        duration_ms=result.duration_ms, cost_usd=result.cost_usd, num_turns=result.num_turns,
        session_id=result.session_id, rejected=json.dumps(rejected), raw_output=result.raw,
    )
    return {
        "run_id": run_id,
        "findings": sum(1 for f in findings if not f.get("duplicate_of")),
        "needs_review": sum(1 for n in needs_review if not n.get("duplicate_of")),
        "duplicates": sum(1 for i in findings + needs_review if i.get("duplicate_of")),
        "rejected": rejected,
        "cost_usd": result.cost_usd,
        "duration_ms": result.duration_ms,
    }


def investigate(conn: sqlite3.Connection, task_id: int, settings: AgentSettings | None = None, again: bool = False) -> dict:
    settings = settings or AgentSettings()
    check_runnable(conn, store.get_task(conn, task_id), again)
    scope = task_scope(conn, task_id)
    prompt = build_prompt(conn, scope.task, scope.audit, scope.own_secrets)
    extra_dirs = [p for p in scope.roots.values() if p != scope.root]
    run_with = choose_runner(settings)
    before = _repo_state(scope.root)
    try:
        run_id = store.start_run(conn, task_id, GENERAL_AGENT)
    except store.StoreError as exc:
        raise InvestigationError(str(exc)) from exc
    try:
        result = run_with(prompt, scope.root, settings, scope.secret_paths, extra_dirs)
    except InvestigationError as exc:
        store.finish_run(conn, run_id, task_id, "failed", error=str(exc))
        raise
    except Exception as exc:
        store.finish_run(conn, run_id, task_id, "failed", error=f"{exc.__class__.__name__}: {exc}")
        raise InvestigationError(f"{exc.__class__.__name__}: {exc}") from exc
    if _repo_state(scope.root) != before:
        error = "The repository changed while the agent was running; results were discarded."
        store.finish_run(conn, run_id, task_id, "failed", error=error, raw_output=result.raw)
        raise InvestigationError(error)
    return record_result(conn, run_id, scope, result)
