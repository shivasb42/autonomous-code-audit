"""Turn a task's findings into GitHub issues, on one project board per audit project.

No AI is involved: every issue is written from what the database already holds (the finding, its
quoted code, Claude's explanation, the task and run). Each issue goes into the GitHub repository
of the file the finding cites (a backend bug found from a mobile task goes to the backend repo),
and is added to a project board named "<project> audit findings", which is created public the
first time. The finding keeps its issue's URL, so an issue is never created twice.

Everything goes through the `gh` command the engineer is logged in with. Issues are created only
when the engineer confirms a preview.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sqlite3
from pathlib import Path, PurePosixPath

from audit_agent import store

LABELS = {
    "audit-agent": ("5319e7", "Found by audit-agent"),
    "unverified": ("fbca04", "Not reproduced yet; a code-backed claim"),
    "needs-review": ("d4c5f9", "Suspected; the code alone couldn't confirm it"),
    "security": ("b60205", "Security"),
    "logic": ("1d76db", "Logic error"),
    "concurrency": ("0e8a16", "Concurrency or reliability"),
    "severity:critical": ("b60205", "Critical severity"),
    "severity:high": ("d93f0b", "High severity"),
    "severity:medium": ("fbca04", "Medium severity"),
    "severity:low": ("c2e0c6", "Low severity"),
}
FENCE_LANGUAGES = {".ts": "ts", ".tsx": "tsx", ".js": "js", ".jsx": "jsx", ".mjs": "js", ".cjs": "js", ".py": "python",
                   ".dart": "dart", ".json": "json"}
_GITHUB_REMOTE = re.compile(r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?$")


class IssueError(Exception):
    pass


def _gh_command() -> str:
    command = os.environ.get("AUDIT_AGENT_GH") or "gh"
    resolved = shutil.which(command) or (command if Path(command).is_file() else None)
    if not resolved:
        raise IssueError("The `gh` command was not found. Install GitHub CLI and run `gh auth login`.")
    return resolved


def gh(args: list[str], stdin: str | None = None) -> str:
    result = subprocess.run([_gh_command(), *args], input=stdin, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-600:]
        raise IssueError(f"gh {' '.join(args[:2])} failed: {detail}")
    return result.stdout


def github_repo(repo_path: str) -> str | None:
    """owner/name of the repository's GitHub remote (origin), or None if it has none."""
    result = subprocess.run(
        ["git", "-C", repo_path, "remote", "get-url", "origin"],
        capture_output=True, text=True, env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"),
    )
    match = _GITHUB_REMOTE.search(result.stdout.strip()) if result.returncode == 0 else None
    return f"{match.group(1)}/{match.group(2)}" if match else None


def board_title(conn: sqlite3.Connection, audit_id: int) -> str:
    project_ids = store.projects_of(conn, [audit_id])
    name = store.get_project(conn, project_ids[-1])["name"] if project_ids else store.get_audit(conn, audit_id)["repo_name"]
    return f"{name} audit findings"


def _fence(code: str, path: str | None) -> str:
    language = FENCE_LANGUAGES.get(PurePosixPath(path or "").suffix.lower(), "")
    fence = "~~~~" if "```" in code else "```"
    return f"{fence}{language}\n{code.rstrip()}\n{fence}"


def _issue(finding: sqlite3.Row, task: sqlite3.Row, file_audit: sqlite3.Row, repo: str | None) -> dict:
    path, line = finding["file_path"], finding["line"]
    where = "not tied to one line"
    if path:
        location = f"{path}:{line}" if line else path
        if repo:
            ref = file_audit["head_commit"] or "HEAD"
            anchor = f"#L{line}" if line else ""
            where = f"[`{location}`](https://github.com/{repo}/blob/{ref}/{path}{anchor})"
        else:
            where = f"`{location}`"
    rows = [("Repository", file_audit["repo_name"]), ("Where", where)]
    if finding["kind"] == "finding":
        rows = [("Severity", finding["severity"]), ("Type", finding["bug_type"])] + rows
    elif finding["bug_type"]:
        rows = [("Type", finding["bug_type"])] + rows
    rows += [("Audit task", f"#{task['id']} {task['title']}"),
             ("Found", f"{finding['created_at'][:10]} by the {finding['agent']} agent (run #{finding['run_id']})")]
    if file_audit["head_commit"]:
        rows.append(("Audited commit", f"`{file_audit['head_commit'][:12]}`"
                     + (" (the working tree had uncommitted changes)" if file_audit["working_tree_dirty"] else "")))
    table = "| | |\n|---|---|\n" + "\n".join(f"| {k} | {str(v).replace('|', '/')} |" for k, v in rows)

    if finding["kind"] == "finding":
        title = f"[audit] {finding['title']}"
        labels = ["audit-agent", "unverified", f"severity:{finding['severity']}", finding["bug_type"]]
        parts = [
            "**Found by audit-agent (Claude). Not verified yet:** the quoted code was checked to exist at this line, "
            "but the bug hasn't been reproduced. Treat it as a code-backed claim.",
            table,
            "### Evidence\n" + _fence(finding["evidence"] or "", path),
            "### What goes wrong\n" + (finding["explanation"] or ""),
        ]
    else:
        title = f"[audit, suspected] {finding['title']}"
        labels = ["audit-agent", "needs-review"] + ([finding["bug_type"]] if finding["bug_type"] else [])
        examined = json.loads(finding["files_examined"] or "[]")
        parts = [
            "**Suspected by audit-agent (Claude), not confirmed:** the code alone couldn't show this is a bug. "
            "It needs a person to check it.",
            table,
            "### Suspicion\n" + (finding["explanation"] or ""),
            "### Why it couldn't be confirmed\n" + (finding["why_unconfirmed"] or "Not stated."),
        ]
        if finding["evidence"]:
            parts.insert(2, "### Code it points to\n" + _fence(finding["evidence"], path))
        if examined:
            parts.append("### Files examined\n" + "\n".join(f"- `{f}`" for f in examined))
    return {
        "finding_id": finding["id"],
        "kind": finding["kind"],
        "title": title[:250],
        "repo": repo,
        "labels": [label for label in labels if label],
        "body": "\n\n".join(parts) + "\n\n<sub>Created by audit-agent from its saved results.</sub>\n",
        "issue_url": finding["issue_url"],
        "problem": None if repo else f"{file_audit['repo_name']} has no GitHub remote (origin)",
    }


def preview(conn: sqlite3.Connection, task_id: int) -> dict:
    """The issues a task's findings would become, without creating anything."""
    task = store.get_task(conn, task_id)
    repos: dict[int, str | None] = {}
    issues = []
    for finding in store.list_findings(conn, task_id=task_id):
        if finding["duplicate_of"]:
            continue
        file_audit_id = finding["file_audit_id"] or finding["audit_id"]
        file_audit = store.get_audit(conn, file_audit_id)
        if file_audit_id not in repos:
            repos[file_audit_id] = github_repo(file_audit["repo_path"])
        issues.append(_issue(finding, task, file_audit, repos[file_audit_id]))
    return {"task_id": task_id, "board": board_title(conn, task["audit_id"]), "issues": issues}


def tasks_missing_issues(conn: sqlite3.Connection) -> list[int]:
    """Tasks with at least one finding or review item that has no GitHub issue yet."""
    return [r[0] for r in conn.execute(
        "SELECT DISTINCT task_id FROM findings WHERE issue_url IS NULL AND duplicate_of IS NULL ORDER BY task_id"
    )]


def preview_all(conn: sqlite3.Connection) -> dict:
    """Every issue that `create_all` would create, across all tasks, without creating anything."""
    issues, boards = [], set()
    for task_id in tasks_missing_issues(conn):
        plan = preview(conn, task_id)
        boards.add(plan["board"])
        issues += [{**i, "task_id": task_id} for i in plan["issues"] if not i["issue_url"]]
    return {"issues": issues, "boards": sorted(boards),
            "ready": sum(1 for i in issues if not i["problem"]),
            "blocked": sum(1 for i in issues if i["problem"])}


def create_all(conn: sqlite3.Connection, log=print) -> dict:
    """Create the missing issues for every task. A task that fails is reported and the rest go on."""
    result = {"created": [], "skipped": [], "warnings": [], "errors": [], "boards": []}
    for task_id in tasks_missing_issues(conn):
        try:
            done = create(conn, task_id, log=log)
        except IssueError as exc:
            result["errors"].append({"task_id": task_id, "error": str(exc)})
            log(f"Issues for task #{task_id} failed: {exc}")
            if str(exc).startswith(("gh auth status failed", "The `gh` command was not found")):
                break
            continue
        result["created"] += [{**c, "task_id": task_id} for c in done["created"]]
        result["skipped"] += [{**s, "task_id": task_id} for s in done["skipped"]]
        result["warnings"] += done["warnings"]
        if done["board"] and done["board"]["title"] not in [b["title"] for b in result["boards"]]:
            result["boards"].append(done["board"])
    return result


def _board(title: str) -> dict:
    """The engineer's project board with this title, created public if it doesn't exist."""
    listed = json.loads(gh(["project", "list", "--owner", "@me", "--limit", "200", "--format", "json"]) or "{}")
    for project in listed.get("projects") or []:
        if project.get("title") == title and not project.get("closed"):
            return {"number": project["number"], "url": project.get("url"), "created": False}
    created = json.loads(gh(["project", "create", "--owner", "@me", "--title", title, "--format", "json"]))
    gh(["project", "edit", str(created["number"]), "--owner", "@me", "--visibility", "PUBLIC"])
    return {"number": created["number"], "url": created.get("url"), "created": True}


def create(conn: sqlite3.Connection, task_id: int, finding_ids: list[int] | None = None, log=print) -> dict:
    """Create GitHub issues for the task's findings that don't have one yet, and put them on the board."""
    plan = preview(conn, task_id)
    wanted = None if finding_ids is None else set(finding_ids)
    todo, skipped = [], []
    for issue in plan["issues"]:
        if wanted is not None and issue["finding_id"] not in wanted:
            continue
        if issue["issue_url"]:
            skipped.append({"finding_id": issue["finding_id"], "reason": f"already has {issue['issue_url']}"})
        elif issue["problem"]:
            skipped.append({"finding_id": issue["finding_id"], "reason": issue["problem"]})
        else:
            todo.append(issue)
    result = {"created": [], "skipped": skipped, "warnings": [], "board": None}
    if not todo:
        return result
    gh(["auth", "status"])
    board = _board(plan["board"])
    result["board"] = {"title": plan["board"], **board}
    if board["created"]:
        log(f"Created the public project board {plan['board']!r}: {board['url']}")
    for repo in sorted({i["repo"] for i in todo}):
        for label in sorted({label for i in todo if i["repo"] == repo for label in i["labels"]}):
            color, description = LABELS.get(label, ("ededed", ""))
            gh(["label", "create", label, "--repo", repo, "--color", color, "--description", description, "--force"])
    for issue in todo:
        args = ["issue", "create", "--repo", issue["repo"], "--title", issue["title"], "--body-file", "-"]
        for label in issue["labels"]:
            args += ["--label", label]
        url = gh(args, stdin=issue["body"]).strip().splitlines()[-1].strip()
        store.set_finding_issue(conn, issue["finding_id"], url)
        log(f"Created {url} for finding #{issue['finding_id']}")
        try:
            gh(["project", "item-add", str(board["number"]), "--owner", "@me", "--url", url, "--format", "json"])
        except IssueError as exc:
            result["warnings"].append(f"{url} was created but not added to the board: {exc}")
        result["created"].append({"finding_id": issue["finding_id"], "url": url, "repo": issue["repo"]})
    return result
