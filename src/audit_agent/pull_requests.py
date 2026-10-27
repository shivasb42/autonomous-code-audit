"""Open a draft pull request for a checked fix, only when the engineer clicks for it, and keep the
finding's GitHub issue told about each fix attempt.

The pull request's commit is built in a temporary bare clone that shares the repository's git
objects, without checking any files out (nothing in the repository or its working tree is written).
It starts from the commit the fix was made on, checks that each changed file there is exactly what
the fix was made against, adds the fix and its test, pushes only a new `audit/...` branch to the
repository's GitHub remote, and opens a draft pull request that says "Fixes #<issue>". Nothing is
merged or deployed, and the main branch is never pushed.

The issue gets a comment when the pull request is opened, and when a fix attempt ends rejected or
unable (why there is no fix, with the test and the app's runs). Each attempt comments once.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
from pathlib import Path

from audit_agent import github_issues, sandbox, store

MAX_OUTPUT_IN_BODY = 5000
_ISSUE_URL = re.compile(r"github\.com/([^/]+/[^/]+)/issues/(\d+)")


class PullRequestError(Exception):
    pass


def _git(cwd: Path, *args: str, check: bool = True, env: dict | None = None,
         input: str | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, input=input,
                            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", **(env or {})})
    if check and result.returncode != 0:
        raise PullRequestError(f"git {' '.join(args[:2])} failed: {(result.stderr or result.stdout).strip()[-600:]}")
    return result


def push_url(repo_root: Path) -> str | None:
    result = _git(repo_root, "remote", "get-url", "origin", check=False)
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _fence(text: str) -> str:
    text = (text or "").strip()
    if len(text) > MAX_OUTPUT_IN_BODY:
        text = "..." + text[-MAX_OUTPUT_IN_BODY:]
    return f"~~~~\n{text}\n~~~~"


def preview(conn: sqlite3.Connection, attempt_id: int) -> dict:
    """What the pull request would be, and anything that stops it, without changing anything."""
    attempt = store.get_fix(conn, attempt_id)
    finding = store.get_finding(conn, attempt["finding_id"])
    audit = store.get_audit(conn, finding["file_audit_id"] or finding["audit_id"])
    root = Path(audit["repo_path"])
    repo = github_issues.github_repo(str(root))
    files = json.loads(attempt["files"] or "{}")
    problems, warnings = [], []
    if attempt["outcome"] != "fixed":
        problems.append("Only a fix the app checked (outcome fixed) can become a pull request.")
    if attempt["pr_url"]:
        problems.append(f"This fix already has a pull request: {attempt['pr_url']}")
    if not repo:
        problems.append(f"{audit['repo_name']} has no GitHub remote (origin).")
    if not finding["issue_url"]:
        problems.append("The finding has no GitHub issue.")
    if not attempt["base_branch"] or not attempt["base_commit"]:
        problems.append("The repository wasn't on a branch when the fix was made, so there is no base for a pull request.")
    elif root.is_dir():
        for rel, info in files.items():
            shown = _git(root, "show", f"{attempt['base_commit']}:{rel}", check=False)
            if shown.returncode != 0 or _sha(shown.stdout) != info["before_sha"]:
                problems.append(f"{rel} had uncommitted changes when it was fixed (or isn't in commit "
                                f"{attempt['base_commit'][:12]}). Commit them, then run Reproduce + fix again.")
        pushed = _git(root, "branch", "-r", "--contains", attempt["base_commit"], check=False).stdout.split()
        if not any(b.endswith("/" + attempt["base_branch"]) for b in pushed):
            warnings.append(f"Commit {attempt['base_commit'][:12]} isn't on origin/{attempt['base_branch']} yet, so the pull "
                            "request will also contain your unpushed commits.")
    issue = _ISSUE_URL.search(finding["issue_url"] or "")
    issue_ref = (f"#{issue.group(2)}" if issue.group(1) == repo else f"{issue.group(1)}#{issue.group(2)}") if issue else None
    branch = f"audit/finding-{finding['id']}-fix-{attempt_id}"
    title = f"Fix: {finding['title']}"[:200]
    body = "\n\n".join(p for p in [
        f"Fixes {issue_ref}" if issue_ref else None,
        "**Fix proposed by audit-agent (Claude) and checked by the app. Not reviewed by a person yet.**",
        f"### The bug\n{finding['title']} (`{finding['file_path']}:{finding['line']}`, {finding['severity']} "
        f"{finding['bug_type']})\n\n{finding['explanation']}",
        f"### The change\n{attempt['summary'] or 'See the diff.'}",
        "### How it was checked\n"
        f"- `{attempt['test_path']}` (\"{attempt['test_name']}\") failed on the unchanged code and passes with this change. "
        "The app ran both itself, each in a fresh throwaway copy with the network off.\n"
        f"- {attempt['reason']}",
        "<details><summary>Test output before the fix</summary>\n\n" + _fence(attempt["before_output"]) + "\n\n</details>",
        "<details><summary>Test output with the fix</summary>\n\n" + _fence(attempt["after_output"]) + "\n\n</details>",
        "<sub>Opened by audit-agent after the engineer approved it.</sub>",
    ] if p)
    return {
        "attempt_id": attempt_id, "finding_id": finding["id"], "repo": repo, "base": attempt["base_branch"],
        "base_commit": attempt["base_commit"], "branch": branch, "title": title, "body": body,
        "files": sorted(files) + ([attempt["test_path"]] if attempt["test_path"] else []),
        "problems": problems, "warnings": warnings,
    }


def open_pr(conn: sqlite3.Connection, attempt_id: int, log=print) -> dict:
    """Push the fix to a new branch and open a draft pull request. Runs only when the engineer clicks."""
    plan = preview(conn, attempt_id)
    if plan["problems"]:
        raise PullRequestError(plan["problems"][0])
    attempt = store.get_fix(conn, attempt_id)
    finding = store.get_finding(conn, attempt["finding_id"])
    root = Path(store.get_audit(conn, finding["file_audit_id"] or finding["audit_id"])["repo_path"])
    remote = push_url(root)
    if not remote:
        raise PullRequestError("The repository has no origin remote to push to.")
    if plan["branch"] == plan["base"] or not plan["branch"].startswith("audit/"):
        raise PullRequestError("Refusing to push to anything but a new audit/ branch.")
    # The commit is built straight from the base commit's tree plus the changed files, with a temporary index and
    # no working tree, so no file of the repository is written out (a large repository costs nothing here). The
    # clone shares the repository's objects; the few new ones go into the clone, which is deleted afterwards.
    clone = sandbox.work_root() / "pull-requests" / f"fix-{attempt_id}-{secrets.token_hex(3)}"
    clone.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["git", "clone", "--quiet", "--shared", "--bare", str(root), str(clone)],
                       check=True, capture_output=True, text=True)
        index = {"GIT_INDEX_FILE": str(clone / "audit-index")}
        base = plan["base_commit"]
        _git(clone, "read-tree", base, env=index)
        files = json.loads(attempt["files"])
        for rel, info in files.items():
            current = _git(clone, "show", f"{base}:{rel}", check=False)
            if current.returncode != 0 or _sha(current.stdout) != info["before_sha"]:
                raise PullRequestError(f"{rel} at {base[:12]} isn't what the fix was made against.")
            mode = _git(clone, "ls-tree", base, "--", rel).stdout.split()[0]
            _stage(clone, index, rel, info["after"], mode)
        _stage(clone, index, attempt["test_path"], attempt["test_code"], "100644")
        tree = _git(clone, "write-tree", env=index).stdout.strip()
        message = f"{plan['title']}\n\nFound and fixed by audit-agent (finding #{finding['id']}, fix attempt #{attempt_id})."
        commit = _git(clone, "commit-tree", tree, "-p", base, input=message).stdout.strip()
        log(f"Pushing branch {plan['branch']} to {plan['repo']} ...")
        _git(clone, "push", "--quiet", remote, f"{commit}:refs/heads/{plan['branch']}")
        output = github_issues.gh(["pr", "create", "--repo", plan["repo"], "--draft", "--base", plan["base"],
                                   "--head", plan["branch"], "--title", plan["title"], "--body-file", "-"], stdin=plan["body"])
    except github_issues.IssueError as exc:
        raise PullRequestError(f"The branch {plan['branch']} was pushed, but the pull request failed: {exc}") from exc
    except subprocess.CalledProcessError as exc:
        raise PullRequestError(f"git clone failed: {(exc.stderr or '').strip()[-600:]}") from exc
    finally:
        shutil.rmtree(clone, ignore_errors=True)
    url = next((line.strip() for line in reversed(output.splitlines()) if line.strip().startswith("http")), output.strip())
    store.set_fix_pr(conn, attempt_id, url, plan["branch"])
    log(f"Opened draft pull request {url}")
    comment = None
    try:
        comment = post_comment(conn, attempt_id, log)
    except PullRequestError as exc:
        log(f"The pull request was opened, but commenting on the issue failed: {exc}")
    return {"url": url, "branch": plan["branch"], "comment_url": comment, "preview": preview(conn, attempt_id)}


def pending(conn: sqlite3.Connection) -> list[int]:
    """Fix attempts that could become a pull request: the latest checked fix of each finding whose fixes have
    no pull request yet."""
    return [r[0] for r in conn.execute(
        """SELECT MAX(a.id) FROM fix_attempts a
           WHERE a.status = 'done' AND a.outcome = 'fixed'
             AND NOT EXISTS (SELECT 1 FROM fix_attempts p WHERE p.finding_id = a.finding_id AND p.pr_url IS NOT NULL)
           GROUP BY a.finding_id ORDER BY MAX(a.id)"""
    )]


def preview_all(conn: sqlite3.Connection) -> dict:
    """Every pull request "Open all pending" would open, and the ones it can't, without changing anything."""
    plans = [preview(conn, attempt_id) for attempt_id in pending(conn)]
    return {"ready": [p for p in plans if not p["problems"]], "blocked": [p for p in plans if p["problems"]]}


def open_all(conn: sqlite3.Connection, log=print) -> dict:
    """Open a draft pull request for every pending checked fix, one after another. One that fails is reported
    and the rest go on."""
    opened, failed, skipped = [], [], []
    for attempt_id in pending(conn):
        plan = preview(conn, attempt_id)
        if plan["problems"]:
            skipped.append({"attempt_id": attempt_id, "finding_id": plan["finding_id"], "reason": plan["problems"][0]})
            continue
        try:
            result = open_pr(conn, attempt_id, log)
            opened.append({"attempt_id": attempt_id, "finding_id": plan["finding_id"], "url": result["url"],
                           "comment_url": result["comment_url"]})
        except PullRequestError as exc:
            failed.append({"attempt_id": attempt_id, "finding_id": plan["finding_id"], "error": str(exc)})
            log(f"Pull request for fix attempt #{attempt_id} failed: {exc}")
    return {"opened": opened, "failed": failed, "skipped": skipped}


def _stage(repo: Path, index_env: dict, rel: str, content: str, mode: str) -> None:
    blob = _git(repo, "hash-object", "-w", "--stdin", "--path", rel, input=content).stdout.strip()
    _git(repo, "update-index", "--add", "--cacheinfo", f"{mode},{blob},{rel}", env=index_env)


# --- Comments on the finding's issue ----------------------------------------------------------------

def _details(summary: str, text: str | None) -> str | None:
    return f"<details><summary>{summary}</summary>\n\n{_fence(text)}\n\n</details>" if text else None


def comment_body(attempt: sqlite3.Row, finding: sqlite3.Row) -> str | None:
    """What to say on the issue about a fix attempt: the pull request, or why there is no fix. None when there
    is nothing to report yet (a checked fix without a pull request, or a claim that wasn't reproduced)."""
    when = (attempt["finished_at"] or attempt["started_at"])[:10]
    test = (f"`{attempt['test_path']}`" + (f" (\"{attempt['test_name']}\")" if attempt["test_name"] else "")
            if attempt["test_path"] else None)
    footer = "<sub>Posted by audit-agent. Nothing was changed in the repository; the work ran in a throwaway copy.</sub>"
    if attempt["pr_url"]:
        parts = [
            f"**audit-agent opened a draft pull request with a fix: {attempt['pr_url']}**",
            f"Branch `{attempt['pr_branch']}`. Fix attempt #{attempt['id']}, {when}.",
            f"The test {test} failed on the unchanged code and passes with the fix. {attempt['reason'] or ''}".strip(),
            f"**The change:** {attempt['summary']}" if attempt["summary"] else None,
            "Review it before merging; no person has checked it yet.",
        ]
    elif attempt["outcome"] == "fix_rejected":
        parts = [
            f"**audit-agent reproduced this bug, but its fix was rejected** (fix attempt #{attempt['id']}, {when})",
            f"The bug is real: the test {test} failed on the unchanged code, run by the app itself in a throwaway copy "
            "with the network off." if test else "The bug was reproduced.",
            f"Why there is no fix:\n> {(attempt['reason'] or 'not stated').replace(chr(10), chr(10) + '> ')}",
            _details(f"Test: {attempt['test_path']}", attempt["test_code"]),
            _details("Proposed diff (rejected)", attempt["patch"]),
            _details("App's run before the fix", attempt["before_output"]),
            _details("App's run with the fix", attempt["after_output"]),
            _details("Existing tests covering the changed files", attempt["related_output"]),
        ]
    elif attempt["outcome"] == "unable":
        parts = [
            f"**audit-agent couldn't reproduce or fix this automatically** (fix attempt #{attempt['id']}, {when})",
            f"Why:\n> {(attempt['reason'] or 'not stated').replace(chr(10), chr(10) + '> ')}",
            f"**Manual steps to check it:**\n{attempt['manual_steps']}" if attempt["manual_steps"] else None,
            _details(f"Test it wrote: {attempt['test_path']}", attempt["test_code"]),
            "This doesn't mean the bug isn't real; it couldn't be shown with an automated test here.",
        ]
    else:
        return None
    return "\n\n".join(p for p in [*parts, footer] if p)


def post_comment(conn: sqlite3.Connection, attempt_id: int, log=print) -> str | None:
    """Comment on the finding's issue about the attempt, once. Returns the comment's URL, or None if there is
    nothing to post or it was posted already."""
    attempt = store.get_fix(conn, attempt_id)
    finding = store.get_finding(conn, attempt["finding_id"])
    if attempt["issue_comment_url"] or not finding["issue_url"] or attempt["status"] != "done":
        return None
    body = comment_body(attempt, finding)
    if body is None:
        return None
    try:
        output = github_issues.gh(["issue", "comment", finding["issue_url"], "--body-file", "-"], stdin=body)
    except github_issues.IssueError as exc:
        raise PullRequestError(str(exc)) from exc
    url = next((line.strip() for line in reversed(output.splitlines()) if line.strip().startswith("http")),
               finding["issue_url"])
    store.set_fix_comment(conn, attempt_id, url)
    log(f"Commented on {finding['issue_url']} about fix attempt #{attempt_id}")
    return url


def post_missing_comments(conn: sqlite3.Connection, log=print) -> dict:
    """Post every comment that's due but missing (for example for attempts made before comments existed)."""
    posted, failed = [], []
    for attempt in store.fixes_missing_comments(conn):
        try:
            if url := post_comment(conn, attempt["id"], log):
                posted.append({"attempt_id": attempt["id"], "url": url})
        except PullRequestError as exc:
            failed.append({"attempt_id": attempt["id"], "error": str(exc)})
            log(f"Commenting about fix attempt #{attempt['id']} failed: {exc}")
    return {"posted": posted, "failed": failed}
