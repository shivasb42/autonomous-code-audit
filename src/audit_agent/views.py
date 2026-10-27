"""Text and JSON views of a stored inventory. Everything here reads from the database."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter

from audit_agent import review, store

SECTION_COLUMNS = {
    "files": ["path", "app_root", "category", "language", "supported", "line_count", "size_bytes", "note"],
    "modules": ["path", "package_root", "languages", "file_count", "line_count"],
    "dependencies": ["manifest_path", "ecosystem", "name", "version_spec", "scope"],
    "entry-points": ["kind", "path", "source_path", "detail"],
    "relationships": ["source_path", "line", "kind", "specifier", "target_path", "target_package"],
    "unsupported": ["technology", "kind", "file_count", "evidence_path", "reason"],
    "skipped": ["reason", "file_count", "example_path"],
    "apps": ["root", "app_type", "type_source", "detected_type", "also_targets", "file_count", "manifests", "evidence"],
}

TYPE_LABELS = {"backend": "Backend", "web": "Web", "mobile": "Mobile", "unknown": "Unknown"}


def app_rows(conn: sqlite3.Connection, audit_ids: list[int]) -> list[dict]:
    return [
        {
            "name": store.app_name(r["repo_name"], r["root"]),
            "path": store.app_path(r["repo_path"], r["root"]),
            "audit_id": r["audit_id"],
            "root": r["root"],
            "type": r["app_type"],
            "detected_type": r["detected_type"],
            "type_source": r["type_source"],
            "also_targets": [t for t in r["also_targets"].split(",") if t],
            "source_files": r["file_count"],
            "manifests": json.loads(r["manifests"]),
            "evidence": json.loads(r["evidence"]),
        }
        for r in store.list_apps(conn, audit_ids)
    ]


def format_apps(rows: list[dict]) -> str:
    if not rows:
        return "Apps: none found"
    width = max(len(r["name"]) for r in rows)
    lines = [f"Apps ({len(rows)}):"]
    for r in rows:
        label = TYPE_LABELS[r["type"]]
        if r["also_targets"]:
            label += f", also targets {', '.join(r['also_targets'])}"
        if r["type_source"] == "engineer":
            label += f" (set by you; detected as {r['detected_type']})"
        elif r["type"] == "unknown":
            tied = any(e["strength"] == "strong" for e in r["evidence"])
            label += " (the evidence is tied)" if tied else " (no strong signal)"
        lines.append(f"  {r['name']:<{width}}  {label}  [{r['source_files']} source files]")
        order = [r["detected_type"]] + [t for t in TYPE_LABELS if t != r["detected_type"]]
        for app_type in order:
            items = [e for e in r["evidence"] if e["type"] == app_type]
            if items:
                signals = [e["signal"] + ("" if e["strength"] == "strong" else " (supporting)") for e in items]
                lines.append(f"  {'':<{width}}    {app_type}: " + "; ".join(signals))
        if not r["evidence"]:
            manifests = ", ".join(r["manifests"]) or "no manifest"
            lines.append(f"  {'':<{width}}    no backend, web, or mobile signals ({manifests})")
    lines.append("\nCorrect a type with: audit-agent app-type <app> backend|web|mobile|unknown")
    return "\n".join(lines)


def _counts(conn: sqlite3.Connection, sql: str, audit_id: int) -> list[sqlite3.Row]:
    return conn.execute(sql, (audit_id,)).fetchall()


def _join_counts(rows: list[sqlite3.Row]) -> str:
    return ", ".join(f"{row[0]} {row[1]}" for row in rows) or "none"


def summary(conn: sqlite3.Connection, audit_id: int) -> dict:
    audit = store.get_audit(conn, audit_id)

    def one(sql: str) -> int:
        return conn.execute(sql, (audit_id,)).fetchone()[0]

    return {
        "audit": dict(audit),
        "files_by_category": {
            r["category"]: r["n"]
            for r in _counts(
                conn,
                "SELECT category, COUNT(*) AS n FROM inventory_files WHERE audit_id = ? GROUP BY category ORDER BY n DESC",
                audit_id,
            )
        },
        "languages": [
            dict(r)
            for r in _counts(
                conn,
                """SELECT language, MAX(supported) AS supported, COUNT(*) AS files,
                          COALESCE(SUM(line_count), 0) AS lines
                   FROM inventory_files WHERE audit_id = ? AND category = 'source'
                   GROUP BY language ORDER BY files DESC, language""",
                audit_id,
            )
        ],
        "modules": one("SELECT COUNT(*) FROM inventory_modules WHERE audit_id = ?"),
        "manifests": one("SELECT COUNT(DISTINCT manifest_path) FROM inventory_dependencies WHERE audit_id = ?"),
        "dependencies_by_ecosystem": {
            r[0]: r[1]
            for r in _counts(
                conn,
                "SELECT ecosystem, COUNT(*) FROM inventory_dependencies WHERE audit_id = ? GROUP BY ecosystem",
                audit_id,
            )
        },
        "entry_points_by_kind": {
            r[0]: r[1]
            for r in _counts(
                conn,
                "SELECT kind, COUNT(*) AS n FROM inventory_entry_points WHERE audit_id = ? GROUP BY kind ORDER BY n DESC",
                audit_id,
            )
        },
        "relationships_by_kind": {
            r[0]: r[1]
            for r in _counts(
                conn,
                "SELECT kind, COUNT(*) AS n FROM inventory_relationships WHERE audit_id = ? GROUP BY kind ORDER BY n DESC",
                audit_id,
            )
        },
        "cross_module_links": one(
            """SELECT COUNT(DISTINCT s.module_path || '>' || t.module_path)
               FROM inventory_relationships r
               JOIN inventory_files s ON s.audit_id = r.audit_id AND s.path = r.source_path
               JOIN inventory_files t ON t.audit_id = r.audit_id AND t.path = r.target_path
               WHERE r.audit_id = ? AND r.kind = 'internal' AND s.module_path != t.module_path"""
        ),
        "unsupported": [dict(r) for r in store.load_section(conn, audit_id, "unsupported")],
        "skipped": [dict(r) for r in store.load_section(conn, audit_id, "skipped")],
    }


def format_summary(data: dict) -> str:
    audit = data["audit"]
    commit = (audit["head_commit"] or "no commits")[:12]
    branch = audit["branch"] or "detached HEAD"
    lines = [
        f"Audit #{audit['id']}: {audit['repo_name']} ({audit['repo_path']})",
        f"Status: {audit['status']}" + (f" ({audit['error']})" if audit["error"] else ""),
        f"Commit {commit} on {branch}"
        + (" (working tree has uncommitted changes)" if audit["working_tree_dirty"] else ""),
        "Scope: tracked files" + (" plus untracked code, config, and docs" if audit["include_untracked"] else ""),
        "",
        f"Files: {sum(data['files_by_category'].values())} ("
        + ", ".join(f"{n} {c}" for c, n in data["files_by_category"].items())
        + ")",
        "Languages:",
    ]
    if data["languages"]:
        width = max(len(lang["language"]) for lang in data["languages"])
        for lang in data["languages"]:
            support = "supported" if lang["supported"] else "unsupported"
            lines.append(
                f"  {lang['language']:<{width}}  {lang['files']:>5} files  {lang['lines']:>8,} lines  {support}"
            )
    else:
        lines.append("  none")
    deps = data["dependencies_by_ecosystem"]
    lines += [
        f"Modules: {data['modules']} ({data['cross_module_links']} cross-module import links)",
        f"Dependencies: {sum(deps.values())} from {data['manifests']} manifests ({_join_counts(list(deps.items()))})",
        f"Entry points: {sum(data['entry_points_by_kind'].values())} "
        f"({_join_counts([(n, k) for k, n in data['entry_points_by_kind'].items()])})",
        f"Relationships: {sum(data['relationships_by_kind'].values())} imports "
        f"({_join_counts([(n, k) for k, n in data['relationships_by_kind'].items()])})",
        "Unsupported:",
    ]
    if data["unsupported"]:
        for item in data["unsupported"]:
            lines.append(f"  {item['technology']} ({item['kind']}, {item['file_count']} files): {item['reason']}")
    else:
        lines.append("  none")
    lines.append("Skipped (not stored):")
    if data["skipped"]:
        for item in data["skipped"]:
            lines.append(f"  {item['file_count']} {item['reason']}, e.g. {item['example_path']}")
    else:
        lines.append("  none")
    return "\n".join(lines)


TASK_COLUMNS = ["id", "priority", "status", "file_count", "line_count", "title", "priority_reason"]


def task_rows(conn: sqlite3.Connection, audit_id: int, status: str | None = None) -> list[dict]:
    store.get_audit(conn, audit_id)
    return [{c: row[c] for c in TASK_COLUMNS} for row in store.list_tasks(conn, audit_id, status)]


def format_task_list(conn: sqlite3.Connection, audit_id: int, rows: list[dict]) -> str:
    audit = store.get_audit(conn, audit_id)
    counts = dict(
        conn.execute(
            "SELECT status, COUNT(*) FROM audit_tasks WHERE audit_id = ? GROUP BY status", (audit_id,)
        ).fetchall()
    )
    lines = [
        f"Audit #{audit_id}: {audit['repo_name']}",
        f"Tasks: {sum(counts.values())} ("
        + ", ".join(f"{counts.get(s, 0)} {s}" for s in store.TASK_STATUSES)
        + ")",
        "",
        format_table(rows, TASK_COLUMNS),
        "",
        "Not covered by any task:",
    ]
    gaps = store.not_covered(conn, audit_id)
    lines += [f"  {g['what']}: {g['file_count']} files, e.g. {g['example_path']}" for g in gaps] or ["  none"]
    lines.append("\nShow one task with: audit-agent task <id>")
    return "\n".join(lines)


def task_detail(conn: sqlite3.Connection, task_id: int) -> dict:
    task = store.get_task(conn, task_id)
    context = {name: [dict(r) for r in rows] for name, rows in store.task_context(conn, task_id).items()}
    for call in context["api_calls"]:
        call["route_app"] = store.app_name(call["route_repo"], call["route_app_root"] or ".") if call["route_repo"] else None
    root = review.task_apps(conn, task["audit_id"]).get(task_id)
    apps = {a["root"]: a for a in app_rows(conn, [task["audit_id"]])}
    app = apps.get(root)
    return {
        "task": dict(task),
        "app": {"name": app["name"], "type": app["type"]} if app else None,
        "api": json.loads(task["detail"]) if task["kind"] == "api" and task["detail"] else None,
        "in_batch": store.task_in_open_batch(conn, task_id),
        **context,
        "findings": [dict(r) for r in store.list_findings(conn, task_id=task_id)],
        "runs": [dict(r) for r in store.task_runs(conn, task_id)],
        "api_seen": api_seen(conn, task) if task["kind"] == "files" else None,
    }


def api_seen(conn: sqlite3.Connection, task: sqlite3.Row) -> dict:
    """Which of a file task's files finished API-call tasks already looked at, and what those tasks found in them."""
    rows = conn.execute(
        """SELECT tf.path, t.id AS api_task_id, t.title AS api_task_title, a.repo_name
           FROM audit_task_files tf
           JOIN api_task_files af ON af.audit_id = tf.audit_id AND af.path = tf.path
           JOIN audit_tasks t ON t.id = af.task_id AND t.kind = 'api' AND t.status = 'done'
           JOIN audits a ON a.id = t.audit_id
           WHERE tf.task_id = ? ORDER BY tf.path, t.id""",
        (task["id"],),
    ).fetchall()
    files: dict[str, list[dict]] = {}
    for r in rows:
        files.setdefault(r["path"], []).append({"id": r["api_task_id"], "title": r["api_task_title"], "repo": r["repo_name"]})
    api_ids = sorted({r["api_task_id"] for r in rows})
    found = []
    if api_ids:
        marks = ",".join("?" * len(api_ids))
        paths = ",".join("?" * len(files))
        found = [dict(r) for r in conn.execute(
            f"""SELECT id, kind, severity, bug_type, title, file_path, line, issue_url, task_id FROM findings
                WHERE task_id IN ({marks}) AND COALESCE(file_audit_id, audit_id) = ? AND file_path IN ({paths})
                  AND duplicate_of IS NULL
                ORDER BY kind, file_path, line""",
            (*api_ids, task["audit_id"], *files),
        )]
    total = conn.execute("SELECT COUNT(*) FROM audit_task_files WHERE task_id = ?", (task["id"],)).fetchone()[0]
    return {"files": [{"path": p, "api_tasks": t} for p, t in files.items()], "total_files": total, "findings": found}


def reproduction_state(verification: sqlite3.Row | dict | None) -> str:
    """not_tried, running, failed, or the verdict of the latest attempt."""
    if verification is None:
        return "not_tried"
    if verification["status"] == "done":
        return verification["verdict"]
    return verification["status"]


def fix_state(attempt: sqlite3.Row | dict | None) -> str:
    """not_tried, running, failed, or the outcome of the latest "Reproduce + fix" attempt."""
    if attempt is None:
        return "not_tried"
    return attempt["outcome"] if attempt["status"] == "done" else attempt["status"]


def findings_overview(conn: sqlite3.Connection) -> dict:
    """Every finding (not needs-review items) across tasks, with its app and its latest reproduction."""
    rows = conn.execute(
        """SELECT f.id, f.title, f.severity, f.bug_type, f.file_path, f.line, f.issue_url, f.task_id, f.possible_duplicate_of,
                  a.id AS repo_audit_id, a.repo_name, inf.app_root, ap.app_type,
                  v.id AS v_id, v.status AS v_status, v.verdict AS v_verdict, v.reason AS v_reason, v.cost_usd AS v_cost,
                  (SELECT COUNT(*) FROM verifications x WHERE x.finding_id = f.id) AS attempts,
                  fx.id AS fx_id, fx.status AS fx_status, fx.outcome AS fx_outcome, fx.cost_usd AS fx_cost, fx.pr_url AS fx_pr
           FROM findings f
           JOIN audits a ON a.id = COALESCE(f.file_audit_id, f.audit_id)
           LEFT JOIN inventory_files inf ON inf.audit_id = a.id AND inf.path = f.file_path
           LEFT JOIN inventory_apps ap ON ap.audit_id = a.id AND ap.root = inf.app_root
           LEFT JOIN verifications v ON v.id = (SELECT MAX(id) FROM verifications y WHERE y.finding_id = f.id)
           LEFT JOIN fix_attempts fx ON fx.id = (SELECT MAX(id) FROM fix_attempts z WHERE z.finding_id = f.id)
           WHERE f.kind = 'finding' AND f.duplicate_of IS NULL
           ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3
                    ELSE 4 END, a.repo_name, f.file_path, f.line"""
    ).fetchall()
    apps: dict[str, dict] = {}
    findings = []
    for r in rows:
        root = r["app_root"] or "."
        key = f"{r['repo_audit_id']}:{root}"
        apps.setdefault(key, {"key": key, "name": store.app_name(r["repo_name"], root), "audit_id": r["repo_audit_id"],
                              "type": r["app_type"] or "unknown"})
        latest = {"status": r["v_status"], "verdict": r["v_verdict"]} if r["v_id"] else None
        findings.append({
            "id": r["id"], "title": r["title"], "severity": r["severity"], "bug_type": r["bug_type"],
            "file_path": r["file_path"], "line": r["line"], "issue_url": r["issue_url"], "task_id": r["task_id"],
            "possible_duplicate_of": r["possible_duplicate_of"],
            "app_key": key, "reproduction": reproduction_state(latest), "attempts": r["attempts"],
            "reason": r["v_reason"], "cost_usd": r["v_cost"],
            "fix": fix_state({"status": r["fx_status"], "outcome": r["fx_outcome"]} if r["fx_id"] else None),
            "fix_cost_usd": r["fx_cost"], "pr_url": r["fx_pr"],
        })
    names = Counter(a["name"] for a in apps.values())
    per_app = Counter(f["app_key"] for f in findings)
    for app in apps.values():
        app["label"] = app["name"] + (f" (audit {app['audit_id']})" if names[app["name"]] > 1 else "")
        app["findings"] = per_app[app["key"]]
    for f in findings:
        f["app"] = apps[f["app_key"]]["label"]
        f["app_type"] = apps[f["app_key"]]["type"]
    return {"findings": findings, "apps": sorted(apps.values(), key=lambda a: a["label"])}


def finding_detail(conn: sqlite3.Connection, finding_id: int) -> dict:
    finding = dict(store.get_finding(conn, finding_id))
    audit = store.get_audit(conn, finding["file_audit_id"] or finding["audit_id"])
    attempts = [
        {k: v for k, v in dict(row).items() if k != "transcript"}
        for row in conn.execute("SELECT * FROM verifications WHERE finding_id = ? ORDER BY id DESC", (finding_id,))
    ]
    latest = attempts[0] if attempts else None
    fixes = [{k: v for k, v in dict(row).items() if k not in ("transcript", "files")}
             for row in store.list_fixes(conn, finding_id)]
    return {"finding": {**finding, "repo_name": audit["repo_name"]}, "reproduction": reproduction_state(latest),
            "attempts": attempts, "fix": fix_state(fixes[0] if fixes else None), "fixes": fixes}


def _audit_apps(conn: sqlite3.Connection, audit: sqlite3.Row) -> list[dict]:
    """An audit's apps with task counts by status. An audit made before apps were detected
    shows as one app of unknown type covering all its tasks."""
    apps = app_rows(conn, [audit["id"]])
    if not apps:
        apps = [{"name": audit["repo_name"], "path": audit["repo_path"], "audit_id": audit["id"], "root": None,
                 "type": "unknown", "detected_type": "unknown", "type_source": "detected", "also_targets": [],
                 "source_files": None, "manifests": [], "evidence": [], "not_detected": True}]
    task_root = review.task_apps(conn, audit["id"])
    counts: dict[str | None, dict[str, int]] = {}
    for task in store.list_tasks(conn, audit["id"]):
        root = task_root.get(task["id"]) if apps[0]["root"] is not None else None
        bucket = counts.setdefault(root, {s: 0 for s in store.TASK_STATUSES})
        bucket[task["status"]] += 1
    for app in apps:
        app["task_counts"] = counts.get(app["root"], {s: 0 for s in store.TASK_STATUSES})
        app["repo_name"] = audit["repo_name"]
    return apps


def project_overview(conn: sqlite3.Connection) -> list[dict]:
    """Every project with its apps, newest first, then the audits that belong to no project."""
    groups = []
    grouped: set[int] = set()
    for project in reversed(store.list_projects(conn)):
        audits = store.project_audits(conn, project["id"])
        grouped.update(a["id"] for a in audits)
        groups.append({
            "id": project["id"], "name": project["name"], "root_path": project["root_path"],
            "api_mapped_at": project["api_mapped_at"],
            "apps": [app for audit in audits for app in _audit_apps(conn, audit)],
        })
    loose = [a for a in store.list_audits(conn) if a["id"] not in grouped]
    if loose:
        groups.append({"id": None, "name": "Audits not in a project", "root_path": None, "api_mapped_at": None,
                       "apps": [app for audit in loose for app in _audit_apps(conn, audit)]})
    return groups


def closest_route(pattern: str | None, method: str, routes: list[dict]) -> dict | None:
    """The route sharing the longest leading path with the call (a route parameter matches any
    segment; the project's common prefix such as /api may be missing from the call). Ties prefer
    literal matches, then the call's method, then a similar length. A shared common prefix alone
    is not enough, so unrelated calls get no closest route."""
    if not pattern:
        return None
    paths = {id(r): [s for s in r["pattern"].split("/") if s] for r in routes}
    firsts = Counter(segs[0] for segs in paths.values() if segs)
    common = {s for s, n in firsts.items() if n >= 5 and n / max(1, len(routes)) >= 0.3}
    call = [s for s in pattern.split("/") if s]
    candidates = [call] + [[c] + call for c in common if not call or call[0] != c]
    best, best_score = None, None
    for route in routes:
        route_segs = paths[id(route)]
        for segs in candidates:
            shared = literal = 0
            for c, r in zip(segs, route_segs):
                if c != r and r != ":":
                    break
                shared += 1
                literal += c == r
            meaningful = shared - (1 if segs and segs[0] in common else 0)
            score = (shared, literal, route["method"] == method, -abs(len(segs) - len(route_segs)))
            if meaningful >= 1 and (best_score is None or score > best_score):
                best, best_score = route, score
    return best


def api_map_view(conn: sqlite3.Connection, project_id: int) -> dict:
    """A project's API map by app: links between apps, calls that reach no route, every route with
    the frontend files that call it, and routes only mentioned or not referenced at all."""
    project = store.get_project(conn, project_id)
    audit_ids = [a["id"] for a in store.project_audits(conn, project_id)]
    known = {(a["audit_id"], a["root"]): a for a in app_rows(conn, audit_ids)}

    def app(audit_id: int, repo_name: str, root: str | None) -> dict:
        found = known.get((audit_id, root))
        return {"name": found["name"], "type": found["type"]} if found else {"name": repo_name, "type": "unknown"}

    routes: dict[int, dict] = {}
    for r in conn.execute(
        """SELECT r.id, r.audit_id, r.method, r.path, r.pattern, r.file_path, r.line, r.handler_path, a.repo_name,
                  f.app_root
           FROM api_routes r JOIN audits a ON a.id = r.audit_id
           LEFT JOIN inventory_files f ON f.audit_id = r.audit_id AND f.path = r.file_path
           WHERE r.project_id = ? ORDER BY r.path, r.method""",
        (project_id,),
    ):
        routes[r["id"]] = {
            "id": r["id"], "method": r["method"], "path": r["path"], "pattern": r["pattern"],
            "file_path": r["file_path"], "line": r["line"], "handler_path": r["handler_path"],
            "app": app(r["audit_id"], r["repo_name"], r["app_root"]), "callers": [],
        }

    counts = {s: 0 for s in store.API_CALL_STATUSES}
    links: dict[tuple, int] = {}
    problems = []
    for c in conn.execute(
        """SELECT c.audit_id, c.source_path, c.line, c.method, COALESCE(c.pattern, c.raw) AS url, c.pattern,
                  c.status, c.via, c.route_id, a.repo_name, f.app_root
           FROM api_calls c JOIN audits a ON a.id = c.audit_id
           LEFT JOIN inventory_files f ON f.audit_id = c.audit_id AND f.path = c.source_path
           WHERE c.project_id = ? ORDER BY a.repo_name, c.source_path, c.line""",
        (project_id,),
    ):
        counts[c["status"]] += 1
        caller = app(c["audit_id"], c["repo_name"], c["app_root"])
        route = routes.get(c["route_id"])
        if c["status"] == "matched" and route:
            route["callers"].append({"app": caller["name"], "path": c["source_path"], "line": c["line"]})
            key = (caller["name"], caller["type"], route["app"]["name"], route["app"]["type"])
            links[key] = links.get(key, 0) + 1
        elif c["status"] in ("broken", "wrong_method"):
            closest = route or closest_route(c["pattern"], c["method"], list(routes.values()))
            problems.append({
                "app": caller["name"], "app_type": caller["type"], "path": c["source_path"], "line": c["line"],
                "method": c["method"], "url": c["url"], "status": c["status"], "via": c["via"],
                "closest": {"method": closest["method"], "path": closest["path"], "app": closest["app"]["name"]}
                if closest else None,
            })

    mentioned = []
    for m in conn.execute(
        """SELECT m.route_id, m.audit_id, m.source_path, m.line, m.text, a.repo_name, f.app_root
           FROM api_mentions m JOIN audits a ON a.id = m.audit_id
           LEFT JOIN inventory_files f ON f.audit_id = m.audit_id AND f.path = m.source_path
           WHERE m.project_id = ? ORDER BY m.source_path, m.line""",
        (project_id,),
    ):
        route = routes[m["route_id"]]
        mentioned.append({"method": route["method"], "path": route["path"], "route_app": route["app"]["name"],
                          "app": app(m["audit_id"], m["repo_name"], m["app_root"])["name"],
                          "file": m["source_path"], "line": m["line"], "text": m["text"]})
    unused_ids = {r["id"] for r in store.unused_api_routes(conn, project_id)}
    return {
        "project": {"id": project["id"], "name": project["name"], "api_mapped_at": project["api_mapped_at"]},
        "counts": counts,
        "links": [{"from": f, "from_type": ft, "to": t, "to_type": tt, "calls": n}
                  for (f, ft, t, tt), n in sorted(links.items(), key=lambda item: -item[1])],
        "problems": problems,
        "routes": list(routes.values()),
        "mentioned": mentioned,
        "unused": [routes[i] for i in routes if i in unused_ids],
    }


def format_findings(rows: list, runs: list | None = None) -> str:
    lines = []
    for run in runs or []:
        cost = f", ${run['cost_usd']:.2f}" if run["cost_usd"] is not None else ""
        took = f", {run['duration_ms'] / 1000:.0f}s" if run["duration_ms"] else ""
        lines.append(f"Run #{run['id']} ({run['agent']} agent): {run['status']}{took}{cost}")
        if run["error"]:
            lines.append(f"  error: {run['error']}")
    findings = [r for r in rows if r["kind"] == "finding"]
    review = [r for r in rows if r["kind"] == "needs_review"]
    lines.append(f"\nFindings ({len(findings)}):" if lines else f"Findings ({len(findings)}):")
    for f in findings:
        lines += [
            f"  [{f['severity'].upper()}] {f['bug_type']}: {f['title']}",
            f"    {f['file_path']}:{f['line']}  (task #{f['task_id']}, {f['agent']} agent)",
            *[f"      | {code}" for code in (f["evidence"] or "").splitlines()[:6]],
            f"    {f['explanation']}",
        ]
    if not findings:
        lines.append("  none")
    lines.append(f"\nNeeds your review ({len(review)}), not counted as bugs:")
    for n in review:
        where = f"{n['file_path']}:{n['line']}  " if n["file_path"] else ""
        lines += [
            f"  - {n['title']}",
            f"    {where}(task #{n['task_id']})",
            f"    Suspicion: {n['explanation']}",
            f"    Not confirmed because: {n['why_unconfirmed'] or 'not stated'}",
        ]
    if not review:
        lines.append("  none")
    return "\n".join(lines)


def format_task_detail(data: dict) -> str:
    task = data["task"]
    lines = [
        f"Task #{task['id']}: {task['title']}",
        f"Audit #{task['audit_id']}  status: {task['status']}  priority: {task['priority']} ({task['priority_reason']})",
        "",
        f"Files to audit ({len(data['files'])}, {task['line_count']:,} lines):",
        *[
            f"  {f['repo_name'] + ': ' if 'repo_name' in f else ''}{f['path']}  ({f['line_count']} lines)"
            + (f"  [{f['role']}]" if "role" in f else "")
            for f in data["files"]
        ],
    ]
    if api := data.get("api"):
        lines += ["", f"API call from {api['caller_app']} ({api['status']}):"]
        lines += [f"  {c['file']}:{c['line']}  {c['method']} {c['url']}  ({c['via']})" for c in api["calls"]]
        target = api["route"] or api["closest"]
        if target:
            label = "Reaches" if api["route"] else "Closest route"
            lines.append(f"  {label}: {target['method']} {target['path']} in {target['repo']}: "
                         f"{target['handler'] or target['file']}")

    def block(title: str, rows: list[dict], render) -> None:
        if api and not rows:
            return
        lines.append("")
        lines.append(f"{title} ({len(rows)}):")
        lines.extend(f"  {render(r)}" for r in rows[:25])
        if len(rows) > 25:
            lines.append(f"  ... and {len(rows) - 25} more")
        if not rows:
            lines.append("  none")

    block("Entry points", data["entry_points"], lambda r: f"{r['path']}  {r['kind']}: {r['detail']}")
    block("Imports these files from elsewhere in the repo", data["imports"], lambda r: r["path"])
    block("Imported by", data["imported_by"], lambda r: r["path"])
    block("Packages used", data["packages"], lambda r: f"{r['name']} ({r['uses']})")
    block("Imports of missing files", data["unresolved"], lambda r: f"{r['path']}:{r['line']}  {r['specifier']}")

    def call_line(r: dict) -> str:
        where = f"{r['path']}:{r['line']}  {r['method']} {r['url']}"
        if r["status"] == "matched":
            return f"{where}  ->  {r['route_repo']}: {r['handler_path']}"
        if r["status"] == "wrong_method":
            return f"{where}  [WRONG METHOD: route is {r['route_method']} {r['route_path']}]"
        return f"{where}  [{r['status'].upper()}]"

    block("API calls made here", data["api_calls"], call_line)
    block("API routes handled here", data["api_routes"], lambda r: f"{r['method']} {r['path']}  ({r['callers']} callers)")
    if data.get("runs") or data.get("findings"):
        lines += ["", format_findings(data["findings"], data["runs"])]
    return "\n".join(lines)


API_SECTIONS = {
    "calls": ["repo_name", "source_path", "line", "method", "pattern", "status", "route_path", "route_repo", "via"],
    "broken": ["repo_name", "source_path", "line", "method", "pattern", "via"],
    "wrong-method": ["repo_name", "source_path", "line", "method", "pattern", "route_method", "route_path", "via"],
    "unresolved": ["repo_name", "source_path", "line", "method", "raw", "via"],
    "routes": ["repo_name", "method", "path", "file_path", "handler_path", "callers"],
    "mentioned": ["repo_name", "method", "path", "mention_repo", "source_path", "line", "text"],
    "unused": ["repo_name", "method", "path", "file_path"],
}


def api_rows(conn: sqlite3.Connection, project_id: int, section: str) -> list[dict]:
    columns = API_SECTIONS[section]
    if section == "routes":
        rows = store.api_routes(conn, project_id)
    elif section == "mentioned":
        rows = store.mentioned_api_routes(conn, project_id)
    elif section == "unused":
        rows = store.unused_api_routes(conn, project_id)
    else:
        status = {"broken": "broken", "wrong-method": "wrong_method", "unresolved": "unresolved"}.get(section)
        rows = store.api_calls(conn, project_id, status)
    return [{c: row[c] for c in columns} for row in rows]


def format_api_summary(conn: sqlite3.Connection, project_id: int) -> str:
    project = store.get_project(conn, project_id)
    audits = store.project_audits(conn, project_id)
    counts = dict(
        conn.execute(
            "SELECT status, COUNT(*) FROM api_calls WHERE project_id = ? GROUP BY status", (project_id,)
        ).fetchall()
    )
    routes = conn.execute("SELECT COUNT(*) FROM api_routes WHERE project_id = ?", (project_id,)).fetchone()[0]
    mentioned = conn.execute(
        "SELECT COUNT(DISTINCT route_id) FROM api_mentions WHERE project_id = ?", (project_id,)
    ).fetchone()[0]
    via = dict(
        conn.execute(
            """SELECT CASE WHEN via LIKE 'wrapper%' THEN 'through a wrapper'
                           WHEN via LIKE 'direct%' THEN 'direct HTTP client call'
                           ELSE 'by function name only' END, COUNT(*)
               FROM api_calls WHERE project_id = ? GROUP BY 1""",
            (project_id,),
        ).fetchall()
    )
    apps = app_rows(conn, [a["id"] for a in audits])
    lines = [
        f"Project #{project['id']}: {project['name']}",
        "Audits: " + ", ".join(f"#{a['id']} {a['repo_name']}" for a in audits),
        *(["Apps: " + ", ".join(f"{a['name']} ({TYPE_LABELS[a['type']]})" for a in apps)] if apps else []),
        f"API map built: {project['api_mapped_at'] or 'not yet'}",
        "",
        f"Backend routes: {routes}  ({mentioned} only mentioned in frontend code, "
        f"{len(store.unused_api_routes(conn, project_id))} not referenced anywhere)",
        f"Frontend calls: {sum(counts.values())}  (" + ", ".join(f"{n} {k}" for k, n in sorted(via.items())) + ")",
    ]
    labels = {
        "matched": "matched to a route",
        "wrong_method": "path exists, but not with this HTTP method",
        "broken": "no route with this path",
        "unresolved": "URL built at runtime, can't be matched",
        "external": "calls to other services, including every call a backend app makes",
    }
    lines += [f"  {counts.get(s, 0):>5}  {labels[s]}" for s in store.API_CALL_STATUSES]
    problems = [dict(r) for r in store.api_calls(conn, project_id) if r["status"] in ("broken", "wrong_method")]
    if problems:
        lines += ["", "Calls that don't reach a route:"]
        for p in problems:
            target = f"  (closest: {p['route_method']} {p['route_path']})" if p["route_path"] else ""
            lines.append(f"  {p['repo_name']}: {p['source_path']}:{p['line']}  {p['method']} {p['pattern']}{target}")
    lines.append(
        "\nList more with: audit-agent api "
        + (project["name"] if " " not in project["name"] else f'"{project["name"]}"')
        + " --section broken|wrong-method|unresolved|routes|mentioned|unused|calls"
    )
    return "\n".join(lines)


def section_rows(conn: sqlite3.Connection, audit_id: int, section: str) -> list[dict]:
    store.get_audit(conn, audit_id)
    columns = SECTION_COLUMNS[section]
    return [{c: row[c] for c in columns} for row in store.load_section(conn, audit_id, section)]


def format_table(rows: list[dict], columns: list[str]) -> str:
    if not rows:
        return "(none)"
    cells = [["" if row[c] is None else str(row[c]) for c in columns] for row in rows]
    widths = [min(60, max(len(c), *(len(r[i]) for r in cells))) for i, c in enumerate(columns)]

    def render(values: list[str]) -> str:
        return "  ".join(
            (v if len(v) <= w else v[: w - 1] + "…").ljust(w) for v, w in zip(values, widths)
        ).rstrip()
    return "\n".join([render(columns), render(["-" * w for w in widths]), *map(render, cells)])
