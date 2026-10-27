"""SQLite persistence for audits and their repository inventories."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from audit_agent.inventory.apps import APP_TYPES
from audit_agent.inventory.models import Inventory
from audit_agent.repo import GitRepository

SCHEMA_VERSION = 16

SCHEMA = """
CREATE TABLE audits (
    id INTEGER PRIMARY KEY,
    repo_path TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    head_commit TEXT,
    branch TEXT,
    working_tree_dirty INTEGER NOT NULL,
    include_untracked INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE inventory_skipped (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    example_path TEXT NOT NULL
);

CREATE TABLE inventory_files (
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    category TEXT NOT NULL,
    language TEXT,
    supported INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL,
    line_count INTEGER,
    module_path TEXT,
    note TEXT,
    PRIMARY KEY (audit_id, path)
);

CREATE TABLE inventory_modules (
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    package_root TEXT,
    languages TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    line_count INTEGER NOT NULL,
    PRIMARY KEY (audit_id, path)
);

CREATE TABLE inventory_dependencies (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    manifest_path TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version_spec TEXT,
    scope TEXT NOT NULL
);

CREATE TABLE inventory_entry_points (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    path TEXT,
    kind TEXT NOT NULL,
    source_path TEXT NOT NULL,
    detail TEXT NOT NULL
);

CREATE TABLE inventory_relationships (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    source_path TEXT NOT NULL,
    kind TEXT NOT NULL,
    specifier TEXT NOT NULL,
    target_path TEXT,
    target_package TEXT,
    line INTEGER NOT NULL
);

CREATE TABLE inventory_unsupported (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    technology TEXT NOT NULL,
    kind TEXT NOT NULL,
    evidence_path TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    reason TEXT NOT NULL
);

CREATE INDEX inventory_relationships_source ON inventory_relationships (audit_id, source_path);
CREATE INDEX inventory_relationships_target ON inventory_relationships (audit_id, target_path);
"""

TASK_STATUSES = ("pending", "running", "done", "failed", "blocked", "cancelled")


def _audit_tasks_ddl(name: str) -> str:
    return f"""
CREATE TABLE {name} (
    id INTEGER PRIMARY KEY,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    line_count INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    priority_reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN {TASK_STATUSES}),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


TASK_TABLES = _audit_tasks_ddl("audit_tasks") + """
-- The primary key keeps any file from belonging to two tasks in the same audit.
CREATE TABLE audit_task_files (
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    task_id INTEGER NOT NULL REFERENCES audit_tasks(id) ON DELETE CASCADE,
    PRIMARY KEY (audit_id, path)
);

CREATE INDEX audit_task_files_task ON audit_task_files (task_id);
"""

API_CALL_STATUSES = ("matched", "wrong_method", "broken", "unresolved", "external")

API_TABLES = f"""
CREATE TABLE projects (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    api_mapped_at TEXT
);

CREATE TABLE project_audits (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    PRIMARY KEY (project_id, audit_id)
);

CREATE TABLE api_routes (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    pattern TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    handler_path TEXT,
    mounted INTEGER NOT NULL
);

CREATE TABLE api_calls (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    source_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    method TEXT NOT NULL,
    raw TEXT NOT NULL,
    pattern TEXT,
    status TEXT NOT NULL CHECK (status IN {API_CALL_STATUSES}),
    route_id INTEGER REFERENCES api_routes(id) ON DELETE SET NULL
);

CREATE INDEX api_calls_source ON api_calls (audit_id, source_path);
CREATE INDEX api_routes_file ON api_routes (audit_id, file_path);
"""

API_TRACE_TABLES = """
ALTER TABLE api_calls ADD COLUMN via TEXT;

-- Frontend text that mentions a route no traced call reaches (from the reverse search).
CREATE TABLE api_mentions (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    route_id INTEGER NOT NULL REFERENCES api_routes(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    source_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    text TEXT NOT NULL
);
"""

FINDING_KINDS = ("finding", "needs_review")
BUG_TYPES = ("logic", "security", "concurrency")
SEVERITIES = ("low", "medium", "high", "critical")

FINDING_TABLES = f"""
CREATE TABLE task_runs (
    id INTEGER PRIMARY KEY,
    task_id INTEGER NOT NULL REFERENCES audit_tasks(id) ON DELETE CASCADE,
    agent TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'done', 'failed')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_ms INTEGER,
    cost_usd REAL,
    num_turns INTEGER,
    session_id TEXT,
    error TEXT,
    rejected TEXT,
    raw_output TEXT
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    task_id INTEGER NOT NULL REFERENCES audit_tasks(id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES task_runs(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    agent TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN {FINDING_KINDS}),
    bug_type TEXT CHECK (bug_type IS NULL OR bug_type IN {BUG_TYPES}),
    severity TEXT CHECK (severity IS NULL OR severity IN {SEVERITIES}),
    title TEXT NOT NULL,
    file_path TEXT,
    line INTEGER,
    evidence TEXT,
    explanation TEXT NOT NULL,
    why_unconfirmed TEXT,
    files_examined TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX findings_task ON findings (task_id);
CREATE INDEX task_runs_task ON task_runs (task_id);
"""

APP_TABLES = f"""
ALTER TABLE inventory_files ADD COLUMN app_root TEXT;
ALTER TABLE projects ADD COLUMN root_path TEXT;

CREATE TABLE inventory_apps (
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    root TEXT NOT NULL,
    app_type TEXT NOT NULL CHECK (app_type IN {APP_TYPES}),
    detected_type TEXT NOT NULL CHECK (detected_type IN {APP_TYPES}),
    type_source TEXT NOT NULL CHECK (type_source IN ('detected', 'engineer')),
    manifests TEXT NOT NULL,
    evidence TEXT NOT NULL,
    also_targets TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    PRIMARY KEY (audit_id, root)
);

-- Keyed by the app folder's absolute path so a correction applies to every later audit of it.
CREATE TABLE app_type_overrides (
    app_path TEXT PRIMARY KEY,
    app_type TEXT NOT NULL CHECK (app_type IN {APP_TYPES}),
    updated_at TEXT NOT NULL
);
"""

TASK_KINDS = ("files", "api")

API_TASK_TABLES = """
ALTER TABLE audit_tasks ADD COLUMN kind TEXT NOT NULL DEFAULT 'files';
ALTER TABLE audit_tasks ADD COLUMN app_root TEXT;
ALTER TABLE audit_tasks ADD COLUMN task_key TEXT;
ALTER TABLE audit_tasks ADD COLUMN detail TEXT;
ALTER TABLE findings ADD COLUMN file_audit_id INTEGER REFERENCES audits(id) ON DELETE CASCADE;

-- Files of an API-call task. Unlike audit_task_files, the same file can be in many of these
-- tasks, and the files can come from any repository in the project.
CREATE TABLE api_task_files (
    task_id INTEGER NOT NULL REFERENCES audit_tasks(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (task_id, audit_id, path)
);

CREATE UNIQUE INDEX audit_tasks_key ON audit_tasks (audit_id, task_key) WHERE task_key IS NOT NULL;
"""

BATCH_STATUSES = ("submitting", "in_progress", "canceling", "ended", "imported", "failed")
BATCH_ITEM_STATUSES = ("waiting", "done", "failed", "canceled")

BATCH_TABLES = f"""
-- A Claude Message Batch. The row is written before the batch is sent, so a crash while sending
-- still leaves a record that recovery can match to the batch Anthropic created.
CREATE TABLE claude_batches (
    id INTEGER PRIMARY KEY,
    anthropic_id TEXT UNIQUE,
    status TEXT NOT NULL CHECK (status IN {BATCH_STATUSES}),
    model TEXT NOT NULL,
    request_count INTEGER NOT NULL,
    succeeded INTEGER NOT NULL DEFAULT 0,
    errored INTEGER NOT NULL DEFAULT 0,
    canceled INTEGER NOT NULL DEFAULT 0,
    expired INTEGER NOT NULL DEFAULT 0,
    recovered INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    ended_at TEXT
);

-- custom_id is the label sent with each request ("task-<id>-<random>"); results come back with it,
-- so a result can always be matched to its task, even from a batch whose id was lost.
CREATE TABLE claude_batch_items (
    batch_id INTEGER NOT NULL REFERENCES claude_batches(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL REFERENCES audit_tasks(id) ON DELETE CASCADE,
    custom_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN {BATCH_ITEM_STATUSES}),
    run_id INTEGER REFERENCES task_runs(id) ON DELETE SET NULL,
    error TEXT,
    PRIMARY KEY (batch_id, task_id)
);

CREATE INDEX claude_batch_items_task ON claude_batch_items (task_id, status);
"""

ISSUE_TABLES = """
ALTER TABLE findings ADD COLUMN issue_url TEXT;
"""

# 'continued': Claude asked for more files, and the task went on to the next batch round.
ROUND_ITEM_STATUSES = ("waiting", "done", "failed", "canceled", "continued")

# SQLite can't change a CHECK constraint in place, so the items table is rebuilt to allow
# 'continued' and to hold what a follow-up round needs.
BATCH_ROUND_TABLES = f"""
CREATE TABLE claude_batch_items_new (
    batch_id INTEGER NOT NULL REFERENCES claude_batches(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL REFERENCES audit_tasks(id) ON DELETE CASCADE,
    custom_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN {ROUND_ITEM_STATUSES}),
    run_id INTEGER REFERENCES task_runs(id) ON DELETE SET NULL,
    error TEXT,
    round INTEGER NOT NULL DEFAULT 1,
    extra_files TEXT NOT NULL DEFAULT '[]',
    previous_report TEXT,
    prior_cost_usd REAL NOT NULL DEFAULT 0,
    report TEXT,
    cost_usd REAL,
    PRIMARY KEY (batch_id, task_id)
);
INSERT INTO claude_batch_items_new (batch_id, task_id, custom_id, status, run_id, error)
    SELECT batch_id, task_id, custom_id, status, run_id, error FROM claude_batch_items;
DROP TABLE claude_batch_items;
ALTER TABLE claude_batch_items_new RENAME TO claude_batch_items;
CREATE INDEX claude_batch_items_task ON claude_batch_items (task_id, status);
"""

VERIFICATION_STATUSES = ("running", "done", "failed")
VERDICTS = ("reproduced", "not_reproduced", "unable")

# One attempt to reproduce a finding with a test. 'failed' means the attempt itself broke (for example
# the API was unreachable) and can be started again; 'done' always has a verdict.
VERIFICATION_TABLES = f"""
CREATE TABLE verifications (
    id INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN {VERIFICATION_STATUSES}),
    verdict TEXT CHECK (verdict IS NULL OR verdict IN {VERDICTS}),
    reason TEXT,
    manual_steps TEXT,
    conclusion TEXT,
    test_path TEXT,
    test_name TEXT,
    test_code TEXT,
    test_output TEXT,
    model TEXT NOT NULL,
    num_turns INTEGER NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL,
    duration_ms INTEGER,
    transcript TEXT,
    error TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE INDEX verifications_finding ON verifications (finding_id);
"""

FIX_OUTCOMES = ("fixed", "fix_rejected", "not_reproduced", "unable")

# One "Reproduce + fix" run of a finding. `files` holds, for each source file the fix changed, the hash
# of the content it started from and the content after the fix, so a pull request can be made later.
FIX_TABLES = f"""
CREATE TABLE fix_attempts (
    id INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN {VERIFICATION_STATUSES}),
    outcome TEXT CHECK (outcome IS NULL OR outcome IN {FIX_OUTCOMES}),
    reason TEXT,
    manual_steps TEXT,
    summary TEXT,
    test_path TEXT,
    test_name TEXT,
    test_code TEXT,
    before_output TEXT,
    after_output TEXT,
    related_output TEXT,
    patch TEXT,
    files TEXT,
    base_commit TEXT,
    base_branch TEXT,
    model TEXT NOT NULL,
    num_turns INTEGER NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL,
    duration_ms INTEGER,
    transcript TEXT,
    error TEXT,
    pr_url TEXT,
    pr_branch TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE INDEX fix_attempts_finding ON fix_attempts (finding_id);
"""

# The comment a fix attempt posted on its finding's GitHub issue: the pull request link for a fix, or why
# there is no fix for a rejected or unable attempt. Kept so a comment is never posted twice.
FIX_COMMENT_TABLES = """
ALTER TABLE fix_attempts ADD COLUMN issue_comment_url TEXT;
"""

# duplicate_of: the investigator said this is the same bug as an already known finding it was shown. Such
# a finding gets no GitHub issue and isn't listed with the others. possible_duplicate_of: the app's own guess
# (same file, nearby line, similar title); only a label for the engineer to check.
DUPLICATE_TABLES = """
ALTER TABLE findings ADD COLUMN duplicate_of INTEGER REFERENCES findings(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN possible_duplicate_of INTEGER REFERENCES findings(id) ON DELETE SET NULL;
"""

SCHEMA += (TASK_TABLES + API_TABLES + API_TRACE_TABLES + FINDING_TABLES + APP_TABLES + API_TASK_TABLES + BATCH_TABLES
           + ISSUE_TABLES + BATCH_ROUND_TABLES + VERIFICATION_TABLES + FIX_TABLES + FIX_COMMENT_TABLES + DUPLICATE_TABLES)

SECTIONS = {
    "files": ("inventory_files", "path"),
    "modules": ("inventory_modules", "path"),
    "dependencies": ("inventory_dependencies", "manifest_path, name"),
    "entry-points": ("inventory_entry_points", "kind, path"),
    "relationships": ("inventory_relationships", "source_path, line"),
    "unsupported": ("inventory_unsupported", "kind, technology"),
    "skipped": ("inventory_skipped", "file_count DESC"),
    "apps": ("inventory_apps", "root"),
}

# Each entry upgrades the schema from version N to N + 1.
MIGRATIONS = {
    1: """
    -- Version 1 audits always included untracked files.
    ALTER TABLE audits ADD COLUMN include_untracked INTEGER NOT NULL DEFAULT 1;
    CREATE TABLE inventory_skipped (
        id INTEGER PRIMARY KEY,
        audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
        reason TEXT NOT NULL,
        file_count INTEGER NOT NULL,
        example_path TEXT NOT NULL
    );
    """,
    2: TASK_TABLES,
    # SQLite cannot change a CHECK constraint in place, so the table is rebuilt to allow
    # 'cancelled'. Foreign keys are off during migrations, so task files survive the rebuild.
    3: _audit_tasks_ddl("audit_tasks_new")
    + """
    INSERT INTO audit_tasks_new
        SELECT id, audit_id, title, line_count, priority, priority_reason, status, created_at, updated_at
        FROM audit_tasks;
    DROP TABLE audit_tasks;
    ALTER TABLE audit_tasks_new RENAME TO audit_tasks;
    """,
    4: API_TABLES,
    5: API_TRACE_TABLES,
    6: FINDING_TABLES,
    7: APP_TABLES,
    8: API_TASK_TABLES,
    9: BATCH_TABLES,
    10: ISSUE_TABLES,
    11: BATCH_ROUND_TABLES,
    12: VERIFICATION_TABLES,
    13: FIX_TABLES,
    14: FIX_COMMENT_TABLES,
    15: DUPLICATE_TABLES,
}


class StoreError(Exception):
    pass


def default_db_path() -> Path:
    if env := os.environ.get("AUDIT_AGENT_DB"):
        return Path(env).expanduser()
    return Path.home() / ".audit-agent" / "audit.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: Path) -> sqlite3.Connection:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = OFF")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == 0:
        conn.executescript(f"BEGIN; {SCHEMA} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;")
    elif version > SCHEMA_VERSION:
        conn.close()
        raise StoreError(f"{path} uses schema version {version}; this build only knows up to {SCHEMA_VERSION}")
    while version and version < SCHEMA_VERSION:
        conn.executescript(f"BEGIN; {MIGRATIONS[version]} PRAGMA user_version = {version + 1}; COMMIT;")
        version += 1
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_outside_repository(db_path: Path, repo: GitRepository) -> None:
    resolved = Path(db_path).expanduser().resolve()
    if resolved.is_relative_to(repo.root):
        raise StoreError(
            f"The audit database {resolved} is inside the repository being audited. "
            "Choose a location outside it so the audit leaves the repository unchanged."
        )


def create_audit(conn: sqlite3.Connection, repo: GitRepository, include_untracked: bool = False) -> int:
    now = _now()
    with conn:
        cursor = conn.execute(
            """INSERT INTO audits (repo_path, repo_name, head_commit, branch, working_tree_dirty,
                                   include_untracked, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 'discovering', ?, ?)""",
            (str(repo.root), repo.name, repo.head_commit, repo.branch, int(repo.dirty),
             int(include_untracked), now, now),
        )
    return cursor.lastrowid


def mark_failed(conn: sqlite3.Connection, audit_id: int, error: str) -> None:
    with conn:
        conn.execute(
            "UPDATE audits SET status = 'failed', error = ?, updated_at = ? WHERE id = ?",
            (error, _now(), audit_id),
        )


def app_path(repo_path: str, root: str) -> str:
    return repo_path if root == "." else str(Path(repo_path) / root)


def app_name(repo_name: str, root: str) -> str:
    return repo_name if root == "." else f"{repo_name}/{root}"


def save_inventory(conn: sqlite3.Connection, audit_id: int, inventory: Inventory) -> None:
    repo_path = get_audit(conn, audit_id)["repo_path"]
    overrides = dict(conn.execute("SELECT app_path, app_type FROM app_type_overrides").fetchall())
    with conn:
        conn.executemany(
            """INSERT INTO inventory_files (audit_id, path, category, language, supported, size_bytes,
                                            line_count, module_path, note, app_root)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (audit_id, f.path, f.category, f.language, int(f.supported), f.size_bytes,
                 f.line_count, f.module_path, f.note, f.app_root)
                for f in inventory.files
            ],
        )
        rows = []
        for app in inventory.apps:
            corrected = overrides.get(app_path(repo_path, app.root))
            rows.append(
                (audit_id, app.root, corrected or app.app_type, app.app_type, "engineer" if corrected else "detected",
                 json.dumps(app.manifests), json.dumps(app.evidence), ",".join(app.also_targets), app.file_count)
            )
        conn.executemany(
            """INSERT INTO inventory_apps (audit_id, root, app_type, detected_type, type_source, manifests,
                                           evidence, also_targets, file_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        conn.executemany(
            "INSERT INTO inventory_modules VALUES (?, ?, ?, ?, ?, ?)",
            [
                (audit_id, m.path, m.package_root, ",".join(m.languages), m.file_count, m.line_count)
                for m in inventory.modules
            ],
        )
        conn.executemany(
            """INSERT INTO inventory_dependencies (audit_id, manifest_path, ecosystem, name, version_spec, scope)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(audit_id, d.manifest_path, d.ecosystem, d.name, d.version_spec, d.scope) for d in inventory.dependencies],
        )
        conn.executemany(
            """INSERT INTO inventory_entry_points (audit_id, path, kind, source_path, detail)
               VALUES (?, ?, ?, ?, ?)""",
            [(audit_id, e.path, e.kind, e.source_path, e.detail) for e in inventory.entry_points],
        )
        conn.executemany(
            """INSERT INTO inventory_relationships
                   (audit_id, source_path, kind, specifier, target_path, target_package, line)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                (audit_id, r.source_path, r.kind, r.specifier, r.target_path, r.target_package, r.line)
                for r in inventory.relationships
            ],
        )
        conn.executemany(
            """INSERT INTO inventory_unsupported (audit_id, technology, kind, evidence_path, file_count, reason)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [(audit_id, u.technology, u.kind, u.evidence_path, u.file_count, u.reason) for u in inventory.unsupported],
        )
        conn.executemany(
            "INSERT INTO inventory_skipped (audit_id, reason, file_count, example_path) VALUES (?, ?, ?, ?)",
            [(audit_id, s.reason, s.file_count, s.example_path) for s in inventory.skipped],
        )
        conn.execute(
            "UPDATE audits SET status = 'inventoried', updated_at = ? WHERE id = ?",
            (_now(), audit_id),
        )


def get_audit(conn: sqlite3.Connection, audit_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    if row is None:
        raise StoreError(f"No audit with id {audit_id}")
    return row


def list_audits(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM audits ORDER BY id").fetchall()


def load_section(conn: sqlite3.Connection, audit_id: int, section: str) -> list[sqlite3.Row]:
    table, order = SECTIONS[section]
    return conn.execute(
        f"SELECT * FROM {table} WHERE audit_id = ? ORDER BY {order}", (audit_id,)
    ).fetchall()


def save_tasks(conn: sqlite3.Connection, audit_id: int, tasks: list) -> None:
    """Insert planned tasks in the order given and mark the audit as planned."""
    now = _now()
    with conn:
        for task in tasks:
            cursor = conn.execute(
                """INSERT INTO audit_tasks (audit_id, title, line_count, priority, priority_reason,
                                            created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (audit_id, task.title, task.line_count, task.priority, task.priority_reason, now, now),
            )
            conn.executemany(
                "INSERT INTO audit_task_files (audit_id, path, task_id) VALUES (?, ?, ?)",
                [(audit_id, path, cursor.lastrowid) for path in task.files],
            )
        conn.execute(
            "UPDATE audits SET status = 'planned', updated_at = ? WHERE id = ?", (now, audit_id)
        )


def task_count(conn: sqlite3.Connection, audit_id: int) -> int:
    """How many file tasks planning created for the audit (API-call tasks are counted apart)."""
    return conn.execute(
        "SELECT COUNT(*) FROM audit_tasks WHERE audit_id = ? AND kind = 'files'", (audit_id,)
    ).fetchone()[0]


def list_tasks(conn: sqlite3.Connection, audit_id: int, status: str | None = None) -> list[sqlite3.Row]:
    sql = """SELECT t.*, COUNT(f.path) + (SELECT COUNT(*) FROM api_task_files af WHERE af.task_id = t.id) AS file_count
             FROM audit_tasks t LEFT JOIN audit_task_files f ON f.task_id = t.id
             WHERE t.audit_id = ?"""
    params: list = [audit_id]
    if status:
        sql += " AND t.status = ?"
        params.append(status)
    sql += " GROUP BY t.id ORDER BY t.priority DESC, t.id"
    return conn.execute(sql, params).fetchall()


def get_task(conn: sqlite3.Connection, task_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM audit_tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        raise StoreError(f"No task with id {task_id}")
    return row


def save_api_tasks(conn: sqlite3.Connection, audit_ids: list[int], tasks: list) -> dict[str, int]:
    """Create or refresh API-call tasks by key. A task that hasn't run yet is updated to the latest
    map; one that ran keeps its files and status. Pending API tasks of these audits whose call no
    longer exists are deleted, since nothing was learned from them."""
    now = _now()
    counts = {"created": 0, "updated": 0, "removed": 0}
    wanted = {(t.audit_id, t.key) for t in tasks}
    with conn:
        for task in tasks:
            row = conn.execute(
                "SELECT id, status FROM audit_tasks WHERE audit_id = ? AND task_key = ?", (task.audit_id, task.key)
            ).fetchone()
            values = (task.title, task.line_count, task.priority, task.priority_reason, task.app_root,
                      json.dumps(task.detail))
            if row is None:
                task_id = conn.execute(
                    """INSERT INTO audit_tasks (audit_id, title, line_count, priority, priority_reason, app_root,
                                                detail, kind, task_key, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'api', ?, ?, ?)""",
                    (task.audit_id, *values, task.key, now, now),
                ).lastrowid
                counts["created"] += 1
            elif row["status"] == "pending":
                task_id = row["id"]
                conn.execute(
                    """UPDATE audit_tasks SET title = ?, line_count = ?, priority = ?, priority_reason = ?,
                              app_root = ?, detail = ?, updated_at = ? WHERE id = ?""",
                    (*values, now, task_id),
                )
                conn.execute("DELETE FROM api_task_files WHERE task_id = ?", (task_id,))
                counts["updated"] += 1
            else:
                continue
            conn.executemany(
                "INSERT OR IGNORE INTO api_task_files (task_id, audit_id, path, role) VALUES (?, ?, ?, ?)",
                [(task_id, audit_id, path, role) for audit_id, path, role in task.files],
            )
        marks = ", ".join("?" * len(audit_ids))
        for row in conn.execute(
            f"SELECT id, audit_id, task_key FROM audit_tasks WHERE kind = 'api' AND status = 'pending' AND audit_id IN ({marks})",
            audit_ids,
        ).fetchall():
            if (row["audit_id"], row["task_key"]) not in wanted:
                conn.execute("DELETE FROM audit_tasks WHERE id = ?", (row["id"],))
                counts["removed"] += 1
    return counts


def api_task_files(conn: sqlite3.Connection, task_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT af.audit_id, af.path, af.role, a.repo_name, a.repo_path, f.language, f.line_count
           FROM api_task_files af JOIN audits a ON a.id = af.audit_id
           LEFT JOIN inventory_files f ON f.audit_id = af.audit_id AND f.path = af.path
           WHERE af.task_id = ?
           ORDER BY CASE af.role WHEN 'caller' THEN 0 WHEN 'wrapper' THEN 1 WHEN 'route' THEN 2 WHEN 'handler' THEN 3
                    ELSE 4 END, a.repo_name, af.path""",
        (task_id,),
    ).fetchall()


def task_context(conn: sqlite3.Connection, task_id: int) -> dict[str, list[sqlite3.Row]]:
    """A task's files and what they connect to, read from the audit's inventory. An API-call task's
    files come from every repository the call touches, each with its role."""
    task = get_task(conn, task_id)
    if task["kind"] == "api":
        empty = ("imports", "imported_by", "packages", "unresolved", "entry_points", "api_calls", "api_routes")
        return {"files": api_task_files(conn, task_id), **{name: [] for name in empty}}
    params = {"audit": task["audit_id"], "task": task_id}
    in_task = "SELECT path FROM audit_task_files WHERE task_id = :task"
    queries = {
        "files": f"""SELECT f.path, f.language, f.line_count FROM inventory_files f
                     WHERE f.audit_id = :audit AND f.path IN ({in_task}) ORDER BY f.path""",
        "imports": f"""SELECT r.target_path AS path, COUNT(*) AS links FROM inventory_relationships r
                       WHERE r.audit_id = :audit AND r.kind = 'internal'
                         AND r.source_path IN ({in_task}) AND r.target_path NOT IN ({in_task})
                       GROUP BY r.target_path ORDER BY links DESC, path""",
        "imported_by": f"""SELECT r.source_path AS path, COUNT(*) AS links FROM inventory_relationships r
                           WHERE r.audit_id = :audit AND r.kind = 'internal'
                             AND r.target_path IN ({in_task}) AND r.source_path NOT IN ({in_task})
                           GROUP BY r.source_path ORDER BY links DESC, path""",
        "packages": f"""SELECT r.target_package AS name, COUNT(*) AS uses FROM inventory_relationships r
                        WHERE r.audit_id = :audit AND r.kind = 'package' AND r.source_path IN ({in_task})
                        GROUP BY r.target_package ORDER BY uses DESC, name""",
        "unresolved": f"""SELECT r.source_path AS path, r.line, r.specifier FROM inventory_relationships r
                          WHERE r.audit_id = :audit AND r.kind = 'unresolved' AND r.source_path IN ({in_task})
                          ORDER BY r.source_path, r.line""",
        "entry_points": f"""SELECT e.path, e.kind, e.detail FROM inventory_entry_points e
                            WHERE e.audit_id = :audit AND e.path IN ({in_task}) ORDER BY e.path""",
        "api_calls": f"""SELECT c.source_path AS path, c.line, c.method, COALESCE(c.pattern, c.raw) AS url, c.status, c.via,
                                r.method AS route_method, r.path AS route_path, r.handler_path,
                                ra.repo_name AS route_repo, rf.app_root AS route_app_root
                         FROM api_calls c
                         LEFT JOIN api_routes r ON r.id = c.route_id
                         LEFT JOIN audits ra ON ra.id = r.audit_id
                         LEFT JOIN inventory_files rf ON rf.audit_id = r.audit_id AND rf.path = r.file_path
                         WHERE c.audit_id = :audit AND c.source_path IN ({in_task}) AND c.status != 'external'
                         ORDER BY CASE c.status WHEN 'broken' THEN 0 WHEN 'wrong_method' THEN 1
                                  WHEN 'unresolved' THEN 2 ELSE 3 END, c.source_path, c.line""",
        "api_routes": f"""SELECT r.method, r.path, r.file_path, r.handler_path,
                                 COUNT(c.id) AS callers
                          FROM api_routes r
                          LEFT JOIN api_calls c ON c.route_id = r.id AND c.status = 'matched'
                          WHERE r.audit_id = :audit
                            AND (r.file_path IN ({in_task}) OR r.handler_path IN ({in_task}))
                          GROUP BY r.id ORDER BY r.path, r.method""",
    }
    return {name: conn.execute(sql, params).fetchall() for name, sql in queries.items()}


def create_project(conn: sqlite3.Connection, name: str, audit_ids: list[int]) -> int:
    """Create a project (or reuse one with the same name) and add audits to it."""
    for audit_id in audit_ids:
        get_audit(conn, audit_id)
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO projects (name, created_at) VALUES (?, ?)", (name, _now())
        )
        project_id = conn.execute("SELECT id FROM projects WHERE name = ?", (name,)).fetchone()[0]
        conn.executemany(
            "INSERT OR IGNORE INTO project_audits (project_id, audit_id) VALUES (?, ?)",
            [(project_id, a) for a in audit_ids],
        )
    return project_id


def create_folder_project(conn: sqlite3.Connection, root_path: str, audit_ids: list[int]) -> int:
    """The project for a folder given to `start`, named after the folder. Starting the same folder
    again reuses its project and replaces its audits, so an older audit is never mapped twice."""
    with conn:
        row = conn.execute("SELECT id FROM projects WHERE root_path = ?", (root_path,)).fetchone()
        if row:
            project_id = row[0]
        else:
            base = name = Path(root_path).name or root_path
            suffix = 1
            while conn.execute("SELECT 1 FROM projects WHERE name = ?", (name,)).fetchone():
                suffix += 1
                name = f"{base} ({suffix})"
            project_id = conn.execute(
                "INSERT INTO projects (name, created_at, root_path) VALUES (?, ?, ?)", (name, _now(), root_path)
            ).lastrowid
        conn.execute("DELETE FROM project_audits WHERE project_id = ?", (project_id,))
        conn.executemany(
            "INSERT INTO project_audits (project_id, audit_id) VALUES (?, ?)", [(project_id, a) for a in audit_ids]
        )
    return project_id


def list_apps(conn: sqlite3.Connection, audit_ids: list[int]) -> list[sqlite3.Row]:
    marks = ", ".join("?" * len(audit_ids))
    return conn.execute(
        f"""SELECT ap.*, a.repo_name, a.repo_path FROM inventory_apps ap JOIN audits a ON a.id = ap.audit_id
            WHERE ap.audit_id IN ({marks}) ORDER BY a.repo_name, ap.root""",
        audit_ids,
    ).fetchall()


def _all_apps(conn: sqlite3.Connection) -> list[tuple[str, sqlite3.Row]]:
    rows = conn.execute(
        "SELECT ap.audit_id, ap.root, a.repo_name, a.repo_path FROM inventory_apps ap JOIN audits a ON a.id = ap.audit_id"
    ).fetchall()
    return [(app_path(r["repo_path"], r["root"]), r) for r in rows]


def find_app_path(conn: sqlite3.Connection, ref: str) -> str:
    """The folder of an inventoried app, given its path or its name (`repo` or `repo/sub/folder`)."""
    resolved = str(Path(ref).expanduser().resolve())
    paths = {path for path, r in _all_apps(conn) if path == resolved or app_name(r["repo_name"], r["root"]) == ref}
    if not paths:
        raise StoreError(f"No inventoried app named or at {ref!r}. List apps with: audit-agent apps")
    if len(paths) > 1:
        raise StoreError(f"{ref!r} matches several apps; give one of these paths instead: " + ", ".join(sorted(paths)))
    return paths.pop()


def set_app_type(conn: sqlite3.Connection, path: str, app_type: str) -> list[int]:
    """Record the engineer's type for the app at `path`, kept for later audits too, and apply it to
    the audits that already have this app. Returns those audits' ids."""
    if app_type not in APP_TYPES:
        raise StoreError(f"App type must be one of {', '.join(APP_TYPES)}")
    matches = [(r["audit_id"], r["root"]) for p, r in _all_apps(conn) if p == path]
    with conn:
        conn.execute(
            """INSERT INTO app_type_overrides (app_path, app_type, updated_at) VALUES (?, ?, ?)
               ON CONFLICT (app_path) DO UPDATE SET app_type = excluded.app_type, updated_at = excluded.updated_at""",
            (path, app_type, _now()),
        )
        conn.executemany(
            "UPDATE inventory_apps SET app_type = ?, type_source = 'engineer' WHERE audit_id = ? AND root = ?",
            [(app_type, audit_id, root) for audit_id, root in matches],
        )
    return sorted({audit_id for audit_id, _ in matches})


def projects_of(conn: sqlite3.Connection, audit_ids: list[int]) -> list[int]:
    marks = ", ".join("?" * len(audit_ids))
    return [r[0] for r in conn.execute(
        f"SELECT DISTINCT project_id FROM project_audits WHERE audit_id IN ({marks}) ORDER BY project_id", audit_ids
    )]


def get_project(conn: sqlite3.Connection, ref: str | int) -> sqlite3.Row:
    """Look a project up by id or by name."""
    ref = str(ref)
    row = conn.execute("SELECT * FROM projects WHERE name = ?", (ref,)).fetchone()
    if row is None and ref.isdigit():
        row = conn.execute("SELECT * FROM projects WHERE id = ?", (int(ref),)).fetchone()
    if row is None:
        raise StoreError(f"No project named or numbered {ref!r}")
    return row


def list_projects(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT p.*, GROUP_CONCAT(a.id || ' ' || a.repo_name, ', ') AS audits
           FROM projects p
           LEFT JOIN project_audits pa ON pa.project_id = p.id
           LEFT JOIN audits a ON a.id = pa.audit_id
           GROUP BY p.id ORDER BY p.id"""
    ).fetchall()


def related_audits(conn: sqlite3.Connection, audit_id: int) -> list[sqlite3.Row]:
    """Other audits that share a project with this one."""
    return conn.execute(
        """SELECT DISTINCT a.* FROM audits a
           JOIN project_audits pa ON pa.audit_id = a.id
           WHERE pa.project_id IN (SELECT project_id FROM project_audits WHERE audit_id = ?)
             AND a.id != ?
           ORDER BY a.id""",
        (audit_id, audit_id),
    ).fetchall()


def start_run(conn: sqlite3.Connection, task_id: int, agent: str) -> int:
    """Claim the task and record a new run. The claim is one conditional update, so two workers
    can never run the same task at once."""
    now = _now()
    with conn:
        claimed = conn.execute(
            """UPDATE audit_tasks SET status = 'running', updated_at = ?
               WHERE id = ? AND status NOT IN ('running', 'cancelled')""",
            (now, task_id),
        ).rowcount
        if not claimed:
            raise StoreError(f"Task {task_id} is already running or was cancelled.")
        cursor = conn.execute(
            "INSERT INTO task_runs (task_id, agent, status, started_at) VALUES (?, ?, 'running', ?)",
            (task_id, agent, now),
        )
    return cursor.lastrowid


OPEN_BATCH_STATUSES = ("submitting", "in_progress", "canceling", "ended")


def task_in_open_batch(conn: sqlite3.Connection, task_id: int) -> bool:
    marks = ", ".join("?" * len(OPEN_BATCH_STATUSES))
    return conn.execute(
        f"""SELECT 1 FROM claude_batch_items i JOIN claude_batches b ON b.id = i.batch_id
            WHERE i.task_id = ? AND i.status = 'waiting' AND b.status IN ({marks})""",
        (task_id, *OPEN_BATCH_STATUSES),
    ).fetchone() is not None


def batched_task_ids(conn: sqlite3.Connection) -> set[int]:
    """Tasks waiting for a result from an open batch."""
    marks = ", ".join("?" * len(OPEN_BATCH_STATUSES))
    return {r[0] for r in conn.execute(
        f"""SELECT i.task_id FROM claude_batch_items i JOIN claude_batches b ON b.id = i.batch_id
            WHERE i.status = 'waiting' AND b.status IN ({marks})""",
        OPEN_BATCH_STATUSES,
    )}


def create_batch(conn: sqlite3.Connection, model: str, items: list[tuple]) -> int:
    """Record a batch before it is sent. Each item is (task_id, custom_id) or (task_id, custom_id, round
    details) for a follow-up round: {"round", "extra_files", "previous_report", "prior_cost_usd"}."""
    now = _now()
    with conn:
        batch_id = conn.execute(
            """INSERT INTO claude_batches (status, model, request_count, created_at, updated_at)
               VALUES ('submitting', ?, ?, ?, ?)""",
            (model, len(items), now, now),
        ).lastrowid
        rows = []
        for task_id, custom_id, *rest in items:
            details = rest[0] if rest else {}
            rows.append((batch_id, task_id, custom_id, details.get("round", 1),
                         json.dumps(details.get("extra_files") or []),
                         json.dumps(details["previous_report"]) if details.get("previous_report") else None,
                         details.get("prior_cost_usd") or 0))
        conn.executemany(
            """INSERT INTO claude_batch_items (batch_id, task_id, custom_id, status, round, extra_files,
                                               previous_report, prior_cost_usd)
               VALUES (?, ?, ?, 'waiting', ?, ?, ?, ?)""",
            rows,
        )
    return batch_id


def continue_batch_item(conn: sqlite3.Connection, custom_id: str, report: dict, cost_usd: float | None,
                        next_batch_id: int | None) -> None:
    """Close an item whose answer asked for more files; the task goes on in another round."""
    with conn:
        conn.execute(
            "UPDATE claude_batch_items SET status = 'continued', report = ?, cost_usd = ?, error = ? WHERE custom_id = ?",
            (json.dumps(report), cost_usd, f"continued in batch #{next_batch_id}" if next_batch_id else None, custom_id),
        )


def update_batch(conn: sqlite3.Connection, batch_id: int, **fields) -> None:
    allowed = {"anthropic_id", "status", "succeeded", "errored", "canceled", "expired", "error", "ended_at"}
    if unknown := set(fields) - allowed:
        raise ValueError(f"unknown batch fields {unknown}")
    assignments = ", ".join(f"{name} = ?" for name in fields)
    with conn:
        conn.execute(
            f"UPDATE claude_batches SET {assignments}, updated_at = ? WHERE id = ?",
            (*fields.values(), _now(), batch_id),
        )


def adopt_batch(conn: sqlite3.Connection, anthropic_id: str, status: str, model: str, request_count: int,
                created_at: str) -> int:
    """Record a batch found on Anthropic's side that this database had lost track of."""
    with conn:
        return conn.execute(
            """INSERT INTO claude_batches (anthropic_id, status, model, request_count, recovered, created_at, updated_at)
               VALUES (?, ?, ?, ?, 1, ?, ?)""",
            (anthropic_id, status, model, request_count, created_at, _now()),
        ).lastrowid


def get_batch(conn: sqlite3.Connection, batch_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM claude_batches WHERE id = ?", (batch_id,)).fetchone()
    if row is None:
        raise StoreError(f"No batch with id {batch_id}")
    return row


def list_batches(conn: sqlite3.Connection, statuses: tuple[str, ...] | None = None) -> list[sqlite3.Row]:
    sql = """SELECT b.*, (SELECT COUNT(*) FROM claude_batch_items i WHERE i.batch_id = b.id AND i.status = 'waiting')
                    AS waiting,
                    (SELECT COUNT(*) FROM claude_batch_items i WHERE i.batch_id = b.id AND i.status = 'continued')
                    AS continued,
                    (SELECT MAX(i.round) FROM claude_batch_items i WHERE i.batch_id = b.id) AS round
             FROM claude_batches b"""
    params: tuple = ()
    if statuses:
        sql += f" WHERE b.status IN ({', '.join('?' * len(statuses))})"
        params = statuses
    return conn.execute(sql + " ORDER BY b.id DESC", params).fetchall()


def batch_item_by_custom_id(conn: sqlite3.Connection, custom_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM claude_batch_items WHERE custom_id = ?", (custom_id,)).fetchone()


def add_batch_item(conn: sqlite3.Connection, batch_id: int, task_id: int, custom_id: str) -> None:
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO claude_batch_items (batch_id, task_id, custom_id, status) VALUES (?, ?, ?, 'waiting')",
            (batch_id, task_id, custom_id),
        )


def finish_batch_item(conn: sqlite3.Connection, custom_id: str, status: str, run_id: int | None = None,
                      error: str | None = None) -> None:
    with conn:
        conn.execute(
            "UPDATE claude_batch_items SET status = ?, run_id = ?, error = ? WHERE custom_id = ?",
            (status, run_id, error, custom_id),
        )


def fail_interrupted_runs(conn: sqlite3.Connection) -> int:
    """Mark runs left 'running' by a process that stopped as failed, so their tasks can be sent
    again. Returns how many tasks were affected."""
    now = _now()
    with conn:
        conn.execute(
            """UPDATE task_runs SET status = 'failed', finished_at = ?,
                   error = 'Interrupted: the process running this investigation stopped before it finished.'
               WHERE status = 'running'""",
            (now,),
        )
        return conn.execute(
            "UPDATE audit_tasks SET status = 'failed', updated_at = ? WHERE status = 'running'", (now,)
        ).rowcount


def finish_run(
    conn: sqlite3.Connection,
    run_id: int,
    task_id: int,
    status: str,
    *,
    error: str | None = None,
    duration_ms: int | None = None,
    cost_usd: float | None = None,
    num_turns: int | None = None,
    session_id: str | None = None,
    rejected: str | None = None,
    raw_output: str | None = None,
) -> None:
    now = _now()
    with conn:
        conn.execute(
            """UPDATE task_runs SET status = ?, finished_at = ?, error = ?, duration_ms = ?, cost_usd = ?,
                   num_turns = ?, session_id = ?, rejected = ?, raw_output = ?
               WHERE id = ?""",
            (status, now, error, duration_ms, cost_usd, num_turns, session_id, rejected, raw_output, run_id),
        )
        conn.execute("UPDATE audit_tasks SET status = ?, updated_at = ? WHERE id = ?", (status, now, task_id))


def save_findings(
    conn: sqlite3.Connection,
    run_id: int,
    task_id: int,
    audit_id: int,
    agent: str,
    findings: list[dict],
    needs_review: list[dict],
) -> None:
    now = _now()
    rows = [
        (task_id, run_id, audit_id, agent, "finding", f["bug_type"], f["severity"], f["title"], f["file_path"],
         f["line"], f["evidence"], f["explanation"], None, None, f.get("file_audit_id"), f.get("duplicate_of"),
         f.get("possible_duplicate_of"), now)
        for f in findings
    ] + [
        (task_id, run_id, audit_id, agent, "needs_review", n.get("bug_type"), None, n["title"], n.get("file_path"),
         n.get("line"), n.get("evidence"), n["explanation"], n.get("why_unconfirmed"),
         json.dumps(n.get("files_examined") or []), n.get("file_audit_id"), n.get("duplicate_of"),
         n.get("possible_duplicate_of"), now)
        for n in needs_review
    ]
    with conn:
        conn.executemany(
            """INSERT INTO findings (task_id, run_id, audit_id, agent, kind, bug_type, severity, title, file_path,
                                     line, evidence, explanation, why_unconfirmed, files_examined, file_audit_id,
                                     duplicate_of, possible_duplicate_of, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )


def list_findings(conn: sqlite3.Connection, *, audit_id: int | None = None, task_id: int | None = None,
                  kind: str | None = None) -> list[sqlite3.Row]:
    sql = """SELECT f.*, t.title AS task_title, fa.repo_name AS file_repo
             FROM findings f JOIN audit_tasks t ON t.id = f.task_id
             LEFT JOIN audits fa ON fa.id = COALESCE(f.file_audit_id, f.audit_id)
             WHERE 1 = 1"""
    params: list = []
    if audit_id is not None:
        sql += " AND f.audit_id = ?"
        params.append(audit_id)
    if task_id is not None:
        sql += " AND f.task_id = ?"
        params.append(task_id)
    if kind:
        sql += " AND f.kind = ?"
        params.append(kind)
    sql += """ ORDER BY f.kind, CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
               WHEN 'low' THEN 3 ELSE 4 END, f.file_path, f.line"""
    return conn.execute(sql, params).fetchall()


def known_findings(conn: sqlite3.Connection, task_id: int, limit: int = 60) -> list[sqlite3.Row]:
    """Findings and review items already saved (by any task) that cite one of this task's files, most severe
    first; duplicates point to these instead of being listed themselves."""
    task = get_task(conn, task_id)
    if task["kind"] == "api":
        files = "SELECT audit_id, path FROM api_task_files WHERE task_id = :task"
    else:
        files = "SELECT audit_id, path FROM audit_task_files WHERE task_id = :task"
    return conn.execute(
        f"""SELECT f.id, f.kind, f.severity, f.bug_type, f.title, f.file_path, f.line, a.repo_name,
                   a.id AS file_audit_id
            FROM findings f JOIN audits a ON a.id = COALESCE(f.file_audit_id, f.audit_id)
            WHERE f.duplicate_of IS NULL
              AND (COALESCE(f.file_audit_id, f.audit_id), f.file_path) IN ({files})
            ORDER BY f.kind, CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                     WHEN 'low' THEN 3 ELSE 4 END, f.file_path, f.line
            LIMIT :limit""",
        {"task": task_id, "limit": limit},
    ).fetchall()


def get_finding(conn: sqlite3.Connection, finding_id: int) -> sqlite3.Row:
    row = conn.execute(
        """SELECT f.*, t.title AS task_title, t.kind AS task_kind FROM findings f
           JOIN audit_tasks t ON t.id = f.task_id WHERE f.id = ?""",
        (finding_id,),
    ).fetchone()
    if row is None:
        raise StoreError(f"No finding with id {finding_id}")
    return row


def start_verification(conn: sqlite3.Connection, finding_id: int, model: str) -> int:
    """Record a new verification of the finding. Refused while another one of it is running."""
    with conn:
        cursor = conn.execute(
            """INSERT INTO verifications (finding_id, status, model, started_at)
               SELECT ?, 'running', ?, ? WHERE NOT EXISTS
                   (SELECT 1 FROM verifications WHERE finding_id = ? AND status = 'running')""",
            (finding_id, model, _now(), finding_id),
        )
    if not cursor.rowcount:
        raise StoreError(f"Finding {finding_id} is already being reproduced.")
    return cursor.lastrowid


VERIFICATION_FIELDS = {
    "status", "verdict", "reason", "manual_steps", "conclusion", "test_path", "test_name", "test_code", "test_output",
    "num_turns", "input_tokens", "output_tokens", "cache_write_tokens", "cache_read_tokens", "cost_usd",
    "duration_ms", "transcript", "error",
}


def finish_verification(conn: sqlite3.Connection, verification_id: int, status: str, **fields) -> None:
    if status not in ("done", "failed"):
        raise ValueError(f"a verification finishes as done or failed, not {status}")
    if unknown := set[str](fields) - VERIFICATION_FIELDS:
        raise ValueError(f"unknown verification fields {unknown}")
    if status == "done" and fields.get("verdict") not in VERDICTS:
        raise ValueError("a finished verification needs a verdict")
    fields = {"status": status, **fields, "finished_at": _now()}
    with conn:
        conn.execute(
            f"UPDATE verifications SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?",
            (*fields.values(), verification_id),
        )


def get_verification(conn: sqlite3.Connection, verification_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM verifications WHERE id = ?", (verification_id,)).fetchone()
    if row is None:
        raise StoreError(f"No verification with id {verification_id}")
    return row


def list_verifications(conn: sqlite3.Connection, *, finding_id: int | None = None,
                       audit_id: int | None = None) -> list[sqlite3.Row]:
    sql = """SELECT v.id, v.finding_id, v.status, v.verdict, v.reason, v.test_path, v.model, v.num_turns,
                    v.cost_usd, v.duration_ms, v.error, v.started_at, v.finished_at, f.title, f.audit_id
             FROM verifications v JOIN findings f ON f.id = v.finding_id WHERE 1 = 1"""
    params: list = []
    if finding_id is not None:
        sql += " AND v.finding_id = ?"
        params.append(finding_id)
    if audit_id is not None:
        sql += " AND f.audit_id = ?"
        params.append(audit_id)
    return conn.execute(sql + " ORDER BY v.id", params).fetchall()


def fail_interrupted_verifications(conn: sqlite3.Connection) -> int:
    """Mark verifications left 'running' by a process that stopped as failed, so they can be started again."""
    with conn:
        return conn.execute(
            """UPDATE verifications SET status = 'failed', finished_at = ?,
                   error = 'Interrupted: the process reproducing this finding stopped before it finished.'
               WHERE status = 'running'""",
            (_now(),),
        ).rowcount


def start_fix(conn: sqlite3.Connection, finding_id: int, model: str, base_commit: str | None,
              base_branch: str | None) -> int:
    """Record a new "Reproduce + fix" run of the finding. Refused while another one of it is running."""
    with conn:
        cursor = conn.execute(
            """INSERT INTO fix_attempts (finding_id, status, model, base_commit, base_branch, started_at)
               SELECT ?, 'running', ?, ?, ?, ? WHERE NOT EXISTS
                   (SELECT 1 FROM fix_attempts WHERE finding_id = ? AND status = 'running')""",
            (finding_id, model, base_commit, base_branch, _now(), finding_id),
        )
    if not cursor.rowcount:
        raise StoreError(f"Finding {finding_id} is already being fixed.")
    return cursor.lastrowid


FIX_FIELDS = {
    "status", "outcome", "reason", "manual_steps", "summary", "test_path", "test_name", "test_code", "before_output",
    "after_output", "related_output", "patch", "files", "num_turns", "input_tokens", "output_tokens",
    "cache_write_tokens", "cache_read_tokens", "cost_usd", "duration_ms", "transcript", "error",
}


def finish_fix(conn: sqlite3.Connection, attempt_id: int, status: str, **fields) -> None:
    if status not in ("done", "failed"):
        raise ValueError(f"a fix attempt finishes as done or failed, not {status}")
    if unknown := set(fields) - FIX_FIELDS:
        raise ValueError(f"unknown fix attempt fields {unknown}")
    if status == "done" and fields.get("outcome") not in FIX_OUTCOMES:
        raise ValueError("a finished fix attempt needs an outcome")
    fields = {"status": status, **fields, "finished_at": _now()}
    with conn:
        conn.execute(
            f"UPDATE fix_attempts SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?",
            (*fields.values(), attempt_id),
        )


def get_fix(conn: sqlite3.Connection, attempt_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM fix_attempts WHERE id = ?", (attempt_id,)).fetchone()
    if row is None:
        raise StoreError(f"No fix attempt with id {attempt_id}")
    return row


def list_fixes(conn: sqlite3.Connection, finding_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM fix_attempts WHERE finding_id = ? ORDER BY id DESC", (finding_id,)).fetchall()


def set_fix_pr(conn: sqlite3.Connection, attempt_id: int, url: str, branch: str) -> None:
    with conn:
        conn.execute("UPDATE fix_attempts SET pr_url = ?, pr_branch = ? WHERE id = ?", (url, branch, attempt_id))


def set_fix_comment(conn: sqlite3.Connection, attempt_id: int, url: str) -> None:
    with conn:
        conn.execute("UPDATE fix_attempts SET issue_comment_url = ? WHERE id = ?", (url, attempt_id))


def fixes_missing_comments(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Finished fix attempts whose issue should have a comment and doesn't yet: a pull request was
    opened, or the fix was rejected, or the finding couldn't be reproduced or fixed here."""
    return conn.execute(
        """SELECT a.* FROM fix_attempts a JOIN findings f ON f.id = a.finding_id
           WHERE a.status = 'done' AND a.issue_comment_url IS NULL AND f.issue_url IS NOT NULL
             AND (a.pr_url IS NOT NULL OR a.outcome IN ('fix_rejected', 'unable'))
           ORDER BY a.id"""
    ).fetchall()


def fail_interrupted_fixes(conn: sqlite3.Connection) -> int:
    with conn:
        return conn.execute(
            """UPDATE fix_attempts SET status = 'failed', finished_at = ?,
                   error = 'Interrupted: the process fixing this finding stopped before it finished.'
               WHERE status = 'running'""",
            (_now(),),
        ).rowcount


def set_finding_issue(conn: sqlite3.Connection, finding_id: int, url: str) -> None:
    with conn:
        conn.execute("UPDATE findings SET issue_url = ? WHERE id = ?", (url, finding_id))


def task_runs(conn: sqlite3.Connection, task_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT id, agent, status, started_at, finished_at, duration_ms, cost_usd, num_turns, error, rejected
           FROM task_runs WHERE task_id = ? ORDER BY id""",
        (task_id,),
    ).fetchall()


def project_audits(conn: sqlite3.Connection, project_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT a.* FROM audits a JOIN project_audits pa ON pa.audit_id = a.id
           WHERE pa.project_id = ? ORDER BY a.id""",
        (project_id,),
    ).fetchall()


def unused_api_routes(conn: sqlite3.Connection, project_id: int) -> list[sqlite3.Row]:
    """Routes no traced call reaches and no frontend code even mentions."""
    return conn.execute(
        """SELECT r.*, a.repo_name FROM api_routes r JOIN audits a ON a.id = r.audit_id
           WHERE r.project_id = ?
             AND NOT EXISTS (SELECT 1 FROM api_calls c WHERE c.route_id = r.id)
             AND NOT EXISTS (SELECT 1 FROM api_mentions m WHERE m.route_id = r.id)
           ORDER BY a.repo_name, r.path, r.method""",
        (project_id,),
    ).fetchall()


def mentioned_api_routes(conn: sqlite3.Connection, project_id: int) -> list[sqlite3.Row]:
    """Routes with no traced call whose path still appears in frontend code."""
    return conn.execute(
        """SELECT r.method, r.path, ra.repo_name, ma.repo_name AS mention_repo,
                  m.source_path, m.line, m.text
           FROM api_mentions m
           JOIN api_routes r ON r.id = m.route_id
           JOIN audits ra ON ra.id = r.audit_id
           JOIN audits ma ON ma.id = m.audit_id
           WHERE m.project_id = ?
           ORDER BY r.path, r.method, m.source_path, m.line""",
        (project_id,),
    ).fetchall()


def api_calls(conn: sqlite3.Connection, project_id: int, status: str | None = None) -> list[sqlite3.Row]:
    sql = """SELECT c.*, a.repo_name, r.method AS route_method, r.path AS route_path,
                    r.handler_path, ra.repo_name AS route_repo
             FROM api_calls c
             JOIN audits a ON a.id = c.audit_id
             LEFT JOIN api_routes r ON r.id = c.route_id
             LEFT JOIN audits ra ON ra.id = r.audit_id
             WHERE c.project_id = ?"""
    params: list = [project_id]
    if status:
        sql += " AND c.status = ?"
        params.append(status)
    sql += " ORDER BY a.repo_name, c.source_path, c.line"
    return conn.execute(sql, params).fetchall()


def api_routes(conn: sqlite3.Connection, project_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT r.*, a.repo_name,
                  (SELECT COUNT(*) FROM api_calls c WHERE c.route_id = r.id AND c.status = 'matched') AS callers
           FROM api_routes r JOIN audits a ON a.id = r.audit_id
           WHERE r.project_id = ? ORDER BY a.repo_name, r.path, r.method""",
        (project_id,),
    ).fetchall()


def not_covered(conn: sqlite3.Connection, audit_id: int) -> list[sqlite3.Row]:
    """Source files that no task can cover: unsupported languages and files too large to read."""
    return conn.execute(
        """SELECT CASE WHEN supported = 0 THEN language ELSE language || ' over 2 MB' END AS what,
                  COUNT(*) AS file_count, MIN(path) AS example_path
           FROM inventory_files
           WHERE audit_id = ? AND category = 'source' AND (supported = 0 OR line_count IS NULL)
           GROUP BY what ORDER BY file_count DESC, what""",
        (audit_id,),
    ).fetchall()
