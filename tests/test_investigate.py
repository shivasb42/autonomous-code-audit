import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from audit_agent import investigate, planning, review, store
from audit_agent.inventory import discover
from audit_agent.repo import open_repository
from tests.helpers import make_repo, repo_fingerprint
from tests.test_cli import run_cli
from tests.test_inventory import DART_REPO, NODE_REPO

FAKE_CLAUDE = """#!{python}
import json, os, pathlib, sys
args = sys.argv[1:]
prompt = sys.stdin.read()
log = os.environ.get("FAKE_CLAUDE_LOG")
if log:
    pathlib.Path(log).write_text(json.dumps({{"args": args, "prompt": prompt, "cwd": os.getcwd()}}))
mode = os.environ.get("FAKE_CLAUDE_MODE", "ok")
if mode == "fail":
    print("not logged in", file=sys.stderr)
    sys.exit(1)
if mode == "edit":
    pathlib.Path("SNEAKY.txt").write_text("changed")
report = json.loads(pathlib.Path(os.environ["FAKE_CLAUDE_REPORT"]).read_text())
print(json.dumps({{"type": "result", "is_error": False, "result": "done", "structured_output": report,
                  "total_cost_usd": 0.12, "duration_ms": 1500, "num_turns": 5, "session_id": "s1"}}))
"""

REPORT = {
    "findings": [
        {
            "title": "App starts before async setup finishes",
            "bug_type": "concurrency",
            "severity": "high",
            "file": "lib/main.dart",
            "line": 10,
            "evidence": "runApp(const App());",
            "explanation": "main is async but nothing is awaited before runApp.",
        },
        {
            "title": "Cited with a slightly wrong line",
            "bug_type": "logic",
            "severity": "low",
            "file": "./lib/main.dart",
            "line": 3,
            "evidence": "runApp(const App());",
            "explanation": "The quoted code is on line 10, so the line is corrected.",
        },
        {
            "title": "Cites a file that doesn't exist",
            "bug_type": "security",
            "severity": "critical",
            "file": "lib/auth/secret_handler.dart",
            "line": 4,
            "evidence": "token = read()",
            "explanation": "Made up.",
        },
        {
            "title": "Quotes code that isn't there",
            "bug_type": "logic",
            "severity": "medium",
            "file": "lib/main.dart",
            "line": 9,
            "evidence": "if (user.isAdmin) deleteEverything();",
            "explanation": "This code doesn't exist.",
        },
    ],
    "needs_review": [
        {
            "title": "Backend may not check ownership",
            "suspicion": "The API call could let users act on other users' data.",
            "files_examined": ["lib/src/api.dart"],
            "why_unconfirmed": "The backend handler is not in this repository.",
        }
    ],
}


class InvestigateTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.conn = store.connect(self.base / "audit.db")
        self.addCleanup(self.conn.close)

        fake = self.base / "fake-claude"
        fake.write_text(FAKE_CLAUDE.format(python=sys.executable))
        fake.chmod(0o755)
        self.report_path = self.base / "report.json"
        self.report_path.write_text(json.dumps(REPORT))
        self.log_path = self.base / "claude-log.json"
        env = mock.patch.dict(
            os.environ,
            {"AUDIT_AGENT_CLAUDE": str(fake), "FAKE_CLAUDE_REPORT": str(self.report_path), "FAKE_CLAUDE_LOG": str(self.log_path)},
        )
        env.start()
        self.addCleanup(env.stop)

    def _audit(self, files, name="repo"):
        root = make_repo(self.base / name, files)
        repo = open_repository(root)
        audit_id = store.create_audit(self.conn, repo)
        store.save_inventory(self.conn, audit_id, discover(repo))
        planning.plan_audit(self.conn, audit_id)
        return root, audit_id

    def _task(self, audit_id, title):
        return {t["title"]: t["id"] for t in store.list_tasks(self.conn, audit_id)}[title]

    def test_findings_are_checked_against_the_code_before_saving(self):
        root, audit_id = self._audit(DART_REPO)
        task_id = self._task(audit_id, "Audit lib")
        before = repo_fingerprint(root)

        summary = investigate.investigate(self.conn, task_id)

        self.assertEqual(before, repo_fingerprint(root))
        self.assertEqual(store.get_task(self.conn, task_id)["status"], "done")
        findings = {f["title"]: f for f in store.list_findings(self.conn, task_id=task_id, kind="finding")}
        self.assertEqual(set(findings), {"App starts before async setup finishes", "Cited with a slightly wrong line"})
        self.assertEqual(findings["Cited with a slightly wrong line"]["line"], 10)
        self.assertEqual(findings["App starts before async setup finishes"]["agent"], "general")

        review_items = {f["title"]: f for f in store.list_findings(self.conn, task_id=task_id, kind="needs_review")}
        self.assertIn("Backend may not check ownership", review_items)
        self.assertIn("not found", review_items["Quotes code that isn't there"]["why_unconfirmed"])
        self.assertEqual([r["title"] for r in summary["rejected"]], ["Cites a file that doesn't exist"])

        run = store.task_runs(self.conn, task_id)[-1]
        self.assertEqual((run["status"], run["cost_usd"], run["num_turns"]), ("done", 0.12, 5))

    def test_known_findings_are_shown_and_repeats_are_kept_out(self):
        from audit_agent import github_issues, views
        root, audit_id = self._audit(DART_REPO)
        task_id = self._task(audit_id, "Audit lib")
        investigate.investigate(self.conn, task_id)
        first = {f["title"]: f["id"] for f in store.list_findings(self.conn, task_id=task_id)}
        known_id = first["App starts before async setup finishes"]
        review_id = first["Quotes code that isn't there"]

        evidence = "runApp(const App());"
        self.report_path.write_text(json.dumps({
            "findings": [
                {"title": "App is started before setup is done", "bug_type": "concurrency", "severity": "high",
                 "file": "lib/main.dart", "line": 10, "evidence": evidence, "explanation": "Same bug.",
                 "duplicate_of": known_id},
                {"title": "Made-up duplicate number", "bug_type": "logic", "severity": "low", "file": "lib/main.dart",
                 "line": 10, "evidence": evidence, "explanation": "x", "duplicate_of": 99999},
                {"title": "App starts before the async setup finishes", "bug_type": "concurrency", "severity": "medium",
                 "file": "lib/main.dart", "line": 11, "evidence": evidence, "explanation": "Claude didn't say."},
                {"title": "Unrelated crash on resume", "bug_type": "logic", "severity": "low", "file": "lib/main.dart",
                 "line": 10, "evidence": evidence, "explanation": "A different bug at the same place."},
            ],
            "needs_review": [{"title": "Ownership again", "suspicion": "s", "why_unconfirmed": "w",
                              "duplicate_of": f"#{review_id}"}],
        }))
        summary = investigate.investigate(self.conn, task_id, again=True)

        prompt = json.loads(self.log_path.read_text())["prompt"]
        self.assertIn("Already known in these files", prompt)
        self.assertIn(f"#{known_id} [high concurrency] App starts before async setup finishes", prompt)
        self.assertIn(f"#{review_id} [to review] Quotes code that isn't there", prompt)
        self.assertNotIn("Backend may not check ownership", prompt, "items citing no file of the task aren't listed")

        saved = {f["title"]: f for f in store.list_findings(self.conn, task_id=task_id) if f["id"] not in first.values()}
        self.assertEqual(saved["App is started before setup is done"]["duplicate_of"], known_id)
        self.assertEqual(saved["Ownership again"]["duplicate_of"], review_id)
        self.assertIsNone(saved["Made-up duplicate number"]["duplicate_of"], "only numbers the prompt listed count")
        self.assertEqual(saved["App starts before the async setup finishes"]["possible_duplicate_of"], known_id)
        self.assertIsNone(saved["App starts before the async setup finishes"]["duplicate_of"], "a hint never hides")
        self.assertIsNone(saved["Unrelated crash on resume"]["possible_duplicate_of"], "a different bug isn't flagged")
        self.assertEqual((summary["findings"], summary["needs_review"], summary["duplicates"]), (3, 0, 2))

        repeat_ids = {saved["App is started before setup is done"]["id"], saved["Ownership again"]["id"]}
        issues = {i["finding_id"] for i in github_issues.preview(self.conn, task_id)["issues"]}
        self.assertFalse(repeat_ids & issues, "repeats get no GitHub issue")
        listed = {f["id"] for f in views.findings_overview(self.conn)["findings"]}
        self.assertFalse(repeat_ids & listed, "repeats aren't listed on the Findings tab")
        self.assertIn(saved["App starts before the async setup finishes"]["id"], listed)

    def test_agent_runs_read_only_with_task_context(self):
        root, audit_id = self._audit(NODE_REPO)
        task_id = self._task(audit_id, "Audit src")
        self.report_path.write_text(json.dumps({"findings": [], "needs_review": []}))

        investigate.investigate(self.conn, task_id)

        log = json.loads(self.log_path.read_text())
        args = log["args"]
        self.assertEqual(Path(log["cwd"]).resolve(), root.resolve())
        self.assertEqual(args[args.index("--tools") + 1], "Read,Grep,Glob")
        self.assertEqual(args[args.index("--permission-mode") + 1], "dontAsk")
        for tool in ("Bash", "Edit", "Write", "WebFetch"):
            self.assertIn(tool, args)
        self.assertTrue(
            any(a.startswith("Read(//") and a.endswith("/repo/.env)") for a in args),
            "the repo's .env is denied by absolute path",
        )
        self.assertIn("--json-schema", args)
        self.assertIn("src/index.js", log["prompt"])
        self.assertIn("Never open these files", log["prompt"])
        self.assertIn(".env", log["prompt"])
        self.assertIn("Missing or bypassable authentication", log["prompt"])
        self.assertEqual(store.list_findings(self.conn, task_id=task_id), [])
        self.assertEqual(store.get_task(self.conn, task_id)["status"], "done")

    def test_cancelled_and_done_tasks_are_refused(self):
        _, audit_id = self._audit(DART_REPO)
        task_id = self._task(audit_id, "Audit lib")
        review.cancel_tasks(self.conn, [task_id])
        with self.assertRaises(investigate.InvestigationError):
            investigate.investigate(self.conn, task_id)

        review.restore_tasks(self.conn, [task_id])
        investigate.investigate(self.conn, task_id)
        with self.assertRaises(investigate.InvestigationError):
            investigate.investigate(self.conn, task_id)
        investigate.investigate(self.conn, task_id, again=True)
        self.assertEqual(len(store.task_runs(self.conn, task_id)), 2)

    def test_failed_runs_mark_the_task_failed(self):
        _, audit_id = self._audit(DART_REPO)
        task_id = self._task(audit_id, "Audit lib")
        with mock.patch.dict(os.environ, {"FAKE_CLAUDE_MODE": "fail"}):
            with self.assertRaises(investigate.InvestigationError) as caught:
                investigate.investigate(self.conn, task_id)
        self.assertIn("not logged in", str(caught.exception))
        self.assertEqual(store.get_task(self.conn, task_id)["status"], "failed")
        self.assertIn("not logged in", store.task_runs(self.conn, task_id)[-1]["error"])

    def test_results_are_discarded_if_the_repository_changes(self):
        _, audit_id = self._audit(DART_REPO)
        task_id = self._task(audit_id, "Audit lib")
        with mock.patch.dict(os.environ, {"FAKE_CLAUDE_MODE": "edit"}):
            with self.assertRaises(investigate.InvestigationError):
                investigate.investigate(self.conn, task_id)
        self.assertEqual(store.list_findings(self.conn, task_id=task_id), [])
        self.assertEqual(store.get_task(self.conn, task_id)["status"], "failed")

    def test_missing_claude_gives_install_instructions(self):
        _, audit_id = self._audit(DART_REPO)
        task_id = self._task(audit_id, "Audit lib")
        with mock.patch.dict(os.environ, {"AUDIT_AGENT_CLAUDE": str(self.base / "nope")}):
            with self.assertRaises(investigate.InvestigationError) as caught:
                investigate.investigate(self.conn, task_id)
        self.assertIn("npm install -g @anthropic-ai/claude-code", str(caught.exception))

    def test_cli_investigate_and_findings(self):
        root = make_repo(self.base / "cli-repo", DART_REPO)
        db = str(self.base / "cli.db")
        run_cli("start", str(root), "--db", db)
        run_cli("plan", "1", "--db", db)
        tasks = json.loads(run_cli("tasks", "1", "--json", "--db", db).stdout)
        task_id = next(t["id"] for t in tasks if t["title"] == "Audit lib")

        prompt = run_cli("investigate", str(task_id), "--show-prompt", "--db", db)
        self.assertIn("Files to audit", prompt.stdout)

        result = run_cli("investigate", str(task_id), "--db", db)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[HIGH] concurrency: App starts before async setup finishes", result.stdout)
        self.assertIn("Needs your review (2)", result.stdout)
        self.assertIn("Rejected 1 claims", result.stdout)

        listed = json.loads(run_cli("findings", "1", "--kind", "finding", "--json", "--db", db).stdout)
        self.assertEqual(len(listed), 2)


if __name__ == "__main__":
    unittest.main()
