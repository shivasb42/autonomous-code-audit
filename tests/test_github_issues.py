import json
import os
import subprocess
import sys
import threading
import unittest
from unittest import mock

from audit_agent import github_issues, investigate, runner, store, web
from audit_agent.inventory import discover
from audit_agent.repo import open_repository
from tests import test_review
from tests.helpers import make_repo
from tests.test_review import ReviewTestCase

FAKE_GH = """#!{python}
import json, os, pathlib, sys
args = sys.argv[1:]
stdin = "" if sys.stdin.isatty() else sys.stdin.read()
with open(os.environ["FAKE_GH_LOG"], "a") as log:
    log.write(json.dumps({{"args": args, "stdin": stdin}}) + "\\n")
state_path = pathlib.Path(os.environ["FAKE_GH_STATE"])
state = json.loads(state_path.read_text()) if state_path.exists() else {{"projects": [], "issues": 0}}
if os.environ.get("FAKE_GH_FAIL") and args[:2] == ["issue", "create"]:
    print("HTTP 403: Resource not accessible", file=sys.stderr)
    sys.exit(1)
out = ""
if args[:2] == ["project", "list"]:
    out = json.dumps({{"projects": state["projects"], "totalCount": len(state["projects"])}})
elif args[:2] == ["project", "create"]:
    number = len(state["projects"]) + 1
    project = {{"number": number, "title": args[args.index("--title") + 1], "url": f"https://github.com/users/me/projects/{{number}}"}}
    state["projects"].append(project)
    out = json.dumps(project)
elif args[:2] == ["issue", "create"]:
    state["issues"] += 1
    out = f"https://github.com/{{args[args.index('--repo') + 1]}}/issues/{{state['issues']}}\\n"
elif args[:2] == ["project", "item-add"]:
    out = json.dumps({{"id": "PVTI_1"}})
state_path.write_text(json.dumps(state))
print(out)
"""

FINDING = {"bug_type": "concurrency", "severity": "high", "title": "App starts before async setup finishes",
           "file_path": "lib/main.dart", "line": 10, "evidence": "runApp(const App());",
           "explanation": "main is async but nothing is awaited before runApp."}
REVIEW_ITEM = {"title": "Backend may not check ownership", "explanation": "The API call could act on other users' data.",
               "why_unconfirmed": "The backend handler is not in this repository.", "files_examined": ["lib/src/api.dart"]}


class IssuesTestCase(ReviewTestCase):
    def setUp(self):
        super().setUp()
        self.root = self.base / "repo"
        subprocess.run(["git", "-C", str(self.root), "remote", "add", "origin", "https://github.com/acme/mobile.git"],
                       check=True)
        fake = self.base / "fake-gh"
        fake.write_text(FAKE_GH.format(python=sys.executable))
        fake.chmod(0o755)
        self.gh_log = self.base / "gh-log.jsonl"
        env = mock.patch.dict(os.environ, {"AUDIT_AGENT_GH": str(fake), "FAKE_GH_LOG": str(self.gh_log),
                                           "FAKE_GH_STATE": str(self.base / "gh-state.json")})
        env.start()
        self.addCleanup(env.stop)
        self.task_id = self.tasks["Audit lib"]["id"]
        self.add_findings([FINDING], [REVIEW_ITEM])

    def add_findings(self, findings, review, task_id=None):
        task_id = task_id or self.task_id
        run_id = store.start_run(self.conn, task_id, investigate.GENERAL_AGENT)
        store.save_findings(self.conn, run_id, task_id, self.audit_id, investigate.GENERAL_AGENT, findings, review)
        store.finish_run(self.conn, run_id, task_id, "done")

    def calls(self):
        if not self.gh_log.exists():
            return []
        return [json.loads(line) for line in self.gh_log.read_text().splitlines()]


class GithubIssuesTest(IssuesTestCase):
    def test_preview_writes_each_issue_from_the_saved_finding_without_calling_gh(self):
        plan = github_issues.preview(self.conn, self.task_id)
        self.assertEqual(plan["board"], "repo audit findings")
        finding, suspected = sorted(plan["issues"], key=lambda i: i["kind"])
        self.assertEqual(finding["title"], "[audit] App starts before async setup finishes")
        self.assertEqual(finding["repo"], "acme/mobile")
        self.assertEqual(finding["labels"], ["audit-agent", "unverified", "severity:high", "concurrency"])
        commit = store.get_audit(self.conn, self.audit_id)["head_commit"]
        self.assertIn(f"https://github.com/acme/mobile/blob/{commit}/lib/main.dart#L10", finding["body"])
        self.assertIn("```dart\nrunApp(const App());\n```", finding["body"])
        self.assertIn("Not verified yet", finding["body"])
        self.assertEqual(suspected["title"], "[audit, suspected] Backend may not check ownership")
        self.assertEqual(suspected["labels"], ["audit-agent", "needs-review"])
        self.assertIn("The backend handler is not in this repository.", suspected["body"])
        self.assertEqual(self.calls(), [])

    def test_create_makes_issues_on_a_new_public_board_once(self):
        result = github_issues.create(self.conn, self.task_id, log=lambda m: None)
        self.assertEqual(len(result["created"]), 2)
        self.assertEqual(result["board"]["title"], "repo audit findings")
        calls = [c["args"] for c in self.calls()]
        self.assertIn(["project", "edit", "1", "--owner", "@me", "--visibility", "PUBLIC"], calls)
        created = [c for c in self.calls() if c["args"][:2] == ["issue", "create"]]
        self.assertEqual([c["args"][c["args"].index("--repo") + 1] for c in created], ["acme/mobile", "acme/mobile"])
        self.assertIn("runApp(const App());", created[0]["stdin"] + created[1]["stdin"])
        self.assertEqual(len([c for c in calls if c[:2] == ["project", "item-add"]]), 2)
        self.assertTrue(all(f["issue_url"].startswith("https://github.com/acme/mobile/issues/")
                            for f in store.list_findings(self.conn, task_id=self.task_id)))

        again = github_issues.create(self.conn, self.task_id, log=lambda m: None)
        self.assertEqual(again["created"], [])
        self.assertEqual(len(again["skipped"]), 2)
        self.assertEqual(len([c for c in self.calls() if c["args"][:2] == ["issue", "create"]]), 2, "never twice")

    def test_an_existing_board_is_reused(self):
        github_issues.create(self.conn, self.task_id, log=lambda m: None)
        other = self.tasks["Audit lib/src"]["id"]
        self.add_findings([{**FINDING, "title": "Another"}], [], task_id=other)
        github_issues.create(self.conn, other, log=lambda m: None)
        creates = [c for c in self.calls() if c["args"][:2] == ["project", "create"]]
        self.assertEqual(len(creates), 1)

    def test_a_finding_in_another_repository_goes_to_that_repository(self):
        backend = make_repo(self.base / "server", {"routes/teams.js": "exports.list = () => {};\n"})
        subprocess.run(["git", "-C", str(backend), "remote", "add", "origin", "git@github.com:acme/server.git"], check=True)
        repo = open_repository(backend)
        server_id = store.create_audit(self.conn, repo)
        store.save_inventory(self.conn, server_id, discover(repo))
        with self.conn:
            self.conn.execute("DELETE FROM findings")
        self.add_findings([{**FINDING, "file_path": "routes/teams.js", "line": 1, "evidence": "exports.list",
                            "file_audit_id": server_id}], [])
        (issue,) = github_issues.preview(self.conn, self.task_id)["issues"]
        self.assertEqual(issue["repo"], "acme/server")
        self.assertIn("https://github.com/acme/server/blob/", issue["body"])

    def test_a_repository_without_a_github_remote_is_skipped(self):
        subprocess.run(["git", "-C", str(self.root), "remote", "remove", "origin"], check=True)
        result = github_issues.create(self.conn, self.task_id, log=lambda m: None)
        self.assertEqual(result["created"], [])
        self.assertIn("no GitHub remote", result["skipped"][0]["reason"])
        self.assertEqual(self.calls(), [])

    def test_create_all_covers_every_task_once(self):
        other = self.tasks["Audit lib/src"]["id"]
        self.add_findings([{**FINDING, "title": "Another"}], [], task_id=other)
        plan = github_issues.preview_all(self.conn)
        self.assertEqual((plan["ready"], plan["blocked"]), (3, 0))
        self.assertEqual({i["task_id"] for i in plan["issues"]}, {self.task_id, other})
        self.assertEqual(self.calls(), [], "the preview creates nothing")

        result = github_issues.create_all(self.conn, log=lambda m: None)
        self.assertEqual(len(result["created"]), 3)
        self.assertEqual(github_issues.tasks_missing_issues(self.conn), [])
        self.assertEqual(github_issues.preview_all(self.conn)["ready"], 0)
        again = github_issues.create_all(self.conn, log=lambda m: None)
        self.assertEqual(again["created"], [])
        self.assertEqual(len([c for c in self.calls() if c["args"][:2] == ["issue", "create"]]), 3)

    def test_create_all_reports_a_failing_task_and_goes_on(self):
        with mock.patch.dict(os.environ, {"FAKE_GH_FAIL": "1"}):
            result = github_issues.create_all(self.conn, log=lambda m: None)
        self.assertEqual(result["created"], [])
        self.assertEqual(result["errors"][0]["task_id"], self.task_id)

    def test_only_the_chosen_findings_are_created(self):
        finding = next(f for f in store.list_findings(self.conn, task_id=self.task_id) if f["kind"] == "finding")
        result = github_issues.create(self.conn, self.task_id, [finding["id"]], log=lambda m: None)
        self.assertEqual([c["finding_id"] for c in result["created"]], [finding["id"]])


class IssuesPageTest(IssuesTestCase):
    request = test_review.ReviewPageTest.request
    post = test_review.ReviewPageTest.post

    def setUp(self):
        super().setUp()
        fake_runner = runner.Runner(self.db_path, investigate.AgentSettings(), 1, lambda *a: None, lambda m: None)
        self.server = web.ReviewServer(self.db_path, port=0, runner=fake_runner)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def test_preview_then_create_from_the_page(self):
        plan = json.loads(self.request("GET", f"/api/tasks/{self.task_id}/issues")[1])
        self.assertEqual(len(plan["issues"]), 2)
        status, data = self.post(f"/api/tasks/{self.task_id}/issues", {})
        self.assertEqual(status, 200, data)
        self.assertEqual(len(json.loads(data)["created"]), 2)
        detail = json.loads(self.request("GET", f"/api/tasks/{self.task_id}")[1])
        self.assertTrue(all(f["issue_url"] for f in detail["findings"]))

    def test_create_all_from_the_page(self):
        plan = json.loads(self.request("GET", "/api/issues")[1])
        self.assertEqual(plan["ready"], 2)
        status, data = self.post("/api/issues", {})
        self.assertEqual(status, 200, data)
        body = json.loads(data)
        self.assertEqual((len(body["created"]), body["preview"]["ready"]), (2, 0))
        self.assertIn(b'id="issues-all"', self.request("GET", "/")[1])

    def test_gh_errors_are_reported(self):
        with mock.patch.dict(os.environ, {"FAKE_GH_FAIL": "1"}):
            status, data = self.post(f"/api/tasks/{self.task_id}/issues", {})
        self.assertEqual(status, 502)
        self.assertIn("Resource not accessible", json.loads(data)["error"])


if __name__ == "__main__":
    unittest.main()
