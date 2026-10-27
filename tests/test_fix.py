import json
import os
import re
import subprocess
import sys
import threading
import unittest
from unittest import mock

from audit_agent import api_runner, fix, github_issues, pull_requests, runner, sandbox, store, web
from tests import test_review
from tests.helpers import repo_fingerprint
from tests.test_api_runner import ScriptedApi, tool_use
from tests.test_reproduce import FakeJest, ReproduceTestCase, answer, jest_report, ASSERTION

BUGGY = "return token.length > 0;"
TEST_NAME = "verify rejects a wrong token"
TEST_CODE = ('import { verify } from "../../controller/user";\n// FAKE:fixable\n'
             'describe("verify", () => { it("rejects a wrong token", () => {\n'
             '  expect(verify("wrong")).toBe(false);\n}); });\n')
TEST_PATH = "tests/__audit__/finding-1.test.ts"


class FixingJest(FakeJest):
    """A fake jest that knows whether the fix is in: the test fails while the buggy line is there. The related
    existing tests fail when the source contains BREAKS_OTHER."""

    def run(self, ws, test_path, timeout, name_pattern=None):
        code = (ws.repo / test_path).read_text()
        if "FAKE:fixable" not in code:
            return super().run(ws, test_path, timeout, name_pattern)
        ws.runs += 1
        source = (ws.repo / "controller/user.ts").read_text()
        self.runs.append({"root": ws.root, "code": code, "source": source})
        if BUGGY in source:
            report = jest_report("failed", [ASSERTION], [{"matcherResult": {"pass": False}}])
        else:
            report = jest_report("passed")
        return sandbox.TestRun(0, False, "console output", report, 1000, timeout)

    def run_related(self, ws, source_paths, timeout):
        ws.runs += 1
        source = (ws.repo / "controller/user.ts").read_text()
        self.related = getattr(self, "related", []) + [{"root": ws.root, "paths": source_paths}]
        status = "failed" if "BREAKS_OTHER" in source else "passed"
        report = {"numTotalTests": 1, "testResults": [{
            "name": str(ws.package / "tests/auth/signup.test.ts"), "status": status, "message": "",
            "assertionResults": [{"ancestorTitles": [], "title": "works", "fullName": "works", "status": status,
                                  "failureMessages": [ASSERTION] if status == "failed" else [],
                                  "failureDetails": [{"matcherResult": {}}] if status == "failed" else []}]}]}
        return sandbox.TestRun(0, False, "related output", report, 2000, timeout)


def fix_script(new=" return false;", finish=None):
    return [
        answer(tool_use("write_test", {"path": TEST_PATH, "content": TEST_CODE}, "t1"), cache_write=3000),
        answer(tool_use("run_test", {}, "t2"), cache_read=3000),
        answer(tool_use("confirm_bug", {"test_name": TEST_NAME}, "t3"), cache_read=3200),
        answer(tool_use("edit_file", {"path": "controller/user.ts", "old_string": BUGGY, "new_string": new.strip()}, "t4"),
               cache_read=3400),
        answer(tool_use("run_test", {}, "t5"), cache_read=3600),
        answer(tool_use("finish", finish or {"outcome": "fixed", "summary": "Reject tokens that don't match the secret."},
                        "t6"), cache_read=3800),
    ]


class FixTestCase(ReproduceTestCase):
    def setUp(self):
        super().setUp()
        self.jest = FixingJest()
        store.set_finding_issue(self.conn, self.finding_id, "https://github.com/acme/svc/issues/7")

    def fix(self, responses, **settings):
        api = ScriptedApi(responses)
        with mock.patch.object(api_runner, "_send", api):
            result = fix.fix(self.conn, self.finding_id, fix.FixSettings(**settings), log=lambda m: None, toolchain=self.jest)
        return api, result


class FixTest(FixTestCase):
    def test_a_confirmed_bug_is_fixed_and_checked_by_the_app(self):
        before = repo_fingerprint(self.root)
        api, result = self.fix(fix_script())
        self.assertEqual((result["status"], result["outcome"]), ("done", "fixed"), result["reason"])
        self.assertIn("failed on the unchanged code and passes with the fix", result["reason"])
        self.assertIn(f"-  {BUGGY}", result["patch"])
        self.assertIn("+  return false;", result["patch"])
        files = json.loads(result["files"])
        self.assertEqual(list(files), ["controller/user.ts"])
        self.assertIn("return false;", files["controller/user.ts"]["after"])
        self.assertEqual(result["test_code"], TEST_CODE)
        self.assertEqual(result["test_name"], TEST_NAME)
        self.assertIn("FAILED", result["before_output"])
        self.assertIn("PASSED", result["after_output"])
        self.assertIn("PASSED: works", result["related_output"])
        self.assertEqual(result["summary"], "Reject tokens that don't match the secret.")
        self.assertEqual(result["base_branch"], "main")
        self.assertEqual(result["num_turns"], 6)

        self.assertEqual(before, repo_fingerprint(self.root), "the repository is never written")
        self.assertEqual(list(self.runs_folder().iterdir()), [], "every copy is deleted")
        self.assertIn("confirm_bug", {t["name"] for t in api.requests[0]["tools"]})
        self.assertIn("Step 2, fix it", api.requests[0]["system"][0]["text"])
        roots = [r["root"] for r in self.jest.runs]
        self.assertEqual(len(roots), 4, "agent's run, app's run before, agent's run after editing, app's run after")
        self.assertEqual(len(set(roots)), 3, "the app's runs before and after each use a fresh copy")

    def test_a_test_that_passes_on_unchanged_code_stops_without_fixing(self):
        code = TEST_CODE.replace("FAKE:fixable", "FAKE:pass")
        responses = [answer(tool_use("write_test", {"path": TEST_PATH, "content": code}, "t1")),
                     answer(tool_use("confirm_bug", {"test_name": TEST_NAME}, "t2"))]
        api, result = self.fix(responses)
        self.assertEqual(result["outcome"], "not_reproduced")
        self.assertEqual(len(api.requests), 2, "nothing more is sent once the claim isn't reproduced")
        self.assertIsNone(result["patch"])

    def test_editing_needs_a_confirmed_bug_and_freezes_the_test(self):
        responses = [
            answer(tool_use("write_test", {"path": TEST_PATH, "content": TEST_CODE}, "t1")),
            answer(tool_use("edit_file", {"path": "controller/user.ts", "old_string": BUGGY, "new_string": "return false;"}, "t2")),
            answer(tool_use("confirm_bug", {"test_name": TEST_NAME}, "t3")),
            answer(tool_use("write_test", {"path": TEST_PATH, "content": TEST_CODE + "// weaker\n"}, "t4"),
                   tool_use("edit_file", {"path": "tests/setup/app.ts", "old_string": "return {}", "new_string": "return 1"}, "t5"),
                   tool_use("edit_file", {"path": "package.json", "old_string": "svc", "new_string": "x"}, "t6")),
            *fix_script()[3:],
        ]
        api, result = self.fix(responses)
        errors = {r["tool_use_id"]: r["content"] for m in api.requests[-1]["messages"] if m["role"] == "user"
                  and isinstance(m["content"], list) for r in m["content"] if r.get("is_error")}
        self.assertIn("Prove the bug first", errors["t2"])
        self.assertIn("frozen", errors["t4"])
        self.assertIn("Tests and test setup can't be changed", errors["t5"])
        self.assertIn("can't be changed", errors["t6"])
        self.assertEqual(result["outcome"], "fixed")
        self.assertEqual(result["test_code"], TEST_CODE, "the test that was confirmed is the one saved")

    def test_a_fix_that_breaks_existing_tests_is_rejected(self):
        _, result = self.fix(fix_script(new="return false; // BREAKS_OTHER"))
        self.assertEqual(result["outcome"], "fix_rejected")
        self.assertIn("breaks existing tests that passed before", result["reason"])
        self.assertIn("tests/auth/signup.test.ts › works", result["reason"])

    def test_a_fix_that_doesnt_make_the_test_pass_is_rejected(self):
        responses = fix_script()
        responses[3] = answer(tool_use("edit_file", {"path": "controller/user.ts", "old_string": "const secret",
                                                     "new_string": "const theSecret"}, "t4"))
        _, result = self.fix(responses)
        self.assertEqual(result["outcome"], "fix_rejected")
        self.assertIn("still doesn't pass", result["reason"])

    def test_running_out_after_confirming_keeps_that_the_bug_is_real(self):
        _, result = self.fix(fix_script()[:4], max_turns=4)
        self.assertEqual(result["outcome"], "fix_rejected")
        self.assertIn("The bug was reproduced, but no fix was finished", result["reason"])
        self.assertIn("FAILED", result["before_output"])

    def test_unable_keeps_the_manual_steps(self):
        _, result = self.fix([answer(tool_use("finish", {"outcome": "unable", "unable_reason": "Needs a device.",
                                                         "manual_steps": "Open the app on a phone."}, "t1"))])
        self.assertEqual((result["outcome"], result["reason"], result["manual_steps"]),
                         ("unable", "Needs a device.", "Open the app on a phone."))


FAKE_GH = """#!{python}
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a") as log:
    log.write(json.dumps({{"args": args, "stdin": sys.stdin.read()}}) + "\\n")
if args[:2] == ["issue", "comment"]:
    print(args[2] + "#issuecomment-1")
else:
    print("https://github.com/acme/svc/pull/3")
"""


class PullRequestTest(FixTestCase):
    def setUp(self):
        super().setUp()
        self.remote = self.base / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.remote)], check=True)
        git = ["git", "-C", str(self.root)]
        subprocess.run([*git, "remote", "add", "origin", str(self.remote)], check=True)
        subprocess.run([*git, "push", "-q", "origin", "main"], check=True)
        subprocess.run([*git, "fetch", "-q", "origin"], check=True)
        fake = self.base / "fake-gh"
        fake.write_text(FAKE_GH.format(python=sys.executable))
        fake.chmod(0o755)
        self.gh_log = self.base / "gh.jsonl"
        env = mock.patch.dict(os.environ, {
            "AUDIT_AGENT_GH": str(fake), "FAKE_GH_LOG": str(self.gh_log),
            "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@example.com",
        })
        env.start()
        self.addCleanup(env.stop)
        slug = mock.patch.object(github_issues, "github_repo", return_value="acme/svc")
        slug.start()
        self.addCleanup(slug.stop)

    def branches(self):
        out = subprocess.run(["git", "-C", str(self.remote), "branch", "--list"], capture_output=True, text=True).stdout
        return sorted(b.strip("* ").strip() for b in out.splitlines())

    def test_a_draft_pr_is_opened_only_on_a_new_branch_when_asked(self):
        _, result = self.fix(fix_script())
        self.assertEqual(self.branches(), ["main"], "finishing a fix pushes nothing")
        plan = pull_requests.preview(self.conn, result["id"])
        self.assertEqual(plan["problems"], [])
        self.assertEqual(plan["warnings"], [])
        self.assertEqual(plan["branch"], f"audit/finding-{self.finding_id}-fix-{result['id']}")
        self.assertIn("Fixes #7", plan["body"])
        self.assertEqual(plan["files"], ["controller/user.ts", TEST_PATH])

        before = repo_fingerprint(self.root)
        main_before = subprocess.run(["git", "-C", str(self.remote), "rev-parse", "main"], capture_output=True, text=True).stdout
        opened = pull_requests.open_pr(self.conn, result["id"], log=lambda m: None)
        self.assertEqual(opened["url"], "https://github.com/acme/svc/pull/3")
        self.assertEqual(before, repo_fingerprint(self.root), "the repository and its working tree are untouched")
        self.assertEqual(self.branches(), sorted(["main", plan["branch"]]))
        self.assertEqual(main_before, subprocess.run(["git", "-C", str(self.remote), "rev-parse", "main"],
                                                     capture_output=True, text=True).stdout, "main is never pushed")
        shown = subprocess.run(["git", "-C", str(self.remote), "show", f"{plan['branch']}:controller/user.ts"],
                               capture_output=True, text=True).stdout
        self.assertIn("return false;", shown)
        self.assertNotIn(BUGGY, shown)
        test = subprocess.run(["git", "-C", str(self.remote), "show", f"{plan['branch']}:{TEST_PATH}"],
                              capture_output=True, text=True).stdout
        self.assertEqual(test, TEST_CODE)

        changed = subprocess.run(["git", "-C", str(self.remote), "diff", "--name-only", "main", plan["branch"]],
                                 capture_output=True, text=True).stdout.split()
        self.assertEqual(sorted(changed), sorted(["controller/user.ts", TEST_PATH]), "only the fix and its test change")

        create, comment = [json.loads(line) for line in self.gh_log.read_text().splitlines()]
        self.assertEqual(create["args"][:2], ["pr", "create"])
        self.assertIn("--draft", create["args"])
        self.assertEqual(create["args"][create["args"].index("--base") + 1], "main")
        self.assertIn("Fixes #7", create["stdin"])
        self.assertEqual(comment["args"][:3], ["issue", "comment", "https://github.com/acme/svc/issues/7"])
        self.assertIn("https://github.com/acme/svc/pull/3", comment["stdin"], "the issue links the pull request")
        saved = store.get_fix(self.conn, result["id"])
        self.assertEqual(saved["pr_url"], "https://github.com/acme/svc/pull/3")
        self.assertEqual(saved["issue_comment_url"], "https://github.com/acme/svc/issues/7#issuecomment-1")
        self.assertEqual(opened["comment_url"], saved["issue_comment_url"])
        self.assertIn("already has a pull request", pull_requests.preview(self.conn, result["id"])["problems"][0])
        self.assertEqual(list((sandbox.work_root() / "pull-requests").iterdir()), [], "the temporary clone is deleted")

    def test_fixes_made_against_uncommitted_changes_cant_become_a_pr(self):
        (self.root / "controller/user.ts").write_text(SOURCE_WITH_LOCAL_EDIT)
        _, result = self.fix(fix_script())
        self.assertEqual(result["outcome"], "fixed")
        problems = pull_requests.preview(self.conn, result["id"])["problems"]
        self.assertIn("had uncommitted changes", problems[0])
        with self.assertRaises(pull_requests.PullRequestError):
            pull_requests.open_pr(self.conn, result["id"], log=lambda m: None)
        self.assertEqual(self.branches(), ["main"])

    def test_only_checked_fixes_can_become_a_pr(self):
        _, result = self.fix(fix_script(new="return false; // BREAKS_OTHER"))
        self.assertIn("Only a fix the app checked", pull_requests.preview(self.conn, result["id"])["problems"][0])

    def test_open_all_pending_opens_one_pr_per_finding_once(self):
        _, first = self.fix(fix_script())
        _, latest = self.fix(fix_script())
        self.fix(fix_script(new="return false; // BREAKS_OTHER"))
        self.assertEqual(pull_requests.pending(self.conn), [latest["id"]], "only the latest checked fix of a finding")
        plan = pull_requests.preview_all(self.conn)
        self.assertEqual([p["attempt_id"] for p in plan["ready"]], [latest["id"]])

        result = pull_requests.open_all(self.conn, log=lambda m: None)
        self.assertEqual([o["attempt_id"] for o in result["opened"]], [latest["id"]])
        self.assertEqual((result["failed"], result["skipped"]), ([], []))
        self.assertEqual(self.branches(), sorted(["main", f"audit/finding-{self.finding_id}-fix-{latest['id']}"]))
        self.assertEqual(pull_requests.pending(self.conn), [], "a finding with a pull request is done")
        self.assertEqual(pull_requests.open_all(self.conn, log=lambda m: None)["opened"], [])
        self.assertIsNone(store.get_fix(self.conn, first["id"])["pr_url"])

    def gh_calls(self):
        return [json.loads(line) for line in self.gh_log.read_text().splitlines()] if self.gh_log.exists() else []

    def test_rejected_and_unable_attempts_comment_on_the_issue_once(self):
        _, rejected = self.fix(fix_script(new="return false; // BREAKS_OTHER"))
        _, unable = self.fix([answer(tool_use("finish", {"outcome": "unable", "unable_reason": "Needs a device.",
                                                         "manual_steps": "Open the app on a phone."}, "t1"))])
        _, fixed = self.fix(fix_script())
        due = [a["id"] for a in store.fixes_missing_comments(self.conn)]
        self.assertEqual(due, [rejected["id"], unable["id"]], "a fix without a pull request has nothing to report yet")

        result = pull_requests.post_missing_comments(self.conn, log=lambda m: None)
        self.assertEqual([p["attempt_id"] for p in result["posted"]], due)
        bodies = [c["stdin"] for c in self.gh_calls()]
        self.assertIn("reproduced this bug, but its fix was rejected", bodies[0])
        self.assertIn("breaks existing tests", bodies[0])
        self.assertIn("Proposed diff (rejected)", bodies[0])
        self.assertIn("couldn't reproduce or fix this automatically", bodies[1])
        self.assertIn("Open the app on a phone.", bodies[1])
        self.assertEqual(pull_requests.post_missing_comments(self.conn, log=lambda m: None)["posted"], [],
                         "nothing is posted twice")
        self.assertEqual(len(self.gh_calls()), 2)

    def test_the_fix_queue_comments_when_an_attempt_is_rejected(self):
        with mock.patch.object(api_runner, "_send", ScriptedApi(fix_script(new="return false; // BREAKS_OTHER"))):
            work = runner.FixRunner(self.base / "audit.db", fix.FixSettings(), 1,
                                    lambda conn, fid, s, log=print: fix.fix(conn, fid, s, log=log, toolchain=self.jest),
                                    lambda m: None)
            work.submit([self.finding_id])
            self.assertTrue(work.wait_idle(20))
        (call,) = self.gh_calls()
        self.assertEqual(call["args"][:3], ["issue", "comment", "https://github.com/acme/svc/issues/7"])
        (attempt,) = store.list_fixes(self.conn, self.finding_id)
        self.assertEqual(attempt["issue_comment_url"], "https://github.com/acme/svc/issues/7#issuecomment-1")


SOURCE_WITH_LOCAL_EDIT = """export function verify(token: string) {
  // a local edit that isn't committed
  const secret = process.env.JWT_SECRET;
  const { MONGODB_URI, PORT } = process.env;
  if (token === secret) return true;
  return token.length > 0;
}
"""


def fake_fix(conn, finding_id, settings, log=print):
    attempt_id = store.start_fix(conn, finding_id, "claude-sonnet-5-5", "abc", "main")
    log("  the app's run on the unchanged code: failed assertion")
    store.finish_fix(conn, attempt_id, "done", outcome="fixed", reason="The test failed before and passes after.",
                     patch="-a\n+b\n", files="{}", transcript="SECRET", test_code="expect(1).toBe(1);", cost_usd=0.3)
    return dict(store.get_fix(conn, attempt_id))


class FixPageTest(FixTestCase):
    request = test_review.ReviewPageTest.request
    post = test_review.ReviewPageTest.post

    def setUp(self):
        super().setUp()
        fixer = runner.FixRunner(self.base / "audit.db", fix.FixSettings(), 1, fake_fix, lambda m: None)
        self.server = web.ReviewServer(self.base / "audit.db", port=0, fixer=fixer)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def test_fix_from_the_page_and_see_the_diff(self):
        listed = {f["id"]: f for f in json.loads(self.request("GET", "/api/findings")[1])["findings"]}
        self.assertEqual(listed[self.finding_id]["fix"], "not_tried")
        status, data = self.post("/api/fix", {"ids": [self.finding_id, self.review_id], "parallel": 2})
        self.assertEqual(status, 200, data)
        sent = json.loads(data)
        self.assertEqual(sent["queued"], [self.finding_id])
        self.assertEqual(sent["status"]["limits"]["max_cost_usd"], fix.DEFAULT_MAX_COST_USD)
        self.assertTrue(self.server.fixer.wait_idle(5))
        listed = {f["id"]: f for f in json.loads(self.request("GET", "/api/findings")[1])["findings"]}
        self.assertEqual((listed[self.finding_id]["fix"], listed[self.finding_id]["fix_cost_usd"]), ("fixed", 0.3))
        detail = json.loads(self.request("GET", f"/api/findings/{self.finding_id}")[1])
        self.assertEqual(detail["fix"], "fixed")
        (attempt,) = detail["fixes"]
        self.assertEqual(attempt["patch"], "-a\n+b\n")
        self.assertNotIn("transcript", attempt)
        self.assertEqual(detail["reproduction"], "not_tried", "the verifier's results are separate")
        preview = json.loads(self.request("GET", f"/api/fixes/{attempt['id']}/pr")[1])
        self.assertIn("problems", preview)

    def test_page_has_the_fix_controls(self):
        page = self.request("GET", "/")[1]
        for control in (b'id="fx-send"', b'id="fx-parallel"', b'id="fx-stop"', b'id="f-fix"', b"pr-btn", b"Open draft PR",
                        b'id="prs-all"'):
            self.assertIn(control, page)
        status, data = self.request("GET", "/api/prs")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data), {"ready": [], "blocked": []})

    def test_the_fix_queue_checks_its_own_running_attempts(self):
        store.start_fix(self.conn, self.finding_id, "m", None, None)
        result = self.server.fixer.submit([self.finding_id])
        self.assertEqual(result["skipped"][0]["reason"], "already being fixed")
        self.assertEqual(store.fail_interrupted_fixes(self.conn), 1)


if __name__ == "__main__":
    unittest.main()
