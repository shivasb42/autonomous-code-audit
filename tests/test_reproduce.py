import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from audit_agent import api_runner, cli, investigate, planning, reproduce, sandbox, store
from audit_agent.inventory import discover
from audit_agent.repo import open_repository
from tests.helpers import make_repo, repo_fingerprint
from tests.test_api_runner import ScriptedApi, tool_use

SOURCE = """export function verify(token: string) {
  const secret = process.env.JWT_SECRET;
  const { MONGODB_URI, PORT } = process.env;
  if (token === secret) return true;
  return token.length > 0;
}
"""
EXAMPLE = 'import { createTestApp } from "../setup/app";\n' + "".join(f"// line {i}\n" for i in range(40)) + \
    'it("works", () => { expect(createTestApp()).toBeDefined(); });\n'
REPO = {
    "package.json": json.dumps({"name": "svc", "devDependencies": {"jest": "^29.7.0"}, "scripts": {"test": "jest"}}),
    "package-lock.json": "{}\n",
    "jest.config.ts": 'export default { preset: "ts-jest", roots: ["<rootDir>/tests"] };\n',
    "controller/user.ts": SOURCE,
    "tests/setup/app.ts": "export function createTestApp() { return {}; }\n",
    "tests/auth/signup.test.ts": EXAMPLE,
    ".env.example": "JWT_SECRET=example-value-from-the-repo\n",
}
FINDING = {"bug_type": "security", "severity": "high", "title": "Any non-empty token is accepted",
           "file_path": "controller/user.ts", "line": 5, "evidence": "return token.length > 0;",
           "explanation": "verify returns true for every non-empty token, so authentication can be bypassed."}
TEST_NAME = "verify rejects a wrong token"


def jest_report(status, messages=(), details=(), title="rejects a wrong token", message=""):
    tests = [] if status is None else [{
        "ancestorTitles": ["verify"], "title": title, "fullName": f"verify {title}", "status": status,
        "failureMessages": list(messages), "failureDetails": list(details),
    }]
    return {"testResults": [{"name": "/x/tests/__audit__/finding.test.ts", "status": "failed" if status != "passed" else "passed",
                             "message": message, "assertionResults": tests}]}


ASSERTION = ("Error: expect(received).toBe(expected)\n\nExpected: false\nReceived: true\n    at Object.<anonymous> "
             "(tests/__audit__/finding-1.test.ts:5:30)")


class FakeJest(sandbox.Jest):
    """Stands in for npm and jest. The test file says how its run should end with a `FAKE:<mode>` comment."""

    def __init__(self):
        self.installs = 0
        self.runs = []

    def install(self, package_dir, env, writable, log):
        self.installs += 1
        self.install_env = env
        (package_dir / "node_modules" / ".bin").mkdir(parents=True)
        (package_dir / "node_modules" / ".bin" / "jest").write_text("")

    def run(self, ws, test_path, timeout, name_pattern=None):
        ws.runs += 1
        code = (ws.repo / test_path).read_text()
        self.runs.append({"root": ws.root, "code": code, "env": (ws.package / ".env").read_text(),
                          "files": sorted(p.relative_to(ws.repo).as_posix() for p in ws.repo.rglob("*") if p.is_file())})
        mode = re.search(r"FAKE:(\w+)", code).group(1)
        if mode == "tamper":
            (ws.repo / "controller/user.ts").write_text("export function verify() { return false; }\n")
            mode = "pass"
        if mode == "slow":
            return sandbox.TestRun(None, True, "still running", None, timeout * 1000, timeout)
        report = {
            "fail": jest_report("failed", [ASSERTION], [{"matcherResult": {"pass": False, "message": "..."}}]),
            "pass": jest_report("passed"),
            "throw": jest_report("failed", ["TypeError: Cannot read properties of undefined (reading 'length')"], [{}]),
            "compile": jest_report(None, message="SyntaxError: Unexpected token (3:4)"),
        }[mode]
        return sandbox.TestRun(1 if mode != "pass" else 0, False, "console output", report, 1200, timeout)


def answer(*blocks, input_tokens=2000, output_tokens=300, cache_write=0, cache_read=0):
    return {"id": "msg", "content": list(blocks), "stop_reason": "tool_use",
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens,
                      "cache_creation_input_tokens": cache_write, "cache_read_input_tokens": cache_read}}


def test_code(mode, imports=True):
    head = 'import { verify } from "../../controller/user";\n' if imports else ""
    return head + f'// FAKE:{mode}\ndescribe("verify", () => {{ it("rejects a wrong token", () => {{\n' \
                  '  expect(verify("wrong")).toBe(false);\n}}); }});\n'


def script(mode="fail", imports=True, finish=None):
    return [
        answer(tool_use("read_file", {"path": "controller/user.ts"}, "t1"), cache_write=3000),
        answer(tool_use("write_test", {"path": "tests/__audit__/finding-1.test.ts", "content": test_code(mode, imports)}, "t2"),
               cache_read=3000),
        answer(tool_use("run_test", {}, "t3"), cache_read=3500),
        answer(tool_use("finish", finish or {"outcome": "test_written", "test_name": TEST_NAME,
                                             "conclusion": "verify accepts any token."}, "t4"), cache_read=4000),
    ]


class ReproduceTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        work = mock.patch.dict(os.environ, {"AUDIT_AGENT_WORK": str(self.base / "work"),
                                            "ANTHROPIC_API_KEY": "sk-ant-test-key"})
        work.start()
        self.addCleanup(work.stop)
        self.root = make_repo(self.base / "repo", REPO, untracked={".env": "JWT_SECRET=super-secret-real-value\n"})
        self.conn = store.connect(self.base / "audit.db")
        self.addCleanup(self.conn.close)
        repo = open_repository(self.root)
        self.audit_id = store.create_audit(self.conn, repo)
        store.save_inventory(self.conn, self.audit_id, discover(repo))
        planning.plan_audit(self.conn, self.audit_id)
        self.task_id = self.conn.execute("SELECT task_id FROM audit_task_files WHERE path = 'controller/user.ts'").fetchone()[0]
        run_id = store.start_run(self.conn, self.task_id, investigate.GENERAL_AGENT)
        store.save_findings(self.conn, run_id, self.task_id, self.audit_id, investigate.GENERAL_AGENT, [FINDING],
                            [{"title": "Maybe", "explanation": "Unclear", "why_unconfirmed": "No code"}])
        store.finish_run(self.conn, run_id, self.task_id, "done", raw_output="INVESTIGATOR-REASONING-MARKER")
        rows = store.list_findings(self.conn, task_id=self.task_id)
        self.finding_id = next(r["id"] for r in rows if r["kind"] == "finding")
        self.review_id = next(r["id"] for r in rows if r["kind"] == "needs_review")
        self.jest = FakeJest()

    def reproduce(self, responses, finding_id=None, **settings):
        api = ScriptedApi(responses)
        with mock.patch.object(api_runner, "_send", api):
            result = reproduce.reproduce(self.conn, finding_id or self.finding_id, reproduce.ReproduceSettings(**settings),
                                         log=lambda m: None, toolchain=self.jest)
        return api, result

    def runs_folder(self):
        return sandbox.package_home(self.root, ".") / "runs"


class ReproduceTest(ReproduceTestCase):
    def test_a_failing_assertion_is_reproduced_and_everything_is_saved(self):
        before = repo_fingerprint(self.root)
        api, result = self.reproduce(script("fail"))

        self.assertEqual((result["status"], result["verdict"]), ("done", "reproduced"))
        self.assertIn("failed on the unchanged code", result["reason"])
        self.assertIn("expect(verify(\"wrong\")).toBe(false)", result["test_code"])
        self.assertEqual(result["test_path"], "tests/__audit__/finding-1.test.ts")
        self.assertIn("FAILED: verify rejects a wrong token", result["test_output"])
        self.assertEqual((result["num_turns"], result["input_tokens"], result["output_tokens"]), (4, 8000, 1200))
        self.assertEqual((result["cache_write_tokens"], result["cache_read_tokens"]), (3000, 10500))
        self.assertAlmostEqual(result["cost_usd"], api_runner.estimate_cost("claude-sonnet-5-5", 8000, 1200, 3000, 10500))
        self.assertIn("write_test", result["transcript"])

        self.assertEqual(before, repo_fingerprint(self.root), "the repository is never written")
        self.assertEqual(len(self.jest.runs), 2, "Claude's run, then the app's own final run")
        self.assertNotEqual(self.jest.runs[0]["root"], self.jest.runs[1]["root"], "the final run uses a fresh copy")
        self.assertEqual(list(self.runs_folder().iterdir()), [], "copies are deleted after saving")

    def test_copies_hold_tracked_code_and_a_fake_env_only(self):
        self.reproduce(script("fail"))
        run = self.jest.runs[0]
        self.assertIn("controller/user.ts", run["files"])
        self.assertNotIn(".env.example", run["files"])
        self.assertFalse(any(f.startswith(".git/") for f in run["files"]))
        self.assertIn("JWT_SECRET=test-jwt-secret", run["env"])
        self.assertIn("MONGODB_URI=mongodb://127.0.0.1:27017/audit-test", run["env"])
        self.assertIn("PORT=3999", run["env"])
        self.assertNotIn("super-secret-real-value", run["env"])
        self.assertNotIn("example-value-from-the-repo", run["env"])
        self.assertNotIn("ANTHROPIC_API_KEY", self.jest.install_env, "none of the engineer's variables reach the copy")

    def test_the_verifier_gets_only_the_claim_and_cacheable_prefixes(self):
        api, _ = self.reproduce(script("fail"))
        first = api.requests[0]
        self.assertEqual(len(first["messages"]), 1)
        claim = first["messages"][0]["content"][0]["text"]
        for text in (FINDING["title"], FINDING["evidence"], FINDING["explanation"], "security", "controller/user.ts, line 5"):
            self.assertIn(text, claim)
        self.assertIn("    5    return token.length > 0;", claim, "the cited file is included")
        self.assertNotIn("INVESTIGATOR-REASONING-MARKER", json.dumps(first))
        self.assertIn("try hard to disprove it", first["system"][0]["text"])
        self.assertEqual([b.get("cache_control") for b in first["system"]], [reproduce.CACHE, reproduce.CACHE])
        setup = first["system"][1]["text"]
        self.assertIn("tests/__audit__/", setup)
        self.assertIn("tests/auth/signup.test.ts", setup, "an existing test is given as an example")
        self.assertIn("tests/setup/app.ts", setup)
        self.assertIn("JWT_SECRET", setup)
        self.assertEqual({t["name"] for t in first["tools"]},
                         {"read_file", "search", "list_files", "write_test", "run_test", "finish"})

        later = api.requests[2]["messages"]
        self.assertEqual(later[-1]["content"][-1]["cache_control"], reproduce.CACHE, "each turn caches the conversation")
        self.assertNotIn("cache_control", json.dumps(later[:-1]), "only the newest message carries the breakpoint")

    def test_the_shared_prefix_is_identical_across_findings(self):
        run_id = store.start_run(self.conn, self.task_id, investigate.GENERAL_AGENT)
        store.save_findings(self.conn, run_id, self.task_id, self.audit_id, investigate.GENERAL_AGENT,
                            [{**FINDING, "title": "Another", "line": 2, "evidence": "const secret = process.env.JWT_SECRET;"}], [])
        other = max(r["id"] for r in store.list_findings(self.conn, task_id=self.task_id))
        first, _ = self.reproduce(script("fail"))
        second, _ = self.reproduce(script("pass"), finding_id=other)
        self.assertEqual(first.requests[0]["system"], second.requests[0]["system"])
        self.assertEqual(first.requests[0]["tools"], second.requests[0]["tools"])
        self.assertNotEqual(first.requests[0]["messages"], second.requests[0]["messages"])
        self.assertEqual(self.jest.installs, 1, "dependencies are installed once and reused")

    def test_a_passing_test_is_not_reproduced(self):
        _, result = self.reproduce(script("pass"))
        self.assertEqual(result["verdict"], "not_reproduced")
        self.assertIn("passed on the unchanged code", result["reason"])

    def test_the_verdict_comes_from_the_apps_run_not_claude(self):
        responses = script("pass")
        responses[-1] = answer(tool_use("finish", {"outcome": "test_written", "test_name": TEST_NAME,
                                                   "conclusion": "Reproduced! The bug is real."}, "t4"))
        _, result = self.reproduce(responses)
        self.assertEqual(result["verdict"], "not_reproduced")
        self.assertEqual(result["conclusion"], "Reproduced! The bug is real.")

    def test_unable_keeps_the_reason_and_manual_steps(self):
        responses = [answer(tool_use("finish", {"outcome": "unable", "conclusion": "Needs Stripe.",
                                                "unable_reason": "The webhook needs a real Stripe signature.",
                                                "manual_steps": "1. Send a test webhook from the Stripe dashboard."}, "t1"))]
        _, result = self.reproduce(responses)
        self.assertEqual(result["verdict"], "unable")
        self.assertIn("Stripe signature", result["reason"])
        self.assertIn("Stripe dashboard", result["manual_steps"])
        self.assertEqual(self.jest.runs, [])

    def test_tests_that_dont_fail_an_assertion_are_not_proof(self):
        cases = {"throw": "threw an error instead of failing an expect", "compile": "could not run",
                 "slow": "took longer than", "tamper": "changed files of the code it tests"}
        for mode, reason in cases.items():
            with self.subTest(mode):
                _, result = self.reproduce(script(mode))
                self.assertEqual(result["verdict"], "unable")
                self.assertIn(reason, result["reason"])
        _, result = self.reproduce(script("fail", imports=False))
        self.assertEqual(result["verdict"], "unable")
        self.assertIn("imports no code", result["reason"])

    def test_naming_a_test_that_doesnt_exist_is_not_proof(self):
        _, result = self.reproduce(script("fail", finish={"outcome": "test_written", "test_name": "something else",
                                                          "conclusion": "x"}))
        self.assertEqual(result["verdict"], "unable")
        self.assertIn("No test named 'something else'", result["reason"])

    def test_limits_end_in_unable_with_the_reason(self):
        _, result = self.reproduce(script("fail")[:2], max_turns=2)
        self.assertEqual(result["verdict"], "unable")
        self.assertIn("2 turns", result["reason"])

        _, result = self.reproduce([answer(tool_use("list_files", {}, "t1"), input_tokens=500_000)], max_cost_usd=0.5)
        self.assertEqual(result["verdict"], "unable")
        self.assertIn("cost limit", result["reason"])

    def test_api_failure_is_recorded_and_can_be_started_again(self):
        def broken(body, api_key, timeout):
            raise investigate.InvestigationError("The Anthropic API returned 500")
        with mock.patch.object(api_runner, "_send", broken), self.assertRaises(reproduce.ReproduceError):
            reproduce.reproduce(self.conn, self.finding_id, log=lambda m: None, toolchain=self.jest)
        (row,) = store.list_verifications(self.conn, finding_id=self.finding_id)
        self.assertEqual((row["status"], row["verdict"]), ("failed", None))
        self.assertIn("500", row["error"])
        _, result = self.reproduce(script("fail"))
        self.assertEqual(result["verdict"], "reproduced")

    def test_only_one_run_per_finding_at_a_time_and_interrupted_ones_are_closed(self):
        store.start_verification(self.conn, self.finding_id, "m")
        with self.assertRaises(reproduce.ReproduceError):
            self.reproduce(script("fail"))
        self.assertEqual(store.fail_interrupted_verifications(self.conn), 1)
        self.assertEqual(self.reproduce(script("fail"))[1]["verdict"], "reproduced")

    def test_needs_review_items_and_missing_keys_are_refused_before_anything_is_sent(self):
        with self.assertRaises(reproduce.ReproduceError):
            self.reproduce([], finding_id=self.review_id)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY")
            with self.assertRaises(reproduce.ReproduceError):
                self.reproduce([])
        self.assertEqual(store.list_verifications(self.conn), [])

    def test_a_package_without_jest_is_unable_without_calling_claude(self):
        (self.root / "package.json").write_text(json.dumps({"name": "svc"}))
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=T", "-c", "user.email=t@e", "commit", "-qam", "no jest"],
                       check=True)
        api, result = self.reproduce([])
        self.assertEqual(api.requests, [])
        self.assertEqual(result["verdict"], "unable")
        self.assertIn("jest", result["reason"])
        self.assertEqual(result["cost_usd"], 0)


class VerifierToolsTest(ReproduceTestCase):
    def setUp(self):
        super().setUp()
        files = sandbox.copyable_files(self.root)
        setup = sandbox.test_setup(self.root, files, ".")
        template = sandbox.prepare(self.root, files, ".", self.jest, log=lambda m: None)
        self.ws = sandbox.new_workspace(self.root, files, setup, template, "tools")
        self.addCleanup(sandbox.remove, self.ws)
        self.tools = reproduce.VerifierTools(self.ws, self.jest, 60, log=lambda m: None)

    def test_one_test_file_only_inside_the_audit_folder(self):
        for path in ("controller/user.test.ts", "tests/__audit__/../x.test.ts", "tests/__audit__/sub/x.test.ts",
                     "/tmp/x.test.ts", "tests/__audit__/notes.md", "tests/__audit__/.env"):
            with self.subTest(path), self.assertRaises(api_runner.ToolError):
                self.tools.write_test(path, "x")
        self.assertIn("Wrote", self.tools.write_test("tests/__audit__/finding-1.test.ts", test_code("pass")))
        self.tools.write_test("./tests/__audit__/finding-1.test.ts", test_code("fail"))
        with self.assertRaises(api_runner.ToolError):
            self.tools.write_test("tests/__audit__/finding-2.test.ts", "x")
        with self.assertRaises(api_runner.ToolError):
            self.tools.write_test("tests/__audit__/finding-1.test.ts", "x" * (sandbox.MAX_TEST_BYTES + 1))
        self.assertIn("FAILED", self.tools.run("run_test", {}))

    def test_reading_and_no_other_commands(self):
        self.assertIn("token.length", self.tools.run("read_file", {"path": "controller/user.ts"}))
        with self.assertRaises(api_runner.ToolError):
            self.tools.run("read_file", {"path": ".env"})
        with self.assertRaises(api_runner.ToolError):
            self.tools.run("run_test", {})
        with self.assertRaises(api_runner.ToolError):
            self.tools.run("bash", {"command": "ls"})


class CopyTest(ReproduceTestCase):
    def test_files_are_cloned_or_copied_with_the_same_content(self):
        target = self.base / "copy" / "user.ts"
        target.parent.mkdir()
        sandbox.clone_file(self.root / "controller/user.ts", target)
        self.assertEqual(target.read_text(), SOURCE)
        target.write_text("changed")
        self.assertEqual((self.root / "controller/user.ts").read_text(), SOURCE, "changing a clone leaves the repository alone")
        with mock.patch.object(sandbox, "_clonefile", None), mock.patch.object(sandbox.sys, "platform", "other"):
            fallback = self.base / "copy" / "plain.ts"
            sandbox.clone_file(self.root / "controller/user.ts", fallback)
        self.assertEqual(fallback.read_text(), SOURCE)

    def test_a_copy_that_fails_halfway_is_removed(self):
        files = sandbox.copyable_files(self.root)
        setup = sandbox.test_setup(self.root, files, ".")
        template = sandbox.prepare(self.root, files, ".", self.jest, log=lambda m: None)
        real_clone = sandbox.clone_file
        calls = []

        def disk_full(source, target):
            calls.append(target)
            if len(calls) > 2:
                raise OSError(28, "No space left on device")
            real_clone(source, target)

        with mock.patch.object(sandbox, "clone_file", disk_full), self.assertRaises(OSError):
            sandbox.new_workspace(self.root, files, setup, template, "full")
        self.assertEqual(list(self.runs_folder().iterdir()), [])


class JestResultsTest(unittest.TestCase):
    def run_of(self, report, timed_out=False):
        return sandbox.TestRun(1, timed_out, "out", report, 10)

    def test_assertions_are_told_apart_from_errors(self):
        failed = jest_report("failed", [ASSERTION], [{"matcherResult": {"pass": False}}])
        self.assertEqual(sandbox.classify(self.run_of(failed), TEST_NAME)[0], "failed_assertion")
        by_message = jest_report("failed", [ASSERTION], [{}])
        self.assertEqual(sandbox.classify(self.run_of(by_message), TEST_NAME)[0], "failed_assertion")
        thrown = jest_report("failed", ["TypeError: boom"], [{}])
        self.assertEqual(sandbox.classify(self.run_of(thrown), TEST_NAME)[0], "errored")
        self.assertEqual(sandbox.classify(self.run_of(jest_report("passed")), " verify  rejects a wrong token ")[0], "passed")
        self.assertEqual(sandbox.classify(self.run_of(jest_report("passed")), None)[0], "passed", "a single test needs no name")
        self.assertEqual(sandbox.classify(self.run_of(jest_report("pending")), TEST_NAME)[0], "did_not_run")
        self.assertEqual(sandbox.classify(self.run_of(None), TEST_NAME)[0], "did_not_run")
        self.assertEqual(sandbox.classify(self.run_of(None, timed_out=True), TEST_NAME)[0], "timed_out")

    def test_jest_command(self):
        command = sandbox.Jest().command(Path("/w/repo"), "tests/__audit__/f.test.ts", Path("/w/out.json"), Path("/w/c"), None)
        self.assertEqual(command[0], "/w/repo/node_modules/.bin/jest")
        for flag in ("--runInBand", "--forceExit", "--ci", "--json", "--outputFile=/w/out.json", "tests/__audit__/f.test.ts"):
            self.assertIn(flag, command)

    def test_fake_env_values(self):
        self.assertEqual(sandbox.fake_value("JWT_SECRET"), "test-jwt-secret")
        self.assertEqual(sandbox.fake_value("STRIPE_API_KEY"), "test-stripe-api-key")
        self.assertEqual(sandbox.fake_value("REDIS_URL"), "redis://127.0.0.1:6379")
        self.assertEqual(sandbox.fake_value("API_BASE_URL"), "http://127.0.0.1:9")
        self.assertEqual(sandbox.fake_value("FANTASY_MODE"), "test")


def _sandbox_works() -> bool:
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        return False
    return subprocess.run(["sandbox-exec", "-p", "(version 1)(allow default)", "true"], capture_output=True).returncode == 0


PROBE = """
import socket, sys
out = []
listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen()
socket.create_connection(listener.getsockname(), timeout=2); out.append("localhost ok")
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3); out.append("REMOTE CONNECTED")
except PermissionError:
    out.append("remote blocked")
except OSError as exc:
    out.append(f"remote failed differently: {exc}")
open(sys.argv[1] + "/inside.txt", "w").write("ok"); out.append("inside ok")
try:
    open(sys.argv[2], "w").write("x"); out.append("OUTSIDE WRITTEN")
except PermissionError:
    out.append("outside blocked")
print("|".join(out))
"""


@unittest.skipUnless(_sandbox_works(), "needs macOS sandbox-exec (run the tests outside another sandbox)")
class NetworkOffTest(unittest.TestCase):
    def test_tests_reach_localhost_only_and_write_only_their_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            inside, outside = Path(tmp) / "run", Path.home() / f".audit-agent-sandbox-probe-{os.getpid()}"
            inside.mkdir()
            result = sandbox.run_sandboxed([sys.executable, "-c", PROBE, str(inside), str(outside)], inside,
                                           dict(os.environ), [inside], network=False, timeout=30)
            self.assertFalse(outside.exists())
        self.assertEqual(result.output.strip(), "localhost ok|remote blocked|inside ok|outside blocked", result.output)


class ReproduceCliTest(ReproduceTestCase):
    def cli(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main([*args, "--db", str(self.base / "audit.db")])
        return code, out.getvalue()

    def test_show_prompt_sends_nothing(self):
        with mock.patch.object(api_runner, "_send", side_effect=AssertionError("sent")):
            code, out = self.cli("reproduce", str(self.finding_id), "--show-prompt")
        self.assertEqual(code, 0)
        self.assertIn(FINDING["title"], out)
        self.assertIn("tests/__audit__/finding-", out)

    def test_list_and_show_verifications(self):
        _, result = self.reproduce(script("fail"))
        code, out = self.cli("verifications")
        self.assertEqual(code, 0)
        self.assertIn("reproduced", out)
        code, out = self.cli("verifications", "--id", str(result["id"]))
        self.assertIn("Verdict: reproduced", out)
        self.assertIn('expect(verify("wrong")).toBe(false)', out)
        self.assertIn("output of the app's own run", out)

    def test_setup_check_runs_an_existing_test_without_claude(self):
        with mock.patch.object(reproduce, "_network_blocked", return_value=True), \
                mock.patch.object(api_runner, "_send", side_effect=AssertionError("sent")):
            (self.root / "tests/auth/signup.test.ts").write_text(EXAMPLE + "// FAKE:pass\n")
            subprocess.run(["git", "-C", str(self.root), "-c", "user.name=T", "-c", "user.email=t@e", "commit", "-qam", "x"],
                           check=True)
            result = reproduce.check_setup(self.conn, self.audit_id, log=lambda m: None, toolchain=self.jest)
        self.assertEqual((result["passed"], result["failed"]), (1, 0))
        self.assertTrue(result["repository_unchanged"] and result["copy_unchanged"])
        self.assertEqual(result["example"], "tests/auth/signup.test.ts")
        self.assertEqual(list(self.runs_folder().iterdir()), [])


if __name__ == "__main__":
    unittest.main()
