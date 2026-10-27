import json
import os
import threading
import time
from unittest import mock

from audit_agent import investigate, reproduce, runner, store, web
from tests import test_review
from tests.test_review import ReviewTestCase

FINDING = {"bug_type": "concurrency", "severity": "high", "title": "App starts before async setup finishes",
           "file_path": "lib/main.dart", "line": 1, "evidence": "void main() {}", "explanation": "Nothing is awaited."}


def fake_reproduce(conn, finding_id, settings, log=print, verdict="reproduced", fail=False, delay=0.0):
    """Stands in for a live reproduction: records an attempt the way reproduce.reproduce() does."""
    verification_id = store.start_verification(conn, finding_id, "claude-sonnet-5-5")
    log("  ran the test: 0 passed, 1 failed")
    time.sleep(delay)
    if fail:
        store.finish_verification(conn, verification_id, "failed", error="The Anthropic API returned 500")
        raise reproduce.ReproduceError("The Anthropic API returned 500")
    store.finish_verification(conn, verification_id, "done", verdict=verdict,
                              reason='"x rejects y" failed on the unchanged code:\nExpected: 200\nReceived: 500',
                              test_path="test/__audit__/finding-1.test.ts", test_name="x rejects y",
                              test_code="expect(res.status).toBe(200);", test_output="FAILED: x rejects y",
                              transcript="SECRET-TRANSCRIPT", cost_usd=0.12, num_turns=5, cache_read_tokens=900,
                              input_tokens=100)
    return dict(store.get_verification(conn, verification_id))


class FindingsTestCase(ReviewTestCase):
    def setUp(self):
        super().setUp()
        key = mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test-key"})
        key.start()
        self.addCleanup(key.stop)
        task_id = self.tasks["Audit lib"]["id"]
        run_id = store.start_run(self.conn, task_id, investigate.GENERAL_AGENT)
        store.save_findings(self.conn, run_id, task_id, self.audit_id, investigate.GENERAL_AGENT,
                            [FINDING, {**FINDING, "title": "No issue yet", "severity": "low", "bug_type": "logic"}],
                            [{"title": "Maybe", "explanation": "Unclear", "why_unconfirmed": "No code"}])
        store.finish_run(self.conn, run_id, task_id, "done")
        rows = {r["title"]: r["id"] for r in store.list_findings(self.conn, task_id=task_id)}
        self.with_issue, self.without_issue, self.review_item = rows[FINDING["title"]], rows["No issue yet"], rows["Maybe"]
        store.set_finding_issue(self.conn, self.with_issue, "https://github.com/acme/mobile/issues/1")
        store.set_finding_issue(self.conn, self.review_item, "https://github.com/acme/mobile/issues/2")

    def make_runner(self, fn=fake_reproduce, parallel=2, log=None):
        return runner.ReproductionRunner(self.db_path, reproduce.ReproduceSettings(), parallel, fn, log or (lambda m: None))

    def add_findings_with_issues(self, count):
        task_id = self.tasks["Audit lib/src"]["id"]
        run_id = store.start_run(self.conn, task_id, investigate.GENERAL_AGENT)
        store.save_findings(self.conn, run_id, task_id, self.audit_id, investigate.GENERAL_AGENT,
                            [{**FINDING, "title": f"Extra {i}"} for i in range(count)], [])
        ids = [r["id"] for r in store.list_findings(self.conn, task_id=task_id)]
        for i in ids:
            store.set_finding_issue(self.conn, i, f"https://github.com/acme/mobile/issues/{i + 10}")
        return ids


class ReproductionRunnerTest(FindingsTestCase):
    def test_only_findings_with_a_github_issue_are_sent(self):
        work = self.make_runner(fn=lambda *a, **k: time.sleep(0.2))
        result = work.submit([self.with_issue, self.without_issue, self.review_item, 99999])
        self.assertEqual(result["queued"], [self.with_issue])
        self.assertEqual([s["reason"] for s in result["skipped"]],
                         ["needs a GitHub issue first", "needs-review items aren't reproduced", "no such finding"])
        self.assertEqual(work.submit([self.with_issue])["skipped"][0]["reason"], "already sent")
        work.wait_idle(5)

    def test_nothing_is_sent_without_an_api_key(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY")
            result = self.make_runner().submit([self.with_issue])
        self.assertEqual(result["queued"], [])
        self.assertIn("API key", result["skipped"][0]["reason"])
        self.assertEqual(store.list_verifications(self.conn), [])

    def test_several_run_at_once_up_to_the_limit_and_a_failure_does_not_stop_the_rest(self):
        ids = self.add_findings_with_issues(4)
        lock, active, peak = threading.Lock(), [0], [0]

        def slow(conn, finding_id, settings, log=print):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            try:
                return fake_reproduce(conn, finding_id, settings, log, fail=finding_id == ids[0], delay=0.1)
            finally:
                with lock:
                    active[0] -= 1

        lines = []
        work = self.make_runner(fn=slow, parallel=2, log=lines.append)
        work.submit(ids)
        self.assertTrue(work.wait_idle(10))
        self.assertEqual(peak[0], 2)
        finished = {f["id"]: f for f in work.status()["finished"]}
        self.assertEqual(finished[ids[0]]["status"], "failed")
        self.assertEqual({finished[i]["verdict"] for i in ids[1:]}, {"reproduced"})
        text = "\n".join(lines)
        self.assertIn(f"Finding #{ids[1]}: ran the test: 0 passed, 1 failed", text, "progress goes to the server log")
        self.assertIn(f"Finding #{ids[1]} reproduced, $0.12", text)
        self.assertIn(f"Finding #{ids[0]} failed: The Anthropic API returned 500", text)

        self.assertEqual(work.submit([ids[0]])["queued"], [ids[0]], "a failed one can be sent again")
        self.assertTrue(work.wait_idle(10))

    def test_running_ones_show_their_latest_log_lines(self):
        release = threading.Event()

        def waiting(conn, finding_id, settings, log=print):
            log("Preparing a test copy ...")
            release.wait(5)
            return fake_reproduce(conn, finding_id, settings, log)

        work = self.make_runner(fn=waiting)
        work.submit([self.with_issue])
        time.sleep(0.2)
        running = work.status()["running"]
        self.assertEqual(running[0]["log"], ["Preparing a test copy ..."])
        release.set()
        self.assertTrue(work.wait_idle(5))

    def test_rate_limits_wait_and_retry(self):
        calls = []

        def limited(conn, finding_id, settings, log=print):
            calls.append(finding_id)
            if len(calls) == 1:
                raise reproduce.ReproduceError("The Anthropic API returned 429: rate_limit_error")
            return fake_reproduce(conn, finding_id, settings, log)

        with mock.patch.object(runner, "RETRY_WAITS_S", (0.05,)):
            work = self.make_runner(fn=limited)
            work.submit([self.with_issue])
            self.assertTrue(work.wait_idle(5))
        self.assertEqual(len(calls), 2)
        self.assertEqual(work.status()["finished"][0]["verdict"], "reproduced")

    def test_limits_and_parallel_bounds(self):
        work = self.make_runner()
        status = work.status()
        self.assertEqual(status["runner"], "Anthropic API (saved key)")
        self.assertEqual(status["limits"], {"max_turns": reproduce.DEFAULT_MAX_TURNS,
                                            "max_cost_usd": reproduce.DEFAULT_MAX_COST_USD,
                                            "timeout_s": reproduce.DEFAULT_TIMEOUT_S})
        with self.assertRaises(ValueError):
            work.set_parallel(runner.MAX_REPRODUCE_PARALLEL + 1)


class FindingsPageTest(FindingsTestCase):
    request = test_review.ReviewPageTest.request
    post = test_review.ReviewPageTest.post

    def setUp(self):
        super().setUp()
        self.server = web.ReviewServer(self.db_path, port=0, reproducer=self.make_runner())
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def findings(self):
        return {f["id"]: f for f in json.loads(self.request("GET", "/api/findings")[1])["findings"]}

    def test_findings_are_listed_across_tasks_with_what_the_filters_need(self):
        data = json.loads(self.request("GET", "/api/findings")[1])
        listed = {f["id"]: f for f in data["findings"]}
        self.assertEqual(set(listed), {self.with_issue, self.without_issue}, "needs-review items aren't listed")
        first = listed[self.with_issue]
        self.assertEqual((first["severity"], first["bug_type"], first["reproduction"]), ("high", "concurrency", "not_tried"))
        self.assertTrue(first["issue_url"])
        self.assertIsNone(listed[self.without_issue]["issue_url"])
        self.assertEqual(data["apps"][0]["key"], first["app_key"])
        self.assertEqual(data["apps"][0]["findings"], 2)

    def test_reproduce_from_the_page_and_see_the_verdict_test_and_output(self):
        status, data = self.post("/api/reproduce", {"ids": [self.with_issue, self.without_issue], "parallel": 3})
        self.assertEqual(status, 200, data)
        sent = json.loads(data)
        self.assertEqual(sent["queued"], [self.with_issue])
        self.assertEqual(sent["skipped"][0]["reason"], "needs a GitHub issue first")
        self.assertEqual(sent["status"]["parallel"], 3)
        self.assertTrue(self.server.reproducer.wait_idle(5))

        progress = json.loads(self.request("GET", "/api/reproduce")[1])
        self.assertFalse(progress["active"])
        self.assertEqual(progress["finished"][0]["verdict"], "reproduced")
        listed = self.findings()[self.with_issue]
        self.assertEqual((listed["reproduction"], listed["cost_usd"], listed["attempts"]), ("reproduced", 0.12, 1))

        detail = json.loads(self.request("GET", f"/api/findings/{self.with_issue}")[1])
        self.assertEqual(detail["reproduction"], "reproduced")
        (attempt,) = detail["attempts"]
        self.assertEqual(attempt["test_code"], "expect(res.status).toBe(200);")
        self.assertEqual(attempt["test_output"], "FAILED: x rejects y")
        self.assertIn("failed on the unchanged code", attempt["reason"])
        self.assertNotIn("transcript", attempt)

    def test_failed_attempts_show_why(self):
        self.server.reproducer.reproduce_fn = lambda conn, fid, s, log=print: fake_reproduce(conn, fid, s, log, fail=True)
        self.post("/api/reproduce", {"ids": [self.with_issue]})
        self.assertTrue(self.server.reproducer.wait_idle(5))
        self.assertEqual(self.findings()[self.with_issue]["reproduction"], "failed")
        detail = json.loads(self.request("GET", f"/api/findings/{self.with_issue}")[1])
        self.assertIn("500", detail["attempts"][0]["error"])

    def test_sending_needs_the_page_header_ids_and_a_valid_limit(self):
        status, _ = self.request("POST", "/api/reproduce", {"ids": [self.with_issue]},
                                 headers={"Content-Type": "application/json"})
        self.assertEqual(status, 403)
        self.assertEqual(self.post("/api/reproduce", {"ids": "all"})[0], 400)
        self.assertEqual(self.post("/api/reproduce", {"ids": [self.with_issue], "parallel": 9})[0], 400)
        self.assertEqual(store.list_verifications(self.conn), [])

    def test_stop_drops_the_queue(self):
        ids = self.add_findings_with_issues(3)
        self.server.reproducer.reproduce_fn = lambda conn, fid, s, log=print: fake_reproduce(conn, fid, s, log, delay=0.3)
        self.server.reproducer.set_parallel(1)
        self.post("/api/reproduce", {"ids": ids})
        time.sleep(0.1)
        status, data = self.post("/api/reproduce/stop", {})
        self.assertEqual(json.loads(data)["dropped"], 2)
        self.assertTrue(self.server.reproducer.wait_idle(5))
        self.assertEqual(len(store.list_verifications(self.conn)), 1)

    def test_page_has_the_findings_tab_and_controls(self):
        page = self.request("GET", "/")[1]
        for control in (b'id="tab-findings"', b'id="f-issue" checked', b'id="f-app"', b'id="f-severity"', b'id="f-type"',
                        b'id="f-repro"', b'id="f-reproduce"', b'id="f-parallel"', b'id="f-stop"', b'id="f-detail"'):
            self.assertIn(control, page)

    def test_default_server_uses_the_real_reproduction(self):
        server = web.ReviewServer(self.db_path, port=0)
        self.addCleanup(server.server_close)
        self.assertIs(server.reproducer.reproduce_fn, reproduce.reproduce)


if __name__ == "__main__":
    import unittest
    unittest.main()
