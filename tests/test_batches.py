import json
import os
import re
import unittest
from datetime import datetime, timezone
from unittest import mock

from audit_agent import api_runner, batches, investigate, runner, store
from tests import test_review
from tests.test_review import ReviewTestCase

FINDING = {"title": "App starts before async setup finishes", "bug_type": "concurrency", "severity": "high",
           "file": "lib/main.dart", "line": 10, "evidence": "runApp(const App());",
           "explanation": "main is async but nothing is awaited before runApp."}


def succeeded(findings=(FINDING,), files_needed=None):
    report = {"findings": list(findings), "needs_review": []}
    if files_needed:
        report["files_needed"] = files_needed
    return {"type": "succeeded", "message": {
        "id": "msg_1", "model": "claude-sonnet-5-5", "stop_reason": "tool_use",
        "content": [{"type": "tool_use", "id": "t1", "name": "submit_report", "input": report}],
        "usage": {"input_tokens": 10_000, "output_tokens": 1_000},
    }}


ROUND_COST = api_runner.estimate_cost("claude-sonnet-5-5", 10_000, 1_000) / 2


class FakeAnthropic:
    """Stands in for Anthropic's Message Batches API; nothing leaves the machine."""

    def __init__(self):
        self.batches: dict[str, dict] = {}
        self.fail_create: Exception | None = None
        self.answer = lambda custom_id, params: succeeded()

    def add(self, requests, status="in_progress"):
        batch_id = f"msgbatch_{len(self.batches) + 1:04d}"
        self.batches[batch_id] = {"requests": requests, "status": status,
                                  "created_at": datetime.now(timezone.utc).isoformat()}
        return batch_id

    def end(self):
        for batch in self.batches.values():
            batch["status"] = "ended"

    def info(self, batch_id):
        batch = self.batches[batch_id]
        ended = batch["status"] == "ended"
        n = len(batch["requests"])
        return {"id": batch_id, "type": "message_batch", "processing_status": batch["status"],
                "created_at": batch["created_at"],
                "request_counts": {"processing": 0 if ended else n, "succeeded": n if ended else 0,
                                   "errored": 0, "canceled": 0, "expired": 0},
                "results_url": f"{batches.BATCHES_URL}/{batch_id}/results" if ended else None}

    def __call__(self, method, url, key, body=None, timeout=60):
        if method == "POST" and url == batches.BATCHES_URL:
            batch_id = self.add(body["requests"])
            if self.fail_create:
                raise self.fail_create
            return json.dumps(self.info(batch_id)).encode()
        if url.startswith(batches.BATCHES_URL + "?"):
            data = [self.info(b) for b in reversed(list(self.batches))]
            return json.dumps({"data": data, "has_more": False, "last_id": None}).encode()
        if match := re.fullmatch(re.escape(batches.BATCHES_URL) + r"/(\w+)/results", url):
            lines = [json.dumps({"custom_id": r["custom_id"], "result": self.answer(r["custom_id"], r["params"])})
                     for r in self.batches[match[1]]["requests"]]
            return "\n".join(lines).encode()
        if match := re.fullmatch(re.escape(batches.BATCHES_URL) + r"/(\w+)/cancel", url):
            self.batches[match[1]]["status"] = "canceling"
            return json.dumps(self.info(match[1])).encode()
        if match := re.fullmatch(re.escape(batches.BATCHES_URL) + r"/(\w+)", url):
            return json.dumps(self.info(match[1])).encode()
        raise AssertionError(f"unexpected request {method} {url}")


class BatchTestCase(ReviewTestCase):
    def setUp(self):
        super().setUp()
        self.fake = FakeAnthropic()
        for patcher in (mock.patch.object(api_runner, "http_request", self.fake),
                        mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.lib = self.tasks["Audit lib"]["id"]
        self.lines = []

    def log(self, message):
        self.lines.append(message)


class BatchTest(BatchTestCase):
    def test_each_task_is_one_request_with_its_code_and_a_label(self):
        result = batches.submit(self.conn, [self.lib], log=self.log)
        self.assertEqual(result["queued"], [self.lib])
        (remote,) = self.fake.batches.values()
        (request,) = remote["requests"]
        self.assertRegex(request["custom_id"], rf"^task-{self.lib}-[0-9a-f]{{8}}$")
        params = request["params"]
        self.assertEqual(params["tool_choice"], {"type": "auto"}, "forcing a tool isn't supported by every model")
        self.assertEqual([t["name"] for t in params["tools"]], ["submit_report"])
        prompt = params["messages"][0]["content"]
        self.assertIn("=== lib/main.dart ===", prompt)
        self.assertIn("   10    runApp(const App());", prompt)
        self.assertIn("you cannot open files", prompt.lower())
        self.assertNotIn("super-secret-value", prompt)

        batch = store.list_batches(self.conn)[0]
        self.assertEqual((batch["anthropic_id"], batch["status"], batch["waiting"]), ("msgbatch_0001", "in_progress", 1))
        self.assertTrue(store.task_in_open_batch(self.conn, self.lib))
        self.assertEqual(store.get_task(self.conn, self.lib)["status"], "pending")

    def test_a_batched_task_is_not_sent_again(self):
        batches.submit(self.conn, [self.lib], log=self.log)
        again = batches.submit(self.conn, [self.lib], log=self.log)
        self.assertEqual(again["queued"], [])
        self.assertIn("waiting in a Claude batch", again["skipped"][0]["reason"])
        live = runner.Runner(self.db_path, investigate.AgentSettings(), 1, lambda *a: None, lambda m: None)
        self.assertEqual(live.submit([self.lib])["skipped"], [{"id": self.lib, "reason": "waiting in a batch"}])
        with self.assertRaises(investigate.InvestigationError):
            investigate.investigate(self.conn, self.lib)

    def test_results_are_checked_and_saved_once_the_batch_ends(self):
        batches.submit(self.conn, [self.lib], log=self.log)
        self.assertEqual(batches.check(self.conn, self.log)["in_progress"], 1)
        self.assertEqual(store.list_findings(self.conn, task_id=self.lib), [])

        self.fake.end()
        self.assertEqual(batches.check(self.conn, self.log)["imported"], 1)
        (finding,) = store.list_findings(self.conn, task_id=self.lib)
        self.assertEqual((finding["file_path"], finding["line"]), ("lib/main.dart", 10))
        (run,) = store.task_runs(self.conn, self.lib)
        self.assertEqual(run["status"], "done")
        self.assertAlmostEqual(run["cost_usd"], api_runner.estimate_cost("claude-sonnet-5-5", 10_000, 1_000) / 2)
        self.assertEqual(store.get_task(self.conn, self.lib)["status"], "done")
        self.assertEqual(store.list_batches(self.conn)[0]["status"], "imported")

        self.assertEqual(batches.check(self.conn, self.log)["checked"], 0)
        self.assertEqual(len(store.list_findings(self.conn, task_id=self.lib)), 1, "importing never repeats")

    def test_a_report_written_as_text_is_accepted(self):
        text = "Here is my report:\n```json\n" + json.dumps({"findings": [FINDING], "needs_review": []}) + "\n```"
        self.fake.answer = lambda custom_id, params: {"type": "succeeded", "message": {
            "id": "msg_2", "model": "claude-sonnet-5-5", "stop_reason": "end_turn",
            "content": [{"type": "text", "text": text}], "usage": {"input_tokens": 100, "output_tokens": 50}}}
        batches.submit(self.conn, [self.lib], log=self.log)
        self.fake.end()
        batches.check(self.conn, self.log)
        self.assertEqual(len(store.list_findings(self.conn, task_id=self.lib)), 1)

    def test_an_answer_without_a_report_fails_the_task_clearly(self):
        self.fake.answer = lambda custom_id, params: {"type": "succeeded", "message": {
            "id": "msg_3", "model": "claude-sonnet-5-5", "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "I looked at the code."}], "usage": {}}}
        batches.submit(self.conn, [self.lib], log=self.log)
        self.fake.end()
        batches.check(self.conn, self.log)
        self.assertIn("had no report", store.task_runs(self.conn, self.lib)[0]["error"])

    def test_made_up_citations_are_rejected_like_a_live_run(self):
        bad = {**FINDING, "file": "lib/does_not_exist.dart"}
        self.fake.answer = lambda custom_id, params: succeeded([bad])
        batches.submit(self.conn, [self.lib], log=self.log)
        self.fake.end()
        batches.check(self.conn, self.log)
        self.assertEqual(store.list_findings(self.conn, task_id=self.lib), [])
        self.assertIn("does not exist", store.task_runs(self.conn, self.lib)[0]["rejected"])

    def test_errored_and_expired_requests(self):
        other = self.tasks["Audit lib/src"]["id"]
        self.fake.answer = lambda custom_id, params: (
            {"type": "errored", "error": {"type": "error", "error": {"type": "invalid_request_error", "message": "too long"}}}
            if custom_id.startswith(f"task-{self.lib}-") else {"type": "expired"}
        )
        batches.submit(self.conn, [self.lib, other], log=self.log)
        self.fake.end()
        batches.check(self.conn, self.log)
        self.assertEqual(store.get_task(self.conn, self.lib)["status"], "failed")
        self.assertIn("too long", store.task_runs(self.conn, self.lib)[0]["error"])
        self.assertEqual(store.get_task(self.conn, other)["status"], "pending", "an expired request can be sent again")
        self.assertFalse(store.task_in_open_batch(self.conn, other))

    def test_a_lost_reply_is_recovered_by_count_and_time(self):
        self.fake.fail_create = TimeoutError("The read operation timed out")
        batches.submit(self.conn, [self.lib], log=self.log)
        batch = store.list_batches(self.conn)[0]
        self.assertEqual((batch["status"], batch["anthropic_id"]), ("submitting", None))
        self.assertTrue(store.task_in_open_batch(self.conn, self.lib), "not sent twice while unconfirmed")

        self.fake.end()
        batches.check(self.conn, self.log)
        batch = store.list_batches(self.conn)[0]
        self.assertEqual((batch["anthropic_id"], batch["status"]), ("msgbatch_0001", "imported"))
        self.assertEqual(len(store.list_findings(self.conn, task_id=self.lib)), 1)

    def test_a_batch_whose_record_was_lost_is_found_through_its_labels(self):
        batches.submit(self.conn, [self.lib], log=self.log)
        self.fake.add([{"custom_id": "someone-elses-request", "params": {}}], status="ended")
        with self.conn:
            self.conn.execute("DELETE FROM claude_batches")
        self.fake.end()

        summary = batches.recover(self.conn, self.log)
        self.assertEqual(summary["adopted"], 1, "only the batch carrying this database's task labels")
        (batch,) = store.list_batches(self.conn)
        self.assertEqual((batch["anthropic_id"], batch["recovered"], batch["status"]), ("msgbatch_0001", 1, "imported"))
        self.assertEqual(len(store.list_findings(self.conn, task_id=self.lib)), 1)

    def test_a_refused_batch_frees_its_tasks(self):
        self.fake.fail_create = investigate.InvestigationError("The Anthropic API returned 400: bad request")
        with self.assertRaises(batches.BatchError):
            batches.submit(self.conn, [self.lib], log=self.log)
        self.assertEqual(store.list_batches(self.conn)[0]["status"], "failed")
        self.assertFalse(store.task_in_open_batch(self.conn, self.lib))

    def test_cancel(self):
        batches.submit(self.conn, [self.lib], log=self.log)
        batches.cancel(self.conn, store.list_batches(self.conn)[0]["id"], self.log)
        self.assertEqual(store.list_batches(self.conn)[0]["status"], "canceling")

    def test_batches_need_a_key(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY")
            with self.assertRaises(batches.BatchError):
                batches.submit(self.conn, [self.lib])


class BatchRoundsTest(BatchTestCase):
    def prompts(self):
        return [r["params"]["messages"][0]["content"] for b in self.fake.batches.values() for r in b["requests"]]

    def test_a_task_that_asks_for_a_file_gets_another_round_with_it(self):
        def answer(custom_id, params):
            if "=== [requested] lib/src/api.dart ===" in params["messages"][0]["content"]:
                return succeeded()
            return succeeded([], [{"path": "lib/src/api.dart", "why": "to see what Api does"}])

        self.fake.answer = answer
        batches.submit(self.conn, [self.lib], log=self.log)
        self.assertIn("files_needed", self.fake.batches["msgbatch_0001"]["requests"][0]["params"]["tools"][0]["input_schema"]["properties"])
        self.fake.end()
        batches.check(self.conn, self.log)

        self.assertEqual(len(self.fake.batches), 2, "the next round was sent as a new batch")
        first, second = store.list_batches(self.conn)[1], store.list_batches(self.conn)[0]
        self.assertEqual((first["status"], first["continued"]), ("imported", 1))
        self.assertEqual((second["status"], second["round"]), ("in_progress", 2))
        self.assertEqual(store.list_findings(self.conn, task_id=self.lib), [], "nothing saved until the last round")
        self.assertTrue(store.task_in_open_batch(self.conn, self.lib))
        round_two = self.prompts()[1]
        self.assertIn("This is round 2 of at most 3", round_two)
        self.assertIn("=== [requested] lib/src/api.dart ===", round_two)
        self.assertIn("Your answer in the previous round", round_two)

        self.fake.end()
        batches.check(self.conn, self.log)
        (finding,) = store.list_findings(self.conn, task_id=self.lib)
        self.assertEqual(finding["file_path"], "lib/main.dart")
        (run,) = store.task_runs(self.conn, self.lib)
        self.assertEqual((run["status"], run["num_turns"]), ("done", 2))
        self.assertAlmostEqual(run["cost_usd"], 2 * ROUND_COST, msg="the cost covers both rounds")
        self.assertFalse(store.task_in_open_batch(self.conn, self.lib))

    def test_made_up_and_secret_files_are_refused(self):
        (self.root_dir / ".env").write_text("TOKEN=secret\n")
        accepted, refused = batches.resolve_needed(
            self.conn, self.lib, [{"path": "lib/nope.dart", "why": "x"}, {"path": ".env", "why": "x"},
                                  {"path": "lib/main.dart", "why": "already included"}], [])
        self.assertEqual(accepted, [])
        self.assertEqual(refused, ["lib/nope.dart (not found in the project)", ".env (may contain secrets)"])

        self.fake.answer = lambda custom_id, params: succeeded([FINDING], [{"path": ".env", "why": "x"}])
        batches.submit(self.conn, [self.lib], log=self.log)
        self.fake.end()
        batches.check(self.conn, self.log)
        self.assertEqual(len(self.fake.batches), 1, "no second round for files that can't be given")
        self.assertEqual(store.task_runs(self.conn, self.lib)[0]["num_turns"], 1)
        self.assertNotIn("TOKEN=secret", "".join(self.prompts()))

    def test_the_last_round_cannot_ask_for_more(self):
        asks = iter(["lib/src/api.dart", "lib/src/io_stub.dart", "lib/src/io_real.dart"])
        self.fake.answer = lambda custom_id, params: succeeded([FINDING], [{"path": next(asks), "why": "x"}])
        with mock.patch.object(batches, "MAX_ROUNDS", 2):
            batches.submit(self.conn, [self.lib], log=self.log)
            self.fake.end()
            batches.check(self.conn, self.log)
            self.fake.end()
            batches.check(self.conn, self.log)
        self.assertEqual(len(self.fake.batches), 2)
        self.assertIn("This is the last round (2 of 2)", self.prompts()[1])
        self.assertEqual(store.task_runs(self.conn, self.lib)[0]["num_turns"], 2)

    def test_if_the_next_round_cant_be_sent_the_answer_so_far_is_saved(self):
        self.fake.answer = lambda custom_id, params: succeeded([FINDING], [{"path": "lib/src/api.dart", "why": "x"}])
        batches.submit(self.conn, [self.lib], log=self.log)
        self.fake.end()
        self.fake.fail_create = investigate.InvestigationError("The Anthropic API returned 400: too many batches")
        batches.check(self.conn, self.log)
        self.assertEqual(len(store.list_findings(self.conn, task_id=self.lib)), 1)
        self.assertEqual(store.task_runs(self.conn, self.lib)[0]["status"], "done")
        self.assertTrue(any("saving the answers so far" in line for line in self.lines))

    @property
    def root_dir(self):
        return self.base / "repo"


class BatchPageTest(BatchTestCase):
    request = test_review.ReviewPageTest.request
    post = test_review.ReviewPageTest.post

    def setUp(self):
        super().setUp()
        import threading
        from audit_agent import web
        fake_runner = runner.Runner(self.db_path, investigate.AgentSettings(), 2, lambda *a: None, lambda m: None)
        self.server = web.ReviewServer(self.db_path, port=0, runner=fake_runner)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def test_send_check_and_see_tasks_in_a_batch(self):
        status, data = self.post("/api/batches", {"ids": [self.lib]})
        self.assertEqual(status, 200, data)
        self.assertEqual(json.loads(data)["result"]["queued"], [self.lib])
        queue = json.loads(self.request("GET", f"/api/audits/{self.audit_id}/tasks")[1])
        self.assertTrue(next(t for t in queue["tasks"] if t["id"] == self.lib)["in_batch"])
        self.assertTrue(json.loads(self.request("GET", f"/api/tasks/{self.lib}")[1])["in_batch"])

        self.fake.end()
        status, data = self.post("/api/batches/check", {})
        self.assertEqual(json.loads(data)["result"]["imported"], 1)
        listed = json.loads(self.request("GET", "/api/batches")[1])
        self.assertEqual(listed["batches"][0]["status"], "imported")
        self.assertTrue(listed["available"])

    def test_page_explains_a_missing_key(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY")
            status, data = self.post("/api/batches", {"ids": [self.lib]})
        self.assertEqual(status, 400)
        self.assertIn("set-api-key", json.loads(data)["error"])


if __name__ == "__main__":
    unittest.main()
