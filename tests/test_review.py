import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from audit_agent import planning, review, store, views, web
from audit_agent.inventory import discover
from audit_agent.repo import open_repository
from tests.helpers import make_repo
from tests.test_inventory import DART_REPO

REVIEW_REPO = {
    **DART_REPO,
    "lib/scripts/seed.dart": "void seed() {}\n",
    "lib/scripts/tools/migrate.dart": "void migrate() {}\n",
}


class ReviewTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.db_path = self.base / "audit.db"
        self.conn = store.connect(self.db_path)
        self.addCleanup(self.conn.close)
        repo = open_repository(make_repo(self.base / "repo", REVIEW_REPO))
        self.audit_id = store.create_audit(self.conn, repo)
        store.save_inventory(self.conn, self.audit_id, discover(repo))
        planning.plan_audit(self.conn, self.audit_id)
        self.tasks = {t["title"]: t for t in review.find_tasks(self.conn, self.audit_id)}

    def status(self, title: str) -> str:
        return store.get_task(self.conn, self.tasks[title]["id"])["status"]


class ReviewTest(ReviewTestCase):
    def test_cancel_and_restore_one_task(self):
        task_id = self.tasks["Audit lib/src"]["id"]
        self.assertEqual(review.cancel_tasks(self.conn, [task_id]), 1)
        self.assertEqual(self.status("Audit lib/src"), "cancelled")
        self.assertEqual(review.cancel_tasks(self.conn, [task_id]), 0, "cancelling twice changes nothing")
        self.assertEqual(review.restore_tasks(self.conn, [task_id]), 1)
        self.assertEqual(self.status("Audit lib/src"), "pending")

    def test_done_tasks_cannot_be_cancelled(self):
        task_id = self.tasks["Audit lib/src"]["id"]
        self.conn.execute("UPDATE audit_tasks SET status = 'done' WHERE id = ?", (task_id,))
        self.conn.commit()
        self.assertEqual(review.cancel_tasks(self.conn, [task_id]), 0)
        self.assertEqual(self.status("Audit lib/src"), "done")

    def test_folder_filter_only_matches_tasks_entirely_inside_the_folder(self):
        matched = {t["title"] for t in review.find_tasks(self.conn, self.audit_id, review.TaskFilter(folder="lib/scripts"))}
        self.assertTrue(matched)
        for title in matched:
            files = self.tasks[title]["files"]
            self.assertTrue(all(p.startswith("lib/scripts/") for p in files), title)
        self.assertNotIn("Audit lib", matched)

    def test_bulk_cancel_test_code_then_restore(self):
        changed = review.cancel_matching(self.conn, self.audit_id, review.TaskFilter(tests="only"))
        self.assertEqual(changed, 1)
        self.assertEqual(self.status("Audit test"), "cancelled")
        self.assertEqual(self.status("Audit lib"), "pending")
        cancelled = review.find_tasks(self.conn, self.audit_id, review.TaskFilter(status="cancelled"))
        self.assertEqual([t["title"] for t in cancelled], ["Audit test"])
        self.assertEqual(review.restore_matching(self.conn, self.audit_id, review.TaskFilter(status="cancelled")), 1)
        self.assertEqual(self.status("Audit test"), "pending")

    def test_search_matches_titles_and_file_paths(self):
        found = {t["title"] for t in review.find_tasks(self.conn, self.audit_id, review.TaskFilter(search="BUTTON.dart"))}
        self.assertEqual(found, {"Audit lib/src/widgets"})

    def add_api_task(self, paths, status="done"):
        task_id = self.conn.execute(
            """INSERT INTO audit_tasks (audit_id, title, line_count, priority, priority_reason, status, created_at,
                                        updated_at, kind, task_key)
               VALUES (?, 'GET /me', 1, 1, 'r', ?, 't', 't', 'api', ?)""",
            (self.audit_id, status, f"key-{len(paths)}-{status}"),
        ).lastrowid
        self.conn.executemany("INSERT INTO api_task_files (task_id, audit_id, path, role) VALUES (?, ?, ?, 'handler')",
                              [(task_id, self.audit_id, p) for p in paths])
        self.conn.commit()
        return task_id

    def test_file_tasks_show_what_finished_api_tasks_already_looked_at(self):
        lib = self.tasks["Audit lib"]
        first = lib["files"][0]
        api_task = self.add_api_task([first])
        self.add_api_task(lib["files"], status="pending")
        found = {t["title"]: t for t in review.find_tasks(self.conn, self.audit_id)}
        self.assertEqual((found["Audit lib"]["api_covered"], found["Audit lib"]["api_task_ids"]), (1, [api_task]),
                         "only finished API tasks count")
        self.assertEqual(found["Audit test"]["api_covered"], 0)

        def titles(api):
            return {t["title"] for t in review.find_tasks(self.conn, self.audit_id, review.TaskFilter(api=api))}
        some = "some" if len(lib["files"]) > 1 else "all"
        self.assertEqual(titles(some), {"Audit lib"})
        self.assertNotIn("Audit lib", titles("none"))
        self.assertIn("Audit test", titles("none"))
        self.assertTrue(all(t["kind"] == "files" for t in review.find_tasks(
            self.conn, self.audit_id, review.TaskFilter(api="none"))), "the filter shows file groups only")

        seen = views.task_detail(self.conn, lib["id"])["api_seen"]
        self.assertEqual(seen["files"], [{"path": first, "api_tasks": [{"id": api_task, "title": "GET /me", "repo": "repo"}]}])
        self.assertEqual(seen["total_files"], len(lib["files"]))
        self.assertEqual(seen["findings"], [])

    def test_planning_again_keeps_cancellations(self):
        review.cancel_matching(self.conn, self.audit_id, review.TaskFilter(tests="only"))
        _, created = planning.plan_audit(self.conn, self.audit_id)
        self.assertFalse(created)
        self.assertEqual(self.status("Audit test"), "cancelled")

    def test_version_3_database_is_upgraded_without_losing_tasks(self):
        old_path = self.base / "v3.db"
        v3_schema = (
            store.SCHEMA.replace(store.DUPLICATE_TABLES, "")
            .replace(store.FIX_COMMENT_TABLES, "")
            .replace(store.FIX_TABLES, "")
            .replace(store.VERIFICATION_TABLES, "")
            .replace(store.BATCH_ROUND_TABLES, "")
            .replace(store.ISSUE_TABLES, "")
            .replace(store.BATCH_TABLES, "")
            .replace(store.API_TASK_TABLES, "")
            .replace(store.APP_TABLES, "")
            .replace(store.FINDING_TABLES, "")
            .replace(store.API_TRACE_TABLES, "")
            .replace(store.API_TABLES, "")
            .replace(", 'cancelled')", ")")
        )
        old = sqlite3.connect(old_path)
        old.executescript(
            v3_schema
            + """INSERT INTO audits (id, repo_path, repo_name, working_tree_dirty, status, created_at, updated_at)
                     VALUES (1, '/r', 'r', 0, 'planned', 't', 't');
                 INSERT INTO audit_tasks VALUES (7, 1, 'Audit lib', 10, 5, 'reason', 'pending', 't', 't');
                 INSERT INTO audit_task_files VALUES (1, 'lib/a.dart', 7);
                 PRAGMA user_version = 3;"""
        )
        old.close()

        conn = store.connect(old_path)
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], store.SCHEMA_VERSION)
        self.assertEqual(conn.execute("SELECT task_id FROM audit_task_files").fetchall()[0][0], 7)
        self.assertEqual(review.cancel_tasks(conn, [7]), 1)
        self.assertEqual(store.get_task(conn, 7)["status"], "cancelled")


class ReviewPageTest(ReviewTestCase):
    def setUp(self):
        super().setUp()
        self.server = web.ReviewServer(self.db_path, port=0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def request(self, method, path, body=None, headers=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        all_headers = {"Host": host or f"127.0.0.1:{self.port}", **(headers or {})}
        payload = None if body is None else json.dumps(body)
        conn.request(method, path, body=payload, headers=all_headers)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, data

    def post(self, path, body, **kwargs):
        headers = {"Content-Type": "application/json", "X-Audit-Agent": "1"}
        return self.request("POST", path, body, headers=headers, **kwargs)

    def test_page_and_task_queue_are_served(self):
        status, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Audit review", page)

        status, data = self.request("GET", "/api/projects")
        groups = json.loads(data)
        self.assertEqual([g["name"] for g in groups], ["Audits not in a project"])
        self.assertEqual([(a["name"], a["type"]) for a in groups[0]["apps"]], [("repo", "mobile")])
        self.assertEqual(sum(groups[0]["apps"][0]["task_counts"].values()), len(self.tasks))

        status, data = self.request("GET", f"/api/audits/{self.audit_id}/tasks?tests=hide")
        self.assertEqual(status, 200)
        queue = json.loads(data)
        self.assertNotIn("Audit test", [t["title"] for t in queue["tasks"]])
        self.assertEqual(queue["counts"]["pending"], queue["total"])
        self.assertEqual({g["what"] for g in queue["not_covered"]}, {"Swift", "Kotlin"})

        status, data = self.request("GET", f"/api/tasks/{self.tasks['Audit lib']['id']}")
        detail = json.loads(data)
        self.assertEqual([e["path"] for e in detail["entry_points"]], ["lib/main.dart"])
        self.assertEqual(detail["api_seen"]["files"], [])

        status, data = self.request("GET", f"/api/audits/{self.audit_id}/tasks?api=none")
        self.assertEqual(status, 200)
        listed = json.loads(data)["tasks"]
        self.assertEqual(len(listed), len(self.tasks))
        self.assertEqual({t["api_covered"] for t in listed}, {0})
        self.assertEqual(self.request("GET", f"/api/audits/{self.audit_id}/tasks?api=bogus")[0], 400)
        self.assertIn(b'id="api-seen"', page)

    def test_cancel_and_restore_through_the_page(self):
        task_id = self.tasks["Audit lib/src"]["id"]
        status, data = self.post("/api/tasks/cancel", {"ids": [task_id]})
        self.assertEqual((status, json.loads(data)), (200, {"changed": 1}))
        self.assertEqual(self.status("Audit lib/src"), "cancelled")

        status, data = self.post(f"/api/audits/{self.audit_id}/restore", {"filter": {"status": "cancelled"}})
        self.assertEqual(json.loads(data), {"changed": 1})
        self.assertEqual(self.status("Audit lib/src"), "pending")

    def test_writes_without_the_page_header_are_refused(self):
        task_id = self.tasks["Audit lib/src"]["id"]
        status, _ = self.request(
            "POST", "/api/tasks/cancel", {"ids": [task_id]}, headers={"Content-Type": "application/json"}
        )
        self.assertEqual(status, 403)
        status, _ = self.request("POST", "/api/tasks/cancel", {"ids": [task_id]},
                                 headers={"Content-Type": "text/plain", "X-Audit-Agent": "1"})
        self.assertEqual(status, 403)
        self.assertEqual(self.status("Audit lib/src"), "pending")

    def test_requests_for_other_hosts_are_refused(self):
        status, _ = self.request("GET", "/api/audits", host="evil.example:80")
        self.assertEqual(status, 403)
        status, _ = self.post("/api/tasks/cancel", {"ids": [1]}, host="evil.example:80")
        self.assertEqual(status, 403)

    def test_bad_input_gets_a_clear_error(self):
        status, data = self.post("/api/tasks/cancel", {"ids": "all"})
        self.assertEqual(status, 400)
        self.assertIn("ids", json.loads(data)["error"])
        status, _ = self.request("GET", "/api/tasks/99999")
        self.assertEqual(status, 404)
        status, _ = self.request("GET", f"/api/audits/{self.audit_id}/tasks?status=nope")
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
