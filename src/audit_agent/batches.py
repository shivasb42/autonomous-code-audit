"""Send tasks to Claude as a Message Batch: half the price, results within 24 hours (usually less).

A batch request can't go back and forth, so each task becomes one request that already contains
its files' code, with a single tool, submit_report, that Claude must call. Results are checked
and saved exactly like a live run (investigate.record_result).

When Claude needs code it wasn't given, it lists the files in its answer ("files_needed"). Files
that exist in the project and aren't secrets are added, and the task goes into the next batch with
them and with Claude's previous answer, up to MAX_ROUNDS rounds. Only the last round's report is
saved, and its cost includes every round.

Nothing is lost if the app stops or a batch id goes missing:
- The batch row is saved before the batch is sent, and Anthropic's batch id right after.
- Every request carries a label naming its task (custom_id "task-<id>-<random>"), and every result
  comes back with that label, so a result can always be matched to its task.
- `recover` lists the batches on the Anthropic account (their results stay available for 29 days),
  matches ones this database lost track of, and imports their results.
"""

from __future__ import annotations

import copy
import json
import re
import secrets
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from audit_agent import api_runner, credentials, store
from audit_agent import investigate as investigation
from audit_agent.inventory.languages import is_secret_file

BATCHES_URL = "https://api.anthropic.com/v1/messages/batches"
BATCH_DISCOUNT = 0.5
MAX_FILE_CHARS = 120_000
MAX_PROMPT_CHARS = 400_000
MAX_REQUESTS_PER_BATCH = 5000
LIST_PAGES = 20
SUBMIT_MATCH_WINDOW = timedelta(minutes=15)
POLL_SECONDS = 60
CUSTOM_ID = re.compile(r"^task-(\d+)-[0-9a-f]{8}$")
MAX_ROUNDS = 3
MAX_FILES_PER_ROUND = 8

SYSTEM_PROMPT = """You are a careful code auditor. Everything you can see is in this message: you cannot open \
files yourself, run, or edit anything. Investigate the code you are given, then call submit_report exactly once with \
your result. Never report a problem you cannot point to in the code shown."""

FILES_NEEDED = {
    "type": "array",
    "description": "Files you need to see to confirm or rule out a suspicion. You get another round with them.",
    "items": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Relative to its repository root, or absolute for another repository"},
            "why": {"type": "string"},
        },
        "required": ["path", "why"],
    },
}


def _submit_tool() -> dict:
    tool = copy.deepcopy(next(t for t in api_runner.TOOLS if t["name"] == "submit_report"))
    tool["input_schema"]["properties"]["files_needed"] = FILES_NEEDED
    return tool


def _round_note(round_no: int) -> str:
    base = ("\nIn this run you cannot open files yourself. The code of the files is included below with line numbers; "
            "cite those line numbers.\n")
    if round_no < MAX_ROUNDS:
        return base + (
            f"This is round {round_no} of at most {MAX_ROUNDS}. If confirming or ruling out a suspicion needs code that "
            "isn't shown (an imported module, a validator, middleware, a model), list those files in files_needed with "
            "why, and you'll get another round with them. Report now what you can already show; ask only for files you "
            f"really need (at most {MAX_FILES_PER_ROUND}).\n"
        )
    return base + (
        f"This is the last round ({round_no} of {MAX_ROUNDS}): you can't ask for more files. Anything that still depends "
        "on code you can't see goes under \"needs_review\", naming the file.\n"
    )


class BatchError(Exception):
    pass


def _log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def api_key() -> str:
    key = credentials.get_api_key()
    if not key:
        raise BatchError("Batches use the Anthropic API. Save a key with `audit-agent set-api-key` first.")
    return key


def _get(url: str, key: str) -> dict:
    return json.loads(api_runner.http_request("GET", url, key, timeout=120))


def _numbered(text: str) -> str:
    return "\n".join(f"{n:>5}  {line}" for n, line in enumerate(text.splitlines(), 1))


def _task_files(conn: sqlite3.Connection, scope: investigation.TaskScope) -> list[tuple[str, Path]]:
    """(label, file on disk) for every file the task covers. Files in the task's own repository are
    labelled by their relative path, others by their absolute path, which is how findings cite them."""
    task = scope.task
    if task["kind"] == "api":
        rows = [(Path(r["repo_path"]), r["path"], r["role"]) for r in store.api_task_files(conn, task["id"])]
    else:
        rows = [(scope.root, r["path"], None) for r in store.task_context(conn, task["id"])["files"]]
    files = []
    for root, path, role in rows:
        on_disk = root / path
        label = _label(scope, on_disk)
        files.append((f"[{role}] {label}" if role else label, on_disk))
    return files


def _label(scope: investigation.TaskScope, on_disk: Path) -> str:
    try:
        return on_disk.relative_to(scope.root).as_posix()
    except ValueError:
        return str(on_disk)


def _is_secret(scope: investigation.TaskScope, on_disk: Path) -> bool:
    return is_secret_file(on_disk.name) or on_disk.resolve() in {p.resolve() for p in scope.secret_paths}


def build_request(conn: sqlite3.Connection, task_id: int, model: str, round_no: int = 1,
                  extra_files: list[list[str]] | None = None, previous_report: dict | None = None,
                  refused: list[str] | None = None) -> tuple[str, dict]:
    """The batch request for one task: (custom_id, Messages API parameters). A follow-up round also
    gets the files Claude asked for (extra_files, as [repository root, relative path]) and its
    previous answer."""
    scope = investigation.task_scope(conn, task_id)
    files = _task_files(conn, scope)
    files += [(f"[requested] {_label(scope, Path(root) / rel)}", Path(root) / rel) for root, rel in extra_files or []]
    sections, total, left_out = [], 0, []
    for label, on_disk in files:
        if _is_secret(scope, on_disk):
            continue
        try:
            text = on_disk.read_text(encoding="utf-8", errors="replace")
        except OSError:
            left_out.append(f"{label} (could not be read)")
            continue
        if len(text) > MAX_FILE_CHARS or total + len(text) > MAX_PROMPT_CHARS:
            left_out.append(f"{label} (too large to include)")
            continue
        total += len(text)
        sections.append(f"=== {label} ===\n{_numbered(text)}")
    prompt = investigation.build_prompt(conn, scope.task, scope.audit, scope.own_secrets) + "\n" + _round_note(round_no)
    if previous_report:
        prompt += (
            "\nYour answer in the previous round is below. The files you asked for are now included, marked "
            "[requested]. This round's report replaces the previous one, so include every finding that still holds.\n"
            + json.dumps({k: previous_report.get(k, []) for k in ("findings", "needs_review", "files_needed")}, indent=1)
            + "\n"
        )
    if refused:
        prompt += "\nFiles you asked for that can't be provided: " + "; ".join(refused) + "\n"
    if left_out:
        prompt += "\nNot included: " + "; ".join(left_out) + "\n"
    prompt += "\n" + "\n\n".join(sections)
    params = {
        "model": model,
        "max_tokens": api_runner.MAX_OUTPUT_TOKENS,
        "system": SYSTEM_PROMPT,
        "tools": [_submit_tool()],
        # Forcing a specific tool ("tool" or "any") isn't supported by every model, so Claude is told
        # to call submit_report and an answer written as JSON text is accepted too (see _result).
        "tool_choice": {"type": "auto"},
        "messages": [{"role": "user", "content": prompt}],
    }
    return f"task-{task_id}-{secrets.token_hex(4)}", params


def resolve_needed(conn: sqlite3.Connection, task_id: int, requested: list, already: list[list[str]]) -> tuple[list[list[str]], list[str]]:
    """Check the files Claude asked for. Returns (new files as [root, relative path], refusals).
    A file must exist in one of the project's repositories, must not be a secret, and must not be
    one the task already has."""
    scope = investigation.task_scope(conn, task_id)
    have = {Path(root) / rel for root, rel in already} | {on_disk for _, on_disk in _task_files(conn, scope)}
    have = {p.resolve() for p in have}
    accepted, refused = [], []
    for item in requested or []:
        path = str((item or {}).get("path") if isinstance(item, dict) else item or "").strip()
        if not path:
            continue
        located = investigation._relative(path, scope.roots)
        if located is None:
            refused.append(f"{path} (not found in the project)")
            continue
        root, rel = located
        on_disk = (root / rel).resolve()
        if _is_secret(scope, on_disk):
            refused.append(f"{path} (may contain secrets)")
        elif on_disk in have:
            continue
        elif len(accepted) >= MAX_FILES_PER_ROUND:
            refused.append(f"{path} (more than {MAX_FILES_PER_ROUND} files in one round)")
        else:
            accepted.append([str(root), rel])
            have.add(on_disk)
    return accepted, refused


def _nothing_was_created(error: Exception) -> bool:
    """True when the failed request certainly didn't create a batch (it was refused or never sent)."""
    message = str(error)
    return message.startswith(("The Anthropic API returned 4", "The Anthropic API rejected", "Network calls are turned off",
                               "Python could not verify"))


def submit(conn: sqlite3.Connection, task_ids: list[int], model: str | None = None, exclude: set[int] = frozenset(),
           log=_log) -> dict:
    """Send tasks as one or more batches. Returns the batches created and why tasks were skipped."""
    key = api_key()
    model = model or api_runner.DEFAULT_MODEL
    requests, skipped = [], []
    for task_id in dict.fromkeys(task_ids):
        try:
            task = store.get_task(conn, task_id)
            if task_id in exclude:
                raise investigation.InvestigationError("already sent to Claude live")
            investigation.check_runnable(conn, task)
            requests.append((task_id, *build_request(conn, task_id, model)))
        except (store.StoreError, investigation.InvestigationError) as exc:
            skipped.append({"id": task_id, "reason": str(exc)})
    created = _send(conn, key, model, [(task_id, custom_id, params, {}) for task_id, custom_id, params in requests], log)
    return {"batches": created, "queued": [r[0] for r in requests], "skipped": skipped}


def _send(conn: sqlite3.Connection, key: str, model: str, requests: list[tuple], log) -> list[int]:
    """Record and send (task_id, custom_id, params, round details) requests, in batches of at most
    MAX_REQUESTS_PER_BATCH. Raises BatchError if Anthropic certainly didn't create a batch."""
    created = []
    for start in range(0, len(requests), MAX_REQUESTS_PER_BATCH):
        chunk = requests[start:start + MAX_REQUESTS_PER_BATCH]
        batch_id = store.create_batch(conn, model, [(task_id, custom_id, details) for task_id, custom_id, _, details in chunk])
        body = {"requests": [{"custom_id": custom_id, "params": params} for _, custom_id, params, _ in chunk]}
        try:
            response = json.loads(api_runner.http_request("POST", BATCHES_URL, key, body, timeout=600))
        except Exception as exc:
            if _nothing_was_created(exc):
                store.update_batch(conn, batch_id, status="failed", error=str(exc))
                with conn:
                    conn.execute("UPDATE claude_batch_items SET status = 'failed', error = ? WHERE batch_id = ?",
                                 (str(exc), batch_id))
                log(f"Batch #{batch_id} was not created: {exc}")
                raise BatchError(f"Anthropic did not accept the batch: {exc}") from exc
            store.update_batch(conn, batch_id, error=f"No reply after sending ({exc}). Run recover to find it.")
            log(f"Batch #{batch_id}: no reply after sending ({exc}); `recover` will look for it on Anthropic's side")
            created.append(batch_id)
            continue
        store.update_batch(conn, batch_id, anthropic_id=response["id"], status=response.get("processing_status", "in_progress"))
        log(f"Batch #{batch_id} sent as {response['id']}: {len(chunk)} task(s), model {model}")
        created.append(batch_id)
    return created


def _result(message: dict, model: str) -> investigation.AgentResult:
    report = next((b.get("input") for b in message.get("content") or []
                   if b.get("type") == "tool_use" and b.get("name") == "submit_report"), None)
    if not isinstance(report, dict):
        text = "\n".join(b.get("text", "") for b in message.get("content") or [] if b.get("type") == "text")
        try:
            report = investigation._extract_report({"result": text}) if text.strip() else None
        except investigation.InvestigationError:
            report = None
    if not isinstance(report, dict) or not {"findings", "needs_review"} & set(report):
        raise investigation.InvestigationError(
            f"Claude's batch answer had no report (stop reason: {message.get('stop_reason')})."
        )
    usage = message.get("usage") or {}
    cost = api_runner.estimate_cost(message.get("model") or model, int(usage.get("input_tokens") or 0),
                                    int(usage.get("output_tokens") or 0))
    return investigation.AgentResult(
        report=report,
        cost_usd=None if cost is None else cost * BATCH_DISCOUNT,
        duration_ms=None,
        num_turns=1,
        session_id=message.get("id"),
        raw=json.dumps({"batch": True, "message": message})[-200_000:],
    )


def _finalize(conn: sqlite3.Connection, custom_id: str, task_id: int, answer: investigation.AgentResult,
              total_cost: float | None, rounds: int) -> str:
    """Check and save the report that ends a task's batch rounds."""
    try:
        run_id = store.start_run(conn, task_id, investigation.GENERAL_AGENT)
    except store.StoreError as exc:
        store.finish_batch_item(conn, custom_id, "failed", error=f"Not imported: {exc}")
        return "skipped"
    final = investigation.AgentResult(report=answer.report, cost_usd=total_cost, duration_ms=None, num_turns=rounds,
                                      session_id=answer.session_id, raw=answer.raw)
    try:
        summary = investigation.record_result(conn, run_id, investigation.task_scope(conn, task_id), final)
    except investigation.InvestigationError as exc:
        store.finish_run(conn, run_id, task_id, "failed", error=str(exc), raw_output=answer.raw)
        store.finish_batch_item(conn, custom_id, "failed", run_id, str(exc))
        return "errored"
    store.finish_batch_item(conn, custom_id, "done", run_id)
    return f"done:{summary['findings']}"


def _import_line(conn: sqlite3.Connection, batch: sqlite3.Row, line: dict, followups: list[dict]) -> str | None:
    """Save one result line, or add it to `followups` when Claude asked for files it should get.
    Returns its outcome, or None when the line isn't ours or was imported already."""
    custom_id = str(line.get("custom_id") or "")
    match = CUSTOM_ID.match(custom_id)
    if not match:
        return None
    task_id = int(match.group(1))
    item = store.batch_item_by_custom_id(conn, custom_id)
    if item is None:
        try:
            store.get_task(conn, task_id)
        except store.StoreError:
            return None
        store.add_batch_item(conn, batch["id"], task_id, custom_id)
    elif item["status"] != "waiting":
        return None
    result = line.get("result") or {}
    kind = result.get("type")
    if kind in ("canceled", "expired"):
        store.finish_batch_item(conn, custom_id, "canceled" if kind == "canceled" else "failed",
                                error=f"The request was {kind} before Claude answered.")
        return kind
    try:
        answer = _result(result.get("message") or {}, batch["model"]) if kind == "succeeded" else None
    except investigation.InvestigationError as exc:
        answer, error = None, str(exc)
    else:
        error = None if answer else (
            "Batch request failed: "
            + ((result.get("error") or {}).get("error", {}).get("message") or json.dumps(result)[:500])
        )
    if answer is None:
        try:
            run_id = store.start_run(conn, task_id, investigation.GENERAL_AGENT)
        except store.StoreError as exc:
            store.finish_batch_item(conn, custom_id, "failed", error=f"Not imported: {exc}")
            return "skipped"
        store.finish_run(conn, run_id, task_id, "failed", error=error,
                         raw_output=json.dumps(result.get("message") or result)[-200_000:])
        store.finish_batch_item(conn, custom_id, "failed", run_id, error)
        return "errored"

    item = store.batch_item_by_custom_id(conn, custom_id)
    round_no, have = item["round"], json.loads(item["extra_files"] or "[]")
    total_cost = (item["prior_cost_usd"] or 0) + (answer.cost_usd or 0)
    if round_no < MAX_ROUNDS:
        new_files, refused = resolve_needed(conn, task_id, answer.report.get("files_needed"), have)
        if new_files:
            followups.append({"task_id": task_id, "custom_id": custom_id, "round": round_no + 1,
                              "extra_files": have + new_files, "refused": refused, "answer": answer,
                              "total_cost": total_cost})
            return "continued"
    return _finalize(conn, custom_id, task_id, answer, total_cost, round_no)


def _send_followups(conn: sqlite3.Connection, batch: sqlite3.Row, followups: list[dict], key: str, log) -> None:
    """Send the next round for tasks whose answer asked for more files. If that can't be sent, save
    the answers so far instead, so nothing that was paid for is lost."""
    model = batch["model"] if batch["model"] != "unknown" else api_runner.DEFAULT_MODEL
    try:
        requests = []
        for f in followups:
            custom_id, params = build_request(conn, f["task_id"], model, f["round"], f["extra_files"],
                                              f["answer"].report, f["refused"])
            requests.append((f["task_id"], custom_id, params,
                             {"round": f["round"], "extra_files": f["extra_files"],
                              "previous_report": f["answer"].report, "prior_cost_usd": f["total_cost"]}))
        created = _send(conn, key, model, requests, log)
    except Exception as exc:
        log(f"Couldn't send the next round ({exc}); saving the answers so far")
        for f in followups:
            _finalize(conn, f["custom_id"], f["task_id"], f["answer"], f["total_cost"], f["round"] - 1)
        return
    for f in followups:
        store.continue_batch_item(conn, f["custom_id"], f["answer"].report, f["answer"].cost_usd,
                                  created[0] if created else None)
    log(f"Sent {len(followups)} task(s) to round {max(f['round'] for f in followups)} with the files Claude asked for, "
        f"as batch(es) {', '.join(f'#{b}' for b in created)}")


def import_results(conn: sqlite3.Connection, batch: sqlite3.Row, results_url: str, key: str, log=_log) -> dict:
    """Download an ended batch's results and save them. Safe to repeat: imported lines are skipped."""
    data = api_runner.http_request("GET", results_url, key, timeout=600).decode("utf-8", errors="replace")
    outcomes: dict[str, int] = {}
    findings = 0
    followups: list[dict] = []
    for raw in data.splitlines():
        if not raw.strip():
            continue
        outcome = _import_line(conn, batch, json.loads(raw), followups)
        if outcome is None:
            continue
        if outcome.startswith("done:"):
            findings += int(outcome.split(":", 1)[1])
            outcome = "done"
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    if followups:
        _send_followups(conn, batch, followups, key, log)
    with conn:
        conn.execute(
            """UPDATE claude_batch_items SET status = 'failed', error = 'No result came back for this request.'
               WHERE batch_id = ? AND status = 'waiting'""",
            (batch["id"],),
        )
    store.update_batch(conn, batch["id"], status="imported", ended_at=_now())
    log(f"Batch #{batch['id']} ({batch['anthropic_id']}) imported: "
        + ", ".join(f"{n} {k}" for k, n in sorted(outcomes.items())) + f"; {findings} findings")
    return {"outcomes": outcomes, "findings": findings}


def _apply_status(conn: sqlite3.Connection, batch: sqlite3.Row, info: dict, key: str, log) -> str:
    counts = info.get("request_counts") or {}
    status = info.get("processing_status", batch["status"])
    store.update_batch(conn, batch["id"], status="ended" if status == "ended" else status,
                       succeeded=counts.get("succeeded", 0), errored=counts.get("errored", 0),
                       canceled=counts.get("canceled", 0), expired=counts.get("expired", 0))
    if status == "ended" and info.get("results_url"):
        import_results(conn, store.get_batch(conn, batch["id"]), info["results_url"], key, log)
        return "imported"
    return status


def check(conn: sqlite3.Connection, log=_log) -> dict:
    """Ask Anthropic about every open batch, import the ones that ended, and look for batches sent
    without a recorded id."""
    key = api_key()
    summary = {"checked": 0, "imported": 0, "in_progress": 0}
    if any(b["anthropic_id"] is None for b in store.list_batches(conn, ("submitting",))):
        recover(conn, log=log)
    for batch in store.list_batches(conn, ("in_progress", "canceling", "ended")):
        if not batch["anthropic_id"]:
            continue
        summary["checked"] += 1
        outcome = _apply_status(conn, batch, _get(f"{BATCHES_URL}/{batch['anthropic_id']}", key), key, log)
        summary["imported" if outcome == "imported" else "in_progress"] += 1
    return summary


def _list_remote(key: str) -> list[dict]:
    found, after = [], None
    for _ in range(LIST_PAGES):
        url = f"{BATCHES_URL}?limit=100" + (f"&after_id={after}" if after else "")
        page = _get(url, key)
        found += page.get("data") or []
        if not page.get("has_more") or not page.get("last_id"):
            break
        after = page["last_id"]
    return found


def _parse_time(value: str | None) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _results_are_ours(conn: sqlite3.Connection, results_url: str, key: str) -> bool:
    data = api_runner.http_request("GET", results_url, key, timeout=600).decode("utf-8", errors="replace")
    for raw in data.splitlines():
        if raw.strip():
            match = CUSTOM_ID.match(str(json.loads(raw).get("custom_id") or ""))
            if match and conn.execute("SELECT 1 FROM audit_tasks WHERE id = ?", (int(match.group(1)),)).fetchone():
                return True
    return False


def recover(conn: sqlite3.Connection, log=_log) -> dict:
    """Find batches this database lost track of, by listing the batches on the Anthropic account.

    - A batch sent without a recorded id (the app stopped or the reply was lost) is matched to its
      saved row by request count and creation time.
    - Any other ended batch whose results carry this database's task labels is adopted.
    Their results are then imported. Batches from other tools are left alone."""
    key = api_key()
    known = {b["anthropic_id"] for b in store.list_batches(conn) if b["anthropic_id"]}
    waiting_rows = [b for b in store.list_batches(conn, ("submitting",)) if not b["anthropic_id"]]
    summary = {"matched": 0, "adopted": 0, "unrecognized_in_progress": 0}
    for info in _list_remote(key):
        if info.get("id") in known:
            continue
        counts = info.get("request_counts") or {}
        total = sum(int(v or 0) for v in counts.values())
        created = _parse_time(info.get("created_at"))
        match = next(
            (row for row in waiting_rows
             if row["request_count"] == total and created and _parse_time(row["created_at"])
             and timedelta(minutes=-1) <= created - _parse_time(row["created_at"]) <= SUBMIT_MATCH_WINDOW),
            None,
        )
        if match is not None:
            waiting_rows.remove(match)
            store.update_batch(conn, match["id"], anthropic_id=info["id"], status=info.get("processing_status", "in_progress"),
                               error=None)
            log(f"Recovered batch #{match['id']}: it was sent as {info['id']}")
            summary["matched"] += 1
            known.add(info["id"])
            _apply_status(conn, store.get_batch(conn, match["id"]), info, key, log)
            continue
        if info.get("processing_status") != "ended":
            summary["unrecognized_in_progress"] += 1
            continue
        if not info.get("results_url") or not _results_are_ours(conn, info["results_url"], key):
            continue
        batch_id = store.adopt_batch(conn, info["id"], "ended", "unknown", total, info.get("created_at") or _now())
        log(f"Adopted lost batch {info['id']} as #{batch_id}")
        summary["adopted"] += 1
        known.add(info["id"])
        import_results(conn, store.get_batch(conn, batch_id), info["results_url"], key, log)
    for row in waiting_rows:
        age = datetime.now(timezone.utc) - (_parse_time(row["created_at"]) or datetime.now(timezone.utc))
        if age > timedelta(hours=1):
            store.update_batch(conn, row["id"], status="failed",
                               error="Anthropic has no matching batch; it was probably never received.")
            with conn:
                conn.execute("UPDATE claude_batch_items SET status = 'failed' WHERE batch_id = ? AND status = 'waiting'",
                             (row["id"],))
    return summary


def cancel(conn: sqlite3.Connection, batch_id: int, log=_log) -> None:
    batch = store.get_batch(conn, batch_id)
    if batch["status"] not in ("in_progress",) or not batch["anthropic_id"]:
        raise BatchError(f"Batch #{batch_id} is {batch['status']}; only a batch in progress can be cancelled.")
    info = json.loads(api_runner.http_request("POST", f"{BATCHES_URL}/{batch['anthropic_id']}/cancel", api_key(), {}))
    store.update_batch(conn, batch_id, status=info.get("processing_status", "canceling"))
    log(f"Batch #{batch_id} is being cancelled; finished requests will still be imported")


def batch_rows(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in store.list_batches(conn)[:50]]


class Poller:
    """Checks open batches every minute while the review page runs, so results appear on their own."""

    def __init__(self, db_path: Path, log=_log, interval: float = POLL_SECONDS):
        self.db_path = db_path
        self.log = log
        self.interval = interval
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.last_error: str | None = None
        self.last_checked: str | None = None

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def check_now(self) -> dict:
        with self._lock:
            conn = store.connect(self.db_path)
            try:
                result = check(conn, self.log)
                self.last_error = None
                return result
            except Exception as exc:
                self.last_error = str(exc)
                raise
            finally:
                self.last_checked = _now()
                conn.close()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            conn = store.connect(self.db_path)
            try:
                has_open = bool(store.list_batches(conn, store.OPEN_BATCH_STATUSES))
            finally:
                conn.close()
            if not has_open or not credentials.get_api_key():
                continue
            try:
                self.check_now()
            except Exception as exc:
                self.log(f"Checking batches failed: {exc}")
