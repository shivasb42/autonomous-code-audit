"""Reproduce + fix: one agent proves a finding with a test and then fixes it, in a throwaway copy.

This is the cheaper option, chosen per finding, next to the independent verifier (see reproduce,
which is unchanged). The agent first writes a test. The app runs it itself on the unchanged code in
a fresh copy (confirm_bug); only if it fails an assertion there may the agent edit source files,
and from then on the test is frozen. When the agent finishes, the app checks the fix in another
fresh copy: the test must pass, and the existing tests that cover the changed files must not newly
fail. Nothing is written to the repository; a draft pull request is opened only when the engineer
asks for it (see pull_requests).
"""

from __future__ import annotations

import difflib
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import PurePosixPath

from audit_agent import api_runner, credentials, reproduce, sandbox, store
from audit_agent.investigate import InvestigationError, _repo_state
from audit_agent.repo import open_repository

DEFAULT_MAX_TURNS = 45
DEFAULT_MAX_COST_USD = 2.50
DEFAULT_TIMEOUT_S = 2700
RELATED_TIMEOUT_S = 1200
MAX_CONFIRMS = 3
MAX_FILES_CHANGED = 8
MAX_CHANGED_LINES = 300
MAX_SAVED_OUTPUT = 30_000
PROTECTED_NAMES = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", *sandbox.JEST_CONFIGS}


class FixError(Exception):
    pass


@dataclass
class FixSettings:
    model: str | None = None
    max_turns: int = DEFAULT_MAX_TURNS
    max_cost_usd: float = DEFAULT_MAX_COST_USD
    timeout_s: int = DEFAULT_TIMEOUT_S
    test_timeout_s: int = sandbox.TEST_TIMEOUT_S
    related_timeout_s: int = RELATED_TIMEOUT_S


SYSTEM_PROMPT = """You check one claimed bug and, only if it is real, fix it. Another agent made the claim; try to \
disprove it first: look for validation, middleware, guards, or callers that make the claimed failure impossible.

You work in a throwaway copy of the repository. You can read and search its files, write one test file in the folder \
you are given, run it, and later edit source files. You cannot run any other command or use the network. Outside \
services (payments, email, push notifications, other APIs) must be mocked in the test.

Step 1, prove it. Write one test that checks the CORRECT behavior the code should have, so it fails on the unchanged \
code only if the claimed bug is real. Check every outcome with expect(...), including errors (for code that throws, \
use `await expect(promise).resolves...` or `expect(() => fn()).not.toThrow()`). Import the code under test from the \
repository and drive it the way real callers do, following the existing tests and test setup. Keep it to the \
smallest test that shows the claimed behavior. Run it with run_test; fix the test if it fails for an unrelated \
reason. When it fails because of the bug, call confirm_bug with the test's full name (describe names and test name \
joined by spaces). The app then runs the test itself on the unchanged code. If it passes there, the claim is not \
reproduced and you are done.

Step 2, fix it. After confirm_bug succeeds, edit_file is enabled and the test is frozen. Make the smallest change to \
the application code that fixes the bug, in the code's own style. Don't refactor, rename, reformat, add \
dependencies, or change tests, test setup, configuration, or package files. Run run_test until your test passes, \
and run_related_tests to check that the existing tests covering your change still pass.

When you are done, call finish once: outcome "fixed" with a short summary of the change for the pull request, or \
"unable" if the claim can't be tested here at all (it needs a real payment provider, a device, production data, or \
timing you can't control), with unable_reason and manual_steps a person could follow."""

_SHARED = {t["name"]: t for t in reproduce.TOOLS}
TOOLS = [
    _SHARED["read_file"], _SHARED["search"], _SHARED["list_files"], _SHARED["write_test"], _SHARED["run_test"],
    {
        "name": "confirm_bug",
        "description": "Ask the app to run your test on the unchanged code in a fresh copy. If the named test fails an "
                       "assertion there, the bug is confirmed and editing is enabled; if it passes, the claim is not "
                       "reproduced.",
        "input_schema": {"type": "object", "properties": {"test_name": {"type": "string"}}, "required": ["test_name"]},
    },
    {
        "name": "edit_file",
        "description": "Replace one exact, unique piece of text in a source file of the repository (only after "
                       "confirm_bug succeeded). Tests, test setup, configuration, and package files can't be edited.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the repository root"},
                "old_string": {"type": "string", "description": "Text to replace, copied exactly; must appear once"},
                "new_string": {"type": "string"},
            },
            "required": ["path", "old_string", "new_string"],
        },
    },
    {
        "name": "run_related_tests",
        "description": "Run the repository's existing tests that depend on the files you changed (can take minutes).",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "finish",
        "description": "Finish. Call this exactly once.",
        "input_schema": {
            "type": "object",
            "properties": {
                "outcome": {"type": "string", "enum": ["fixed", "unable"]},
                "summary": {"type": "string", "description": "What the fix changes and why, for the pull request"},
                "unable_reason": {"type": "string"},
                "manual_steps": {"type": "string"},
            },
            "required": ["outcome"],
        },
    },
]


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class FixTools(reproduce.VerifierTools):
    """The verifier's tools (read, write the one test, run it) plus confirm_bug, then editing once the bug is confirmed."""

    def __init__(self, ws: sandbox.Workspace, toolchain: sandbox.Jest, settings: FixSettings, confirm, log=print):
        super().__init__(ws, toolchain, settings.test_timeout_s, log)
        self.settings = settings
        self.confirm = confirm
        self.phase = "test"
        self.confirms = 0
        self.test_name: str | None = None
        self.test_code: str | None = None
        self.before_run: sandbox.TestRun | None = None
        self.not_reproduced: str | None = None
        self.originals: dict[str, str] = {}

    def write_test(self, path: str, content: str) -> str:
        if self.phase != "test":
            raise api_runner.ToolError("The test is frozen now that the bug is confirmed. Fix the application code instead.")
        return super().write_test(path, content)

    def confirm_bug(self, test_name: str) -> str:
        if self.phase != "test" or self.not_reproduced:
            raise api_runner.ToolError("confirm_bug already ran.")
        if not self.test_path:
            raise api_runner.ToolError("Write your test with write_test and run it first.")
        if self.confirms >= MAX_CONFIRMS:
            raise api_runner.ToolError(f"confirm_bug was already tried {MAX_CONFIRMS} times. Call finish.")
        self.confirms += 1
        code = (self.ws.repo / self.test_path).read_text(errors="replace")
        if not reproduce.IMPORTS_REPOSITORY.search(code):
            raise api_runner.ToolError("The test imports no code from the repository, so it can't show a bug in it.")
        outcome, detail, run = self.confirm(self.test_path, code, test_name)
        self.log(f"  the app's run on the unchanged code: {outcome.replace('_', ' ')}")
        if outcome == "failed_assertion":
            self.phase, self.test_name, self.test_code, self.before_run = "fix", test_name, code, run
            return (f"Confirmed. {detail}\n\nThe bug is real. The test is frozen now, and edit_file and run_related_tests "
                    "are enabled. Fix the application code.")
        if outcome == "passed":
            self.not_reproduced, self.test_name, self.test_code, self.before_run = detail, test_name, code, run
            return "Not reproduced: the test passed on the unchanged code. There is nothing to fix. Call finish now."
        return (f"Not confirmed ({outcome.replace('_', ' ')}). {detail}\n\nChange the test so it fails an expect because "
                "of the claimed bug, or call finish with outcome unable.")

    def edit_file(self, path: str, old_string: str, new_string: str) -> str:
        if self.phase != "fix":
            raise api_runner.ToolError("Prove the bug first: edit_file is enabled only after confirm_bug succeeds.")
        rel = PurePosixPath(path.strip().removeprefix("./"))
        name = rel.as_posix()
        if name not in self.ws.hashes:
            raise api_runner.ToolError(f"{name} is not a file of the repository. Only existing source files can be edited.")
        if rel.is_relative_to(PurePosixPath(self.ws.test_dir).parent) or sandbox.EXISTING_TEST.search(name):
            raise api_runner.ToolError("Tests and test setup can't be changed.")
        if rel.name in PROTECTED_NAMES or rel.name.startswith("tsconfig") or rel.parts[0] == ".github":
            raise api_runner.ToolError("Package, lock, and configuration files can't be changed.")
        if not name.endswith(sandbox.SOURCE_SUFFIXES):
            raise api_runner.ToolError("Only source code files can be edited.")
        if name not in self.originals and len(self.originals) >= MAX_FILES_CHANGED:
            raise api_runner.ToolError(f"A fix may change at most {MAX_FILES_CHANGED} files.")
        target = self.ws.repo / name
        text = target.read_text(errors="replace")
        count = text.count(old_string) if old_string else 0
        if count == 0:
            raise api_runner.ToolError("old_string was not found in the file. Read the file again and copy the text exactly.")
        if count > 1:
            raise api_runner.ToolError(f"old_string appears {count} times. Include more surrounding lines so it is unique.")
        self.originals.setdefault(name, text)
        target.write_text(text.replace(old_string, new_string, 1))
        return f"Edited {name}. Run run_test to check your test now passes."

    def changed(self) -> dict[str, str]:
        current = {rel: (self.ws.repo / rel).read_text(errors="replace") for rel in self.originals}
        return {rel: text for rel, text in current.items() if text != self.originals[rel]}

    def run_related_tests(self) -> str:
        changed = self.changed()
        if self.phase != "fix" or not changed:
            raise api_runner.ToolError("Edit the code first.")
        run = self.toolchain.run_related(self.ws, sorted(changed), self.settings.related_timeout_s)
        self.log(f"  ran the related existing tests: {len(sandbox.failures(run, self.ws.package))} failing")
        return sandbox.describe(run)

    def run(self, name: str, arguments: dict) -> str:
        arguments = {k: v for k, v in arguments.items() if v is not None}
        if name == "confirm_bug":
            return self.confirm_bug(**arguments)
        if name == "edit_file":
            return self.edit_file(**arguments)
        if name == "run_related_tests":
            return self.run_related_tests()
        return super().run(name, arguments)


def system_blocks(repo_name: str, setup: sandbox.TestSetup) -> list[dict]:
    return [
        {"type": "text", "text": SYSTEM_PROMPT, "cache_control": reproduce.CACHE},
        {"type": "text", "text": reproduce.setup_prompt(repo_name, setup), "cache_control": reproduce.CACHE},
    ]


def converse(system: list[dict], prompt: str, tools: FixTools, settings: FixSettings, model: str, api_key: str,
             usage: reproduce.Usage) -> reproduce.Conversation:
    convo = reproduce.Conversation(messages=[{"role": "user", "content": prompt}])
    started = time.monotonic()
    nudges = 0
    while True:
        if tools.not_reproduced:
            return convo
        if usage.turns >= settings.max_turns:
            convo.limit = f"Stopped after {settings.max_turns} turns, the limit per finding."
            return convo
        if time.monotonic() - started > settings.timeout_s:
            convo.limit = f"Stopped after {settings.timeout_s} seconds, the time limit per finding."
            return convo
        body = {**reproduce.request_body(model, system, convo.messages), "tools": TOOLS}
        response = api_runner._send(body, api_key, timeout=300)
        usage.turns += 1
        usage.add(response.get("usage") or {})
        content = response.get("content") or []
        convo.messages.append({"role": "assistant", "content": content})
        tool_uses = [b for b in content if b.get("type") == "tool_use"]
        finish = next((b.get("input") for b in tool_uses if b.get("name") == "finish"), None)
        if isinstance(finish, dict):
            convo.finish = finish
            return convo
        cost = usage.cost(model)
        if cost is not None and cost >= settings.max_cost_usd:
            convo.limit = f"Stopped at ${cost:.2f}, the ${settings.max_cost_usd:.2f} cost limit per finding."
            return convo
        if not tool_uses:
            nudges += 1
            if nudges > 2:
                convo.limit = "The agent stopped without calling finish."
                return convo
            convo.messages.append({"role": "user", "content": "Call the finish tool now with your result."})
            continue
        results = []
        for block in tool_uses:
            try:
                output, is_error = tools.run(block.get("name", ""), block.get("input") or {}), False
            except (api_runner.ToolError, TypeError, ValueError, OSError) as exc:
                output, is_error = str(exc), True
            if len(output) > api_runner.MAX_TOOL_OUTPUT:
                output = output[:api_runner.MAX_TOOL_OUTPUT] + "\n[output truncated]"
            results.append({"type": "tool_result", "tool_use_id": block.get("id"), "content": output, "is_error": is_error})
        convo.messages.append({"role": "user", "content": results})


def make_patch(originals: dict[str, str], changed: dict[str, str]) -> str:
    return "".join(
        "".join(difflib.unified_diff(originals[rel].splitlines(keepends=True), text.splitlines(keepends=True),
                                     fromfile=f"a/{rel}", tofile=f"b/{rel}"))
        for rel, text in sorted(changed.items())
    )


def decide(convo: reproduce.Conversation, tools: FixTools, t: reproduce.Target, setup: sandbox.TestSetup, template,
           toolchain: sandbox.Jest, settings: FixSettings, label: str) -> dict:
    """The outcome and what to save. The fix is judged only by runs the app does itself in fresh copies."""
    finish = convo.finish or {}
    result = {"summary": finish.get("summary"), "test_path": tools.test_path, "test_name": tools.test_name,
              "test_code": tools.test_code}
    if tools.test_path and not tools.test_code:
        result["test_code"] = (tools.ws.repo / tools.test_path).read_text(errors="replace")
    if tools.before_run:
        result["before_output"] = sandbox.describe(tools.before_run)
    if tools.not_reproduced:
        return {**result, "outcome": "not_reproduced", "reason": tools.not_reproduced}
    confirmed = tools.phase == "fix"
    if convo.limit:
        if confirmed:
            return {**result, "outcome": "fix_rejected", "reason": f"The bug was reproduced, but no fix was finished. {convo.limit}"}
        return {**result, "outcome": "unable", "reason": convo.limit}
    if finish.get("outcome") == "unable":
        reason = finish.get("unable_reason") or "The agent could not test it."
        if confirmed:
            return {**result, "outcome": "fix_rejected", "reason": f"The bug was reproduced, but the agent didn't fix it: {reason}"}
        return {**result, "outcome": "unable", "reason": reason, "manual_steps": finish.get("manual_steps")}
    if not confirmed:
        return {**result, "outcome": "unable", "reason": "The agent finished without confirming the bug with confirm_bug."}
    changed = tools.changed()
    if not changed:
        return {**result, "outcome": "fix_rejected", "reason": "The bug was reproduced, but no code was changed."}
    patch = make_patch(tools.originals, changed)
    result["patch"] = patch
    result["files"] = json.dumps({rel: {"before_sha": _sha(tools.originals[rel]), "after": text}
                                  for rel, text in changed.items()})
    size = sum(1 for line in patch.splitlines() if line[:1] in "+-" and not line.startswith(("+++", "---")))
    if size > MAX_CHANGED_LINES:
        return {**result, "outcome": "fix_rejected", "reason": f"The fix changes {size} lines; the limit is {MAX_CHANGED_LINES}."}

    after = sandbox.new_workspace(t.repo_root, t.files, setup, template, f"{label}-after")
    try:
        for rel, text in changed.items():
            (after.repo / rel).write_text(text)
        (after.repo / tools.test_path).write_text(result["test_code"])
        run = toolchain.run(after, tools.test_path, settings.test_timeout_s)
        tampered = [rel for rel in sandbox.changed_files(after) if rel not in changed]
        tampered += [rel for rel, text in changed.items() if (after.repo / rel).read_text(errors="replace") != text]
        outcome, detail = sandbox.classify(run, tools.test_name)
        result["after_output"] = sandbox.describe(run)
        if tampered:
            return {**result, "outcome": "fix_rejected",
                    "reason": "The test changed files while it ran, so the result can't be trusted: " + ", ".join(tampered[:5])}
        if outcome != "passed":
            return {**result, "outcome": "fix_rejected", "reason": f"The test still doesn't pass with the fix. {detail}"}
        related = toolchain.run_related(after, sorted(changed), settings.related_timeout_s)
        after_failures = sandbox.failures(related, after.package)
    finally:
        sandbox.remove(after)
    related_text = sandbox.describe(related)
    if related.timed_out or related.report is None:
        result["related_output"] = related_text[:MAX_SAVED_OUTPUT]
        return {**result, "outcome": "fix_rejected",
                "reason": "The existing tests covering the changed files could not be run, so the fix isn't checked."}
    new_failures = after_failures
    if after_failures:
        base = sandbox.new_workspace(t.repo_root, t.files, setup, template, f"{label}-base")
        try:
            before_failures = sandbox.failures(toolchain.run_related(base, sorted(changed), settings.related_timeout_s),
                                               base.package)
        finally:
            sandbox.remove(base)
        new_failures = after_failures - before_failures
        related_text += f"\n\n{len(after_failures & before_failures)} of these also fail on the unchanged code."
    result["related_output"] = related_text[:MAX_SAVED_OUTPUT]
    if new_failures:
        return {**result, "outcome": "fix_rejected",
                "reason": "The fix breaks existing tests that passed before: " + "; ".join(sorted(new_failures)[:5])}
    total = int((related.report or {}).get("numTotalTests") or 0)
    covered = (f"the {total} existing test(s) covering the changed files don't newly fail" if total
               else "no existing tests cover the changed files")
    return {**result, "outcome": "fixed",
            "reason": f"The test failed on the unchanged code and passes with the fix, and {covered}."}


def show_prompt(conn, finding_id: int) -> str:
    t = reproduce.target(conn, finding_id)
    package = sandbox.find_package(t.repo_root, t.files, t.finding["file_path"])
    setup = sandbox.test_setup(t.repo_root, t.files, package)
    return "\n\n".join([*(b["text"] for b in system_blocks(t.repo_name, setup)), "--- message ---",
                        reproduce.claim_prompt(conn, t.finding, t.repo_root, setup)])


def fix(conn, finding_id: int, settings: FixSettings | None = None, log=print, toolchain: sandbox.Jest | None = None) -> dict:
    """Reproduce one finding and, if the bug is real, fix it in a throwaway copy. Sends the claim to Claude, so it runs
    only when the engineer starts it. Never writes to the repository."""
    settings = settings or FixSettings()
    toolchain = toolchain or sandbox.Jest()
    model = settings.model or api_runner.DEFAULT_MODEL
    try:
        t = reproduce.target(conn, finding_id)
    except reproduce.ReproduceError as exc:
        raise FixError(str(exc)) from exc
    api_key = credentials.get_api_key()
    if not api_key:
        raise FixError("No Anthropic API key found. Save one with `audit-agent set-api-key`.")
    repo = open_repository(t.repo_root)
    try:
        attempt_id = store.start_fix(conn, finding_id, model, repo.head_commit, repo.branch)
    except store.StoreError as exc:
        raise FixError(str(exc)) from exc
    label = f"f{attempt_id}"
    usage, convo, ws = reproduce.Usage(), None, None
    started = time.monotonic()
    before = _repo_state(t.repo_root)

    def saved(status: str, **fields) -> dict:
        transcript = json.dumps(convo.messages)[-200_000:] if convo else None
        store.finish_fix(conn, attempt_id, status, transcript=transcript,
                         duration_ms=int((time.monotonic() - started) * 1000), **usage.fields(model), **fields)
        return dict(store.get_fix(conn, attempt_id))

    try:
        try:
            package = sandbox.find_package(t.repo_root, t.files, t.finding["file_path"])
            setup = sandbox.test_setup(t.repo_root, t.files, package)
            template = sandbox.prepare(t.repo_root, t.files, package, toolchain, log)
            ws = sandbox.new_workspace(t.repo_root, t.files, setup, template, label)

            def confirm(test_path: str, code: str, test_name: str):
                fresh = sandbox.new_workspace(t.repo_root, t.files, setup, template, f"{label}-before")
                try:
                    (fresh.repo / test_path).write_text(code)
                    run = toolchain.run(fresh, test_path, settings.test_timeout_s)
                    changed = sandbox.changed_files(fresh)
                finally:
                    sandbox.remove(fresh)
                if changed:
                    return "tampered", "The test changed files of the code it tests: " + ", ".join(changed[:5]), run
                return (*sandbox.classify(run, test_name), run)

            tools = FixTools(ws, toolchain, settings, confirm, log)
            log(f"Reproducing and fixing finding #{finding_id} with {model} ...")
            prompt = reproduce.claim_prompt(conn, t.finding, t.repo_root, setup) + \
                "\n\nIf confirm_bug confirms the bug, fix it with the smallest change to the application code."
            convo = converse(system_blocks(t.repo_name, setup), prompt, tools, settings, model, api_key, usage)
            result = decide(convo, tools, t, setup, template, toolchain, settings, label)
        except sandbox.SandboxError as exc:
            result = {"outcome": "unable", "reason": str(exc)}
        if _repo_state(t.repo_root) != before:
            kept = {k: v for k, v in result.items() if k not in ("outcome", "reason")}
            return saved("failed", error="The repository changed while the finding was being fixed, so the result "
                                         "was discarded.", **kept)
        return saved("done", **result)
    except InvestigationError as exc:
        saved("failed", error=str(exc))
        raise FixError(str(exc)) from exc
    except Exception as exc:
        saved("failed", error=f"{exc.__class__.__name__}: {exc}")
        raise
    finally:
        sandbox.remove(ws)
