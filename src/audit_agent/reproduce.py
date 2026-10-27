"""Reproduce a finding with a test: an independent Claude verifier writes one test in a throwaway copy.

The verifier starts from a fresh context that holds only the claim (file, line, quoted code,
explanation, bug type) and the relevant files, never the investigator's reasoning, and is told to
try to disprove it. It can read the copy, write one test file in a dedicated folder, and ask the app
to run that test with the network off. The verdict comes from the app's own final run of the test
in another fresh copy, not from Claude: the test fails with an assertion -> reproduced; it passes ->
not reproduced; it can't be tested here -> unable, with manual steps for a person.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from audit_agent import api_runner, credentials, sandbox, store
from audit_agent.investigate import InvestigationError, _repo_state

DEFAULT_MAX_TURNS = 30
DEFAULT_MAX_COST_USD = 1.50
DEFAULT_TIMEOUT_S = 1800
MAX_OUTPUT_TOKENS = 8000
MAX_CITED_LINES = 600
CACHE = {"type": "ephemeral"}
IMPORTS_REPOSITORY = re.compile(r"""(?:from\s+|require\(\s*|import\(\s*|jest\.mock\(\s*)['"]\.\.?/""")


class ReproduceError(Exception):
    pass


@dataclass
class ReproduceSettings:
    model: str | None = None
    max_turns: int = DEFAULT_MAX_TURNS
    max_cost_usd: float = DEFAULT_MAX_COST_USD
    timeout_s: int = DEFAULT_TIMEOUT_S
    test_timeout_s: int = sandbox.TEST_TIMEOUT_S


SYSTEM_PROMPT = """You are an independent verifier. Another agent claims there is a bug in this code. Find out whether \
the claim is true by writing one automated test, and try hard to disprove it first: look for validation, middleware, \
guards, or callers that make the claimed failure impossible.

You work in a throwaway copy of the repository. You can read and search its files, write one test file in the folder \
you are given, and run that test. You cannot run any other command, change any other file, or use the network. \
Outside services (payments, email, push notifications, other APIs) must be mocked in the test.

How to write the test:
- The test checks the CORRECT behavior the code should have. If the claimed bug is real, the test fails on the \
unchanged code; if the claim is wrong, it passes. Never write a test that passes because the bug exists, and never \
add an assertion that fails for a reason unrelated to the claim.
- Check every outcome with expect(...), including errors: for code that throws or rejects, use \
`await expect(promise).resolves...` or `expect(() => fn()).not.toThrow()`, so the failure is an assertion failure.
- Import the code under test from the repository and drive it the way real callers do (for a route, send an HTTP \
request to the test app). Follow the repository's existing tests and test setup.
- Write the smallest test that shows the claimed behavior. One focused test is best.
- Run it with run_test. If it fails for an unrelated reason (a typo, a missing mock, wrong setup), fix the test and \
run it again. Don't change what it checks just to make it fail.

When you are done, call finish once:
- outcome "test_written", with test_name set to the full name of the test that checks the claim (describe names and \
test name joined by spaces). The app runs that test again itself and the result is the verdict: it fails -> \
reproduced, it passes -> not reproduced.
- outcome "unable" only if the claim can't be tested here at all (it needs a real payment provider, a device, \
production data, or timing you can't control). Say why in unable_reason and give manual_steps a person could follow \
to check it."""

TOOLS = [
    *(t for t in api_runner.TOOLS if t["name"] in ("read_file", "search", "list_files")),
    {
        "name": "write_test",
        "description": "Create or overwrite your test file. Only one test file is allowed, inside the test folder named "
                       "in the task, with a name like finding-12.test.ts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the repository root"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "run_test",
        "description": "Run your test file with jest (--runInBand --forceExit) with the network off, and get each "
                       "test's result and the output.",
        "input_schema": {
            "type": "object",
            "properties": {"test_name_pattern": {"type": "string", "description": "Only run tests whose name matches"}},
        },
    },
    {
        "name": "finish",
        "description": "Finish the verification. Call this exactly once.",
        "input_schema": {
            "type": "object",
            "properties": {
                "outcome": {"type": "string", "enum": ["test_written", "unable"]},
                "test_name": {"type": "string", "description": "Full name of the test that checks the claim"},
                "conclusion": {"type": "string", "description": "What you found, in two or three sentences"},
                "unable_reason": {"type": "string"},
                "manual_steps": {"type": "string"},
            },
            "required": ["outcome", "conclusion"],
        },
    },
]


# --- Prompts --------------------------------------------------------------------------------------

def setup_prompt(repo_name: str, setup: sandbox.TestSetup) -> str:
    """The part of the prompt shared by every finding in the package (cached)."""
    parts = [
        f"Repository \"{repo_name}\"" + (f", package {setup.package_rel}" if setup.package_rel != "." else "") + ".",
        f"Tests run with jest, one file at a time (`jest <file> --runInBand --forceExit`), with the network off and a "
        f"time limit. Write your one test file in {setup.test_dir}/ (for example {setup.test_dir}/finding.test.ts); "
        "nothing else can be written.",
        "A fake .env file is in place (no real secrets). Variable names the code reads: "
        + (", ".join(setup.env_names[:120]) or "none found") + ".",
    ]
    if setup.jest_config:
        parts.append(f"Jest configuration, {setup.jest_config[0]}:\n```\n{setup.jest_config[1].strip()}\n```")
    if setup.helpers:
        parts.append("Test helper files (read them for setup, mocks, and factories):\n"
                     + "\n".join(f"  - {h}" for h in setup.helpers))
    for path, text in setup.examples:
        parts.append(f"Example of an existing test, {path}:\n```\n{text}\n```")
    return "\n\n".join(parts)


def _numbered(text: str, start: int, end: int) -> str:
    lines = text.splitlines()
    return "\n".join(f"{n:>5}  {lines[n - 1]}" for n in range(start, min(end, len(lines)) + 1))


def claim_prompt(conn: sqlite3.Connection, finding: sqlite3.Row, repo_root: Path, setup: sandbox.TestSetup) -> str:
    """The claim and its files: nothing from the investigator's run."""
    cited = repo_root / finding["file_path"]
    text = cited.read_text(errors="replace") if cited.is_file() else ""
    total = text.count("\n") + 1
    line = finding["line"] or 1
    start, end = (1, total) if total <= MAX_CITED_LINES else (max(1, line - 250), min(total, line + 250))
    related = [f["path"] for f in store.task_context(conn, finding["task_id"])["files"]
               if f["path"] != finding["file_path"] and (repo_root / f["path"]).is_file()]
    parts = [
        f"Claim to check (finding #{finding['id']}, {finding['severity'] or 'unknown'} severity, {finding['bug_type']} bug):",
        f"Title: {finding['title']}",
        f"File: {finding['file_path']}, line {line}",
        "Quoted code:\n```\n" + (finding["evidence"] or "").strip() + "\n```",
        f"Explanation: {finding['explanation']}",
    ]
    if related:
        parts.append("Other files that were examined together with it:\n" + "\n".join(f"  - {p}" for p in related[:30]))
    if text:
        shown = f"lines {start}-{end} of {total}" if (start, end) != (1, total) else f"{total} lines"
        parts.append(f"=== {finding['file_path']} ({shown}) ===\n{_numbered(text, start, end)}")
    parts.append(f"Write your test as {setup.test_dir}/finding-{finding['id']}.test.ts (or .js to match the "
                 "repository). Try to disprove the claim before you conclude it is real.")
    return "\n\n".join(parts)


def system_blocks(repo_name: str, setup: sandbox.TestSetup) -> list[dict]:
    # Two cache breakpoints: tools + instructions are the same for every finding; the test setup is the
    # same for every finding in this package.
    return [
        {"type": "text", "text": SYSTEM_PROMPT, "cache_control": CACHE},
        {"type": "text", "text": setup_prompt(repo_name, setup), "cache_control": CACHE},
    ]


def request_body(model: str, system: list[dict], messages: list[dict]) -> dict:
    """The request, with a cache breakpoint on the newest message so the next turn reads the whole
    conversation so far from the cache."""
    last = messages[-1]
    content = last["content"]
    blocks = [{"type": "text", "text": content}] if isinstance(content, str) else [dict(b) for b in content]
    blocks[-1] = {**blocks[-1], "cache_control": CACHE}
    return {"model": model, "max_tokens": MAX_OUTPUT_TOKENS, "system": system, "tools": TOOLS,
            "messages": [*messages[:-1], {**last, "content": blocks}]}


# --- Tools ----------------------------------------------------------------------------------------

class VerifierTools:
    """Read the copy, write the one test file, and run it. Nothing else."""

    def __init__(self, ws: sandbox.Workspace, toolchain: sandbox.Jest, test_timeout_s: float, log=print):
        self.ws = ws
        self.reader = api_runner.ReadOnlyTools(ws.repo, [], set())
        self.toolchain = toolchain
        self.test_timeout_s = test_timeout_s
        self.test_path: str | None = None
        self.log = log

    def write_test(self, path: str, content: str) -> str:
        rel = PurePosixPath(path.strip().removeprefix("./"))
        if rel.is_absolute() or ".." in rel.parts or rel.parent.as_posix() != self.ws.test_dir:
            raise api_runner.ToolError(f"Tests can only be written directly in {self.ws.test_dir}/.")
        if not sandbox.TEST_FILE_NAME.match(rel.name):
            raise api_runner.ToolError("Name the file like finding-12.test.ts (letters, digits, - or _, then .test.ts/.js).")
        if self.test_path and rel.as_posix() != self.test_path:
            raise api_runner.ToolError(f"You already wrote {self.test_path}; only one test file is allowed. Overwrite it instead.")
        data = content.encode()
        if len(data) > sandbox.MAX_TEST_BYTES:
            raise api_runner.ToolError(f"The test is too long ({len(data)} bytes; the limit is {sandbox.MAX_TEST_BYTES}).")
        target = self.ws.repo / rel
        if target.is_symlink() or not target.parent.resolve() == (self.ws.repo / self.ws.test_dir).resolve():
            raise api_runner.ToolError(f"Tests can only be written directly in {self.ws.test_dir}/.")
        target.write_bytes(data)
        self.test_path = rel.as_posix()
        return f"Wrote {self.test_path} ({content.count(chr(10)) + 1} lines). Run it with run_test."

    def run_test(self, test_name_pattern: str | None = None) -> str:
        if not self.test_path:
            raise api_runner.ToolError("Write your test with write_test first.")
        run = self.toolchain.run(self.ws, self.test_path, self.test_timeout_s, test_name_pattern)
        tests = sandbox._tests(run)
        self.log(f"  ran the test: {sum(t.get('status') == 'passed' for t in tests)} passed, "
                 f"{sum(t.get('status') == 'failed' for t in tests)} failed" + (" (timed out)" if run.timed_out else ""))
        return sandbox.describe(run)

    def run(self, name: str, arguments: dict) -> str:
        arguments = {k: v for k, v in arguments.items() if v is not None}
        if name == "write_test":
            return self.write_test(**arguments)
        if name == "run_test":
            return self.run_test(**arguments)
        return self.reader.run(name, arguments)


# --- The conversation -----------------------------------------------------------------------------

@dataclass
class Usage:
    turns: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0

    def add(self, usage: dict) -> None:
        self.input_tokens += int(usage.get("input_tokens") or 0)
        self.output_tokens += int(usage.get("output_tokens") or 0)
        self.cache_write_tokens += int(usage.get("cache_creation_input_tokens") or 0)
        self.cache_read_tokens += int(usage.get("cache_read_input_tokens") or 0)

    def cost(self, model: str) -> float | None:
        return api_runner.estimate_cost(model, self.input_tokens, self.output_tokens, self.cache_write_tokens,
                                        self.cache_read_tokens)

    def fields(self, model: str) -> dict:
        return {"num_turns": self.turns, "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "cache_write_tokens": self.cache_write_tokens, "cache_read_tokens": self.cache_read_tokens,
                "cost_usd": self.cost(model)}


@dataclass
class Conversation:
    finish: dict | None = None
    limit: str | None = None
    messages: list = field(default_factory=list)


def converse(system: list[dict], prompt: str, tools: VerifierTools, settings: ReproduceSettings, model: str,
             api_key: str, usage: Usage, log=print) -> Conversation:
    convo = Conversation(messages=[{"role": "user", "content": prompt}])
    started = time.monotonic()
    nudges = 0
    while True:
        if usage.turns >= settings.max_turns:
            convo.limit = f"Stopped after {settings.max_turns} turns, the limit per finding, before the verifier finished."
            return convo
        if time.monotonic() - started > settings.timeout_s:
            convo.limit = f"Stopped after {settings.timeout_s} seconds, the time limit per finding."
            return convo
        response = api_runner._send(request_body(model, system, convo.messages), api_key, timeout=300)
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
            convo.limit = f"Stopped at ${cost:.2f}, the ${settings.max_cost_usd:.2f} cost limit per finding, before the verifier finished."
            return convo
        if not tool_uses:
            nudges += 1
            if nudges > 2:
                convo.limit = "The verifier stopped without calling finish."
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


# --- Verdict --------------------------------------------------------------------------------------

def decide(convo: Conversation, tools: VerifierTools, repo_root: Path, files: list[str], setup: sandbox.TestSetup,
           template: Path, toolchain: sandbox.Jest, settings: ReproduceSettings, label: str) -> dict:
    """The verdict and what to save with it. A test's result is taken only from a final run the app does
    itself, in a new copy of the unchanged code with just the test file added."""
    finish = convo.finish or {}
    result = {"conclusion": finish.get("conclusion"), "test_path": tools.test_path,
              "test_name": finish.get("test_name"), "test_code": None}
    if tools.test_path:
        result["test_code"] = (tools.ws.repo / tools.test_path).read_text(errors="replace")
    if convo.limit:
        return {**result, "verdict": "unable", "reason": convo.limit}
    if finish.get("outcome") == "unable":
        return {**result, "verdict": "unable", "reason": finish.get("unable_reason") or "The verifier could not test it.",
                "manual_steps": finish.get("manual_steps")}
    if not tools.test_path:
        return {**result, "verdict": "unable", "reason": "The verifier finished without writing a test."}
    if not IMPORTS_REPOSITORY.search(result["test_code"]):
        return {**result, "verdict": "unable",
                "reason": "The test imports no code from the repository, so it can't show a bug in it."}
    final = sandbox.new_workspace(repo_root, files, setup, template, f"{label}-final")
    try:
        (final.repo / tools.test_path).write_text(result["test_code"])
        run = toolchain.run(final, tools.test_path, settings.test_timeout_s)
        changed = sandbox.changed_files(final)
    finally:
        sandbox.remove(final)
    result["test_output"] = sandbox.describe(run)
    if changed:
        return {**result, "verdict": "unable",
                "reason": "The test changed files of the code it tests, so its result can't be trusted: " + ", ".join(changed[:5])}
    outcome, detail = sandbox.classify(run, finish.get("test_name"))
    if outcome == "failed_assertion":
        return {**result, "verdict": "reproduced", "reason": detail}
    if outcome == "passed":
        return {**result, "verdict": "not_reproduced", "reason": detail}
    return {**result, "verdict": "unable", "reason": detail}


# --- Entry points ---------------------------------------------------------------------------------

@dataclass
class Target:
    finding: sqlite3.Row
    repo_name: str
    repo_root: Path
    files: list[str]


def target(conn: sqlite3.Connection, finding_id: int) -> Target:
    try:
        finding = store.get_finding(conn, finding_id)
    except store.StoreError as exc:
        raise ReproduceError(str(exc)) from exc
    if finding["kind"] != "finding":
        raise ReproduceError(f"#{finding_id} is a needs-review item, not a finding; only findings are reproduced.")
    if not finding["file_path"]:
        raise ReproduceError(f"Finding #{finding_id} cites no file.")
    audit = store.get_audit(conn, finding["file_audit_id"] or finding["audit_id"])
    root = Path(audit["repo_path"])
    if not root.is_dir():
        raise ReproduceError(f"The repository {root} no longer exists.")
    return Target(finding, audit["repo_name"], root, sandbox.copyable_files(root))


def show_prompt(conn: sqlite3.Connection, finding_id: int) -> str:
    t = target(conn, finding_id)
    package = sandbox.find_package(t.repo_root, t.files, t.finding["file_path"])
    setup = sandbox.test_setup(t.repo_root, t.files, package)
    blocks = system_blocks(t.repo_name, setup)
    return "\n\n".join([*(b["text"] for b in blocks), "--- message ---", claim_prompt(conn, t.finding, t.repo_root, setup)])


def reproduce(conn: sqlite3.Connection, finding_id: int, settings: ReproduceSettings | None = None, log=print,
              toolchain: sandbox.Jest | None = None) -> dict:
    """Try to reproduce one finding. Sends the claim to Claude, so it runs only when the engineer starts it."""
    settings = settings or ReproduceSettings()
    toolchain = toolchain or sandbox.Jest()
    model = settings.model or api_runner.DEFAULT_MODEL
    t = target(conn, finding_id)
    api_key = credentials.get_api_key()
    if not api_key:
        raise ReproduceError("No Anthropic API key found. Save one with `audit-agent set-api-key`.")
    try:
        verification_id = store.start_verification(conn, finding_id, model)
    except store.StoreError as exc:
        raise ReproduceError(str(exc)) from exc
    label = f"v{verification_id}"
    usage, convo, ws = Usage(), None, None
    started = time.monotonic()
    before = _repo_state(t.repo_root)

    def saved(status: str, **fields) -> dict:
        transcript = json.dumps(convo.messages)[-200_000:] if convo else None
        store.finish_verification(conn, verification_id, status, transcript=transcript,
                                  duration_ms=int((time.monotonic() - started) * 1000), **usage.fields(model), **fields)
        return dict(store.get_verification(conn, verification_id))

    try:
        try:
            package = sandbox.find_package(t.repo_root, t.files, t.finding["file_path"])
            setup = sandbox.test_setup(t.repo_root, t.files, package)
            template = sandbox.prepare(t.repo_root, t.files, package, toolchain, log)
            ws = sandbox.new_workspace(t.repo_root, t.files, setup, template, label)
            tools = VerifierTools(ws, toolchain, settings.test_timeout_s, log)
            log(f"Verifying finding #{finding_id} with {model} ...")
            convo = converse(system_blocks(t.repo_name, setup), claim_prompt(conn, t.finding, t.repo_root, setup),
                             tools, settings, model, api_key, usage, log)
            result = decide(convo, tools, t.repo_root, t.files, setup, template, toolchain, settings, label)
        except sandbox.SandboxError as exc:
            result = {"verdict": "unable", "reason": str(exc)}
        if _repo_state(t.repo_root) != before:
            kept = {k: v for k, v in result.items() if k not in ("verdict", "reason")}
            return saved("failed", error="The repository changed while the finding was being reproduced, so the "
                                         "result was discarded.", **kept)
        return saved("done", **result)
    except InvestigationError as exc:
        saved("failed", error=str(exc))
        raise ReproduceError(str(exc)) from exc
    except Exception as exc:
        saved("failed", error=f"{exc.__class__.__name__}: {exc}")
        raise
    finally:
        sandbox.remove(ws)


def check_setup(conn: sqlite3.Connection, audit_id: int, log=print, toolchain: sandbox.Jest | None = None) -> dict:
    """Prepare an audit's test copy and run one existing test in it with the network off. Uses no Claude."""
    toolchain = toolchain or sandbox.Jest()
    audit = store.get_audit(conn, audit_id)
    root = Path(audit["repo_path"])
    files = sandbox.copyable_files(root)
    manifests = sorted((f for f in files if PurePosixPath(f).name == "package.json"), key=lambda f: (f.count("/"), f))
    package = None
    for manifest in manifests:
        try:
            package = sandbox.find_package(root, files, manifest)
            break
        except sandbox.SandboxError:
            continue
    if package is None:
        raise sandbox.SandboxError(f"{audit['repo_name']} has no package that tests with jest.")
    setup = sandbox.test_setup(root, files, package)
    if not setup.examples:
        raise sandbox.SandboxError(f"{audit['repo_name']} has no existing jest tests to try.")
    before = _repo_state(root)
    template = sandbox.prepare(root, files, package, toolchain, log)
    ws = sandbox.new_workspace(root, files, setup, template, "setup-check")
    try:
        example = setup.examples[0][0]
        log(f"Running {example} in a fresh copy with the network off ...")
        run = toolchain.run(ws, example, sandbox.TEST_TIMEOUT_S)
        network_blocked = _network_blocked(ws)
        changed = sandbox.changed_files(ws)
    finally:
        sandbox.remove(ws)
    tests = sandbox._tests(run)
    return {
        "repo": audit["repo_name"], "package": package, "test_dir": setup.test_dir, "example": example,
        "passed": sum(t.get("status") == "passed" for t in tests), "failed": sum(t.get("status") == "failed" for t in tests),
        "duration_ms": run.duration_ms, "network_blocked": network_blocked, "repository_unchanged": _repo_state(root) == before,
        "copy_unchanged": not changed, "env_names": setup.env_names, "output": sandbox.describe(run),
    }


def _network_blocked(ws: sandbox.Workspace) -> bool:
    probe = ("require('net').connect({host: '1.1.1.1', port: 443, timeout: 3000})"
             ".on('connect', () => { console.log('CONNECTED'); process.exit(0); })"
             ".on('error', (e) => { console.log('BLOCKED ' + e.code); process.exit(0); })"
             ".on('timeout', () => { console.log('TIMEOUT'); process.exit(0); })")
    result = sandbox.run_sandboxed(["node", "-e", probe], ws.package, sandbox.base_env(ws.root / "home", ws.root / "tmp"),
                                   [ws.root], network=False, timeout=15)
    return "BLOCKED" in result.output
