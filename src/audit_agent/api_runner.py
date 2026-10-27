"""Run the investigation agent directly against the Anthropic Messages API.

Claude gets three read-only tools that this module implements itself (read a file, search,
list a folder) plus `submit_report` for the final answer. Every path is checked here: it must
be inside one of the allowed repositories and must not be a secret file. Nothing can be
written or executed, because no such tool exists.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

from audit_agent.investigate import RESULT_SCHEMA, AgentResult, AgentSettings, InvestigationError
from audit_agent.inventory.languages import (
    GENERATED_DIRS,
    GENERATED_DIRS_EXTRA,
    is_secret_file,
)

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_OUTPUT_TOKENS = 16000
# USD per million tokens (input, output); used for the run's cost estimate and --max-budget-usd.
PRICES = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-opus-5-5": (4.0, 20.0),
    "claude-fable-5-1": (10.0, 50.0),
}
RETRY_STATUSES = (429, 500, 502, 503, 504, 529)
MAX_READ_LINES = 400
MAX_TOOL_OUTPUT = 60_000
MAX_SEARCH_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", *GENERATED_DIRS, *GENERATED_DIRS_EXTRA}

SYSTEM_PROMPT = """You are a careful code auditor. You can only read code through the tools you are given; you cannot run, \
edit, or create anything. Paths are relative to the main repository unless you use an absolute path inside one of \
the other repositories listed in the task. Investigate until you are confident, then call submit_report exactly once \
with your result. Never report a problem you cannot point to in the code."""

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file with line numbers. Reads at most 400 lines per call; use start_line to page.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "minimum": 1},
                "end_line": {"type": "integer", "minimum": 1},
            },
            "required": ["path"],
        },
    },
    {
        "name": "search",
        "description": "Search file contents with a regular expression. Returns matching lines as path:line: text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "path": {"type": "string", "description": "Folder or file to search in (default: the repository root)"},
                "glob": {"type": "string", "description": "Only search files whose name matches, e.g. *.ts"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "list_files",
        "description": "List the files and folders directly inside a folder.",
        "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
    {
        "name": "submit_report",
        "description": "Submit the final audit result. Call this exactly once, when you are done.",
        "input_schema": RESULT_SCHEMA,
    },
]


class ToolError(Exception):
    pass


class ReadOnlyTools:
    """File access limited to the given repositories, with secret files refused."""

    def __init__(self, main_root: Path, other_roots: list[Path], denied: set[Path]):
        self.main = main_root.resolve()
        self.roots = [self.main, *(r.resolve() for r in other_roots)]
        self.denied = {p.resolve() for p in denied}

    def _display(self, path: Path) -> str:
        return path.relative_to(self.main).as_posix() if path.is_relative_to(self.main) else str(path)

    def resolve(self, raw: str | None) -> Path:
        raw = (raw or ".").strip()
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = self.main / raw.removeprefix("./")
        resolved = candidate.resolve()
        if not any(resolved == root or resolved.is_relative_to(root) for root in self.roots):
            raise ToolError(f"{raw} is outside the repositories you can read.")
        if resolved in self.denied or is_secret_file(resolved.name):
            raise ToolError(f"{raw} may contain secrets and can't be read.")
        if any(part == ".git" for part in resolved.parts):
            raise ToolError("The .git folder can't be read.")
        return resolved

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        target = self.resolve(path)
        if not target.is_file():
            raise ToolError(f"{path} is not a file.")
        data = target.read_bytes()
        if b"\0" in data[:8192]:
            raise ToolError(f"{path} is a binary file.")
        lines = data.decode("utf-8", errors="replace").splitlines()
        start = max(1, int(start_line or 1))
        end = min(len(lines), int(end_line or start + MAX_READ_LINES - 1), start + MAX_READ_LINES - 1)
        body = "\n".join(f"{n:>5}  {lines[n - 1]}" for n in range(start, end + 1))
        more = f"\n[showing lines {start}-{end} of {len(lines)}]" if end < len(lines) or start > 1 else ""
        return (body or "[empty file]") + more

    def _files(self, base: Path, glob: str | None):
        if base.is_file():
            yield base
            return
        for current, dirs, files in os.walk(base):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".git"))
            for name in sorted(files):
                path = Path(current) / name
                if glob and not path.match(glob):
                    continue
                if is_secret_file(name) or path.resolve() in self.denied:
                    continue
                yield path

    def search(self, pattern: str, path: str | None = None, glob: str | None = None, max_results: int = 100) -> str:
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            raise ToolError(f"Invalid regular expression: {exc}") from exc
        base = self.resolve(path)
        limit = max(1, min(int(max_results or 100), 200))
        hits: list[str] = []
        for file in self._files(base, glob):
            try:
                if file.stat().st_size > MAX_SEARCH_FILE_BYTES:
                    continue
                data = file.read_bytes()
            except OSError:
                continue
            if b"\0" in data[:8192]:
                continue
            for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                if regex.search(line):
                    hits.append(f"{self._display(file)}:{number}: {line.strip()[:240]}")
                    if len(hits) >= limit:
                        return "\n".join(hits) + f"\n[stopped at {limit} results]"
        return "\n".join(hits) or "No matches."

    def list_files(self, path: str | None = None) -> str:
        target = self.resolve(path)
        if not target.is_dir():
            raise ToolError(f"{path} is not a folder.")
        entries = []
        for child in sorted(target.iterdir()):
            if child.name in SKIP_DIRS or child.name.startswith(".git") or is_secret_file(child.name):
                continue
            entries.append(child.name + ("/" if child.is_dir() else ""))
        return "\n".join(entries[:500]) or "[empty folder]"

    def run(self, name: str, arguments: dict) -> str:
        handlers = {"read_file": self.read_file, "search": self.search, "list_files": self.list_files}
        if name not in handlers:
            raise ToolError(f"Unknown tool {name}.")
        output = handlers[name](**{k: v for k, v in arguments.items() if v is not None})
        return output if len(output) <= MAX_TOOL_OUTPUT else output[:MAX_TOOL_OUTPUT] + "\n[output truncated]"


def _send(body: dict, api_key: str, timeout: float) -> dict:
    """POST one Messages API request, retrying rate limits and overloads with backoff."""
    return json.loads(http_request("POST", API_URL, api_key, body, timeout))


def http_request(method: str, url: str, api_key: str, body: dict | None = None, timeout: float = 60) -> bytes:
    """One Anthropic API request, retrying rate limits, overloads, and dropped connections with backoff."""
    if os.environ.get("AUDIT_AGENT_OFFLINE"):
        raise InvestigationError("Network calls are turned off (AUDIT_AGENT_OFFLINE is set).")
    data = None if body is None else json.dumps(body).encode()
    for attempt in range(6):
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"x-api-key": api_key, "anthropic-version": API_VERSION, "content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            if exc.code in RETRY_STATUSES and attempt < 5:
                wait = float(exc.headers.get("retry-after") or 2 ** attempt * 5)
                time.sleep(min(wait, 120))
                continue
            if exc.code in (401, 403):
                raise InvestigationError(
                    f"The Anthropic API rejected the key ({exc.code}). Check it with `audit-agent set-api-key`. {detail}"
                ) from exc
            raise InvestigationError(f"The Anthropic API returned {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                raise InvestigationError(
                    "Python could not verify api.anthropic.com's certificate, so nothing was sent. On macOS with "
                    'Python from python.org, run "/Applications/Python 3.13/Install Certificates.command" once '
                    f"(adjust the version), then try again. ({exc.reason})"
                ) from exc
            if attempt < 5:
                time.sleep(2 ** attempt * 5)
                continue
            raise InvestigationError(f"Could not reach the Anthropic API: {exc.reason}") from exc
    raise InvestigationError("The Anthropic API kept failing after several retries.")


def estimate_cost(model: str, input_tokens: int, output_tokens: int, cache_write_tokens: int = 0,
                  cache_read_tokens: int = 0) -> float | None:
    """Estimated USD cost. Writing to the prompt cache costs 1.25x the input price and reading from it 0.1x."""
    price = PRICES.get(model)
    if price is None:
        return None
    cached = cache_write_tokens * price[0] * 1.25 + cache_read_tokens * price[0] * 0.1
    return (input_tokens * price[0] + output_tokens * price[1] + cached) / 1_000_000


def run_api(
    prompt: str,
    repo_root: Path,
    settings: AgentSettings,
    secret_paths: list[Path],
    extra_dirs: list[Path],
    api_key: str,
) -> AgentResult:
    model = settings.model or DEFAULT_MODEL
    tools = ReadOnlyTools(repo_root, extra_dirs, set(secret_paths))
    messages: list[dict] = [{"role": "user", "content": prompt}]
    started = time.monotonic()
    usage = {"input_tokens": 0, "output_tokens": 0}
    nudges = 0
    last_id = None
    for turn in range(1, settings.max_turns + 1):
        if time.monotonic() - started > settings.timeout_s:
            raise InvestigationError(f"Claude did not finish within {settings.timeout_s} seconds")
        response = _send(
            {"model": model, "max_tokens": MAX_OUTPUT_TOKENS, "system": SYSTEM_PROMPT, "tools": TOOLS, "messages": messages},
            api_key,
            timeout=300,
        )
        last_id = response.get("id")
        for key in usage:
            usage[key] += int((response.get("usage") or {}).get(key) or 0)
        cost = estimate_cost(model, usage["input_tokens"], usage["output_tokens"])
        content = response.get("content") or []
        messages.append({"role": "assistant", "content": content})
        tool_uses = [block for block in content if block.get("type") == "tool_use"]

        report = next((b.get("input") for b in tool_uses if b.get("name") == "submit_report"), None)
        if isinstance(report, dict):
            return AgentResult(
                report=report,
                cost_usd=cost,
                duration_ms=int((time.monotonic() - started) * 1000),
                num_turns=turn,
                session_id=last_id,
                raw=json.dumps({"model": model, "usage": usage, "messages": messages})[-200_000:],
            )
        if settings.max_budget_usd and cost is not None and cost >= settings.max_budget_usd:
            raise InvestigationError(f"Stopped at the ${settings.max_budget_usd:.2f} budget before Claude submitted a result.")
        if response.get("stop_reason") == "max_tokens" and not tool_uses:
            raise InvestigationError("Claude's answer was cut off by the output limit.")
        if not tool_uses:
            nudges += 1
            if nudges > 2:
                raise InvestigationError("Claude stopped without submitting a report.")
            messages.append({"role": "user", "content": "Call the submit_report tool now with your result."})
            continue

        results = []
        for block in tool_uses:
            try:
                output, is_error = tools.run(block.get("name", ""), block.get("input") or {}), False
            except (ToolError, TypeError, ValueError) as exc:
                output, is_error = str(exc), True
            results.append({"type": "tool_result", "tool_use_id": block.get("id"), "content": output, "is_error": is_error})
        messages.append({"role": "user", "content": results})
    raise InvestigationError(f"Claude used all {settings.max_turns} turns without submitting a report.")
