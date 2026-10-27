"""Throwaway copies of a repository where a verifier's test can run with the network off.

Each package gets a template under the work folder: a copy of the repository's tracked files with
its dependencies installed (`npm ci`, the only step allowed to use the network). Each verification
gets a fresh copy of the tracked files from the repository plus a fast clone of the template's
node_modules, a fake env file, and one folder where a test may be written. Real env files and keys
are never copied, and nothing is written to the repository: every copy lives outside it.
"""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from audit_agent.inventory.languages import GENERATED_DIRS, GENERATED_DIRS_EXTRA, is_secret_file
from audit_agent.repo import RepositoryError, list_tracked_files

TEST_TIMEOUT_S = 180
INSTALL_TIMEOUT_S = 1800
MAX_TEST_BYTES = 100_000
TEST_HEAP_MB = 6144
AUDIT_FOLDER = "__audit__"
TEST_FILE_NAME = re.compile(r"^[A-Za-z0-9_-]+\.test\.(?:ts|tsx|js|jsx|mjs|cjs)$")
EXISTING_TEST = re.compile(r"\.(?:test|spec)\.(?:ts|tsx|js|jsx|mjs|cjs)$")
JEST_CONFIGS = ("jest.config.ts", "jest.config.js", "jest.config.cjs", "jest.config.mjs", "jest.config.json")
SOURCE_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".dart")
SKIP_PARTS = {*GENERATED_DIRS, *GENERATED_DIRS_EXTRA}
ANSI = re.compile(r"\x1b\[[0-9;]*m")

ENV_NAME = r"([A-Za-z_][A-Za-z0-9_]*)"
ENV_PATTERNS = [
    re.compile(r"process\.env\." + ENV_NAME),
    re.compile(r"process\.env\[\s*['\"`]" + ENV_NAME + r"['\"`]\s*\]"),
    re.compile(r"import\.meta\.env\." + ENV_NAME),
    re.compile(r"os\.(?:environ\.get|getenv)\(\s*['\"]" + ENV_NAME + r"['\"]"),
    re.compile(r"os\.environ\[\s*['\"]" + ENV_NAME + r"['\"]\s*\]"),
    re.compile(r"(?:Platform\.environment|dotenv\.env)\[\s*['\"]" + ENV_NAME + r"['\"]\s*\]"),
    re.compile(r"String\.fromEnvironment\(\s*['\"]" + ENV_NAME + r"['\"]"),
]
ENV_DESTRUCTURE = re.compile(r"\{([^{}]{1,400})\}\s*=\s*process\.env\b")


class SandboxError(Exception):
    pass


def work_root() -> Path:
    if env := os.environ.get("AUDIT_AGENT_WORK"):
        return Path(env).expanduser().resolve()
    return (Path.home() / ".audit-agent" / "verify").resolve()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- Fake env -------------------------------------------------------------------------------------

def env_names(root: Path, files: list[str]) -> list[str]:
    """Environment variable names the code reads, found by scanning its source files."""
    names: set[str] = set()
    for rel in files:
        if not rel.endswith(SOURCE_SUFFIXES):
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pattern in ENV_PATTERNS:
            names.update(pattern.findall(text))
        for group in ENV_DESTRUCTURE.findall(text):
            for part in group.split(","):
                name = part.split(":")[0].split("=")[0].strip()
                if re.fullmatch(ENV_NAME, name):
                    names.add(name)
    return sorted(names)


def fake_value(name: str) -> str:
    upper = name.upper()
    if upper == "NODE_ENV":
        return "test"
    if "MONGO" in upper and any(w in upper for w in ("URI", "URL")):
        return "mongodb://127.0.0.1:27017/audit-test"
    if "REDIS" in upper and any(w in upper for w in ("URI", "URL", "HOST")):
        return "redis://127.0.0.1:6379"
    if "PORT" in upper:
        return "3999"
    if "EMAIL" in upper or upper.endswith("_MAIL"):
        return "test@example.com"
    if any(w in upper for w in ("SECRET", "KEY", "TOKEN", "PASSWORD", "PASS", "SALT", "PRIVATE", "CREDENTIAL", "AUTH")):
        return "test-" + name.lower().replace("_", "-")
    if any(w in upper for w in ("URL", "URI", "HOST", "ENDPOINT", "ORIGIN", "DOMAIN")):
        return "http://127.0.0.1:9"
    if upper.endswith(("ENABLED", "DEBUG")) or upper.startswith(("ENABLE_", "DISABLE_", "USE_")):
        return "false"
    return "test"


def write_fake_env(folder: Path, names: list[str]) -> None:
    lines = ["# Fake values written by audit-agent for a throwaway test copy. No real secrets."]
    lines += [f"{name}={fake_value(name)}" for name in names]
    (folder / ".env").write_text("\n".join(lines) + "\n")


# --- Packages and their test setup ----------------------------------------------------------------

def copyable_files(repo_root: Path) -> list[str]:
    """Tracked files that may be copied: never secret files or dependency and build folders."""
    try:
        tracked = list_tracked_files(repo_root)
    except RepositoryError as exc:
        raise SandboxError(f"Could not list the files of {repo_root}: {exc}") from exc
    files = []
    root = repo_root.resolve()
    for rel in tracked:
        parts = PurePosixPath(rel).parts
        if is_secret_file(rel) or any(p in SKIP_PARTS or p == ".git" for p in parts):
            continue
        path = repo_root / rel
        if path.is_symlink() and not path.resolve().is_relative_to(root):
            continue
        if path.is_file():
            files.append(rel)
    return files


def _uses_jest(package_json: Path) -> bool:
    try:
        data = json.loads(package_json.read_text())
    except (OSError, ValueError):
        return False
    deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
    return "jest" in deps or "jest" in str((data.get("scripts") or {}).get("test", ""))


def find_package(repo_root: Path, files: list[str], cited_file: str) -> str:
    """The folder (relative to the repository) of the nearest package above the cited file whose tests run with jest."""
    tracked = set(files)
    folder = PurePosixPath(cited_file).parent
    while True:
        rel = "." if str(folder) in ("", ".") else folder.as_posix()
        manifest = "package.json" if rel == "." else f"{rel}/package.json"
        if manifest in tracked and _uses_jest(repo_root / manifest):
            lock = "package-lock.json" if rel == "." else f"{rel}/package-lock.json"
            if lock not in tracked:
                raise SandboxError(f"{manifest} uses jest but has no package-lock.json, which `npm ci` needs.")
            return rel
        if rel == ".":
            raise SandboxError(
                f"No package with jest tests contains {cited_file}. So far only JavaScript and TypeScript "
                "packages that test with jest can be used to reproduce findings."
            )
        folder = folder.parent


def _in_package(files: list[str], package_rel: str) -> list[str]:
    prefix = "" if package_rel == "." else package_rel + "/"
    return [f[len(prefix):] for f in files if f.startswith(prefix)]


def audit_test_dir(files: list[str], package_rel: str) -> str:
    """Where the verifier's test goes, relative to the package: a folder inside the one most existing tests are in."""
    tops = Counter(
        rel.split("/")[0] for rel in _in_package(files, package_rel)
        if EXISTING_TEST.search(rel) and "/" in rel and not set(PurePosixPath(rel).parts) & SKIP_PARTS
    )
    top = tops.most_common(1)[0][0] if tops else "tests"
    return f"{top}/{AUDIT_FOLDER}"


def _join(package_rel: str, rel: str) -> str:
    return rel if package_rel == "." else f"{package_rel}/{rel}"


@dataclass
class TestSetup:
    """What the verifier is told about a package's tests. It is the same for every finding in the package,
    so it can be cached."""
    package_rel: str
    test_dir: str            # relative to the repository root
    jest_config: tuple[str, str] | None
    helpers: list[str]
    examples: list[tuple[str, str]]
    env_names: list[str]


def test_setup(repo_root: Path, files: list[str], package_rel: str) -> TestSetup:
    in_package = _in_package(files, package_rel)
    config = next((c for c in JEST_CONFIGS if c in in_package), None)
    jest_config = None
    if config:
        jest_config = (_join(package_rel, config), (repo_root / _join(package_rel, config)).read_text(errors="replace"))
    else:
        data = json.loads((repo_root / _join(package_rel, "package.json")).read_text())
        if "jest" in data:
            jest_config = (_join(package_rel, "package.json") + ' ("jest" field)', json.dumps(data["jest"], indent=2))
    test_dir = audit_test_dir(files, package_rel)
    top = test_dir.split("/")[0]
    tests = [r for r in in_package if EXISTING_TEST.search(r) and not set(PurePosixPath(r).parts) & SKIP_PARTS]
    helpers = sorted(r for r in in_package if r.startswith(top + "/") and not EXISTING_TEST.search(r)
                     and r.endswith(SOURCE_SUFFIXES))[:30]

    def score(rel: str) -> tuple:
        text = (repo_root / _join(package_rel, rel)).read_text(errors="replace")
        lines = text.count("\n") + 1
        uses_helper = bool(re.search(r"""from\s+['"]\.\.?/[^'"]*(setup|helper)""", text, re.I))
        return (not uses_helper, lines < 20, abs(lines - 60), rel)

    examples = []
    for rel in sorted(tests, key=score)[:2]:
        lines = (repo_root / _join(package_rel, rel)).read_text(errors="replace").splitlines()
        examples.append((_join(package_rel, rel), "\n".join(lines[:150]) + ("\n// ... (shortened)" if len(lines) > 150 else "")))
    return TestSetup(
        package_rel=package_rel,
        test_dir=_join(package_rel, test_dir),
        jest_config=jest_config,
        helpers=[_join(package_rel, h) for h in helpers],
        examples=examples,
        env_names=env_names(repo_root, files),
    )


# --- Running commands with the network off --------------------------------------------------------

def _sbpl(path: Path) -> str:
    return '"' + str(path.resolve()).replace("\\", "\\\\").replace('"', '\\"') + '"'


def sandbox_command(command: list[str], writable: list[Path], network: bool) -> list[str]:
    """Wrap a command so it can write only inside `writable` (plus temp folders) and, unless `network`,
    reach nothing but this machine. Fails rather than run a command unrestricted."""
    if sys.platform == "darwin" and shutil.which("sandbox-exec"):
        rules = ["(version 1)", "(allow default)"]
        if not network:
            rules += [
                "(deny network*)",
                '(allow network* (remote ip "localhost:*"))',
                '(allow network-bind (local ip "localhost:*"))',
                '(allow network-inbound (local ip "localhost:*"))',
                "(allow network* (remote unix-socket))",
                "(allow network-bind (local unix-socket))",
            ]
        paths = [*writable, Path("/dev"), Path("/private/tmp"), Path("/private/var/folders")]
        rules += ["(deny file-write*)", "(allow file-write* " + " ".join(f"(subpath {_sbpl(p)})" for p in paths) + ")"]
        return ["sandbox-exec", "-p", "\n".join(rules), *command]
    if sys.platform.startswith("linux") and shutil.which("unshare"):
        if network:
            return command
        return ["unshare", "--net", "--map-root-user", "sh", "-c", 'ip link set lo up 2>/dev/null; exec "$@"', "sh", *command]
    raise SandboxError(
        "Can't turn the network off for tests on this system (needs sandbox-exec on macOS or unshare on Linux), "
        "so no test was run."
    )


@dataclass
class ProcessResult:
    exit_code: int | None
    output: str
    timed_out: bool
    duration_ms: int


def run_sandboxed(command: list[str], cwd: Path, env: dict, writable: list[Path], network: bool,
                  timeout: float) -> ProcessResult:
    started = time.monotonic()
    proc = subprocess.Popen(
        sandbox_command(command, writable, network), cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", start_new_session=True,
    )
    timed_out = False
    try:
        output, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc.pid)
        output, _ = proc.communicate()
    _kill_group(proc.pid)  # test servers or databases the command left running
    return ProcessResult(proc.returncode, ANSI.sub("", output or ""), timed_out, int((time.monotonic() - started) * 1000))


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def base_env(home: Path, tmp: Path) -> dict:
    """A clean environment: none of the engineer's variables (keys, tokens) reach the copy."""
    cache = work_root() / "cache"
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "LANG": os.environ.get("LANG", "en_US.UTF-8"),
        "CI": "1",
        "FORCE_COLOR": "0",
        "NO_COLOR": "1",
        # ts-jest compiles the whole import graph of a test; Node's default ~2 GB heap runs out on large backends.
        "NODE_OPTIONS": f"--max-old-space-size={TEST_HEAP_MB}",
        "npm_config_cache": str(cache / "npm"),
        "npm_config_update_notifier": "false",
        "npm_config_fund": "false",
        "npm_config_audit": "false",
        # mongodb-memory-server downloads its database binary while installing; tests then find it here offline.
        "MONGOMS_DOWNLOAD_DIR": str(cache / "mongodb-binaries"),
    }


# --- Test results ---------------------------------------------------------------------------------

@dataclass
class TestRun:
    exit_code: int | None
    timed_out: bool
    output: str
    report: dict | None
    duration_ms: int
    timeout_s: float = TEST_TIMEOUT_S


def _tests(run: TestRun) -> list[dict]:
    return [a for r in (run.report or {}).get("testResults") or [] for a in r.get("assertionResults") or []]


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _full_name(test: dict) -> str:
    return _norm(test.get("fullName") or " ".join([*(test.get("ancestorTitles") or []), test.get("title") or ""]))


def _is_assertion(test: dict) -> bool:
    if any(isinstance(d, dict) and "matcherResult" in d for d in test.get("failureDetails") or []):
        return True
    return any(ANSI.sub("", m).lstrip().startswith(("Error: expect(", "expect(", "JestAssertionError"))
               for m in test.get("failureMessages") or [])


def _tail(text: str, limit: int = 1500) -> str:
    text = ANSI.sub("", text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


def _first_lines(text: str, count: int = 12) -> str:
    lines = [line for line in ANSI.sub("", text or "").splitlines() if line.strip()]
    keep = [line for line in lines if "node_modules" not in line][:count]
    return "\n".join(keep)


def classify(run: TestRun, test_name: str | None) -> tuple[str, str]:
    """How the named test ended: passed, failed_assertion, errored, did_not_run, timed_out, or not_found,
    with a short explanation."""
    if run.timed_out:
        return "timed_out", f"The test run took longer than {run.timeout_s:.0f} seconds and was stopped."
    results = (run.report or {}).get("testResults") or []
    if not results:
        return "did_not_run", "Jest produced no results:\n" + _tail(run.output)
    tests = _tests(run)
    if not tests:
        return "did_not_run", "The test file could not run:\n" + _first_lines(results[0].get("message") or run.output, 25)
    chosen = None
    if test_name:
        wanted = _norm(test_name)
        chosen = next((t for t in tests if wanted in (_full_name(t), _norm(t.get("title") or ""))), None)
    elif len(tests) == 1:
        chosen = tests[0]
    if chosen is None:
        names = "; ".join(_full_name(t) for t in tests[:10])
        asked = f"No test named {test_name!r}" if test_name else "The file has several tests and none was named"
        return "not_found", f"{asked}. The file has: {names}"
    status = chosen.get("status")
    if status == "passed":
        return "passed", f"\"{_full_name(chosen)}\" passed on the unchanged code."
    if status != "failed":
        return "did_not_run", f"\"{_full_name(chosen)}\" did not run (status: {status})."
    message = _first_lines("\n".join(chosen.get("failureMessages") or []))
    if _is_assertion(chosen):
        return "failed_assertion", f"\"{_full_name(chosen)}\" failed on the unchanged code:\n{message}"
    return "errored", f"\"{_full_name(chosen)}\" threw an error instead of failing an expect:\n{message}"


def describe(run: TestRun) -> str:
    """The run as the verifier sees it: each test's result, failure messages, and the end of the console output."""
    if run.timed_out:
        return f"TIMED OUT after {run.timeout_s:.0f} seconds.\n\nOutput:\n{_tail(run.output, 4000)}"
    results = (run.report or {}).get("testResults") or []
    lines = []
    for result in results:
        tests = result.get("assertionResults") or []
        if not tests and result.get("message"):
            lines.append("THE TEST FILE COULD NOT RUN:\n" + _first_lines(result["message"], 40))
        for test in tests:
            lines.append(f"{test.get('status', '?').upper()}: {_full_name(test)}")
            if test.get("status") == "failed":
                kind = "assertion failed" if _is_assertion(test) else "error thrown"
                lines.append(f"  ({kind})\n" + _first_lines("\n".join(test.get("failureMessages") or []), 30))
    if not results:
        lines.append("Jest produced no results.")
    lines.append(f"\nExit code {run.exit_code}, {run.duration_ms / 1000:.1f} s.\n\nOutput:\n{_tail(run.output, 4000)}")
    return "\n".join(lines)[:20_000]


# --- Toolchain ------------------------------------------------------------------------------------

class Jest:
    """Installs a package's dependencies with npm and runs one jest test file."""

    name = "jest"

    def install(self, package_dir: Path, env: dict, writable: list[Path], log) -> None:
        if not shutil.which("npm", path=env["PATH"]):
            raise SandboxError("npm is not installed, so the package's dependencies can't be installed.")
        result = run_sandboxed(["npm", "ci", "--no-audit", "--no-fund"], package_dir, env, writable, network=True,
                               timeout=INSTALL_TIMEOUT_S)
        if result.timed_out or result.exit_code != 0:
            raise SandboxError(f"`npm ci` failed in the template copy:\n{_tail(result.output, 2000)}")
        if not (package_dir / "node_modules" / ".bin" / "jest").exists():
            raise SandboxError("`npm ci` finished but node_modules/.bin/jest is missing.")
        log(f"Installed dependencies in {result.duration_ms / 1000:.0f} s.")

    def command(self, package_dir: Path, test_rel: str, out_file: Path, cache_dir: Path,
                name_pattern: str | None) -> list[str]:
        command = [str(package_dir / "node_modules" / ".bin" / "jest"), "--runTestsByPath", test_rel,
                   "--runInBand", "--forceExit", "--ci", "--json", f"--outputFile={out_file}",
                   f"--cacheDirectory={cache_dir}", "--watchman=false"]
        if name_pattern:
            command += ["-t", name_pattern]
        return command

    def run(self, ws: "Workspace", test_path: str, timeout: float, name_pattern: str | None = None) -> TestRun:
        ws.runs += 1
        out_file = ws.root / f"jest-{ws.runs}.json"
        test_rel = PurePosixPath(test_path).relative_to(ws.package_rel).as_posix() if ws.package_rel != "." else test_path
        command = self.command(ws.package, test_rel, out_file, ws.root / "jest-cache", name_pattern)
        result = run_sandboxed(command, ws.package, base_env(ws.root / "home", ws.root / "tmp"), [ws.root],
                               network=False, timeout=timeout)
        report = None
        if out_file.exists():
            try:
                report = json.loads(out_file.read_text())
            except ValueError:
                report = None
        return TestRun(result.exit_code, result.timed_out, result.output, report, result.duration_ms, timeout)

    def run_related(self, ws: "Workspace", source_paths: list[str], timeout: float) -> TestRun:
        """Run the existing tests that depend on the given source files (jest --findRelatedTests). A worker
        process is recycled when it grows too large, since a backend's whole test graph can be big."""
        ws.runs += 1
        out_file = ws.root / f"jest-related-{ws.runs}.json"
        # --roots covers the whole package: a config that limits roots to the test folder leaves source files out of
        # jest's dependency graph, and then no test counts as related to them.
        command = [str(ws.package / "node_modules" / ".bin" / "jest"), "--roots", str(ws.package), "--findRelatedTests",
                   *(str(ws.repo / p) for p in source_paths), "--passWithNoTests", "--forceExit", "--ci", "--json",
                   f"--outputFile={out_file}", f"--cacheDirectory={ws.root / 'jest-cache'}", "--watchman=false",
                   "--maxWorkers=1", "--workerIdleMemoryLimit=3GB"]
        result = run_sandboxed(command, ws.package, base_env(ws.root / "home", ws.root / "tmp"), [ws.root],
                               network=False, timeout=timeout)
        report = None
        if out_file.exists():
            try:
                report = json.loads(out_file.read_text())
            except ValueError:
                report = None
        return TestRun(result.exit_code, result.timed_out, result.output, report, result.duration_ms, timeout)


def failures(run: TestRun, root: Path) -> set[str]:
    """Each failed test as "file › test name", and each test file that could not run as "file (could not run)"."""
    failed = set()
    for result in (run.report or {}).get("testResults") or []:
        name = result.get("name") or "?"
        try:
            name = Path(name).relative_to(root).as_posix()
        except ValueError:
            pass
        tests = result.get("assertionResults") or []
        if not tests and result.get("status") == "failed":
            failed.add(f"{name} (could not run)")
        failed.update(f"{name} › {_full_name(t)}" for t in tests if t.get("status") == "failed")
    return failed


# --- Templates and workspaces ---------------------------------------------------------------------

def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


FICLONE = 0x40049409  # Linux ioctl that makes a copy-on-write clone (Btrfs, XFS)
_clonefile = None
if sys.platform == "darwin":
    _clonefile = ctypes.CDLL(None, use_errno=True).clonefile
    _clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
    _clonefile.restype = ctypes.c_int


def clone_file(source: Path, target: Path) -> None:
    """Copy one file as a copy-on-write clone, which takes no disk space until one side changes.
    Falls back to a plain copy where the file system can't clone (for example across volumes)."""
    if _clonefile is not None:
        if _clonefile(os.fsencode(source), os.fsencode(target), 0) == 0:
            return
    elif sys.platform.startswith("linux"):
        try:
            with open(source, "rb") as src, open(target, "wb") as dst:
                fcntl.ioctl(dst.fileno(), FICLONE, src.fileno())
            return
        except OSError:
            pass
    shutil.copyfile(source, target)


def copy_files(repo_root: Path, files: list[str], dest: Path) -> dict[str, str]:
    """Clone the files into dest and return each one's content hash."""
    hashes = {}
    for rel in files:
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        clone_file(repo_root / rel, target)
        hashes[rel] = _hash_file(target)
    return hashes


def _clone_tree(src: Path, dest: Path) -> None:
    """Copy a folder, using copy-on-write clones where the file system supports them."""
    if sys.platform == "darwin":
        command = ["cp", "-c", "-R", str(src), str(dest)]
    elif sys.platform.startswith("linux"):
        command = ["cp", "-a", "--reflink=auto", str(src), str(dest)]
    else:
        command = None
    if command and subprocess.run(command, capture_output=True).returncode == 0:
        return
    shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(src, dest, symlinks=True)


def _check_outside(path: Path, repo_root: Path) -> None:
    if path.resolve().is_relative_to(repo_root.resolve()):
        raise SandboxError(f"The work folder {path} is inside the repository; set AUDIT_AGENT_WORK to a folder outside it.")


def package_home(repo_root: Path, package_rel: str) -> Path:
    key = _hash(f"{repo_root.resolve()}\0{package_rel}".encode())[:10]
    return work_root() / f"{repo_root.name}-{key}"


def _deps_key(repo_root: Path, package_rel: str) -> str:
    node = shutil.which("node")
    version = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip() if node else ""
    digest = hashlib.sha256(version.encode())
    for name in ("package.json", "package-lock.json"):
        digest.update((repo_root / _join(package_rel, name)).read_bytes())
    return digest.hexdigest()


@contextmanager
def _locked(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def prepare(repo_root: Path, files: list[str], package_rel: str, toolchain: Jest, log=print) -> Path:
    """The template's package folder, with dependencies installed. Built once and reused until the
    package's manifest, lockfile, or Node version changes."""
    home = package_home(repo_root, package_rel)
    _check_outside(home, repo_root)
    with _locked(home / ".lock"):
        key = _deps_key(repo_root, package_rel)
        meta_path = home / "template.json"
        template = home / "template"
        package = template if package_rel == "." else template / package_rel
        if meta_path.exists() and (package / "node_modules").is_dir():
            if json.loads(meta_path.read_text()).get("key") == key:
                return package
        log(f"Preparing a test copy of {repo_root.name} (installing dependencies; this is the only step with network access) ...")
        building = home / "template-building"
        shutil.rmtree(building, ignore_errors=True)
        copy_files(repo_root, files, building)
        built_package = building if package_rel == "." else building / package_rel
        write_fake_env(built_package, env_names(repo_root, files))
        (home / "home").mkdir(parents=True, exist_ok=True)
        (home / "tmp").mkdir(parents=True, exist_ok=True)
        cache = work_root() / "cache"
        cache.mkdir(parents=True, exist_ok=True)
        toolchain.install(built_package, base_env(home / "home", home / "tmp"), [building, cache, home / "home", home / "tmp"], log)
        shutil.rmtree(template, ignore_errors=True)
        building.rename(template)
        meta_path.write_text(json.dumps({"key": key, "package": package_rel, "built_at": _now(),
                                         "repository": str(repo_root)}))
        return package


@dataclass
class Workspace:
    """One throwaway copy: the repository's tracked files, the template's dependencies, a fake env file,
    and an empty folder for the verifier's test."""
    root: Path
    repo: Path
    package: Path
    package_rel: str
    test_dir: str
    hashes: dict[str, str]
    runs: int = 0


def new_workspace(repo_root: Path, files: list[str], setup: TestSetup, template_package: Path, label: str) -> Workspace:
    home = package_home(repo_root, setup.package_rel)
    root = home / "runs" / f"{label}-{secrets.token_hex(3)}"
    _check_outside(root, repo_root)
    repo = root / "repo"
    try:
        hashes = copy_files(repo_root, files, repo)
        package = repo if setup.package_rel == "." else repo / setup.package_rel
        _clone_tree(template_package / "node_modules", package / "node_modules")
        write_fake_env(package, setup.env_names)
        for folder in ("tmp", "home", "jest-cache"):
            (root / folder).mkdir(parents=True, exist_ok=True)
        (repo / setup.test_dir).mkdir(parents=True, exist_ok=True)
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise
    return Workspace(root, repo, package, setup.package_rel, setup.test_dir, hashes)


def changed_files(ws: Workspace) -> list[str]:
    """Copied repository files that are no longer what was copied (a test must not change the code it tests)."""
    changed = []
    for rel, digest in ws.hashes.items():
        path = ws.repo / rel
        if not path.is_file() or _hash_file(path) != digest:
            changed.append(rel)
    return changed


def remove(ws: Workspace | None) -> None:
    if ws is not None:
        shutil.rmtree(ws.root, ignore_errors=True)
