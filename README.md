# Autonomous Code Audit

Find real bugs across a whole repository with Claude, prove them with tests, and fix them only when you say so.

You point it at a local Git repository, or a folder of repositories such as a backend and its web and mobile apps. It inventories the code and plans audit tasks. Claude investigates each task and has to back every finding with code that really exists. An independent agent can then reproduce a finding with a test in a throwaway copy that has the network off. Every step is saved in a local SQLite database, so an interrupted audit picks up where it stopped. Nothing is pushed or posted unless you click.

## What it does

- **Inventory and planning.** Lists files, languages, dependencies, entry points, imports, and apps (backend, web, mobile). It then plans audit tasks: groups of related files, plus one task per API endpoint an app calls.
- **API map.** Links frontend calls (React, Flutter) to the backend routes that handle them, and reports calls that reach no route.
- **Investigation.** Claude audits each task with read-only tools against a checklist of logic, security, and concurrency bugs. A finding is saved only if the file, line, and quoted code really exist. Anything Claude can't show in the code is kept apart as "needs review". The findings already known in a task's files are shown to Claude so they aren't reported twice.
- **Live or batch.** Send tasks live, several at a time, or as a Message Batch at half the price.
- **GitHub issues.** Turn findings into issues on a project board, after a preview.
- **Reproduce (independent verifier).** A fresh Claude context sees only the claim and tries to disprove it by writing one jest test. The app then runs that test itself in a fresh throwaway copy, and the result is the verdict: **reproduced**, **not reproduced**, or **unable** (with manual steps).
- **Reproduce + fix (optional, cheaper).** One agent proves the bug with a test. Only if the app confirms that the test fails on the unchanged code may the agent edit source files in the copy, and the test is frozen from then on. The app then checks that the test passes and that the existing tests covering the change don't newly fail. You see the diff, the test, and every run.
- **Draft pull requests.** For a checked fix, click to push a new `audit/...` branch and open a draft PR that says "Fixes #issue". Rejected or impossible fixes are explained in a comment on the issue.
- **Review page.** A local web page for all of the above: task queue and filters, Findings tab, progress, verdicts, diffs, and PR buttons.

## Safety

- Your repository is never written. Investigators can only read. Tests and fixes run in copy-on-write copies outside the repository, and the repository is checked before and after each run.
- Real `.env` files, keys, and `.git` are never copied. A fake `.env` is generated from the variable names the code reads.
- Tests run in a sandbox with outside network blocked (only localhost) and writes allowed only inside the copy: `sandbox-exec` on macOS, or a network namespace on Linux. Your own environment variables don't reach the tests.
- The only network step for tests is installing dependencies (`npm ci`) once into a template copy.
- Nothing goes to Claude or GitHub unless you start it. PRs are drafts on new branches. Nothing is merged or deployed.

## Requirements

- Python 3.11 or newer (standard library only) and git
- An Anthropic API key (`audit-agent set-api-key`). Investigations can also use the `claude` CLI.
- [GitHub CLI](https://cli.github.com) (`gh auth login`), for issues and pull requests
- For reproducing and fixing: Node.js and npm, and a target package that tests with jest and has a `package-lock.json`. macOS with `sandbox-exec`, or Linux with `unshare`.

## Install

```bash
git clone https://github.com/shivasb42/autonomous-code-audit.git
cd autonomous-code-audit
pip install -e .          # installs the `audit-agent` command
# or run it without installing:
PYTHONPATH=src python3 -m audit_agent --help
```

## Quick start

```bash
audit-agent set-api-key                     # saved outside every repository, readable only by you
audit-agent start ~/code/my-project         # inventory, apps, tasks, and API map, as one project
audit-agent ui --port 9000                  # open the review page
```

On the page:

1. **Tasks tab:** filter the queue, cancel what you don't want, then **Send** (live) or **Batch** (half price).
2. Create GitHub issues for the findings.
3. **Findings tab:** pick findings and click **Reproduce**, or **Reproduce + fix**.
4. For checked fixes: **Open draft PR**, or **Open all pending draft PRs**.

Check the test setup once, without Claude:

```bash
audit-agent reproduce-setup <audit id>      # installs dependencies and runs one existing test with the network off
```

## Commands

| Command | What it does |
|---|---|
| `start <folder>` | Audit a repository or a folder of repositories |
| `audits`, `inventory`, `apps`, `app-type` | See what was discovered; correct an app's type |
| `tasks`, `task`, `plan` | List and inspect audit tasks |
| `map-api`, `api` | Build and show the frontend-to-backend API map |
| `investigate <task>` | Run Claude on one task (`--show-prompt` sends nothing) |
| `batch-send`, `batches`, `batch-check`, `batch-recover`, `batch-cancel` | Message Batches |
| `findings`, `issues` | List findings; preview or create GitHub issues |
| `reproduce <finding>`, `reproduce-setup`, `verifications` | Reproduce findings with tests |
| `prs`, `fix-comments` | Open pending draft PRs; post missing issue comments |
| `ui` | The review page |

Every command takes `--db`. The default database is `~/.audit-agent/audit.db`, or `$AUDIT_AGENT_DB`. Test copies go to `~/.audit-agent/verify`.

## How a reproduction works

1. The template copy is built once per package: tracked files, a fake `.env`, and `npm ci`.
2. Each attempt gets a fresh copy-on-write copy, which costs almost no disk space.
3. Claude reads the copy, writes one test in `tests/__audit__/`, and asks the app to run it.
4. The app runs `jest --runInBand --forceExit` itself in another fresh copy, with the network off. A failed `expect` means reproduced. A pass means not reproduced. Anything else, such as a crash, compile error, timeout, or a test that changes the code under test, means unable, with the reason.
5. The test, its output, the verdict, tokens (including the prompt cache), and the cost are saved. Then the copies are deleted.

## Development

```bash
python3 -m unittest discover -s tests -t .
```

The tests never call Claude or GitHub: they use a scripted fake API, a fake jest, a fake `gh`, and local git remotes. Some tests create git repositories in temporary folders, and one checks the real macOS sandbox, so run them outside other sandboxes.
