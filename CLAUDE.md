# arkkvm-cert-updater

## Manage packages

This project uses uv. Do not use pip, pip-tools, poetry, or conda.

- Add runtime dependency: `uv add <package>` (writes to `[project.dependencies]`)
- Add dev dependency: `uv add --dev <package>` (writes to `[dependency-groups]` per PEP 735)
- Remove dependency: `uv remove <package>`
- Sync environment from lockfile: `uv sync`
- Regenerate lockfile from constraints: `uv lock`
- Upgrade locked versions: `uv lock --upgrade`
- Commit `uv.lock` to version control (current uv guidance is to commit it for applications, CLIs, and libraries)

## Run code

Always use `uv run` to execute Python code and tools. Never call `python`, `pytest`, `ruff`, or other tools directly. They may not resolve to the project's virtual environment.

- Run a script: `uv run python script.py`
- Run a module: `uv run python -m module_name`
- Run a tool: `uv run pytest`, `uv run ruff check .`
- One-off tool (not a project dependency): `uvx <tool>`

## Test code

- Framework: pytest
- Run tests: `uv run pytest`
- Test files go in `tests/` at the project root
- Test file naming: `test_*.py`
- Test function naming: `test_*`
- No `__init__.py` needed in `tests/`
- Coverage: `uv add --dev coverage`, then `uv run coverage run -m pytest` and `uv run coverage report`

## Lint and format code

- Tool: ruff (handles both linting and formatting)
- Lint: `uv run ruff check .`
- Lint and auto-fix: `uv run ruff check --fix .`
- Format: `uv run ruff format .`
- Check formatting: `uv run ruff format --check .`
- Configuration lives in `pyproject.toml` under `[tool.ruff]`

## Check types

- Tool: pyrefly (preferred), ty, or mypy
- Run: `uv run pyrefly check`, `uv run ty check`, or `uv run mypy .`
- Configuration lives in `pyproject.toml` under `[tool.pyrefly]`, `[tool.ty]`, or `[tool.mypy]`

## Avoid these practices

- Do not create or activate virtual environments manually. uv manages `.venv/` automatically.
- Do not install packages globally or with `pip install`.
- Do not create `requirements.txt` for dependency management. Use `pyproject.toml` and `uv.lock`.
- Do not run `python setup.py` commands.
- Do not add dependencies to pyproject.toml by hand. Use `uv add`.
- If you must edit pyproject.toml directly, write dev dependencies under `[dependency-groups]` (PEP 735), not the legacy `[tool.uv.dev-dependencies]` table.

## Layout

CLI that installs a Let's Encrypt certificate on an ArkKVM device through the device's own web API
(local login, WebRTC, `setTLSState` over the `rpc` data channel), then reboots it. Mainly run as a certbot deploy hook.

- `src/arkkvm_cert_updater/`: the package (`cli.py` entry point `main_exit`, `config.py`, `certs.py`, `tls.py`, `device.py`, `updater.py`)
- `certbot/arkkvm-deploy-hook.sh`: certbot deploy hook (Proton Pass, `--reapply`); `certbot/config.env.example`: settings example
- `tests/`: pytest suite; the device, WebRTC and HTTP are faked, hook tests use fake programs
- `pyproject.toml`: packaging (`uv_build`) and the `arkkvm-cert-updater` command

## Commands
- Dev env: `uv sync`
- Tests with coverage: `uv run coverage run -m pytest && uv run coverage report`
- Smoke check: `uv run arkkvm-cert-updater --help`
- ShellCheck: `uvx --from shellcheck-py==0.11.0.1 shellcheck certbot/*.sh`
- End-user install: `uv tool install .` (into `~/.local/bin`)

## Gotchas
- The tests never touch a real device. Never run the updater against a device unless the user asks: every
  install reboots the KVM.
- The hook is `certbot/arkkvm-deploy-hook.sh`. certbot runs with a minimal `PATH`, so the hook finds the
  updater in `~/.local/bin` itself; keep it that way.
- The password has no command-line option, and the updater refuses an unresolved `pass://` value; only the
  hook resolves Proton Pass references.
- certbot's config dir is `~/.config/letsencrypt`. Root is not supported.
- The README covers usage. Keep it in sync when CLI options or settings change.

## Development Standards

### Git Workflow
- Branch names: `feature/description` or `fix/description`
- Commit messages: Follow conventional commits
- PR required before merge
- All CI/CD checks must pass
- Minimum 1 approval required

### GitHub Actions
- Pin every action to a full commit SHA, with the release tag in a comment:
  `uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`. Never use a tag or branch
  (`@v7`, `@main`), which can be moved to different code
- Look up a release's SHA with `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`, and update the
  SHA and the comment together

### Testing Requirements
- Minimum 80% code coverage
- All critical paths must have tests
