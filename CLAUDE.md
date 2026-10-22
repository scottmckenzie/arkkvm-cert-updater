# arkkvm-cert-updater

Single-file CLI that sets an ArkKVM device's TLS mode or custom certificate through
the device's own web API (local login → WebRTC → `setTLSState` over the `rpc` data channel).
It is mainly run as a certbot deploy hook.

## Layout
- `arkkvm_update_cert.py`: all of the code; the entry point is `main()` (arkkvm_update_cert.py:289)
- `certbot-deploy-hook.sh`: certbot hook; reads `ARKKVM_PASSWORD` from `~/.letsencrypt/arkkvm.env`
- `pyproject.toml`: packaging (setuptools, `py-modules`) plus the `arkkvm_update_cert` command
- `tests/`: pytest suite; WebRTC, HTTP and the device are faked (see `tests/test_update_device.py`)

## Commands
- Dev env: `uv sync` (puts the command in `.venv/bin/`)
- Tests: `uv run pytest --cov=arkkvm_update_cert --cov-report=term-missing`
- Smoke check: `uv run arkkvm_update_cert --help`
- After editing `pyproject.toml`: `uv lock && uv sync`, and commit `uv.lock`
- End-user install: `uv tool install .` (into `~/.local/bin`)

## Gotchas
- The tests never touch a real device. Exercising the script for real needs one, and
  `--reboot` or `--mode disabled` can lock you out. Never run it against a device
  unless the user asks.
- The command name (`arkkvm_update_cert`) differs from the project name
  (`arkkvm-cert-updater`). The module must stay listed in `[tool.setuptools] py-modules`.
- The hook calls `$HOME/.local/bin/arkkvm_update_cert` by absolute path, because certbot
  runs with a minimal PATH. Keep it that way.
- The README covers usage. Keep its examples in sync when CLI flags change.

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
