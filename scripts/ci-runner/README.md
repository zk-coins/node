# Self-hosted GitHub Actions runner for `zk-coins/server`

Operator-facing documentation for the self-hosted runner that executes
the `Server + Shared Tests (M3 Ultra)` and `Coverage Gate (100% lines
+ functions)` jobs in `.github/workflows/ci.yaml`. See issue #40 for
the rationale (test + coverage gate in CI rather than pre-push) and
issue #30 for the previous design.

## Hardware target

A single Mac Studio M3 Ultra with 96 GB unified RAM (CONTRIBUTING.md §
"Working on the Plonky2 Migration", invariant 3). The same host that
was previously used as the `ZKCOINS_PREPUSH_REMOTE` target — i.e.
`dfx01`.

## Blast-radius model

The runner executes workflow YAML on PRs. A PR can change the workflow
file itself, so the runner is effectively trusted with arbitrary code
execution as whichever user it runs as.

Two mitigations:

1. **Dedicated `gh-runner` user.** Not `dfx01` owner, not a user with
   sudo, not a user with access to other repos or secrets on the box.
   The runner can only damage its own `$HOME`.
2. **Outside-collaborator approval gate** at the repository level:
   *Settings → Actions → General → "Require approval for all outside
   collaborators"*. Without this, anyone with a fork can run code on
   the runner by opening a PR that edits the workflow. The repository
   is public, so this gate is non-negotiable.

## One-time setup on the host

All commands assume you have shell access to the M3 Ultra (via SSH or
locally) with sudo.

### 1. Create the `gh-runner` user

```bash
# As an admin user on the host:
sudo dscl . -create /Users/gh-runner
sudo dscl . -create /Users/gh-runner UserShell /bin/zsh
sudo dscl . -create /Users/gh-runner RealName "GitHub Actions Runner"
sudo dscl . -create /Users/gh-runner UniqueID 600
sudo dscl . -create /Users/gh-runner PrimaryGroupID 20
sudo dscl . -create /Users/gh-runner NFSHomeDirectory /Users/gh-runner
sudo mkdir -p /Users/gh-runner
sudo chown gh-runner:staff /Users/gh-runner
```

The user has no password (no console / SSH login). All ops happen
through `sudo -iu gh-runner`.

### 2. Install prerequisites for `gh-runner`

```bash
sudo -iu gh-runner bash -lc '
  bash <(curl -fsSL https://raw.githubusercontent.com/zk-coins/server/develop/scripts/ci-runner/bootstrap-prerequisites.sh)
'
```

The bootstrap script is idempotent and installs:

- Homebrew (user-local, prefix `~/homebrew`) — needed for GNU rsync
  (macOS ships `openrsync` which lacks `--mkpath` and other modern
  flags).
- `rustup` with the toolchain pinned by `rust-toolchain` plus
  components `rustfmt`, `clippy`, `llvm-tools-preview`.
- `cargo-llvm-cov`.

### 3. Register the runner with GitHub

GitHub requires a short-lived registration token. Generate one at:

> **Settings → Actions → Runners → New self-hosted runner → macOS / ARM64**

Copy the `--token` value from that page (valid for ~1 hour).

Then on the host:

```bash
sudo -iu gh-runner bash -lc '
  set -euo pipefail
  mkdir -p ~/actions-runner && cd ~/actions-runner

  # Download the latest stable runner package for macOS ARM64.
  RUNNER_VERSION=$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest | jq -r .tag_name | sed s/^v//)
  curl -fsSL -o runner.tar.gz \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-osx-arm64-${RUNNER_VERSION}.tar.gz"
  tar xzf runner.tar.gz
  rm runner.tar.gz

  # Configure — paste the token from the GH UI here.
  ./config.sh \
    --unattended \
    --url https://github.com/zk-coins/server \
    --token PASTE_TOKEN_FROM_GH_UI_HERE \
    --name "$(hostname -s)" \
    --labels self-hosted,macOS,ARM64,m3-ultra,zkcoins-prover \
    --work _work \
    --replace
'
```

### 4. Install + start the launchd service

The runner package ships its own `svc.sh` which creates and loads a
LaunchAgent in `~/Library/LaunchAgents`. Run it from the `gh-runner`
account:

```bash
sudo -iu gh-runner bash -lc 'cd ~/actions-runner && ./svc.sh install && ./svc.sh start'
```

Verify the agent is loaded and the runner registered:

```bash
sudo -iu gh-runner launchctl list | grep actions.runner
```

### 5. Enable the outside-collaborator approval gate

In the GitHub UI: **Settings → Actions → General → "Fork pull request
workflows from outside collaborators"** → *Require approval for all
outside collaborators*.

This is what stops a fork from running arbitrary code on the runner.

## Verifying the runner is online

From any machine with `gh` configured:

```bash
gh api repos/zk-coins/server/actions/runners | jq '.runners[] | {name, status, busy, labels: [.labels[].name]}'
```

A healthy runner reports `"status": "online"` and includes the
`m3-ultra` label.

## Activating the CI jobs

The `server-tests` and `coverage` jobs in `.github/workflows/ci.yaml`
ship gated behind `if: false` so the workflow YAML can land before
the runner exists. After the runner is online and verified, flip
both jobs by removing the `if: false` lines, and open a no-op PR to
measure wall time and confirm the green path.

Once the workflow has produced a green run on `develop`, add the two
new check names as required status checks on the `develop` branch
protection rule:

- `Server + Shared Tests (M3 Ultra)`
- `Coverage Gate (100% lines + functions)`

(The same operation should also drop the stale `Tests` and
`Coverage (MVP scope)` required checks left over from issue #30 —
those job names no longer exist in the current workflow.)

## Operations

### Updating the runner binary

GitHub deprecates old runner versions about every 6 months. The
launchd service auto-updates the runner binary unless you ran
`config.sh --disableupdate`. Check the version with:

```bash
sudo -iu gh-runner bash -lc 'cat ~/actions-runner/.runner | jq -r .version'
```

### Restarting / stopping the runner

```bash
sudo -iu gh-runner bash -lc 'cd ~/actions-runner && ./svc.sh stop'
sudo -iu gh-runner bash -lc 'cd ~/actions-runner && ./svc.sh start'
sudo -iu gh-runner bash -lc 'cd ~/actions-runner && ./svc.sh status'
```

### Removing the runner

```bash
# Generate a *removal* token in the same GH UI page (different from
# the registration token).
sudo -iu gh-runner bash -lc '
  cd ~/actions-runner
  ./svc.sh stop
  ./svc.sh uninstall
  ./config.sh remove --token PASTE_REMOVAL_TOKEN_HERE
'
```

### Workspace cache

By default the runner re-uses `~/actions-runner/_work/server/server/`
across jobs, so cargo's incremental build cache persists. This is
the documented "shared `target/` directory across jobs" trade-off in
issue #40: fast incremental builds, but stale state can occasionally
poison a green-to-red flip. If you see unexplained CI failures that
disappear on rerun, nuke the cache:

```bash
sudo -iu gh-runner bash -lc 'rm -rf ~/actions-runner/_work/server/server/target'
```

### Disk + RAM headroom

The Plonky2 prover wants peak ~50 GB RAM per test thread. The jobs
run with `--test-threads=1` so two parallel jobs (server-tests +
coverage) on the same host would race for RAM. Avoid running two
concurrent zkCoins workflow runs on this runner — workflow-level
`concurrency: cancel-in-progress: true` in `ci.yaml` already takes
care of this for the same PR. For different PRs running in parallel,
add a single self-hosted runner only (one concurrent job per repo)
and let GitHub queue the rest.

Cargo's `target/` grows fast — budget ~30-50 GB. Run `cargo clean`
periodically (or wipe the workspace as above) if disk pressure
becomes an issue.

## Tracking

The runner is a launchd service on `dfx01`, not a Docker container,
so it does not fit the `status-server.py` container-tracking
convention. Track it via the GitHub UI runner page instead.
