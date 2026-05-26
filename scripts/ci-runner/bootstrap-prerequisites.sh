#!/usr/bin/env bash
# Bootstrap prerequisites for the self-hosted GitHub Actions runner
# user (`gh-runner`) on a Mac Studio M3 Ultra. Idempotent — safe to
# re-run.
#
# Installs (all into the calling user's $HOME, no sudo):
#   - Homebrew (prefix ~/homebrew) — for GNU rsync only; the system
#     `openrsync` at /usr/bin/rsync lacks --mkpath and other flags
#     used by older workflows.
#   - rustup with the toolchain pinned by the repo's rust-toolchain
#     file, plus components rustfmt, clippy, llvm-tools-preview.
#   - cargo-llvm-cov for the coverage gate.
#
# This script does NOT register the runner with GitHub — that requires
# a short-lived token from the GH UI. See scripts/ci-runner/README.md.
set -euo pipefail

log() { printf '[bootstrap] %s\n' "$*"; }

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
  echo "bootstrap-prerequisites.sh expects macOS / arm64; got $(uname -s) / $(uname -m)" >&2
  exit 1
fi

# ---- Homebrew (user-local) ----------------------------------------
BREW_PREFIX="$HOME/homebrew"
if [ ! -x "$BREW_PREFIX/bin/brew" ]; then
  log "installing user-local Homebrew at $BREW_PREFIX"
  mkdir -p "$BREW_PREFIX"
  curl -fsSL https://github.com/Homebrew/brew/tarball/master \
    | tar xz --strip-components=1 -C "$BREW_PREFIX"
else
  log "Homebrew already present at $BREW_PREFIX"
fi
export PATH="$BREW_PREFIX/bin:$PATH"

if ! brew list --formula rsync >/dev/null 2>&1; then
  log "installing GNU rsync via brew"
  brew install rsync
else
  log "GNU rsync already installed"
fi

# Persist Homebrew on PATH for non-interactive launchd invocations.
SHELL_RC="$HOME/.zshenv"
if ! grep -qs "$BREW_PREFIX/bin" "$SHELL_RC" 2>/dev/null; then
  log "adding $BREW_PREFIX/bin to $SHELL_RC"
  printf '\nexport PATH="%s/bin:$PATH"\n' "$BREW_PREFIX" >> "$SHELL_RC"
fi

# ---- rustup -------------------------------------------------------
if [ ! -x "$HOME/.cargo/bin/rustup" ]; then
  log "installing rustup"
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --default-toolchain none
else
  log "rustup already installed"
fi
# shellcheck disable=SC1091
. "$HOME/.cargo/env"

# Install the toolchain the repo pins. rustup reads rust-toolchain
# automatically on `cargo` invocations, but we install it eagerly so
# the first CI run does not spend 5 min downloading it.
log "installing toolchain components for the pinned channel"
rustup component add rustfmt clippy llvm-tools-preview

# ---- cargo-llvm-cov ----------------------------------------------
if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  log "installing cargo-llvm-cov"
  cargo install cargo-llvm-cov
else
  log "cargo-llvm-cov already installed"
fi

log "done."
log "next: download the actions runner package and run config.sh + svc.sh"
log "      — see scripts/ci-runner/README.md § 'Register the runner with GitHub'"
