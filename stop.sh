#!/usr/bin/env bash
# stop.sh - stop everything hyproxy on this machine: local dev processes, the
# Docker Compose stack, any installed systemd units, and the user-space Postgres
# dev cluster. Idempotent and safe to re-run; process matches are anchored to
# this repo so it will not touch unrelated programs.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { printf '  %s\n' "$*"; }
step() { printf '==> %s\n' "$*"; }

# Gracefully TERM, then KILL after a short grace period, every process whose
# full command line matches an extended-regex pattern.
kill_pat() {
  local desc="$1" pat="$2" pids
  pids="$(pgrep -f "$pat" 2>/dev/null || true)"
  if [ -z "$pids" ]; then
    info "$desc: not running"
    return
  fi
  info "$desc: stopping ($(echo "$pids" | tr '\n' ' '))"
  # shellcheck disable=SC2086
  kill $pids 2>/dev/null || true
  for _ in 1 2 3 4 5 6; do
    sleep 0.3
    pgrep -f "$pat" >/dev/null 2>&1 || return
  done
  pids="$(pgrep -f "$pat" 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    info "$desc: forcing (SIGKILL)"
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
  fi
}

# --- 1. Frontend dev servers (Vite UI + guac tunnel) -------------------------
step "frontend dev servers"
kill_pat "ui dev server (vite)" "${ROOT}/ui/node_modules/.*vite"
kill_pat "guac tunnel"          "${ROOT}/tunnel/node_modules/.*(vite|tunnel)|${ROOT}/tunnel .*npm"

# --- 2. Go data plane --------------------------------------------------------
step "data plane"
kill_pat "dataplane binary" "bin/dataplane( |$)|/dataplane/bin/dataplane"

# --- 3. Control-plane apps (uvicorn: idp / admin / authz) ---------------------
step "control-plane apps"
kill_pat "uvicorn (idp/admin/authz)" "uvicorn hyproxy\.(idp|admin|authz)\.app:app"

# --- 4. Docker Compose stack -------------------------------------------------
step "docker containers"
if command -v docker >/dev/null 2>&1; then
  if [ -f "${ROOT}/docker-compose.yml" ]; then
    # `down` removes every service in the project regardless of profile; name it
    # explicitly so we hit the stack even when run from elsewhere.
    (cd "$ROOT" && docker compose -p hyproxy down --remove-orphans 2>/dev/null) \
      && info "compose project 'hyproxy' brought down" \
      || info "compose down reported nothing to do"
  else
    info "no docker-compose.yml here; skipping compose"
  fi
  # Belt and suspenders: stop any stray containers named hyproxy-*.
  cids="$(docker ps -q --filter 'name=hyproxy-' 2>/dev/null || true)"
  if [ -n "$cids" ]; then
    info "stopping leftover hyproxy-* containers"
    # shellcheck disable=SC2086
    docker stop $cids >/dev/null 2>&1 || true
  fi
else
  info "docker not installed; skipping containers"
fi

# --- 5. systemd units (production installs only) -----------------------------
step "systemd units"
if command -v systemctl >/dev/null 2>&1; then
  for unit in hyproxy.service hyproxy-acme.timer hyproxy-acme.service; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
      if systemctl is-active --quiet "$unit"; then
        if systemctl stop "$unit" 2>/dev/null; then
          info "$unit: stopped"
        else
          info "$unit: active but stop failed (run as root: 'systemctl stop $unit')"
        fi
      else
        info "$unit: not active"
      fi
    fi
  done
else
  info "systemctl not available; skipping units"
fi

# --- 6. Postgres dev cluster (user-space pgserver) ---------------------------
step "postgres dev cluster"
if [ -d "${ROOT}/server/.dev" ] && command -v uv >/dev/null 2>&1; then
  (cd "${ROOT}/server" && uv run python scripts/devdb.py stop 2>/dev/null) \
    && info "dev cluster stopped" \
    || info "dev cluster not running"
else
  info "no user-space dev cluster (server/.dev absent or uv missing)"
fi

step "done - hyproxy stopped"
