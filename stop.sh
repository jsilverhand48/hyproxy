#!/usr/bin/env bash
# stop.sh - stop the full hyproxy stack on this machine: the baremetal Go data
# plane, the uvicorn control-plane apps, the Docker Compose services, and the
# hyproxy systemd units. Idempotent and safe to re-run; systemd also invokes it
# as the ExecStop of hyproxy.service.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { printf '  %s\n' "$*"; }
step() { printf '==> %s\n' "$*"; }

# TERM every process whose full command line matches the extended-regex
# pattern, wait up to ~2s for them to exit, then SIGKILL any survivors.
# $pids is intentionally unquoted so it expands into one argument per PID.
kill_pat() {
  local desc="$1" pat="$2" pids
  pids="$(pgrep -f "$pat" 2>/dev/null || true)"
  if [ -z "$pids" ]; then
    info "$desc: not running"
    return
  fi
  info "$desc: stopping ($(echo "$pids" | tr '\n' ' '))"
  kill $pids 2>/dev/null || true
  for _ in 1 2 3 4 5 6; do
    sleep 0.3
    pgrep -f "$pat" >/dev/null 2>&1 || return
  done
  pids="$(pgrep -f "$pat" 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    info "$desc: forcing (SIGKILL)"
    kill -9 $pids 2>/dev/null || true
  fi
}


# --- 1. Go data plane --------------------------------------------------------
# The public TLS ingress binary (dataplane/bin/dataplane) launched by start.sh.
step "data plane"
kill_pat "dataplane binary" "bin/dataplane( |$)|/dataplane/bin/dataplane"

# --- 2. Control-plane apps (uvicorn: idp / admin / authz) --------------------
# These normally run inside the compose stack (brought down next), but pgrep
# also sees containerized processes, so this catches those as well as any
# instance that was launched directly on the host.
step "control-plane apps"
kill_pat "uvicorn (idp/admin/authz)" "uvicorn hyproxy\.(idp|admin|authz)\.app:app"

# --- 3. systemd units --------------------------------------------------------
# Stops hyproxy.service plus the ACME renewal timer and oneshot, if installed.
# hyproxy.service's ExecStop is this script, so stopping it re-runs stop.sh;
# the nested run finds nothing left and exits cleanly. A stop failure usually
# means this shell lacks privileges for systemctl.
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

# --- 4. Docker Compose stack -------------------------------------------------
step "docker containers"
if command -v docker >/dev/null 2>&1; then
  if [ -f "${ROOT}/docker-compose.yml" ]; then
    # `down` on the explicit project (matching `name: hyproxy` in
    # docker-compose.yml) removes services from every profile, not just the
    # ones start.sh enabled.
    (cd "$ROOT" && docker compose -p hyproxy down --remove-orphans 2>/dev/null) \
      && info "compose project 'hyproxy' brought down" \
      || info "compose down reported nothing to do"
  else
    info "no docker-compose.yml here; skipping compose"
  fi
  # Catch stray hyproxy-* containers that are no longer part of the project.
  cids="$(docker ps -q --filter 'name=hyproxy-' 2>/dev/null || true)"
  if [ -n "$cids" ]; then
    info "stopping leftover hyproxy-* containers"
    docker stop $cids >/dev/null 2>&1 || true
  fi
else
  info "docker not installed; skipping containers"
fi

step "done - hyproxy stopped"
