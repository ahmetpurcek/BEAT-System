#!/usr/bin/env bash
#############################################################################
# BEAT Kamera Testbedi - durdurucu
# Docker konteynerlerini ve tum sahte kamera yayincilarini kapatir.
#############################################################################
set -u
RUN=/tmp/beat-cam

log() { printf '\033[36m[testbed]\033[0m %s\n' "$*"; }

log "Docker konteynerleri kaldiriliyor..."
docker rm -f beat-cam-open beat-cam-auth beat-cam >/dev/null 2>&1 || true

if [ -d "$RUN" ]; then
  for f in "$RUN"/*.pid; do
    [ -e "$f" ] || continue
    pid=$(cat "$f" 2>/dev/null)
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      log "  durduruldu: $(basename "$f" .pid) (pid $pid)"
    fi
    rm -f "$f"
  done
  rm -f "$RUN"/*.log 2>/dev/null || true
  rmdir "$RUN" 2>/dev/null || true
fi

log "Kalan mediamtx/ffmpeg surecleri kontrol ediliyor..."
left=$(ps -eo pid,args | grep -E "mediamtx|mjpeg_server" | grep -v grep | wc -l)
log "kalan surec sayisi: $left"
log "Testbed durduruldu."
