#!/usr/bin/env bash
#############################################################################
# BEAT Kamera Testbedi - baslatici
#
# Gercek bir IP-kamera agini taklit eder:
#   - 2 mediamtx sunucusu (biri acik, biri kimlik dogrulamali)
#   - 5 RTSP "kamera" (H.264 / H.265, farkli cozunurluk ve kimlikler)
#   - 1 MJPEG-over-HTTP "kamera"
#
# Kullanim:
#   ./start.sh          # baslat + dogrula
#   ./start.sh --clear  # once temizle, sonra baslat
#############################################################################
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN=/tmp/beat-cam
IMG=bluenviron/mediamtx:latest
OPEN_NAME=beat-cam-open
AUTH_NAME=beat-cam-auth
MJPG_PORT=8090

mkdir -p "$RUN"

log()  { printf '\033[36m[testbed]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m  [OK]\033[0m %s\n' "$*"; }
err()  { printf '\033[31m  [!!]\033[0m %s\n' "$*"; }

stop_all() {
  log "Eski ornekler temizleniyor..."
  # 'beat-cam' = onceki denemelerden kalan legacy konteyner (8554/8892'yi tutar)
  docker rm -f "$OPEN_NAME" "$AUTH_NAME" beat-cam >/dev/null 2>&1 || true
  # legacy yayinci pid dosyalari
  for lf in /tmp/cam1.pid; do
    [ -e "$lf" ] || continue
    lp=$(cat "$lf" 2>/dev/null)
    [ -n "${lp:-}" ] && kill "$lp" 2>/dev/null || true
    rm -f "$lf"
  done
  for f in "$RUN"/*.pid; do
    [ -e "$f" ] || continue
    pid=$(cat "$f" 2>/dev/null)
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
    rm -f "$f"
  done
  # mjpeg sunucusu
  if [ -e "$RUN/mjpeg.pid" ]; then
    kill "$(cat "$RUN/mjpeg.pid")" 2>/dev/null || true
    rm -f "$RUN/mjpeg.pid"
  fi
  sleep 1
}

wait_port() {
  local host=$1 port=$2 tries=${3:-30}
  for _ in $(seq 1 "$tries"); do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
      exec 3>&- 2>/dev/null || true
      return 0
    fi
    sleep 0.5
  done
  return 1
}

start_ff() {
  # start_ff <isim> <ffmpeg-arg...>
  local name=$1; shift
  nohup setsid "$@" >"$RUN/$name.log" 2>&1 </dev/null &
  echo $! > "$RUN/$name.pid"
}

publish_rtsp() {
  # publish_rtsp <isim> <url> <cozunurluk> <desen> <codec>
  local name=$1 url=$2 size=$3 pattern=$4 codec=$5
  local venc extra
  case "$codec" in
    h264) venc=libx264; extra=(-preset ultrafast -tune zerolatency -pix_fmt yuv420p) ;;
    h265) venc=libx265; extra=(-preset ultrafast -tune zerolatency -pix_fmt yuv420p -tag:v hvc1) ;;
    *)    venc=libx264; extra=(-preset ultrafast -tune zerolatency -pix_fmt yuv420p) ;;
  esac
  start_ff "$name" ffmpeg -loglevel error -re \
    -f lavfi -i "${pattern}=size=${size}:rate=15" \
    -c:v "$venc" "${extra[@]}" \
    -f rtsp -rtsp_transport tcp "$url"
}

probe() {
  # probe <etiket> <url>
  local label=$1 url=$2 out
  out=$(ffprobe -v error -rtsp_transport tcp -select_streams v:0 \
        -show_entries stream=codec_name,width,height \
        -of default=nw=1 "$url" 2>&1 | tr '\n' ' ')
  if echo "$out" | grep -q codec_name; then
    ok "$(printf '%-22s %s' "$label" "$out")"
    return 0
  else
    err "$(printf '%-22s %s' "$label" "BASARISIZ: $out")"
    return 1
  fi
}

main() {
  if [ "${1:-}" = "--clear" ]; then
    stop_all
  else
    # sadece kendi sureclerimizi durdur
    stop_all
  fi

  log "Docker imaji kontrol ediliyor..."
  docker image inspect "$IMG" >/dev/null 2>&1 || docker pull "$IMG" >/dev/null 2>&1

  log "mediamtx sunuculari baslatiliyor..."
  docker run -d --name "$OPEN_NAME" --network host \
    -v "$HERE/mediamtx-open.yml:/mediamtx.yml:ro" "$IMG" >/dev/null
  docker run -d --name "$AUTH_NAME" --network host \
    -v "$HERE/mediamtx-auth.yml:/mediamtx.yml:ro" "$IMG" >/dev/null

  wait_port 127.0.0.1 8554 30 && ok "acik RTSP sunucu :8554 hazir" || err ":8554 acilmadi"
  wait_port 127.0.0.1 8555 30 && ok "kimlikli RTSP sunucu :8555 hazir" || err ":8555 acilmadi"

  log "Sahte kameralar yayinlanıyor (ffmpeg)..."

  # --- acik sunucu (8554) ---
  publish_rtsp cam1 rtsp://127.0.0.1:8554/cam1 640x360  testsrc2  h264
  publish_rtsp cam2 rtsp://127.0.0.1:8554/cam2 1280x720 testsrc    h264
  publish_rtsp cam3 rtsp://127.0.0.1:8554/cam3 640x360  testsrc2  h265
  publish_rtsp cam4 rtsp://127.0.0.1:8554/cam4 320x240  smptebars h264

  # --- kimlik dogrulamali sunucu (8555): yayin icin admin gerekli ---
  publish_rtsp authcam rtsp://admin:admin123@127.0.0.1:8555/cam1 640x360 testsrc2 h264

  # --- MJPEG-over-HTTP kamerasi ---
  log "MJPEG sunucusu baslatiliyor (:${MJPG_PORT})..."
  nohup setsid python3 "$HERE/mjpeg_server.py" "$MJPG_PORT" 640x360 testsrc2 \
    >"$RUN/mjpeg.log" 2>&1 </dev/null &
  echo $! > "$RUN/mjpeg.pid"
  wait_port 127.0.0.1 "$MJPG_PORT" 20 && ok "MJPEG sunucu :${MJPG_PORT} hazir" || err ":${MJPG_PORT} acilmadi"

  sleep 2
  echo
  log "=== DOGRULAMA (ffprobe) ==="
  probe "cam1 (H264 640x360)"   rtsp://127.0.0.1:8554/cam1
  probe "cam2 (H264 1280x720)"  rtsp://127.0.0.1:8554/cam2
  probe "cam3 (H265 640x360)"   rtsp://127.0.0.1:8554/cam3
  probe "cam4 (H264 320x240)"   rtsp://127.0.0.1:8554/cam4
  probe "authcam (admin)"       rtsp://admin:admin123@127.0.0.1:8555/cam1

  echo
  log "=== ERISIM KONTROLLERI (auth sunucu) ==="
  if ffprobe -v error -rtsp_transport tcp -timeout 3000000 -select_streams v:0 \
       -show_entries stream=codec_name -of default=nw=1 \
       rtsp://127.0.0.1:8555/cam1 >/dev/null 2>&1; then
    err "anonim erisim ENGELLENMEDI (beklenmiyordu!)"
  else
    ok "anonim erisim reddedildi (beklenen)"
  fi
  if ffprobe -v error -rtsp_transport tcp -select_streams v:0 \
       -show_entries stream=codec_name -of default=nw=1 \
       rtsp://viewer:12345@127.0.0.1:8555/cam1 >/dev/null 2>&1; then
    ok "viewer:12345 ile okuma basarili (zayif parola)"
  else
    err "viewer:12345 ile okuma basarisiz"
  fi

  echo
  log "MJPEG testi:"
  if curl -s --max-time 3 "http://127.0.0.1:${MJPG_PORT}/stream.mjpg" | head -c 200 | grep -q "image/jpeg"; then
    ok "MJPEG akisi JPEG kare uretiyor"
  else
    err "MJPEG akisi dogrulanamadi"
  fi

  echo
  log "Testbed hazir. Kamera erisim bilgileri: testbed/README.md"
  log "Durdurmak icin: ./stop.sh"
}

main "$@"
