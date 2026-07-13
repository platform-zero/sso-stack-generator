#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[jellyfin-ffmpeg-websafe-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
CONTRACT_ROOT="${WEBSERVICES_CONTRACT_ROOT:-$ROOT_DIR}"
if [ "$CONTRACT_ROOT" = "$ROOT_DIR" ] && [ ! -f "$CONTRACT_ROOT/stack.config/jellyfin/ffmpeg-websafe.sh" ] && [ -f "$ROOT_DIR/dist/build/build/stack.config/jellyfin/ffmpeg-websafe.sh" ]; then
  CONTRACT_ROOT="$ROOT_DIR/dist/build/build"
elif [ "$CONTRACT_ROOT" = "$ROOT_DIR" ] && [ ! -f "$CONTRACT_ROOT/stack.config/jellyfin/ffmpeg-websafe.sh" ] && [ -f "$ROOT_DIR/dist/build/stack.config/jellyfin/ffmpeg-websafe.sh" ]; then
  CONTRACT_ROOT="$ROOT_DIR/dist/build"
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fake_ffmpeg="$tmp_dir/ffmpeg"
output_file="$tmp_dir/args.txt"
cat > "$fake_ffmpeg" <<'EOF_FFMPEG'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$FAKE_FFMPEG_OUTPUT"
EOF_FFMPEG
chmod +x "$fake_ffmpeg"

FAKE_FFMPEG_OUTPUT="$output_file" \
JELLYFIN_REAL_FFMPEG="$fake_ffmpeg" \
JELLYFIN_FFMPEG_WEBSAFE_LOG="$tmp_dir/websafe-ffmpeg.log" \
JELLYFIN_FORCE_BROWSER_SAFE_H264=true \
JELLYFIN_HLS_TIME=6 \
JELLYFIN_TRANSCODE_H264_PROFILE=baseline \
JELLYFIN_TRANSCODE_H264_LEVEL=31 \
"$CONTRACT_ROOT/stack.config/jellyfin/ffmpeg-websafe.sh" \
  -i input.mkv \
  -codec:v:0 h264_nvenc \
  -profile:v:0 high \
  -g:v:0 72 \
  -hls_time 3 \
  -f hls \
  -y /cache/transcodes/example.m3u8

grep -Fx -- '-hls_time' "$output_file" >/dev/null
if ! awk 'previous == "-hls_time" && $0 == "6" { found = 1 } { previous = $0 } END { exit(found ? 0 : 1) }' "$output_file"; then
  printf '[jellyfin-ffmpeg-websafe-test] expected HLS time override to 6\n' >&2
  cat "$output_file" >&2
  exit 1
fi
if ! awk 'previous == "-profile:v:0" && $0 == "baseline" { found = 1 } { previous = $0 } END { exit(found ? 0 : 1) }' "$output_file"; then
  printf '[jellyfin-ffmpeg-websafe-test] expected browser-safe H.264 profile\n' >&2
  cat "$output_file" >&2
  exit 1
fi
if ! awk 'previous == "-bf:v:0" && $0 == "0" { found = 1 } { previous = $0 } END { exit(found ? 0 : 1) }' "$output_file"; then
  printf '[jellyfin-ffmpeg-websafe-test] expected B-frames disabled for browser-safe mode\n' >&2
  cat "$output_file" >&2
  exit 1
fi

printf '[jellyfin-ffmpeg-websafe-test] ok\n' >&2
