#!/bin/zsh
set -euo pipefail
cd "$(dirname "$0")"
SSHUTTLE="${SSHUTTLE:-/opt/homebrew/bin/sshuttle}"
HOST="${1:-root@117.55.227.80}"
USER_NAME="${SUDO_USER:-$USER}"
cidrs=()
while IFS= read -r line; do
  line="${line%%#*}"
  line="${line// /}"
  [[ -n "$line" ]] && cidrs+=("$line")
done < wechat_cidrs.txt

PY="$(command -v python3 || true)"
if [[ -n "$PY" && "${FORCE_HOP:-}" != 1 ]]; then
  if ! sudo -u "${USER_NAME}" -H "$PY" -c "import sys; sys.path.insert(0, '.'); from direct_or_hop import campus_needs_wechat_hop; raise SystemExit(0 if campus_needs_wechat_hop() else 1)"; then
    echo "微信这会儿校园网通，不开新转发（已有的先留着防抖）"
    exit 0
  fi
fi

echo "用 ${USER_NAME} 的 SSH 走 ${HOST}，转发微信网段…"
IDENT="$PWD/.us_vps_ed25519"
SSH_CMD="sudo -u ${USER_NAME} -H ssh -i ${IDENT} -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=12 -o ServerAliveInterval=15 -o ServerAliveCountMax=4"

if ! sudo -u "${USER_NAME}" -H ssh -i "${IDENT}" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=12 "${HOST}" "echo ok" >/dev/null; then
  echo "SSH 到 ${HOST} 失败" >&2
  exit 1
fi

# 重载时先停旧进程，否则 pf 规则叠两份。
if [[ -f "$PWD/.sshuttle.pid" ]]; then
  old="$(cat "$PWD/.sshuttle.pid" 2>/dev/null || true)"
  if [[ -n "${old}" ]]; then
    kill "${old}" 2>/dev/null || true
  fi
  rm -f "$PWD/.sshuttle.pid"
fi
pkill -f "/opt/homebrew/bin/sshuttle -r ${HOST}" 2>/dev/null || true
sleep 0.4

"${SSHUTTLE}" \
  -r "${HOST}" \
  --method pf \
  --disable-ipv6 \
  --pidfile "$PWD/.sshuttle.pid" \
  -D \
  --exclude 117.55.227.80 \
  --exclude 10.0.0.0/8 \
  --exclude 116.62.109.80/32 \
  --ssh-cmd "${SSH_CMD}" \
  "${cidrs[@]}" >>"$PWD/sshuttle.log" 2>&1

sleep 0.6
if [[ ! -f "$PWD/.sshuttle.pid" ]]; then
  pgrep -n -f "/opt/homebrew/bin/sshuttle -r ${HOST}" >"$PWD/.sshuttle.pid" || true
fi

if [[ -f "$PWD/.sshuttle.pid" ]] && kill -0 "$(cat "$PWD/.sshuttle.pid")" 2>/dev/null; then
  echo "微信 TCP hop 已开，pid=$(cat "$PWD/.sshuttle.pid")"
else
  echo "sshuttle 没留下进程，看 sshuttle.log" >&2
  tail -20 "$PWD/sshuttle.log" >&2 || true
  exit 1
fi
