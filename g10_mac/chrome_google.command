#!/bin/zsh
# 双击：用强制代理打开 Chrome（绕开 QUIC）。
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if [[ ! -x "$CHROME" ]]; then
  echo "没找到 Google Chrome" >&2
  exit 1
fi
pkill -x "Google Chrome" 2>/dev/null || true
sleep 0.4
exec "$CHROME" \
  --proxy-server="http://10.0.165.45:8080" \
  --proxy-bypass-list="*.yungu.org;*.yungu-inc.org;*.yunguhs.com;*.dingtalk.com;*.dingtalkapps.com;127.0.0.1;localhost" \
  "https://www.google.com"
