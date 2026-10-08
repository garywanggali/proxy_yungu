#!/bin/zsh
# Arthur / Fisher 的 G10 Mac：强制浏览器走 G11 8080。
# Chrome 只开 PAC 时会用 QUIC/安全 DNS 直连谷歌，G10 必挂。
# 用法：把 g10_mac 拷过去，终端执行 ./start.sh
set -euo pipefail

PROXY_HOST="10.0.165.18"
PROXY_PORT="8080"
PAC_URL="http://${PROXY_HOST}:${PROXY_PORT}/proxy.pac"

each_svc() {
  networksetup -listallnetworkservices | while IFS= read -r svc; do
    [[ "$svc" == "An asterisk"* ]] && continue
    [[ "$svc" == *"*"* ]] && continue
    case "$svc" in
      Wi-Fi|AirPort|Ethernet|USB*|Thunderbolt*|以太网*|Wi‑Fi) print -r -- "$svc" ;;
    esac
  done
}

echo "G10 → ${PROXY_HOST}:${PROXY_PORT}（关 PAC，开手动 HTTP/HTTPS，Chrome 才会走代理上谷歌）"
each_svc | while IFS= read -r svc; do
  echo "  $svc"
  networksetup -setautoproxystate "$svc" off || true
  networksetup -setwebproxy "$svc" "$PROXY_HOST" "$PROXY_PORT"
  networksetup -setsecurewebproxy "$svc" "$PROXY_HOST" "$PROXY_PORT"
  networksetup -setwebproxystate "$svc" on
  networksetup -setsecurewebproxystate "$svc" on
  networksetup -setsocksfirewallproxystate "$svc" off || true
  networksetup -setproxybypassdomains "$svc" \
    "task.yungu.org" "*.task.yungu.org" "116.62.109.80" \
    "*.yungu.org" "*.yungu-inc.org" "*.yunguhs.com" \
    "*.dingtalk.com" "*.dingtalkapps.com" "*.dingtalk-inc.com" \
    "127.0.0.1" "localhost" "*.local"
done

echo
echo "已开。请完全退出 Chrome / Safari 再打开，然后打开 https://www.google.com"
echo "若仍不行：Chrome 设置 → 隐私和安全 → 安全 DNS → 关闭"
echo "停： $(cd "$(dirname "$0")" && pwd)/stop.sh"
echo "备用 PAC（Safari）：$PAC_URL"
