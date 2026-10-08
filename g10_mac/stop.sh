#!/bin/zsh
set -euo pipefail
networksetup -listallnetworkservices | while IFS= read -r svc; do
  [[ "$svc" == "An asterisk"* ]] && continue
  [[ "$svc" == *"*"* ]] && continue
  case "$svc" in
    Wi-Fi|AirPort|Ethernet|USB*|Thunderbolt*|以太网*|Wi‑Fi)
      networksetup -setwebproxystate "$svc" off || true
      networksetup -setsecurewebproxystate "$svc" off || true
      networksetup -setautoproxystate "$svc" off || true
      echo "已关代理：$svc"
      ;;
  esac
done
