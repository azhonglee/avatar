#!/usr/bin/env bash
# 无 systemd 环境（开发机/容器）守护脚本：独立运行 feishu-gateway，崩溃自动重启。
# 用法：
#   export FEISHU_GW_KEY="<32字节固定密钥>"
#   nohup deploy/feishu-gateway-forever.sh >/dev/null 2>&1 &
set -u
umask 077
ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
LOG="${FEISHU_GW_LOG:-$HOME/.feishu-gateway/logs/gateway.log}"
mkdir -p "$(dirname "$LOG")"
chmod 0700 "$HOME/.feishu-gateway" "$(dirname "$LOG")" 2>/dev/null || true
child=0
trap 'kill -TERM "$child" 2>/dev/null; wait "$child"; exit 0' TERM INT
while true; do
  "$ROOT/bin/feishu-gateway" run >>"$LOG" 2>&1 &
  child=$!
  wait "$child"
  rc=$?
  echo "{\"t\":\"$(date -Iseconds)\",\"level\":\"warn\",\"service\":\"feishu-gateway\",\"msg\":\"feishu-gateway 退出（$rc），5 秒后重启\"}" >>"$LOG"
  sleep 5
done
