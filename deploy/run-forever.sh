#!/usr/bin/env bash
# 没有 systemd 的开发机（容器类环境）用这个：崩溃自动重启，日志写到数据目录。
#   nohup deploy/run-forever.sh >/dev/null 2>&1 &
# 或在 tmux 里直接运行。停止：kill 这个脚本的进程（会把 TERM 转发给 pa）。
set -u
ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
LOG="${PA_LOG:-$HOME/.personal-agent/logs/daemon.log}"
mkdir -p "$(dirname "$LOG")"
child=0
trap 'kill -TERM "$child" 2>/dev/null; wait "$child"; exit 0' TERM INT
while true; do
  "$ROOT/bin/pa" run >>"$LOG" 2>&1 &
  child=$!
  wait "$child"
  echo "{\"t\":\"$(date -Iseconds)\",\"level\":\"warn\",\"msg\":\"pa 退出（$?），10 秒后重启\"}" >>"$LOG"
  sleep 10
done
