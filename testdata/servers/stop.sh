#!/usr/bin/env bash
state=${LAZYMAIL_SERVERS_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/lazymail-servers}
for pidfile in "$state/run/master.pid" "$state/smtp.pid"; do
  [ -f "$pidfile" ] || continue
  pid=$(cat "$pidfile")
  kill "$pid" 2>/dev/null || continue
  for _ in $(seq 50); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
done
exit 0
