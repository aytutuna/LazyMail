#!/usr/bin/env bash
here=$(cd "$(dirname "$0")" && pwd)
id=$(printf %s "$here" | cksum | cut -d' ' -f1)
state=${XDG_CACHE_HOME:-$HOME/.cache}/lazymail-servers-$id
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
