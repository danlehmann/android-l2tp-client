#!/bin/bash
# Stop the VM: try clean poweroff via ssh, then kill qemu.
DIR="$(cd "$(dirname "$0")" && pwd)"
PIDFILE="$DIR/run/qemu.pid"
[ -f "$PIDFILE" ] || { echo "not running"; exit 0; }
PID=$(cat "$PIDFILE")
if sudo kill -0 "$PID" 2>/dev/null; then
  "$DIR/ssh.sh" -o ConnectTimeout=5 poweroff >/dev/null 2>&1 || true
  for i in $(seq 1 60); do sudo kill -0 "$PID" 2>/dev/null || break; sleep 1; done
  sudo kill "$PID" 2>/dev/null || true
fi
sudo rm -f "$PIDFILE"; echo "stopped"
