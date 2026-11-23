#!/bin/bash
# Boot the L2TP/IPsec test server VM in the background (idempotent).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
PIDFILE="$DIR/run/qemu.pid"
mkdir -p "$DIR/run"
if [ -f "$PIDFILE" ] && sudo kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "VM already running (pid $(cat "$PIDFILE"))"; exit 0
fi
# QEMU must run as root to bind host UDP 500/4500 (privileged ports).
sudo qemu-system-aarch64 \
  -name l2tp-testserver \
  -machine virt -cpu max -smp 4 -m 2048 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd \
  -drive if=pflash,format=raw,file="$DIR/image/efivars.fd" \
  -drive if=virtio,format=qcow2,file="$DIR/image/disk.qcow2" \
  -drive if=virtio,format=raw,readonly=on,file="$DIR/image/seed.iso" \
  -netdev user,id=n0,hostfwd=udp::500-:500,hostfwd=udp::4500-:4500,hostfwd=tcp::2222-:22 \
  -device virtio-net-pci,netdev=n0 \
  -device virtio-rng-pci \
  -display none -monitor none \
  -serial file:"$DIR/run/serial.log" \
  -pidfile "$PIDFILE" -daemonize
sudo chmod 644 "$PIDFILE" "$DIR/run/serial.log" 2>/dev/null || true
echo "VM started (pid $(cat "$PIDFILE")). Serial log: $DIR/run/serial.log"
if [ "${1:-}" = "--wait" ]; then
  echo -n "Waiting for SSH"
  for i in $(seq 1 600); do
    if "$DIR/ssh.sh" -o ConnectTimeout=3 true 2>/dev/null; then echo " up (${SECONDS}s)"; exit 0; fi
    echo -n .; sleep 1
  done
  echo " timed out"; exit 1
fi
