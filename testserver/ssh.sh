#!/bin/bash
# SSH into the guest as root (port 2222). Extra args are passed to ssh (e.g. a command).
DIR="$(cd "$(dirname "$0")" && pwd)"
exec ssh -i "$DIR/keys/id_ed25519" -p 2222 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR root@127.0.0.1 "$@"
