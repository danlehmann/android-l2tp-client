#!/bin/bash
# One-time setup of the strongSwan + xl2tpd + pppd test server VM (Debian 13, arm64).
# Downloads Debian's cloud image, verifies it, creates an overlay disk, a fresh SSH key
# and the cloud-init seed. Needs qemu-system-aarch64, qemu-img, cloud-localds (cloud-image-utils),
# the AAVMF firmware (qemu-efi-aarch64), curl and sha512sum. Then run ./start.sh --wait;
# first boot installs packages and reboots once, which can take 10-15 minutes.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
URL=${DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/trixie/latest}
BASE=debian-13-genericcloud-arm64.qcow2
mkdir -p "$DIR/image" "$DIR/keys" "$DIR/run"
cd "$DIR/image"

if [ ! -f "$BASE" ]; then
    curl -fL --proto '=https' -o "$BASE.part" "$URL/$BASE"
    curl -fsSL --proto '=https' -o SHA512SUMS "$URL/SHA512SUMS"
    want=$(awk -v f="$BASE" '$2 == f {print $1}' SHA512SUMS)
    got=$(sha512sum "$BASE.part" | awk '{print $1}')
    [ -n "$want" ] && [ "$want" = "$got" ] || { echo "checksum mismatch for $BASE" >&2; exit 1; }
    mv "$BASE.part" "$BASE"
fi

if [ -f disk.qcow2 ]; then
    echo "image/disk.qcow2 exists; delete image/disk.qcow2 and image/efivars.fd to rebuild"
    exit 0
fi
[ -f "$DIR/keys/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C l2tp-testserver -f "$DIR/keys/id_ed25519"
sed "s#@SSH_PUBKEY@#$(cat "$DIR/keys/id_ed25519.pub")#" "$DIR/seed/user-data" > user-data.rendered
cloud-localds seed.iso user-data.rendered "$DIR/seed/meta-data"
rm user-data.rendered
cp /usr/share/AAVMF/AAVMF_VARS.fd efivars.fd
qemu-img create -q -f qcow2 -b "$BASE" -F qcow2 disk.qcow2 10G
echo "ready: run $DIR/start.sh --wait"
