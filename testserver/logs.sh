#!/bin/bash
# Usage: logs.sh            dump charon, xl2tpd and pppd logs
#        logs.sh -f         follow all three live
#        logs.sh charon|xl2tpd|pppd [-f]   just one
DIR="$(cd "$(dirname "$0")" && pwd)"
S="$DIR/ssh.sh"
FOLLOW=no; WHICH=all
for a in "$@"; do case "$a" in -f) FOLLOW=yes;; charon|xl2tpd|pppd) WHICH=$a;; esac; done
charon() { [ $FOLLOW = yes ] && echo "tail -n 50 -F /var/log/charon.log" || echo "cat /var/log/charon.log"; }
xl2tpd() { [ $FOLLOW = yes ] && echo "journalctl -u xl2tpd -n 50 -f -o short-precise" || echo "journalctl -u xl2tpd --no-pager -o short-precise"; }
pppd()   { [ $FOLLOW = yes ] && echo "tail -n 50 -F /var/log/pppd.log" || echo "cat /var/log/pppd.log"; }
if [ $WHICH != all ]; then exec "$S" "$($WHICH)"; fi
if [ $FOLLOW = yes ]; then
  exec "$S" "tail -n 30 -F /var/log/charon.log /var/log/pppd.log & journalctl -u xl2tpd -n 30 -f -o short-precise & wait"
fi
"$S" "echo '===== charon (/var/log/charon.log) ====='; $(charon); echo; echo '===== xl2tpd (journalctl -u xl2tpd) ====='; $(xl2tpd); echo; echo '===== pppd (/var/log/pppd.log) ====='; $(pppd)"
