#!/bin/bash
# Runs the protocol core against the strongSwan/xl2tpd test VM (testserver/).
set -uo pipefail
cd "$(dirname "$0")"
SERVER=${SERVER:-127.0.0.1}
SRV=testserver
rm -rf build/core build/test && mkdir -p build/core build/test
javac --release 11 -Xlint:-options -d build/core $(find core/src -name '*.java') || exit 1
javac --release 11 -Xlint:-options -cp build/core -d build/test $(find test/src -name '*.java') || exit 1
run() { java -Dsettle=1000 -cp build/core:build/test net.daniellehmann.l2tpvpn.core.Harness "$@"; }
pass=0; fail=0
check() {  # name, expected-regex, logfile
    if grep -qE "$2" "$3"; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1 (see $3)"; fail=$((fail+1)); fi
}
L=build/testlogs; mkdir -p $L

java -cp build/core:build/test net.daniellehmann.l2tpvpn.core.VectorsTest > $L/vectors.log 2>&1
check "known-answer vectors" '^PASS modp2048' $L/vectors.log
! grep -q "^FAIL" $L/vectors.log || { echo "FAIL vectors"; fail=$((fail+1)); }

java -cp build/core:build/test net.daniellehmann.l2tpvpn.core.SocksTest > $L/socks.log 2>&1
check "SOCKS5 proxy" '^ALL PASSED' $L/socks.log

run $SERVER testpsk123 testuser testpass > $L/connect.log 2>&1
check "connect + ping server/host/internet" 'RESULT: OK' $L/connect.log

java -cp build/core:build/test net.daniellehmann.l2tpvpn.core.IkeRobustnessTest > $L/robust.log 2>&1
check "forged/malformed Phase 1 input is ignored" '^PASS random garbage' $L/robust.log
! grep -q "^FAIL" $L/robust.log || { echo "FAIL robustness: $(grep "^FAIL" $L/robust.log)"; fail=$((fail+1)); }

run $SERVER wrongpsk testuser testpass > $L/badpsk.log 2>&1
check "wrong PSK is reported (and retried, never fatal)" 'STATE CONNECTING.*pre-shared key' $L/badpsk.log
! grep -q 'STATE FAILED' $L/badpsk.log || { echo "FAIL wrong PSK was treated as permanent"; fail=$((fail+1)); }

run $SERVER testpsk123 testuser wrong > $L/badpass.log 2>&1
check "wrong password fails fast and permanently" 'STATE FAILED.*username and password' $L/badpass.log

run $SERVER testpsk123 testuser testpass 15 50 > $L/rekey.log 2>&1
check "3 make-before-break rekeys, zero loss" 'RESULT: OK' $L/rekey.log
[ "$(grep -c 'rekey complete' $L/rekey.log)" -ge 3 ] || { echo "FAIL rekey count"; fail=$((fail+1)); }

(sleep 12; $SRV/ssh.sh 'systemctl restart strongswan xl2tpd') >/dev/null 2>&1 &
run $SERVER testpsk123 testuser testpass 2400 40 > $L/restart.log 2>&1
wait
check "recovers from server restart" 'lost our session' $L/restart.log
check "...and is connected again" 'ping 192.168.42.1 ok' <(sed -n '/lost our session/,$p' $L/restart.log)

echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
