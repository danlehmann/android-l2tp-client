#!/bin/bash
# Runs INSIDE the guest (as root). Spins up an L2TP/IPsec CLIENT in a separate
# network+mount namespace (own charon + xl2tpd + pppd), connects to the local
# server over a veth pair, pings through the tunnel, then tears down.
# Usage from host:  ./ssh.sh 'bash -s' < selftest-guest.sh
set -u
W=/root/selftest; rm -rf $W; mkdir -p $W/swanctl/conf.d $W/sd $W/xl2tpd
ip netns del cli 2>/dev/null; ip link del v-srv 2>/dev/null
ip netns add cli
ip link add v-srv type veth peer name v-cli
ip link set v-cli netns cli
ip addr add 10.99.0.1/24 dev v-srv; ip link set v-srv up
ip -n cli addr add 10.99.0.2/24 dev v-cli; ip -n cli link set v-cli up; ip -n cli link set lo up
cp -a /etc/swanctl/. $W/swanctl/; rm -f $W/swanctl/conf.d/*
cat > $W/swanctl/conf.d/cli.conf <<'C'
connections { cli { version = 1
  proposals = ${IKE_PROP:-aes128-sha1-modp1024}
  remote_addrs = 10.99.0.1
  local { auth = psk } remote { auth = psk }
  children { cli { mode = transport
    local_ts = dynamic[udp/1701]
    remote_ts = dynamic[udp/1701]
    esp_proposals = ${ESP_PROP:-aes128-sha1} } } } }
secrets { ike-cli { secret = "testpsk123" } }
C
sed -i "s/\${IKE_PROP:-aes128-sha1-modp1024}/${IKE_PROP:-aes128-sha1-modp1024}/; s/\${ESP_PROP:-aes128-sha1}/${ESP_PROP:-aes128-sha1}/" $W/swanctl/conf.d/cli.conf
cp -a /etc/strongswan.d/. $W/sd/
cat > $W/sd/zz-l2tp-logging.conf <<'C'
charon-systemd { filelog { cli { path = /root/selftest/charon-cli.log
  default = 1
  ike = 1 } } }
C
cat > $W/xl2tpd/xl2tpd.conf <<'C'
[global]
port = 1701
listen-addr = 10.99.0.2
[lac srv]
lns = 10.99.0.1
ppp debug = yes
pppoptfile = /root/selftest/options.cli
length bit = yes
C
cat > $W/options.cli <<'C'
name testuser
password testpass
noauth
noipdefault
refuse-eap
noccp
nodefaultroute
mtu 1400
mru 1400
debug
logfile /root/selftest/pppd-cli.log
C
cat > $W/inner.sh <<'C'
mount -t tmpfs none /run && mkdir -p /run/xl2tpd
mount --bind /root/selftest/swanctl /etc/swanctl
mount --bind /root/selftest/sd /etc/strongswan.d
mount --bind /root/selftest/xl2tpd /etc/xl2tpd
/usr/sbin/charon-systemd >/dev/null 2>&1 &
for i in $(seq 30); do [ -S /run/charon.vici ] && break; sleep 0.5; done
swanctl --load-all >/dev/null 2>&1
echo "--- IKE/ESP initiate"; swanctl --initiate --child cli 2>&1 | grep -E "established|failed|IKE_SA|CHILD_SA" | tail -3
swanctl --list-sas 2>/dev/null | head -8
xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf -p /run/xl2tpd.pid -C /run/xl2tpd/l2tp-control > /root/selftest/xl2tpd-cli.log 2>&1 &
sleep 2; echo "c srv" > /run/xl2tpd/l2tp-control
for i in $(seq 40); do ip -4 addr show ppp0 2>/dev/null | grep -q inet && break; sleep 0.5; done
echo "--- ppp0 in client ns"; ip -4 addr show ppp0
ip route add default dev ppp0 2>/dev/null
echo "--- ping server end 192.168.42.1";  ping -c2 -W3 192.168.42.1 | tail -2
echo "--- ping 10.0.2.2 via tunnel+NAT"; ping -c2 -W3 10.0.2.2 | tail -2
echo "--- ping 1.1.1.1 via tunnel+NAT";  ping -c2 -W3 1.1.1.1 | tail -2
echo "d srv" > /run/xl2tpd/l2tp-control; sleep 2
swanctl --terminate --ike cli >/dev/null 2>&1
kill %2 %1 2>/dev/null; sleep 1; pkill -f "xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf -p /run/xl2tpd.pid" ; true
C
ip netns exec cli unshare -m --propagation private bash $W/inner.sh
sleep 1
ip netns pids cli | xargs -r kill 2>/dev/null; sleep 1
ip netns del cli; ip link del v-srv 2>/dev/null
echo "--- server pppd log tail"; tail -15 /var/log/pppd.log
