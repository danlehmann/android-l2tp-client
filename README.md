# L2TP VPN for Android

L2TP/IPsec (IKEv1, pre-shared key) client for current Android versions, which
dropped built-in L2TP. Plain Java with no third-party libraries. Network access
is limited to the configured VPN server, and nothing collects telemetry.

Because Android apps cannot send raw ESP, the whole stack runs in userspace on
top of `VpnService`:

```
apps ─ TUN ─ PPP (LCP, MS-CHAPv2/CHAP/PAP, IPCP+DNS) ─ L2TPv2 ─ UDP/1701
          ─ ESP transport (AES-CBC/3DES + HMAC-SHA1/2) ─ UDP/4500 (NAT-T, always forced)
control:  IKEv1 Main Mode PSK + Quick Mode (initiator and responder), answers DPD, rekey
liveness: PPP LCP echo, plus a fast probe after every IPsec re-establishment
```

## Behaviour
- Server proposals: AES-256/128 or 3DES, SHA-1/SHA-2, MODP 1024–4096 groups. ESP uses AES
  or 3DES with SHA-1/SHA-2 HMAC. If needed it falls back to PFS or drops the ID payloads.
- Full tunnel. IPv6 is claimed and dropped so it can't leak around the IPv4 tunnel.
- Every 40 min it re-establishes IKE + ESP make-before-break, with no packet loss.
  It also honours rekeys and deletes the server initiates.
- After any IPsec re-establishment it probes the PPP session. If the server lost it,
  the client reconnects fully within about 6 seconds.
- Any failure is retried with backoff (1 s up to 30 s). The TUN interface stays up meanwhile,
  so traffic is blocked rather than leaked. A rejected username/password (authenticated inside
  the tunnel) stops immediately with a clear message. A wrong PSK keeps retrying while showing
  a "check the pre-shared key" hint: IKEv1 cannot authenticate that rejection, so treating it as
  final would let anyone on the path shut the VPN off with one forged packet.
- Network changes (Wi-Fi ↔ cellular, address change) trigger an immediate reconnect.
- Supports Always-on VPN and "Block connections without VPN", and has a Quick Settings tile.
- Optional SOCKS5 proxy (TCP only, port 1080) that gives the device's Linux VM access to the tunnel,
  because Android routes VM traffic around every VPN. See "Linux VM" below.
- The PSK and password are encrypted with a non-exportable Android Keystore key. Backup is disabled.

Not supported: certificate auth (L2TP/IPsec RSA), L2TP tunnel secrets, IPv6 inside the tunnel,
IPv6-only servers.

## Linux VM
Tick "Share with the Linux VM", connect, and the log shows the address to use. The proxy listens
only on the VM's `avf_tap` link, has no password, and accepts only addresses on that link, so
any process in the VM can use it. It refuses connections unless the VPN is connected, and its
lookups and sockets are bound to the VPN network, so nothing falls back to Wi-Fi.

Use `socks5h://` so that names are resolved by the VPN's DNS servers:
```
ALL_PROXY=socks5h://<address>:1080 curl http://intranet.example
ssh -o ProxyCommand='nc -X 5 -x <address>:1080 %h %p' host.example
```

## Install
There are no prebuilt releases. Build the APK as below and install it with
`adb install build/l2tpvpn.apk`, or copy it to the device and open it.
Enter the server, pre-shared key, username and password, then tap Connect and accept
Android's VPN prompt.

## Build
`./build.sh` produces `build/l2tpvpn.apk`. It needs JDK 17+, `aapt2`, `zipalign`, `apksigner`,
an API 34 `android.jar` and Google's `r8` jar. Paths are configurable through environment variables.
On the first run it creates the signing key at `~/.android/l2tpvpn-release.jks`. **Back it up.**
Updates must be signed with the same key.

## Test
`./test.sh` runs known-answer crypto vectors. It then runs the real engine against the
strongSwan + xl2tpd + pppd VM in `testserver/`. The scenarios: connect and ping, forged Phase 1
input, wrong PSK, wrong password, rapid rekeys with continuous pings, and a server restart.
It also tests the SOCKS5 proxy on its own.

The VM is an arm64 Debian 13 guest in QEMU, with test credentials only:
```
testserver/setup.sh          # one-time: download and verify the Debian image, make SSH key and seed
testserver/start.sh --wait   # boots it (sudo, to forward host UDP 500/4500)
./test.sh
testserver/stop.sh
```
The first boot installs packages and reboots once, which can take 10–15 minutes; wait until
`testserver/ssh.sh cat /var/log/provision-done` succeeds before testing.
`testserver/logs.sh` shows the charon, xl2tpd and pppd logs. On a non-arm64 host QEMU emulates
the CPU, which is slow but works.

## Security notes
- MODP1024 and 3DES are still offered because many L2TP servers, including UniFi gateways, need
  them. The server picks the strongest proposal it supports. HMAC-MD5 is not offered.
- IKEv1 with a pre-shared key protects the session only as well as the PSK does. Anyone who
  knows the PSK can impersonate the server, so use a long, random one.
- The app has no analytics and no third-party code. Its only network traffic is to the configured
  server, plus the optional Linux VM proxy.

## License
Apache License 2.0, see [LICENSE](LICENSE).
