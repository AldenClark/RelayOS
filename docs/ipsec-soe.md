# IPsec and SOE hardware qualification

## Supported build path

The default MD/MF build includes strongSwan 6.0.7 from the pinned packages
feed, charon, swanctl/VICI, a selected PSK-capable plugin set, kernel XFRM
and ESP, native XFRM interfaces, ip-full, kmod-crypto-hw-eip93, and
kmod-crypto-airoha-armv8.
The OpenWrt package's dependencies may include IPv6 XFRM even though
RelayOS currently forwards IPv4 only. No userspace TUN/ESP engine,
legacy starter/stroke, or iptables updown plugin is selected.

The first-boot IPsec configuration contains no connection or credential.
Its global enable flag is 0 and automatic strongSwan route installation
is disabled. Settings -> IPsec provides a global switch, multiple peers with
individual switches, basic addressing/PSK settings and advanced proposals.
Save & Apply provisions native swanctl, per-peer XFRM addressing, explicit
protected routes and the IPsec firewall zone. See
[IPsec management](ipsec-management.md) for the complete lifecycle contract.
Manual control fails closed when AirRoute Agent owns the node or ownership
cannot be determined. Credential and runtime configuration directories are
root-only.

## Why EIP-93 is the initial supported hardware path

In the locked OpenWrt commit, both AN7581 and AN7583 SoC device trees expose
crypto@1fb70000 with compatible inside-secure,safexcel-eip93ies and IRQ 44.
The upstream module is kmod-crypto-hw-eip93. Linux v6.18.64 registers
authenc(hmac(sha256),cbc(aes)) with EIP93 priority 1500 when the hardware
advertises those algorithms. The ESP layer requests the normal Crypto API
algorithm; selection and execution still depend on runtime registration,
algorithm, transform flags and request shape. EIP93 does not itself
advertise a direct AES-GCM or full XFRM packet-offload provider.

Sources:
- [OpenWrt crypto packages](https://github.com/openwrt/openwrt/blob/64c777f3af8ad1503c257afe686e44200de832c7/package/kernel/linux/modules/crypto.mk)
- [Linux v6.18.64 EIP93 AEAD driver](https://github.com/gregkh/linux/blob/v6.18.64/drivers/crypto/inside-secure/eip93/eip93-aead.c)
- [Linux v6.18.64 ESP transform allocation](https://github.com/gregkh/linux/blob/v6.18.64/net/ipv4/esp4.c)
- [Linux XFRM device offload](https://docs.kernel.org/networking/xfrm/xfrm_device.html)
- [strongSwan swanctl.conf](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html)

Use modern IKEv2 PSK (random 256-bit secret per peer) and test ESP
`aes128-sha256-noesn` or `aes256-sha256-noesn` for the EIP93 Crypto API
path. ESN uses authencesn instead of authenc in ESP; no EIP93 authencesn
implementation is assumed. For `aes128gcm16-noesn`, the Airoha package
autoloads `aes-ce-cipher`, `aes-ce-blk` and `ghash-ce`. On CPUs with
PMULL, `ghash-ce` registers `rfc4106-gcm-aes-ce` and uses ARMv8 AES
and PMULL instructions for ESP. Establish new SAs after loading the
drivers and check that `seqiv(rfc4106-gcm-aes-ce)` in `/proc/crypto`
has active references while the corresponding CHILD_SA packet counters
increase. Do not select obsolete DES, MD5 or SHA1 merely because the
hardware registers them. Keep anti-replay enabled, rekey before sequence
exhaustion, and configure matching proposals on the first-hop peer.
`hw_offload = no` leaves the normal kernel Crypto API selection intact;
it does not disable EIP93. It is not a substitute for hardware counters.

## Provisioning and remote-peer requirements

Use Settings -> IPsec for supported manual peers. The product configuration
is stored in /etc/config/relay_ipsec; the backend generates owned native
sections in /etc/config/ipsec, network and firewall. The native
/etc/init.d/swanctl script loads the configuration. Do not independently edit
generated sections or place a real key in this repository. Existing unmanaged
IPsec configurations must be reviewed before adopting the editor; they are
not silently overwritten or migrated.

For an IPv4 route-based exit, the first-hop peer and the RelayOS node
must agree on authenticated identities, ESP/IKE proposals, traffic selectors
and per-peer addressing. Use a unique nonzero XFRM interface ID on each
local node, set child if_id_in and if_id_out to the matching local ID, and
create the interface with the native netifd xfrm protocol (ifid, tunlink,
mtu). Route only the peer's unique assigned prefixes via that interface;
never install a remote 0.0.0.0/0 default route on the exit node.
Associate the XFRM address alias with the dedicated IPsec firewall zone, with
only tunnel-to-uplink forwarding/NAT, and keep unencrypted uplink traffic
out of this trusted zone. The editor restricts IKE UDP 500/4500 and ESP to
literal endpoint IPv4 addresses when possible. DNS endpoints require a broader
uplink-zone rule because fw4 cannot use hostnames as source-IP filters; see the
explicit authentication and source-filter tradeoff in
[IPsec management](ipsec-management.md). For NATed edge nodes, prefer initiating
toward the public first hop with NAT-T. Management ports remain closed from
the IPsec zone. Before enabling service, verify routes and firewall
rules and ensure protected peer prefixes cannot fall back to plaintext
uplink routing on tunnel failure.

Keep ipsec.globals.rtinstall_enabled=0 for the RelayOS exit role. An enabled
but empty configuration establishes no SA. The editor coordinates the
interface, route, firewall and policy lifecycle, retaining unreachable route
guards for disabled configured peers. It does not provision the first-hop
server, and successful local configuration is not a successful handshake.

## SOE: staged experimental port, not a supported build feature

The relevant project is hurryman2212/OpenW1700k-test:
- [June 14 implementation](https://github.com/hurryman2212/OpenW1700k-test/commit/7c1b5e662f7790b3d23ed143beadc1dcbf6d15f7)
- [August 5 revised implementation](https://github.com/hurryman2212/OpenW1700k-test/commit/5a81eab57cf284df5bd9c4460e6d7bfe0c9102aa)
- [June netdev RFC](https://lkml.rescloud.iu.edu/hypermail/linux/kernel/2606.1/13044.html)

The August commit includes 28 kernel patches touching XFRM lifecycle and
policy generations, SOE registers, QDMA, Ethernet/DSA, and Netfilter/PPE flow
offload. Its driver identifies airoha,en7581-soe at 0x1fbfa000 and has
32 SA table entries. IPv4 outer tunnel, supported crypto and replay/ESN
constraints must be honored. The original tree uses Linux 6.18.40 and
modular airoha Ethernet/NPU; RelayOS uses 6.18.64 and built-in drivers.
OpenWrt's current kmod-ipsec4 explicitly disables INET_ESP_OFFLOAD;
a real SOE port must add proper kernel/package dependencies and reconcile
the XFRM, QDMA and flowtable API changes. The published code only probes
the EN7581 compatible; do not assume it is safe for AN7583 based on a reset
bit or common SoC family. The upstream lock does not contain this driver.

Use a separate MD-only integration branch for a future port: rebase exact
source patches, build and boot with no automatic packet/PPE offload, then
qualify explicit offload on the correct netdev. Do not advertise hardware
ESP support based solely on a driver module or change MF DTS registers by
analogy. Full packet offload may bypass normal software processing;
validate authenticated state, anti-replay, rekey, policy deletion,
flow invalidation, firewall/NAT semantics, interface teardown and SA-table
exhaustion before enabling. Do not enable global flow offload in the
default firewall solely to obtain an IPsec benchmark.

## Hardware acceptance (both boards)

1. Confirm /proc/crypto lists the EIP93 authenc driver and kernel logs show
   successful probe; compare idle RSS and firmware size with the previous
   WireGuard-only image. Registration alone is not proof of SA offload.
2. Establish IKEv2/ESP and test native ESP and NAT-T independently.
   Inspect swanctl --list-sas and /proc/net/xfrm_stat. Use key-redacted
   diagnostics; do not export raw XFRM state containing keys.
3. Compare WireGuard, AES-CBC/HMAC-SHA256 with EIP93, and AES-GCM with CPU
   crypto on the same link, 64/256/512/1400-byte payloads, both directions,
   multiple streams, recording throughput, CPU, drops and latency. Where
   possible instrument EIP93 request/completion counters or traces;
   use a controlled comparison with the accelerator unregistered and
   new SAs, never infer actual usage solely from algorithm names.
4. Test NAT-T reconnect, peer replacement, SA rekey, disable/enable, restart,
   sustained load, malformed peer rejection, coexistence with WireGuard
   and recovery after failure. The IPsec switch must not create a default
   route or modify the WireGuard configuration.
5. For a later SOE prototype repeat on MD with native ESP/NAT-T, DSA
   egress/ingress, stale-flow and SA eviction tests. Test MF separately
   only after verifying its SOE hardware interface and obtaining driver support.

No throughput or SOE readiness claim is made before device testing.
