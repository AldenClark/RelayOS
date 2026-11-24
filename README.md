# RelayOS — Nokia XG-040G-MD / XG-040G-MF

Minimal OpenWrt images for the **second-hop AirRelay exit node**. These are
not general-purpose customer routers. The intended traffic path is:

1. A first-hop server sends IPv4 packets over **Linux kernel WireGuard**.
2. Linux forwards packets from the WireGuard interface to the copper uplink.
3. nftables performs IPv4 masquerading for direct Internet egress.
4. A future Rust AirRelay Agent handles enrollment, cloud configuration and
   WireGuard peer lifecycle. It does **not** process data-plane packets.

The two supported devices are:

| Device | SoC | Target | Image layout |
| --- | --- | --- | --- |
| Nokia XG-040G-MD | Airoha AN7581 | `airoha/an7581` | UBI |
| Nokia XG-040G-MF | Airoha AN7583 | `airoha/an7583` | UBI |

> **Flash warning:** The UBI profiles assume the compatible UBI boot layout.
> Do not flash UBI sysupgrade images onto an unconverted stock-partition
> installation. This project does not install or change BL2, BL31 or U-Boot.
> Preserve a verified serial/bootloader recovery path before flashing.

## Image contents

- **Included:** SoC Ethernet / DSA / PHY, NAND/UBI, procd, UCI/ubus, netifd,
  Dropbear, firewall4/nftables IPv4 NAT, kernel WireGuard (`kmod-wireguard`),
  `wireguard-tools`, and a small bilingual LuCI HTTPS UI with the **RelayOS Console**
  theme, `luci-proto-wireguard`, `uhttpd`, `uhttpd-mod-ubus`, and `px5g-mbedtls`.
- **Excluded:** DHCP server, PPPoE, Wi-Fi, PON userspace, VoIP, strongSwan,
  AirRoute Core, userspace WireGuard, TUN and TPROXY modules.
- The upstream NPU/crypto support and necessary PHY/flash drivers are
  intentionally retained pending hardware validation.
- A one-line build-time DTS patch disables Nokia PON PCS. Ethernet PCS remains enabled.
- Stage 1 removes unused MMC/SD, ext4, USB support and debug features
  using OpenWrt's native env/kernel-config overlay, preserving SPI NAND,
  UBI, Ethernet/PCS, NPU, hardware RNG and watchdog support. Upstream target
  kernel configs remain unmodified.
- `NET_SELFTESTS` is retained: Linux 6.18 gives this hidden kernel feature a
  `PHYLIB` default and the required DSA switch framework also implies it.
  It provides kernel Ethernet/PHY self-test helpers, not a resident userspace
  testing service. Removing it would require patching upstream Kconfig and
  would not yield a meaningful reduction in idle resource use.
- OpenWrt's top-level `CONFIG_KERNEL_DEBUG_INFO` is explicitly disabled in
  the MD/MF build profiles. This selects Linux's `CONFIG_DEBUG_INFO_NONE=y`
  choice: changing only the target kernel fragment is insufficient, since
  OpenWrt normally enables reduced DWARF debug info for non-small-flash
  targets.
- BusyBox is customized to keep `udhcpc` and NTP client functionality while
  dropping DHCP server, cron and NTP server applets. This sets OpenWrt's
  custom-BusyBox (tainted) build flag intentionally.
- Each CI job selects exactly one Nokia UBI profile and uses a single rootfs.
  Explicit package configuration excludes router packages without modifying
  target.mk. firewall4 retains its upstream kmod-nft-offload dependency;
  installation of that module does not itself enable flow offloading.

## RelayOS Console (default web UI)

Both UBI images bundle `luci-theme-airrelay` as the default LuCI theme, with
up to three top-level navigation items:

1. **Realtime status:** uptime, load, memory, management IPv4, port carriers,
   WireGuard interface state and tunnel IPv4 / counters / sampled rates.
   Live readings refresh every five seconds through existing `ubus` services.
   A small procd service (`airrelay-traffic`) samples `br-lan` byte counters
   every 15 seconds even with no browser open. It atomically retains 241
   counter snapshots in `/tmp/airrelay-traffic/history`, giving up to one hour
   of rates. Data stays in RAM, is cleared on reboot, and never writes flash.
   Charts use a fixed one-hour time axis and break on counter resets or gaps.
   Bridge counters do not cover all hardware-switched traffic; interface-up
   remains distinct from a successful WireGuard handshake. Each tunnel has a
   permission-checked restart action. The helper validates its UCI protocol
   and enabled state, then calls only that netifd interface down/up; it never
   reloads the whole network or changes persistent configuration.
2. **Settings:** management `br-lan` DHCP client or static IPv4 configuration
   with LuCI's Save & Apply / rollback workflow, followed by system management.
   Firmware upgrade retains authenticated upload, `validate_firmware_image`
   and `sysupgrade --test`, with no forced flashing. Factory reset requires
   confirmation before LuCI's native `/sbin/firstboot -r -y` operation. After
   reset the device uses DHCP; find its new address in the upstream lease table.
   The manual WireGuard editor preserves existing interface names and peers,
   supports creating a first tunnel, and uses native UCI confirmed apply.
   It fills missing tunnel-zone membership, outbound forwarding/NAT, and
   explicit UDP listener rules; existing firewall assignments remain intact.
   The editor refuses default-route takeover and rechecks Agent ownership
   before saving. Peer routes are enabled and keepalive is fixed at 25 seconds
   when the manual configuration is saved. Private / preshared keys stay
   concealed, and the last remaining peer cannot be removed. Agent detection uses the OpenWrt rc service `airroute-agent`:
   an installed and enabled service shows the Agent navigation item; enabled
   or still-running services suppress manual editing. Detection failure hides
   the editor. A future Agent package must install that init service name.
   Old `/network` and `/upgrade` URLs alias this page.
3. **AirRoute Agent:** installation state only; no Agent is bundled.

The standard `luci-mod-admin-full` back-end views remain installed for
development and recovery, but they are **not shown in the RelayOS navigation**.
This is a UI simplification, **not** a new authorization boundary. Only the
standalone RelayOS skin is installed; it has independent login, form and
upgrade styling, while preserving LuCI's existing authentication, RPCs and
CSRF protections. English and complete Simplified Chinese translations are
included. Switch languages at the top right; Chinese is the fresh-image default.

If a preserved pre-AirRelay configuration points to a removed skin, repair the
active theme through SSH:

```sh
uci set luci.main.mediaurlbase='/luci-static/airrelay'
uci commit luci
/etc/init.d/uhttpd reload
```

Do not expose development LuCI to an untrusted WAN. Set the administrator
password before deployment; the link remains available from the console.

## Default network and security posture

At factory reset, the upstream Nokia board initialization creates a bridge
with `lan1 lan2 lan3 lan4`. The AirRelay UCI default changes that bridge's
**management interface to a DHCP client** and disables any pre-existing LAN
DHCP server configuration. Plug the device into a network that provides DHCP;
find the assigned address in the upstream router's lease table.

There is no separate WAN port, no DHCP server, and no static `192.168.1.1`
address. All four copper interfaces remain on the same L2 bridge. The
default firewall:

- rejects unsolicited input and forwarding by default;
- permits DHCP client replies on the copper uplink;
- allows SSH (22) and LuCI HTTPS (443) only from RFC1918 IPv4 source ranges
  on the uplink for **initial development**;
- provides a `tunnel` zone referencing the future UCI network `wg0`;
- forwards `wg0` → `lan`, with IPv4 masquerading on the physical uplink.

**Before exposing a node to an untrusted network, set an administrator
password and tighten or remove the development management rules.** LuCI is
retained temporarily for troubleshooting, and is not the future cloud API.
IPv6 forwarding is disabled until an explicit IPv6 routing/security policy
is designed. Use IPv4 uplink connectivity for the initial tests.

The Agent must create `config interface 'wg0'` with `option proto 'wireguard'`
and its peer sections through UCI/netifd. It must not install a default route
through `wg0` on the exit node. Assign unique, non-overlapping `AllowedIPs`
to each first-hop peer. The future Agent must validate cloud input, avoid
shell interpolation, persist sensitive keys with root-only permissions, and
roll back bad changes if a tunnel cannot be established.

## Independent repository architecture

RelayOS is the private product repository. The public AldenClark/openwrt
fork is the upstream mirror, not the home of the product code.

- `upstream.lock`: exact reviewed OpenWrt commit; only the lock is advanced.
  The current candidate is [64c777f](https://github.com/openwrt/openwrt/commit/64c777f3af8ad1503c257afe686e44200de832c7),
  Linux 6.18.64, including previously backported WireGuard, Airoha, mbedTLS,
  firewall4 and runtime fixes. This is an upstream development snapshot,
  not a stable OpenWrt release. Upstream's current default GCC is 15.
- `feeds.conf`: separately pinned official packages and LuCI revisions.
- `configs/common.config` and `configs/{md,mf}.config`: single-profile
  OpenWrt package selections and branding.
- `configs/kernel/`: common and device-specific native env/kernel-config
  overrides. Kconfig and selected packages can impose further requirements.
- `patches/`: one narrow, checked DTS patch, applied only to a disposable
  build checkout. No permanent modifications to upstream platform files.
- `packages/`: product packages via the native src-link feed.
- `overlay/`: default root filesystem configuration.
- `scripts/`, `tests/`: preparation, configuration, build and release
  acceptance checks.

Historical import: AldenClark/openwrt commit
`71c85225fa124d9d7510f561800bd76e27459c88`. Existing package names,
LuCI paths, RPC ACLs, UCI interface/rule identities, board compatible
strings, FIT configuration and UBI layout remain unchanged. Visible branding
and fresh/default hostnames use RelayOS. Do not rename the internal
`luci-theme-airrelay` package or the future `airroute-agent` init service
without an explicit migration plan.

Upstream source is fetched from the mirror, with the official repository as
an exact-SHA fallback while the legacy fork is still being retained. A source
checkout must match the lock. The mirror can follow upstream independently;
a new lock and feed changes are reviewed and validated before release. The
first migrated build must pass both devices' full build and hardware
acceptance before replacing the previous working baseline or resetting the
old fork. Disable Actions in the mirror before restoring its upstream
workflow files to avoid inherited CI. Keep existing releases and record the
legacy product commit for rollback.

## Reproducible build

Run on a Linux build host with the OpenWrt build prerequisites and Node.js,
gettext, device-tree-compiler (fdtget) and u-boot-tools (dumpimage).
Use a fresh product checkout without whitespace in its path.

```sh
scripts/prepare.sh md
scripts/configure.sh md
scripts/test-console.sh md
scripts/build.sh md
# Repeat independently with mf.
```

The scripts create separate disposable OpenWrt worktrees under
`work/md/openwrt` and `work/mf/openwrt`. They refuse to overwrite a
previous checkout/configuration. The only tracked upstream source change
must be the checked PON DTS patch. The local package feed is linked from
`packages/`, with pinned official feeds. No copy of the OpenWrt repository
is committed to RelayOS.

The manual-only GitHub Actions workflow **RelayOS (MD / MF)** offers:

- `validate`: prepare both targets, resolve defconfig, audit merged kernel
  fragments and run the console source/regression tests, without compiling
  the firmware or creating a release.
- `firmware`: perform the same checks, build both full images and verify
  their package manifests, final kernel configs, embedded FIT device trees
  and sysupgrade compatibility metadata. Publish only when both pass.

Select **Actions → RelayOS (MD / MF) → Run workflow**, branch main.
Outputs are named `relayos-airoha-...-sysupgrade.itb` and
`relayos-airoha-...-initramfs-recovery.itb`; the unique prerelease includes
per-device checksums, manifest, effective OpenWrt/kernel configuration,
locked feeds and source provenance. Only UBI images are published. No
workflow flashes hardware or modifies bootloaders. Private repository
runners and artifact storage may incur account usage charges.

The original OpenWrt licenses and component source-offer obligations remain
applicable; if firmware is distributed, provide corresponding sources and
license notices for the GPL-covered components, including the locked
upstream versions and applied patches.

## Hardware acceptance before deployment

1. Boot both variants and verify 2.5GbE `lan1` and Gigabit `lan2..lan4`.
2. Confirm a DHCP lease, HTTPS LuCI, SSH, and four-port bridge behavior.
3. Provision a test `wg0` via UCI/netifd; verify kernel WireGuard handshake.
4. Verify `wg0` → uplink IPv4 forwarding/NAT and blocked unsolicited input.
5. Run sustained throughput, packet-loss, CPU/RSS and restart/recovery tests.
6. Check that disabling PON PCS did not disrupt Ethernet SerDes/PCS.

Do not assume Gigabit WireGuard throughput: measure AN7581 and AN7583
separately. Full kernel builds may exceed standard hosted runner disk/memory
budgets; use a self-hosted Linux runner if necessary.
