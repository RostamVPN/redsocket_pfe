pfe-rs — AF_XDP DSR front-end (triangle routing)
=================================================

Rust rewrite of getlantern/pfe. An XDP program that takes over a NIC queue,
rewrites incoming packets' destination from a cloud-NAT'ed private IP back
to the public EIP, GRE-encapsulates them toward a back-end, and transmits
them back out the same NIC. The back-end answers clients directly with the
EIP as source (direct server return), so the return path skips the cloud.

Packet path
-----------

  client --(dst=EIP:80)--> [cloud 1:1 NAT] --(dst=PRIV:80)--> front NIC
    pfe: dst PRIV -> EIP, GRE encap (outer src=PRIV, dst=BACKEND)
  front --(cloud NATs outer src PRIV->EIP)--> back-end
    GRE decap -> inner packet dst=EIP delivered locally (EIP on a dummy)
    the service on :80 accepts as usual
  back-end --(src=EIP:80, DIRECT to client)--> client   <- DSR leg

Build
-----

    cargo build --release --target x86_64-unknown-linux-gnu
    cargo test                      # pure packet logic, runs anywhere

Build offline: deps are vendored under `vendor/` (wired via `.cargo/config.toml`),
so `cargo build --offline --release` needs no network. Binary needs only glibc.

Front-end (cloud instance)
--------------------------

WARNING: pfe takes over the interface it binds. The bound queue becomes a
black hole: everything arriving there is forwarded to the back-end. Bind
ONLY a secondary/data NIC, never the management interface.

    ethtool -L <iface> combined 1          # pin all RX to one queue
    pfe -i <iface> -m /etc/pfe/map.csv --tunnel gre   # or deploy/pfe.service
                                                      # with /etc/pfe/pfe.env
                                                      # (deploy/pfe.env.example)

  -i, --iface <name>       interface to take over (required)
  -m, --mapfile <path>     route map CSV (required)
  -q, --queue <n>          NIC queue to bind (default 0)
      --mode <mode>        skb | driver | hw  (default skb)
      --tunnel <type>      fou | gre  (default fou; use gre, see below)
      --gateway-mac <mac>  force next-hop MAC (skip ARP discovery)
      --gateway4 <ip>      force the IPv4 gateway IP
  -n, --configtest         validate config and exit (touches nothing)
  -d, --debug              per-packet lines, client addresses masked to /24;
                           -dd hex dumps and full client addresses; -ddd full
                           frames. All of it goes to the journal: use the
                           higher levels for short diagnostics only

Signals: SIGHUP reloads the map atomically; SIGUSR1 dumps stats (also every 60s).

Map file (CSV, # comments):

    # EIP, Private IP, Tunnel Src, Tunnel Dst, Port
    203.0.113.10,10.0.0.10,10.0.0.10,198.51.100.20,5555

  EIP          public address the back-end spoofs on replies
  Private IP   the NAT'ed address on the front NIC (map lookup key)
  Tunnel Src   outer src: the NIC's private IP (cloud NATs it to the EIP)
  Tunnel Dst   back-end host IP
  Port         FoU port only; unused for GRE

XDP mode: some cloud NIC drivers reject native attach (EINVAL); use skb.
The first packet is probed; if the umem layout leaves less room than the
encap needs, pfe exits with an explicit error.

Encapsulation: use GRE. Kernel fou (`ip fou add ... ipproto 4`) re-dispatches
the decapped packet to the IPIP handler, which expects another IP header, so
a bare client packet is rejected. FoU remains only for back-ends with their
own userspace decap.

Back-end (bare metal / container host)
--------------------------------------

See deploy/backend-dsr.sh (idempotent). Requirements:

    modprobe tunnel4
    ip link add pfe-gre0 type gre local <this-host-ip> remote <front EIP> ttl 64
    ip link set pfe-gre0 up
    sysctl -w net.ipv4.conf.pfe-gre0.forwarding=0
    ip link add pfe-dsr0 type dummy && ip link set pfe-dsr0 up
    ip addr add <EIP>/32 dev pfe-dsr0          # per front-end EIP
    sysctl -w net.ipv4.conf.all.rp_filter=0
    sysctl -w net.ipv4.conf.<ingress-nic>.accept_local=1   # REQUIRED
    nft -f <ruleset>      # table inet pfe_dsr in one transaction; the exact
                          # text is in backend-dsr.sh

  - accept_local on the physical ingress NIC is a hard requirement: GRE
    packets arrive with source = the EIP, which is local; without it the
    kernel drops them as martians.
  - rp_filter=0: the decapped traffic is asymmetric by design.
  - The nftables allowlist is mandatory: DSR exposes the host's entire port
    space through every EIP. Decapsulated packets enter from the pfe-greN
    device (the dummy never receives), hence iifname "pfe-gre*" + EIP set.
    The script validates its inputs and loads the table as one `nft -f`
    transaction, so a rejected ruleset leaves the previous table in place;
    a forward chain drops anything routed through a tunnel device.
  - The host/DC egress must not BCP38-filter src=EIP; verify per site.
  - One GRE device per front-end EIP (remote = that EIP).

Operational notes
-----------------

  - Cloud 1:1 NAT: pfe inverts the EIP<->private mapping from the map file;
    egress NAT rewrites the outer GRE source to the EIP automatically.
  - MTU: GRE adds 24 bytes (IP+GRE); clamp client TCP MSS (<=1436).
  - IPv6 map rows parse, but only the IPv4 forward path is exercised.
  - Stats line: rx/rxB/fwd/arpReply/drop/tx/txB plus kernel XDP socket
    counters (rxDrop/rxInvalid/txInvalid/rxRingFull/fillEmpty/txEmpty).
  - Scanner traffic hitting the front NIC is forwarded too (black hole by
    design); the back-end allowlist drops all but service ports.

Repo layout
-----------

    src/main.rs      CLI, signals, main loop, stats
    src/packet.rs    pure packet logic (parse/rewrite/encap/checksums) + tests
    src/xsk.rs       AF_XDP via raw syscalls: umem, rings, XSKMAP, XDP program
    src/ipmap.rs     map file parsing + atomic swap store + tests
    src/neighbor.rs  ifindex/MAC/gateway discovery, ARP cache
    deploy/          pfe.service, pfe.env.example, backend-dsr.sh, map.csv.example

## Related repositories

| Repository | Contents |
|---|---|
| `redsocket_http` | The exit server (Rust). |
| `rostamvpn-android` | The Android app, the shared Rust client core (`redsocket-http-core/`) and the WireGuard-over-TCP core. |
| `rostamvpn-ios` | The iOS app and its Network Extension; its core frameworks are built from the cores in `rostamvpn-android`. |
| `redsocket_pfe` | AF_XDP triangle-routing front-end. |
| `redsocket_wgtcp` | The userspace WireGuard-over-TCP client library and tools; vendored into `rostamvpn-android` for the Android core. |
| `redsocket_proteus` | The server wrapped in Proteus programmable protocols; intended to replace `redsocket_http` once proven. |

## Removed for publication

Deployment and infrastructure documents, exporter scripts, release artifacts,
signing material and API keys (replaced by `REPLACE_WITH_*` placeholders),
server telemetry other than the cid stats, other brands, narrative comments,
and dead code. All third-party dependencies are vendored in the tree and keep
their own license files.
