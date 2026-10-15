#!/usr/bin/env bash
# Copyright 2026 Internet Mastering & Company, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

GRE_LOCAL="${GRE_LOCAL:-}"
GRE_REMOTES="${GRE_REMOTES:-}"
EIPS="${EIPS:-}"
ALLOW_TCP_PORTS="${ALLOW_TCP_PORTS:-80}"
INGRESS_IFACES="${INGRESS_IFACES:-}"

die() { echo "$*" >&2; exit 1; }

is_ipv4() {
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local o
  for o in "${BASH_REMATCH[@]:1}"; do
    [[ $o == 0 || $o != 0* ]] && (( o <= 255 )) || return 1
  done
}

join_commas() { local IFS=,; echo "$*"; }

[[ $EUID -eq 0 ]] || die "run as root"
[[ -n $GRE_LOCAL && -n $GRE_REMOTES && -n $EIPS ]] ||
  die "set GRE_LOCAL=<backend ip> GRE_REMOTES='<frontend eips>' EIPS='<eips>'"
for ip in $GRE_LOCAL $GRE_REMOTES $EIPS; do
  is_ipv4 "$ip" || die "invalid IPv4 address '$ip'"
done
for port in $ALLOW_TCP_PORTS; do
  [[ $port =~ ^[1-9][0-9]{0,4}$ ]] && (( port <= 65535 )) || die "invalid TCP port '$port'"
done

modprobe tunnel4 2>/dev/null || true

i=0
for remote in $GRE_REMOTES; do
  dev="pfe-gre$i"; i=$((i+1))
  if ! ip link show "$dev" >/dev/null 2>&1; then
    ip link add "$dev" type gre local "$GRE_LOCAL" remote "$remote" ttl 64
    ip link set "$dev" up
    echo "gre: $dev local $GRE_LOCAL remote $remote"
  fi
  sysctl -qw "net.ipv4.conf.$dev.rp_filter=0"
  sysctl -qw "net.ipv4.conf.$dev.forwarding=0"
done

DUMMY=pfe-dsr0
ip link show "$DUMMY" >/dev/null 2>&1 || ip link add "$DUMMY" type dummy
ip link set "$DUMMY" up
for eip in $EIPS; do
  ip addr show dev "$DUMMY" | grep -q "inet ${eip}/32" || ip addr add "${eip}/32" dev "$DUMMY"
done
ip addr show dev "$DUMMY" | grep inet

sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.default.rp_filter=0
sysctl -qw "net.ipv4.conf.$DUMMY.rp_filter=0"

for iface in $INGRESS_IFACES; do
  sysctl -qw "net.ipv4.conf.$iface.accept_local=1"
done

# Decapsulated packets enter the input hook from the pfe-greN device (the
# dummy only holds the EIPs; it never receives). Allow only service ports on
# the EIPs; drop everything else arriving through any tunnel, anything from
# the kernel's fallback tunnel devices, and anything routed through a tunnel.
# One nft transaction: a rejected ruleset leaves the previous table in place.
PORTSET=$(join_commas $ALLOW_TCP_PORTS)
EIPSET=$(join_commas $EIPS)
nft -f - <<EOF
add table inet pfe_dsr
delete table inet pfe_dsr
table inet pfe_dsr {
  chain input {
    type filter hook input priority -10; policy accept;
    iifname "pfe-gre*" ip daddr { $EIPSET } tcp dport { $PORTSET } accept
    iifname "pfe-gre*" drop
    iifname { "gre0", "gretap0", "erspan0" } drop
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "pfe-gre*" drop
    oifname "pfe-gre*" drop
  }
}
EOF
nft list table inet pfe_dsr

cat <<EOF
NOTE: make the above persistent (netplan/ifupdown dummy + systemd gre units +
      nftables file include). Minimum surviving set:
  modprobe tunnel4
  per frontend: ip link add pfe-greN type gre local $GRE_LOCAL remote <eip> ttl 64
                ip link set pfe-greN up
  ip link add ${DUMMY} type dummy; ip link set ${DUMMY} up
  ip addr add <eip>/32 dev ${DUMMY}          (per EIP)
  sysctl net.ipv4.conf.all.rp_filter=0
  sysctl net.ipv4.conf.pfe-greN.forwarding=0        (per tunnel)
  sysctl net.ipv4.conf.<ingress-nic>.accept_local=1
  the nftables table inet pfe_dsr (save via \`nft list table inet pfe_dsr\`
  into a file your nftables.conf includes, or a systemd unit running this
  script at boot)
EOF

echo
echo "Note: accept_local on $INGRESS_IFACES is a PRODUCTION requirement"
echo "Real remote clients do not need this."
echo
echo "Remaining per-site check (not scriptable): confirm the DC/host egress"
echo "does NOT filter packets with src == the EIPs (BCP38). Watch the first"
echo "live tunnel from a real client."
