#!/usr/bin/env bash
# Copyright 2026 Internet Mastering & Company, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

GRE_LOCAL="${GRE_LOCAL:-}"
GRE_REMOTES="${GRE_REMOTES:-}"
EIPS="${EIPS:-}"
ALLOW_TCP_PORTS="${ALLOW_TCP_PORTS:-80}"
INGRESS_IFACES="${INGRESS_IFACES:-}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -n $GRE_LOCAL && -n $GRE_REMOTES && -n $EIPS ]] || {
  echo "set GRE_LOCAL=<backend ip> GRE_REMOTES='<frontend eips>' EIPS='<eips>'" >&2
  exit 1
}

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
# the EIPs; drop everything else arriving through any tunnel.
PORTSET=$(echo "$ALLOW_TCP_PORTS" | tr ' ' ',')
EIPSET=$(echo "$EIPS" | tr ' ' ',')
nft delete table inet pfe_dsr 2>/dev/null || true
nft add table inet pfe_dsr
nft add chain inet pfe_dsr input '{ type filter hook input priority -10; policy accept; }'
nft add rule inet pfe_dsr input iifname "pfe-gre*" ip daddr "{ $EIPSET }" tcp dport "{ $PORTSET }" accept
nft add rule inet pfe_dsr input iifname "pfe-gre*" drop
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
  the nftables table inet pfe_dsr (save via \`nft list ruleset > /etc/pfe-dsr.nft\`
  and an include, or a systemd unit running this script at boot)
EOF

echo
echo "Note: accept_local on $INGRESS_IFACES is a PRODUCTION requirement"
echo "Real remote clients do not need this."
echo
echo "Remaining per-site check (not scriptable): confirm the DC/host egress"
echo "does NOT filter packets with src == the EIPs (BCP38). Watch the first"
echo "live tunnel from a real client."
