#!/bin/sh

# Requires Entware coreutils-date installed

SayT() {
   echo -e $$ $@ | logger -t "($(basename $0))"
}
# see https://www.digitalocean.com/community/tutorials/how-to-set-up-wireguard-on-ubuntu-20-04

if [ ! -f /opt/bin/date ];then
    echo -e "\a\n\t*** ERROR Requires Entware 'date' module....ABORTing\n"
    exit 99

fi

# From time+EUI-64 as per RFC 4193 https://www.rfc-editor.org/rfc/rfc4193#section-3.2.2

# Pre-reqs      Entware date (coreutils-date)

[ ! -f /opt/bin/date ] && { SayT "*** ERROR Requires Entware 'date' module....ABORTing\n"; return 1 ;}

NANO_SECS=$(/opt/bin/date +%s%N)

# wl1_hwaddr=24:4B:FE:AC:54:DC
# wan0_gw_mac=AC:9E:17:7E:E4:A0
HEX1=$(nvram get wan0_gw_mac)
HEX2=$(nvram get wl1_hwaddr)

HEX=${NANO_SECS}${HEX1//:/}${HEX2//:/}

echo -e "$HEX" >/tmp/wgm_ula
HASH=$(openssl dgst -sha1 /tmp/wgm_ula | awk '{print $2}' | cut -c 31- )

IPV6="fd"${HASH:0:2}:${HASH:2:4}:${HASH:6:4}"::/64"

# https://blogs.infoblox.com/ipv6-coe/ula-is-broken-in-dual-stack-networks/
SayT "Here is your IPv6 ULA based on this hardware's MACs IPV6="$IPV6
echo -e "\n\tHere is your IPv6 ULA based on this hardware's MACs IPV6="$IPV6" (Use "aa"${HASH:0:2}:${HASH:2:4}:${HASH:6:4}"::/64 for Dual-stack IPv4+IPv6")\n"

rm /tmp/wgm_ula 2>/dev/null
