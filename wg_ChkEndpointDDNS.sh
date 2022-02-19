#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

# v2.01 Hacked and renamed from 'reresolv-dns.sh'to 'wg_ChkEndpointDDNS.sh' by Martineau to convert from BASH etc.
#
#   Usage:  cru a WireGuard_ChkDDNS${WG_INTERFACE} "*/5 * * * * ${INSTALL_DIR}wg_ChkEndpointDDNS.sh $WG_INTERFACE"

# set -e                    # Martineau Hack
# shopt -s nocasematch      # Martineau Hack
# shopt -s extglob          # Martineau Hack
# export LC_ALL=C

#=========================================================================================== Martineau Hack
Say() {
   echo -e $$ $@ | logger -st "($(basename $0))"
}
SayT() {
   echo -e $$ $@ | logger -t "($(basename $0))"
}
Is_IPv4() {
    grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'                    # IPv4 format
}
Is_IPv6() {
    # Note this matches compression anywhere in the address, though it won't match the loopback address ::1
    grep -oE '([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}'       # IPv6 format -very crude
}
Is_IPv4_CIDR() {
        grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}/(3[012]|[12]?[0-9])$'    # IPv4 CIDR range notation
}
Is_Private_IPv4() {
    # 127.  0.0.0 – 127.255.255.255     127.0.0.0 /8
    # 10.   0.0.0 –  10.255.255.255      10.0.0.0 /8
    # 172. 16.0.0 – 172. 31.255.255    172.16.0.0 /12
    # 192.168.0.0 – 192.168.255.255   192.168.0.0 /16
    #grep -oE "(^192\.168\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)|(^172\.([1][6-9]|[2][0-9]|[3][0-1])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)|(^10\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)"
    grep -oE "(^127\.)|(^(0)?10\.)|(^172\.(0)?1[6-9]\.)|(^172\.(0)?2[0-9]\.)|(^172\.(0)?3[0-1]\.)|(^169\.254\.)|(^192\.168\.)"
}
Is_Private_IPv6() {
    grep -oE "(::1$)|([fF][cCdD])"
}
process_peer() {
    #[[ $PEER_SECTION -ne 1 || -z $PUBLIC_KEY || -z $ENDPOINT ]] && return 0                            # Martineau Hack
    if [ $PEER_SECTION -ne 1 ] || [ -z "$PUBLIC_KEY"  ] || [ -z "$ENDPOINT" ];then                      # Martineau Hack
        return 0                                                                                        # Martineau Hack
    fi                                                                                                  # Martineau Hack
    # Ignore this Endpoint if it's an IPv6 address or an IPv4 address/CIDR                              # Martineau Hack
    [ $(echo "$ENDPOINT" | tr ":" " " | wc -w) -gt 2 ] && return 0                                      # Martineau Hack
    local DDNS=$(echo "$ENDPOINT" | awk -F ":" '{print $1}')                                            # Martineau Hack
    if [ -n "$(echo "$DDNS" | Is_IPv4_CIDR)" ] || [ -n "$(echo "$DDNS" | Is_IPv4)" ];then               # Martineau Hack
        SayT "DDNS Endpoint $ENDPOINT re-Resolve not required for '$INTERFACE' Public Key '$PUBLIC_KEY'"    # Martineau Hack
        return 0                                                                                        # Martineau Hack
    fi                                                                                                  # Martineau Hack
    #[[ $(wg show "$INTERFACE" latest-handshakes) =~ ${PUBLIC_KEY//+/\\+}\  ([0-9]+) ]] || return 0     # Martineau Hack
    if [ -n "$( wg show interfaces | grep -ow "$INTERFACE")" ];then                                     # Martineau Hack
        local PREVIOUS=$(wg show "$INTERFACE" latest-handshakes 2>/dev/null | grep -F "$PUBLIC_KEY" | awk '{print $2}')   # Martineau Hack
        #(( ($(date +%s) - ${BASH_REMATCH[1]}) > 135 )) || return 0                                     # Martineau Hack
        [ $(( $(date +%s) - PREVIOUS )) -gt 135 ] || return 0                                           # Martineau Hack
        wg set "$INTERFACE" peer "$PUBLIC_KEY" endpoint "$ENDPOINT"
#=======================================================================================================# MArtineau Hack
        if [ "${INTERFACE:0:3}" == "wg2" ];then
            local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM devices WHERE pubkey='$PUBLIC_KEY';")
        fi

        if [ -z "$DESC" ];then
            # Site2Site maybe?                          # v4.14
            local MATCH_PEER=$(grep -F "$PUBLIC_KEY" ${CONFIG_DIR}*_public.key | awk -F '[\/:\._]' '{print $6}')
            if [ -z "$MATCH_PEER" ];then
                local DESC="# Unidentified"
            else
                local DESC=$(grep -FB1 "[Peer]" ${CONFIG_DIR}${MATCH_PEER}.conf | grep -vF "[Peer]")
                [ -z "$DESC" ] && local DESC=$(grep -FB1 "[Interface]" ${CONFIG_DIR}${MATCH_PEER}.conf | grep -vF "[Interface]")
                [ -z "$DESC" ] && local DESC="# "$DESC
            fi
        fi
        #SayT "DDNS Endpoint $ENDPOINT re-Resolved for '$INTERFACE' Public Key '$PUBLIC_KEY'"            # Martineau Hack
        SayT "DDNS Endpoint $ENDPOINT re-Resolved for '$INTERFACE' ('$DESC')"            # Martineau Hack
    fi

    local DESC=
#=======================================================================================================================
    reset_peer_section
}
reset_peer_section() {
    PEER_SECTION=0
    PUBLIC_KEY=""
    ENDPOINT=""
}
#=======================================================================================================#Martineau Hack
Main() { true; }            # Syntax that is Atom Shellchecker compatible!

SQL_DATABASE="/opt/etc/wireguard.d/WireGuard.db"
#=======================================================================================================================

CONFIG_FILE="$1"
#[[ $CONFIG_FILE =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]] && CONFIG_FILE="/etc/wireguard/$CONFIG_FILE.conf"       # Martineau Hack
#[[ $CONFIG_FILE =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]] && CONFIG_FILE="/opt/etc/wireguard.d/$CONFIG_FILE.conf" # Martineau Hack
#[[ $CONFIG_FILE =~ /?([a-zA-Z0-9_=+.-]{1,15})\.conf$ ]]                                                # Martineau Hack
#INTERFACE="${BASH_REMATCH[1]}"                                                                         # Martineau Hack
if [ -z "$(echo "$CONFIG_FILE" | grep -F "/")" ];then                                                   # Martineau Hack
    [ "${CONFIG_FILE##*.}" != 'conf' ] && SUFFIX=".conf" || SUFFIX=                                     # Martineau Hack
    [ ! -f $CONFIG_FILE ] && PATHNAME="/opt/etc/wireguard.d/${CONFIG_FILE}$SUFFIX"                      # Martineau Hack
fi

CONFIG_FILE=${PATHNAME##*/}
[ -f $PATHNAME ] && INTERFACE=${CONFIG_FILE%.*} || exit                                                 # Martineau Hack

CONFIG_FILE=$PATHNAME                                                                                   # Martineau Hack

reset_peer_section

#while read -r line || [[ -n $line ]]; do                                                               # Martineau Hack
while IFS='' read -r line || [ -n "$line" ]; do                                                         # Martineau Hack
    stripped="${line%%\#*}"
    key="${stripped%%=*}"; key="${key##*([[:space:]])}"; key="${key%%*([[:space:]])}"
    key=$(echo "$key" | awk '{$1=$1};1')                                                                # Martineau Hack
    value="${stripped#*=}"; value="${value##*([[:space:]])}"; value="${value%%*([[:space:]])}"
    value=$(echo "$value" | awk '{$1=$1};1')                                                            # Martineau Hack
    #[[ $key == "["* ]] && { process_peer; reset_peer_section; }                                        # Martineau Hack
    #[[ $key == "[Peer]" ]] && PEER_SECTION=1                                                           # Martineau Hack
    [ "${key:0:1}" == "[" ] && { process_peer; reset_peer_section; }                                    # Martineau Hack
    [ "$key" == "[Peer]" ] && PEER_SECTION=1                                                            # Martineau Hack
    if [ $PEER_SECTION -eq 1 ]; then
        case "$key" in
        PublicKey) PUBLIC_KEY="$value"; continue ;;
        Endpoint) ENDPOINT="$value"; continue ;;
        esac
    fi
done < "$CONFIG_FILE"

process_peer

