#!/bin/sh
VER="v0.9b"
#############################################################################EIC Hack 1 of 2################
#For verbose debugging, uncomment the following two lines, and uncomment the last line of this script
#set -x
#(
############################################################################################################
# shellcheck disable=SC2034
ANSIColours() {

    cRESET="\e[0m";cBLA="\e[30m";cRED="\e[31m";cGRE="\e[32m";cYEL="\e[33m";cBLU="\e[34m";cMAG="\e[35m";cCYA="\e[36m";cGRA="\e[37m"
    cBGRA="\e[90m";cBRED="\e[91m";cBGRE="\e[92m";cBYEL="\e[93m";cBBLU="\e[94m";cBMAG="\e[95m";cBCYA="\e[96m";cBWHT="\e[97m"
    aBOLD="\e[1m";aDIM="\e[2m";aUNDER="\e[4m";aBLINK="\e[5m";aREVERSE="\e[7m"
    cRED_="\e[41m";cGRE_="\e[42m"

}
Is_HND() {
    # Use the following at the command line otherwise 'return X' makes the SSH session terminate!
    #[ -n "$(uname -m | grep "aarch64")" ] && echo Y || echo N
    [ -n "$(uname -m | grep "aarch64")" ] && { echo Y; return 0; } || { echo N; return 1; }
}
Is_AX() {
    # Kernel is '4.1.52+' (i.e. isn't '2.6.36*') and it isn't HND
    # Use the following at the command line otherwise 'return X' makes the SSH session terminate!
    # [ -n "$(uname -r | grep "^4")" ] && [ -z "$(uname -m | grep "aarch64")" ] && echo Y || echo N
    [ -n "$(uname -r | grep "^4")" ] && [ -z "$(uname -m | grep "aarch64")" ] && { echo Y; return 0; } || { echo N; return 1; }
}
Firewall_delete() {

    if [ $FIRMWARE -ge 38601 ];then         # Allow Guest #1 SSID VLANs @ZebMcKayhan
        iptables -t filter -D FORWARD -i br1 -o $VPN_ID -j ACCEPT 2>/dev/null
        iptables -t filter -D FORWARD -i br2 -o $VPN_ID -j ACCEPT 2>/dev/null
        iptables -t nat -D POSTROUTING -s $(nvram get lan_ipaddr)/16 -o $VPN_ID -j MASQUERADE 2>/dev/null
    else
        iptables -t nat -D POSTROUTING -s $(nvram get lan_ipaddr)/24 -o $VPN_ID -j MASQUERADE 2>/dev/null
    fi

    iptables -t mangle -D FORWARD -o $VPN_ID -j MARK --set-xmark 0x01/0x7 2>/dev/null
    iptables -t mangle -D FORWARD -i $VPN_ID -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
    iptables -t mangle -D FORWARD -o $VPN_ID -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
    iptables -t mangle -D PREROUTING -i $VPN_ID -j MARK --set-xmark 0x01/0x7 2>/dev/null

}
# Taken/Adapted from 'vpnrouting.sh' by RMerlin
create_client_list(){
    local OLDIFS=$IFS
    local IFS="<"

    for ENTRY in $VPN_IP_LIST
    do
        [ -z "$ENTRY" ] && continue
        local TARGET_ROUTE=$(echo $ENTRY | cut -d ">" -f 4)
        if [ "$TARGET_ROUTE" = "WAN" ]
        then
            local TARGET_LOOKUP="main"
            #WAN_PRIO=$((WAN_PRIO+1))
            local RULE_PRIO=$WAN_PRIO
            local TARGET_NAME="WAN"
        else
            local TARGET_LOOKUP=$VPN_TBL
            #VPN_PRIO=$((VPN_PRIO+1))
            local RULE_PRIO=$VPN_PRIO
            local TARGET_NAME="VPN 'client' Peer $VPN_UNIT"
        fi
        local VPN_IP=$(echo $ENTRY | cut -d ">" -f 2)
        if [ "$VPN_IP" != "0.0.0.0" ] && [ -n "$VPN_IP" ]
        then
            local SRCC="from"
            local SRCA="$VPN_IP"
        else
            local SRCC=""
            local SRCA=""
        fi
        local DST_IP=$(echo $ENTRY | cut -d ">" -f 3)
        if [ "$DST_IP" != "0.0.0.0" ] && [ -n "$DST_IP" ]
        then
            local DSTC="to"
            local DSTA="$DST_IP"
        else
            local DSTC=""
            local DSTA=""
        fi
        if [ -n "$SRCC" ] || [ -n "$DSTC" ]
        then
            ip rule add $SRCC $SRCA $DSTC $DSTA table $TARGET_LOOKUP priority $RULE_PRIO
            echo -en $cBCYA"\t"
            [ "$DSTC" == "to" ] && DSTC=" to "
            logger -st "wireguard-${MODE}${VPN_NUM}" "Adding Wireguard 'client' Peer route for ${VPN_IP}${DSTC}$DST_IP through $TARGET_NAME"
            echo -en $cRESET
        fi
    done
    local IFS=$OLDIFS
}
purge_client_list(){
    IP_LIST=$(ip rule show | cut -d ":" -f 1)
    for PRIO in $IP_LIST
    do
        if [ "$PRIO" -ge "$START_PRIO" ] && [ "$PRIO" -le "$END_PRIO" ]
        then
            ip rule del prio $PRIO
            echo -en $cBCYA"\t"
            logger -st "wireguard-${MODE}${VPN_NUM}" "Removing Wireguard 'client' Peer rule $PRIO from routing policy"
            echo -en $cRESET
        fi
    done
}
#=============================================Main=============================================================
# shellcheck disable=SC2068
Main() { true; } # Syntax that is Atom Shellchecker compatible!

ANSIColours

FIRMWARE=$(echo $(nvram get buildno) | awk 'BEGIN { FS = "." } {printf("%03d%02d",$1,$2)}')

modprobe xt_set
#############################################################################EIC Hack 1 of 1################
#insmod /opt/lib/modules/wireguard
VPN_ID=$1
[ -z "$1" ] && VPN_ID="wg0"
VPN_NUM=${VPN_ID#"${VPN_ID%?}"}
[ "${VPN_ID:0:3}" == "wg1" ] && { MODE="client"; TXT="to"; } || { MODE="server"; TXT="Hosted at"; }
insmod /opt/lib/modules/wireguard 2> /dev/null
if [ "$1" != "disable" ] && [ "$2" != "disable" ];then
    #echo -e $cBGRA
    #dmesg | grep -a WireGuard | tail -n 1
    #echo -e $cBWHT
    :
fi

############################################################################################################

[ -n "$(echo "$@" | grep "policy")" ] && POLICY_MODE="in Policy Mode " || POLICY_MODE=

# Read the Peer config to set the Annotation Description and LOCAL peer endpoint etc.
if [ -f /jffs/configs/WireguardVPN_map ];then
    if [ "${VPN_ID:0:3}" != "wg2" ];then
        LOCALIP=$(awk -v pattern="${VPN_ID}" 'match($0,"^"pattern) {print $3}' /jffs/configs/WireguardVPN_map)
        export LocalIP=$LOCALIP
        SOCKET=$(awk -v pattern="${VPN_ID}" 'match($0,"^"pattern) {print $4}' /jffs/configs/WireguardVPN_map)
        START_PRIO=99${VPN_NUM}0
        END_PRIO=99${VPN_NUM}9
        WAN_PRIO=99${VPN_NUM}0
        VPN_PRIO=99${VPN_NUM}1
        VPN_TBL=12$VPN_NUM
        VPN_UNIT=$VPN_ID
    else
        SOCKET=$(nvram get wan_gateway)":"$(awk '/Listen/ {print $3}' /opt/etc/wireguard/${VPN_ID}.conf)
    fi
    DESC=$(awk -v pattern="${VPN_ID}" 'match($0,"^"pattern) {print $0}' /jffs/configs/WireguardVPN_map | grep -oE "#.*$" | sed 's/^[ \t]*//;s/[ \t]*$//')

fi

if [ "$1" != "disable" ] && [ "$2" != "disable" ];then

    if [ -n "$LOCALIP" ] || [ "${VPN_ID:0:3}" == "wg2" ];then
        logger -st "wireguard-${MODE}${VPN_NUM}" "Initialising Wireguard VPN $MODE Peer ($VPN_ID) ${POLICY_MODE}${TXT} $SOCKET ($DESC)"

        ip link del dev $VPN_ID 2>/dev/null
        ip link add dev $VPN_ID type wireguard
        wg setconf $VPN_ID /opt/etc/wireguard/$VPN_ID.conf
        ip address add dev $VPN_ID $LOCALIP
        ip link set up dev $VPN_ID
        ifconfig $VPN_ID mtu 1380
        ifconfig $VPN_ID txqueuelen 1000

        host="$(wg show $VPN_ID endpoints | sed -n 's/.*\t\(.*\):.*/\1/p')"
        ip route add $(ip route get $host | sed '/ via [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/{s/^\(.* via [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/}' | head -n 1) 2>/dev/null

        # If there is ALREADY an ACTIVE WireGuard VPN Client, then tough! - make this one the default!!!!
        if [ -z "$POLICY_MODE" ];then
            if [ "$(wg show interfaces | grep -E "wg[0-1]" | wc -w)" -gt 1 ];then
                for THIS in $(wg show interfaces | grep -E "wg[0-1]")
                    do
                        ip route del 0/1 dev $THIS  2>/dev/null
                        ip route del 128/1 dev $THIS  2>/dev/null
                    done
            fi
            ip route add 0/1 dev $VPN_ID 2>/dev/null
            ip route add 128/1 dev $VPN_ID 2>/dev/null
        else
            ip rule add from $(nvram get lan_ipaddr | cut -d"." -f1-3).0/24 table 12$VPN_NUM prio 992$VPN_NUM
            VPN_IP_LIST=$(awk -v pattern="${VPN_NUM}" 'match($0,"^rp1"pattern) {print $0}' /jffs/configs/WireguardVPN_map | grep -oE "<.*$" | sed 's/^[ \t]*//;s/[ \t]*$//')

            create_client_list

        fi

        ip route add 0/1 dev $VPN_ID table 12$VPN_NUM 2>/dev/null
        ip route add 128/1 dev $VPN_ID table 12$VPN_NUM 2>/dev/null

        ip route add $(echo $LOCALIP | cut -d"." -f1-3).0/24 dev $VPN_ID  proto kernel  scope link  src $LOCALIP 2>/dev/null
        ip route show table main dev $(nvram get lan_ifname) | while read ROUTE
            do
                ip route add table 12$VPN_NUM $ROUTE dev $(nvram get lan_ifname) 2>/dev/null
            done

        ip route show table main dev $VPN_ID | while read ROUTE
            do
                ip route add table 12$VPN_NUM $ROUTE dev $VPN_ID 2>/dev/null
            done

        Firewall_delete

        iptables -t mangle -I FORWARD -o $VPN_ID -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        iptables -t mangle -I FORWARD -i $VPN_ID -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        iptables -t mangle -I FORWARD -o $VPN_ID -j MARK --set-xmark 0x01/0x7
        iptables -t mangle -I PREROUTING -i $VPN_ID -j MARK --set-xmark 0x01/0x7

        if [ $FIRMWARE -ge 38601 ];then         # Allow Guest #1 SSID VLANs
            iptables -t filter -I FORWARD -i br1 -o $VPN_ID -j ACCEPT -m comment --comment "WireGuard Guest_VLAN"
            iptables -t filter -I FORWARD -i br2 -o $VPN_ID -j ACCEPT -m comment --comment "WireGuard Guest_VLAN"
            iptables -t nat -I POSTROUTING -s $(nvram get lan_ipaddr)/16 -o $VPN_ID -j MASQUERADE
        else
            iptables -t nat -I POSTROUTING -s $(nvram get lan_ipaddr)/24 -o $VPN_ID -j MASQUERADE
        fi

        if [ "$wgdns" != "" ] && [ ! -f /tmp/resolv.dnsmasq_backup ]; then {
                cp /tmp/resolv.dnsmasq /tmp/resolv.dnsmasq_backup 2>/dev/null
                        echo "server=$wgdns" > /tmp/resolv.dnsmasq
                        service restart_dnsmasq
                }
        fi
        ###############################################################EIC Hack 5 of 5##############################
        echo -en $cBGRE"\t"
        logger -st "wireguard-${MODE}${VPN_NUM}" "Initialisation complete."
        echo -e $cRESET
        ############################################################################################################

    else
        echo -e "\a\n\t";logger -st "wireguard-{$MODE}${VPN_NUM}" "Local Peer I/P endpoint ('/jffs/configs/WireguardVPN_map') not VALID. ABORTing Initialisation."
        echo -e
    fi


else

    ip route del 0.0.0.0/1   dev $VPN_ID   2>/dev/null
    ip route del 128.0.0.0/1 dev $VPN_ID   2>/dev/null
    # Set the default to the last ACTIVE WireGuard interface
    for WG_IFACE in $(wg show interfaces | grep -E "wg1|wg0" | sort -gr)
            do
                ip route add 0/1    dev $WG_IFACE  2>/dev/null
                ip route add 128/1  dev $WG_IFACE  2>/dev/null
            done

    ip link del dev $VPN_ID 2>/dev/null
    Firewall_delete

    ip rule del from $(nvram get lan_ipaddr | cut -d"." -f1-3).0/24 table 12$VPN_NUM prio 992$VPN_NUM   2>/dev/null

    ip route flush table 12$VPN_NUM 2>/dev/null
    ip rule del prio 992$VPN_NUM    2>/dev/null

    purge_client_list

#############################################################################EIC Hack 5 of 7################
        #ipset -F $Nipset 2>/dev/null
        #ipset -X $Nipset 2>/dev/null
############################################################################################################

    #mv /tmp/resolv.dnsmasq_backup /tmp/resolv.dnsmasq 2>/dev/null
#############################################################################EIC Hack 6 of 7################
    #service restart_dnsmasq
    #service restart_dnsmasq 2>&1 1>/dev/null
    echo -en $cBGRE"\t"
    logger -st "wireguard-${MODE}${VPN_NUM}" "Wireguard VPN '$MODE' Peer ($VPN_ID) $TXT $SOCKET ($DESC) DELETED"
    echo -e $cRESET
fi

############################################################################EIC Hack 3 of 3####################################
#) 2>&1 | logger -t $(basename $0)"[$$_***DEBUG]"
###############################################################################################################################

exit
