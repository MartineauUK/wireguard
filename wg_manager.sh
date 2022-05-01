#!/bin/sh
VERSION="v4.17b"
#============================================================================================ © 2021-2022 Martineau v4.17b
#
#       wg_manager   {start|stop|restart|show|create|peer} [ [client [policy|nopolicy] |server]} [wg_instance] ]
#
#       wg_manager   start 0
#                    Initialises remote peer 'client' 'wg0'
#       wg_manager   start client 0
#                    Initialises remote peer 'client' 'wg0'
#       wg_manager   start 1
#                    Initialises local peer 'server' 'wg1'
#       wg_manager   start server 1
#                    Initialises local peer 'server' 'wg21'
#       wg_manager   start client 1
#                    Initialises remote peer 'client' 'wg11' uses interface naming convention as per OpenVPN e.g. tun11
#       wg_manager   start client 1 policy
#                    Initialises remote peer 'client' 'wg11' in 'policy' Selective Routing mode
#       wg_manager   stop client 3
#                    Terminates remote peer 'client' 'wg13'
#       wg_manager   stop 1
#       wg_manager   restart SGS8
#                    Restart legacy-named Peer and auto-detect if it's a 'client' or 'server'
#

# Maintainer: Martineau
# Last Updated Date: 01-May-2022

#
# Description:
#
# Acknowledgement:
#
# Contributors: odkrys,Torson,ZebMcKayhan,jobhax,elorimer,Sh0cker54,here1310,defung,The Chief,abir1909,JGrana,heysoundude,archiel

GIT_REPO="wireguard"
GITHUB_MARTINEAU="https://raw.githubusercontent.com/MartineauUK/$GIT_REPO/main"
GITHUB_MARTINEAU_DEV="https://raw.githubusercontent.com/MartineauUK/$GIT_REPO/dev"
GITHUB_ZEBMCKAYHAN="https://raw.githubusercontent.com/ZebMcKayhan/WireguardManager/main" # v4.15
GITHUB_ZEBMCKAYHAN_DEV="https://raw.githubusercontent.com/ZebMcKayhan/WireguardManager/dev" # v4.15
GITHUB_DIR=$GITHUB_MARTINEAU                       # default for script
CONFIG_DIR="/opt/etc/wireguard.d/"                 # Conform to "standards"         # v2.03 @elorimer
IMPORT_DIR=$CONFIG_DIR                             # Allow custom Peer .config import directory v4.01
INSTALL_DIR="/jffs/addons/wireguard/"
CHECK_GITHUB="Y"                                   # Check versions on Github
SILENT="s"                                         # Default is no progress messages for file downloads
DEBUGMODE=
READLINE="ReadLine"                                # Emulate 'readline' for 'read'  # v2.03
CMDLINE=                                           # Command line INPUT             # v2.03
CMD1=;CMD2=;CMD3=;CMD4=;CMD5=                      # Command recall push stack      # v2.03
SQL_DATABASE="/opt/etc/wireguard.d/WireGuard.db"   # SQL                            # v3.05
INSTALL_MIGRATE="N"                                # Migration from v3.0 to v4.0    # v4.01
IMPORTED_PEER_NAME=                                # Global tacky!                  # v4.15

readonly SCRIPT_WEBPAGE_DIR="$(readlink /www/user)"
readonly SCRIPT_WEB_DIR="$SCRIPT_WEBPAGE_DIR/wireguard.d"
readonly SCRIPT_DIR="/jffs/addons/wireguard"
installedMD5File="${INSTALL_DIR}www-installed.md5"  # Save md5 of last installed www ASP file so you can find it again later (in case of www ASP update)

Say() {
   echo -e $$ $@ | logger -st "($(basename $0))"
}
SayT() {
   echo -e $$ $@ | logger -t "($(basename $0))"
}
# shellcheck disable=SC2034
ANSIColours () {

    local ACTION=$1

cRESET=
    aBOLD=;aDIM=;aUNDER=;aBLINK=;aREVERSE=
    aBOLDr=;aDIMr=;aUNDERr=;aBLINKr=;aREVERSEr=

    cBLA=;cRED=;cGRE=;cYEL=;cBLU=;cMAG=;cCYA=;cGRA=;cFGRESET=
    cBGRA=;cBRED=;cBGRE=;cBYEL=;cBBLU=;cBMAG=;cBCYA=;cBWHT=
    cWRED=;cWGRE=;cWYEL=;cWBLU=;cWMAG=;cWCYA=;cWGRA=
    cYBLU=
    cRED_=;cGRE_=

    if [ "$ACTION" != "disable" ];then
        cRESET="\e[0m";
        aBOLD="\e[1m";aDIM="\e[2m";aUNDER="\e[4m";aBLINK="\e[5m";aREVERSE="\e[7m"
        aBOLDr="\e[21m";aDIMr="\e[22m";aUNDERr="\e[24m";aBLINKr="\e[25m";aREVERSEr="\e[27m"
        cBLA="\e[30m";cRED="\e[31m";cGRE="\e[32m";cYEL="\e[33m";cBLU="\e[34m";cMAG="\e[35m";cCYA="\e[36m";cGRA="\e[37m";cFGRESET="\e[39m"
        cBGRA="\e[90m";cBRED="\e[91m";cBGRE="\e[92m";cBYEL="\e[93m";cBBLU="\e[94m";cBMAG="\e[95m";cBCYA="\e[96m";cBWHT="\e[97m"
        aBOLD="\e[1m";aDIM="\e[2m";aUNDER="\e[4m";aBLINK="\e[5m";aREVERSE="\e[7m"

        cWRED="\e[41m";cWGRE="\e[42m";cWYEL="\e[43m";cWBLU="\e[44m";cWMAG="\e[45m";cWCYA="\e[46m";cWGRA="\e[47m"
        cYBLU="\e[93;48;5;21m"
        cRED_="\e[41m";cGRE_="\e[42m"
    fi

    xHOME="\e[H";xERASE="\e[2J";xERASEDOWN="\e[J";xERASEUP="\e[1J";xCSRPOS="\e[s";xPOSCSR="\e[u";xERASEEOL="\e[K";xQUERYCSRPOS="\e[6n"
    xGoto="\e[Line;Columnf"
}
ShowHelp() {
    # Print between line beginning with'#==' to first blank line inclusive
    echo -en $cBWHT >&2
    awk '/^#==/{f=1} f{print; if (!NF) exit}' $0
    echo -en $cRESET >&2
}
Parse() {
    #
    #   Parse       "Word1,Word2|Word3" ",|" VAR1 VAR2 REST
    #               (Effectivley executes VAR1="Word1";VAR2="Word2";REST="Word3")

local TEXT IFS

    TEXT="$1"
    IFS="$2"
    shift 2
    read -r -- "$@" <<EOF
$TEXT
EOF
}
Is_HND() {
    # Use the following at the command line otherwise 'return X' makes the SSH session terminate!
    #[ -n "$(/bin/uname -m | grep "aarch64")" ] && echo Y || echo N
    [ -n "$(/bin/uname -m | grep "aarch64")" ] && { echo Y; return 0; } || { echo N; return 1; }    # v4.14
}
Is_AX() {
    # Kernel is '4.1.52+' (i.e. isn't '2.6.36*') and it isn't HND
    # Use the following at the command line otherwise 'return X' makes the SSH session terminate!
    # [ -n "$(/bin/uname -r | grep "^4")" ] && [ -z "$(/bin/uname -m | grep "aarch64")" ] && echo Y || echo N
    [ -n "$(/bin/uname -r | grep "^4")" ] && [ -z "$(/bin/uname -m | grep "aarch64")" ] && { echo Y; return 0; } || { echo N; return 1; }   # v4.14
}
Get_Router_Model() {

    # Contribution by @thelonelycoder as odmpid is blank for non SKU hardware,
    local HARDWARE_MODEL
    [ -z "$(nvram get odmpid)" ] && HARDWARE_MODEL=$(nvram get productid) || HARDWARE_MODEL=$(nvram get odmpid)

    echo $HARDWARE_MODEL

    return 0
}
Chain_exists() {

    # Args: {chain_name} [table_name]

    local CHAIN="$1"
    shift

    [ $# -eq 1 ] && local TABLE="-t $1"

    iptables $TABLE -n -L $CHAIN >/dev/null 2>&1
    local RC=$?
    if [ $RC -ne 0 ];then
        echo "N"
        return 1
    else
        echo "Y"
        return 0
    fi
}
Get_WAN_IF_Name() {
    # echo $([ -n "$(nvram get wan0_pppoe_ifname)" ] && echo $(nvram get wan0_pppoe_ifname) || echo $(nvram get wan0_ifname))
    #   nvram get wan0_gw_ifname
    #   nvram get wan0_proto

    local IF_NAME=$(ip route | awk '/^default/{print $NF}')     # Should ALWAYS be 100% reliable ?

    local IF_NAME=$(nvram get wan0_ifname)                      # ...but use the NVRAM e.g. DHCP/Static ?

    # Usually this is probably valid for both eth0/ppp0e ?
    if [ "$(nvram get wan0_gw_ifname)" != "$IF_NAME" ];then
        local IF_NAME=$(nvram get wan0_gw_ifname)
    fi

    if [ ! -z "$(nvram get wan0_pppoe_ifname)" ];then
        local IF_NAME="$(nvram get wan0_pppoe_ifname)"          # PPPoE
    fi

    echo $IF_NAME
}
Repeat() {
    # Print 25 '=' use HDRLINE=$(Repeat 25 "=")
    printf "%${1}s\n" | tr " " "$2"
}
Is_IPv4() {
    grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'                    # IPv4 format
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
Is_IPv6() {
    # Note this matches compression anywhere in the address, though it won't match the loopback address ::1
    grep -oE '([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}'       # IPv6 format -very crude
}
Is_Private_IPv6() {
    grep -oE "(::1$)|([fF][cCdD])"
}
Generate_IPv6_ULA() {

    local USE_ULA=$1                    # 'fcxx' or fdxx' prefix

    # From time+EUI-64 as per RFC 4193 https://www.rfc-editor.org/rfc/rfc4193#section-3.2.2

    # Pre-reqs      Entware date (coreutils-date)

    [ ! -f /opt/bin/date ] && { SayT "***ERROR Requires Entware 'date' module....ABORTing\n"; echo "***ERROR Requires Entware module" 2>&1; return 1 ;}

    local NANO_SECS=$(/opt/bin/date +%s%N)

    # wl1_hwaddr=24:4B:FE:AC:54:DC
    # wan0_gw_mac=AC:9E:17:7E:E4:A0
    local HEX1=$(nvram get wan0_gw_mac)
    local HEX2=$(nvram get wl1_hwaddr)

    local HEX=${NANO_SECS}${HEX1//:/}${HEX2//:/}

    echo -e "$HEX" >/tmp/wgm_ula
    local HASH=$(openssl dgst -sha1 /tmp/wgm_ula | awk '{print $2}' | cut -c 31- )

    local IPV6="fd"${HASH:0:2}:${HASH:2:4}:${HASH:6:4}"::1/64"

    # https://blogs.infoblox.com/ipv6-coe/ula-is-broken-in-dual-stack-networks/         # @heysoundude
    SayT "Here is your IPv6 ULA based on this hardware's MACs IPV6="$IPV6" (Use 'aa"${HASH:0:2}:${HASH:2:4}:${HASH:6:4}"::1/64' for Dual-stack IPv4+IPv6)"

    [ -z "$USE_ULA" ] && local IPV6="$(echo "$IPV6" | sed 's/^fd/aa/')"     # v4.16 Override standard ULA 'fcxx/fdxx' prefix

    rm /tmp/wgm_ula 2>/dev/null

    echo "$IPV6" 2>&1

}
Hex2Dec(){
    # Convert Hex to Dec (portable version) (see https://github.com/chmduquesne/wg-ip/blob/master/wg-ip)
    for I in $(echo "$@"); do
        printf "%d\n" "$(( 0x$I ))"
    done
}
Expand_IPv6() {
    # Returns an expanded IPv6 128-bit address under the form recommended by RFC5952 (see https://github.com/chmduquesne/wg-ip/blob/master/wg-ip)
    # Martineau see https://iplocation.io/ipv6-expand
    local ip=$1

    # Prepend 0 if we start with :
    echo $ip | grep -qs "^:" && local ip="0${ip}"

    # Expand ::
    if echo $ip | grep -qs "::"; then
        local colons=$(echo $ip | sed 's/[^:]//g')
        local missing=$(echo ":::::::::" | sed "s/$colons//")
        local expanded=$(echo $missing | sed 's/:/:0/g')
        local ip=$(echo $ip | sed "s/::/$expanded/")
    fi

    local blocks=$(echo $ip | grep -o "[0-9a-f]\+")
    set $blocks

    printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" $(Hex2Dec $@)

}
Compress_IPv6() {
# Returns a compressed IPv6 128-bit address under the form recommended by RFC5952 (see https://github.com/chmduquesne/wg-IP/blob/master/wg-IP)
# Martineau see https://iplocation.io/ipv6-compress
    local ip=$1

    local blocks=$(echo $ip | grep -o "[0-9a-f]\+")
    set $blocks

    # Compress leading zeros
    #local ip=$(printf "%x:%x:%x:%x:%x:%x:%x:%x\n" $(Hex2Dec $@))       # Martineau HACK!
    [ $# -eq 8 ] && local ip=$(printf "%x:%x:%x:%x:%x:%x:%x:%x\n" $(Hex2Dec $@)) || local ip=$(printf "%x:%x:%x:%x:%x:%x:%x\n" $(Hex2Dec $@))

    # Prepend : for easier matching
    local ip=:$ip

    # :: must compress the longest chain
    # Martineau Hacked
    for pattern in :0:0:0:0:0:0:0:0 \
            :0:0:0:0:0:0:0 \
            :0:0:0:0:0:0 \
            :0:0:0:0:0 \
            :0:0:0:0 \
            :0:0:0 \
            :0:0; do
        if echo $ip | grep -qs $pattern; then
            local ip=$(echo $ip | sed "s/$pattern/::/")
            # if the substitution occured before the end, we have :::
            local ip=$(echo $ip | sed 's/:::/::/')
            break # only one substitution
        fi
    done

    # Remove prepending : if necessary
    echo $ip | grep -qs "^:[^:]" && local ip=$(echo $ip | sed 's/://')

    echo $ip

}
IPv6_RFC() {

    local IPV6=$1                                                               # v4.15

    local IPV6_IP=${IPV6%/*}
    if [ -n "$(echo "$IPV6" | grep -F "/")" ];then
        local IPV6_IP_MASK=${IPV6##*/}
    fi
    local IPV6_SUBNET=${IPV6_IP%:*}
    local IPV6_IP_EXPANDED=$(Expand_IPv6 "$IPV6_IP")
    local IPV6_IP_COMPRESSED=$(Compress_IPv6 "$IPV6_IP_EXPANDED")

    [ -n "$IPV6_IP_MASK" ] && local IPV6=${IPV6_IP_COMPRESSED}"/"$IPV6_IP_MASK || local IPV6=${IPV6_IP_COMPRESSED}

    echo $IPV6

}
Convert_1024KMG() {

    local NUM=$1
    local UNIT=$(echo "$2" | tr '[a-z]' '[A-Z]')

    case "$UNIT" in
        M|MB|MIB)
            NUM=$(echo $NUM | awk '{printf "%.0f", $1*1024*1024}')      # v4.02 Hotfix
            ;;
        G|GB|GIB)
            NUM=$(echo $NUM | awk '{printf "%.0f", $1*1024*1024*1024}') # v4.02 Hotfix
            ;;
        K|KB|KIB)
            NUM=$(echo $NUM | awk '{printf "%.0f", $1*1024}')           # v4.02 Hotfix
            ;;
        B)
            ;;
    esac

    echo $NUM
}
Convert_SECS_to_HHMMSS() {

    local SECS=$1

    local DAYS_TXT=
    if [ $SECS -ge 86400 ] && [ -n "$2" ];then              # More than 24:00 i.e. 1 day?
        local DAYS=$((${SECS}/86400))
        SECS=$((SECS-DAYS*86400))
        local DAYS_TXT=$DAYS" days"
    fi
    local HH=$((${SECS}/3600))
    local MM=$((${SECS}%3600/60))
    local SS=$((${SECS}%60))
    if [ -z "$2" ];then
        echo $(printf "%02d:%02d:%02d" $HH $MM $SS)                    # Return 'hh:mm:ss" format
    else
        if [ -n "$2" ] && [ -z "$DAYS_TXT" ];then
            DAYS_TXT="0 Days, "
        fi
        echo $(printf "%s %02d:%02d:%02d" "$DAYS_TXT" $HH $MM $SS)      # Return in "x days hh:mm:ss" format
    fi
}
EpochTime(){

    #e.g. Convert a time into Epoch seconds...
    #   date -d "2018-11-13 20:56" +%s
    #   1542142560

    # and to convert it back
#
    #   date -d @1542142560 "+%F %T"
    #   2018-11-13 20:56:00
    # or
    #   date -d @1542142560 "+%c"
    #   Tue 13 Nov 2018 08:56:00 PM GMT

    if [ -z "$1" ];then
        RESULT=$(date +%s)                          # Convert current timestamp into Epoch seconds
    else
        if [ -z "$2" ];then
            RESULT=$(date -d @"$1" +%s)             # Convert specified YYYY-MM-DD HH:MM:SS into Epoch seconds
        else
            if [ "$2" == "Human" ];then
                RESULT=$(date -d @"$1" "+%F %T")     # Convert specified Epoch seconds into YYYY-MM-DD HH:MM:SS
            else
                RESULT=$(date -d @"$1" "+%c")        # Convert specified Epoch seconds into ddd mmm dd HH:MM:SS YYYY
            fi
        fi
    fi

    echo $RESULT
}
Size_Human() {

    local SIZE=$1
    if [ -z "$SIZE" ];then
        echo "N/A"
        return 1
    fi
    #echo $(echo $SIZE | awk '{ suffix=" KMGT"; for(i=1; $1>1024 && i < length(suffix); i++) $1/=1024; print int($1) substr(suffix, i, 1), $3; }')

    # if [ $SIZE -gt $((1024*1024*1024*1024)) ];then                                    # 1,099,511,627,776
        # printf "%2.2f TB\n" $(echo $SIZE | awk '{$1=$1/(1024^4); print $1;}')
    # else
        if [ $SIZE -gt $((1024*1024*1024)) ];then                                       # 1,073,741,824
            printf "%2.2f GiB\n" $(echo $SIZE | awk '{$1=$1/(1024^3); print $1;}')
        else
            if [ $SIZE -gt $((1024*1024)) ];then                                        # 1,048,576
                printf "%2.2f MiB\n" $(echo $SIZE | awk '{$1=$1/(1024^2);   print $1;}')
            else
                if [ $SIZE -gt $((1024)) ];then
                    printf "%2.2f KiB\n" $(echo $SIZE | awk '{$1=$1/(1024);   print $1;}')
                else
                    printf "%d Bytes\n" $SIZE
                fi
            fi
        fi
    # fi

    return 0
}
Check_Lock() {
        if [ -f "/tmp/wg.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/wg.lock)" ] && [ "$(sed -n '2p' /tmp/wg.lock)" != "$$" ]; then
            if [ "$(($(date +%s)-$(sed -n '3p' /tmp/wg.lock)))" -gt "1800" ]; then
                Kill_Lock
            else
                logger -st wg "[*] Lock File Detected ($(sed -n '1p' /tmp/wg.lock)) (pid=$(sed -n '2p' /tmp/wg.lock)) - Exiting (cpid=$$)"
                echo; exit 1
            fi
        fi
        if [ -n "$1" ]; then
            echo "$1" > /tmp/wg.lock
        else
            echo "menu" > /tmp/wg.lock
        fi
        echo "$$" >> /tmp/wg.lock
        date +%s >> /tmp/wg.lock
}
Kill_Lock() {

        if [ -f "/tmp/wg.lock" ] && [ -d "/proc/$(sed -n '2p' /tmp/wg.lock)" ]; then
            logger -st wg "[*] Killing Locked Processes ($(sed -n '1p' /tmp/wg.lock)) (pid=$(sed -n '2p' /tmp/wg.lock))"
            logger -st wg "[*] $(ps | awk -v pid="$(sed -n '2p' /tmp/wg.lock)" '$1 == pid')"
            kill "$(sed -n '2p' /tmp/wg.lock)"
            rm -rf /tmp/wg.lock
            echo
        fi
}
Manage_Addon() {

        # https://raw.githubusercontent.com/ZebMcKayhan/WireguardManager/main/wgmExpo.sh

        FN="$1"
        local BRANCH=$2

        if [ "$2" != "remove" ] && [ "$2" != "del" ];then
            [ -z "$BRANCH" ] && local BRANCH="main"
            download_file ${INSTALL_DIR} $FN zebmckayhan $BRANCH dos2unix 777
            chmod +x ${INSTALL_DIR}$FN
            ln -s /jffs/addons/wireguard/$FN /opt/bin/${FN%.*} 2>/dev/null
            md5sum ${INSTALL_DIR}$FN      > ${INSTALL_DIR}${FN%.*}.md5
        else
            rm ${INSTALL_DIR}$FN 2>/dev/null
            rm /opt/bin/$FN 2>/dev/null
        fi
}
download_file() {

        local DIR="$1"
        local FILE="$2"

        local GITHUB="$3"
        local GITHUB_BRANCH="$4"
        local DOSUNIX="$5"
        local CHMOD="$6"

        case $GITHUB in
            martineau)
                [ "$GITHUB_BRANCH" != "dev" ] && GITHUB_DIR=$GITHUB_MARTINEAU || GITHUB_DIR=$GITHUB_MARTINEAU_DEV
            ;;
            zebmckayhan)
                [ "$GITHUB_BRANCH" != "dev" ] && GITHUB_DIR=$GITHUB_ZEBMCKAYHAN || GITHUB_DIR=$GITHUB_ZEBMCKAYHAN_DEV
            ;;
        esac

        [ "$GITHUB_BRANCH" == "dev" ] && local DEVTXT=${cRESET}$cWRED"Github 'dev/development' branch"$cRESET || local DEVTXT=

        STATUS="$(curl --retry 3 -L${SILENT} -w '%{http_code}' "$GITHUB_DIR/$FILE" -o "$DIR/$FILE")"
        if [ "$STATUS" -eq "200" ]; then

            if [ -n "$(echo "$@" | grep -F "dos2unix")" ];then
                [ "$(which dos2unix)" == "/usr/bin/dos2unix" ] && dos2unix $DIR/$FILE || dos2unix -q $DIR/$FILE     # v4.12
            fi

            printf '\t%b%s%b downloaded successfully %b\n' "$cBGRE" "$FILE" "$cRESET" "$DEVTXT"
            [ -n "$CHMOD" ] && chmod $CHMOD "$DIR/$FILE"
        else
            printf '\n%b%s%b download FAILED with curl error %s\n\n' "\n\t\a$cRESET" "'${GITHUB_DIR}/${FILE}'" "$cBRED" "$STATUS"
            echo -e $cRESET"\a\n"

            return 1
        fi
}
_Get_File() {

    local WEBFILE=$1
    local REPOSITORY_OWNER=$2
    local FROM_REPOSITORY="main"
    [ "$3" == "dev" ] && { local FROM_REPOSITORY=$3; local FROM_RESPOSITORY_TXT="${cRESET}${cWRED}Github '$FROM_REPOSITORY' branch$cRESET"; }                                                         # v4.12
    REPOSITORY="https://github.com/odkrys/entware-makefile-for-merlin/raw/main/"      # v4.11

    [ "$REPOSITORY_OWNER" != "odkrys" ] && local REPOSITORY="https://github.com/ZebMcKayhan/Wireguard/raw/${FROM_REPOSITORY}/"    # v4.12 v4.11

    [ -z "$(echo "$@" | grep "NOMSG")" ] && echo -e $cBCYA"\n\tDownloading WireGuard® Kernel module ${cBWHT}'$WEBFILE'$cBCYA for $ROUTER (v$BUILDNO) @$REPOSITORY_OWNER $FROM_RESPOSITORY_TXT"$cRESET    # v4.12

    echo -en $cBGRE

    curl -# -s -fL --retry 3 ${REPOSITORY}${WEBFILE} -o ${INSTALL_DIR}${WEBFILE}      # v4.11
    local RC=$?

    [ $RC -ne 0 ] && { echo -e $cBRED; curl -# -fL --retry 3 ${REPOSITORY}${WEBFILE} -o ${INSTALL_DIR}${WEBFILE}; echo  "URL: '${REPOSITORY}${WEBFILE}'"; } || echo -e "Success!"   # v4.12

    return $?
}
Download_Modules() {

    local ROUTER=$1
    local FROM_REPOSITORY=$2                                                # v4.12
    [ -z "$FROM_REPOSITORY" ] && local FROM_REPOSITORY="main"               # v4.12
    local REPOSITORY_OWNER="odkrys"                                         # v4.11
    local USE_ENTWARE_KERNEL_MODULE="N"                                     # v4.12

    if [ -f ${INSTALL_DIR}WireguardVPN.conf ] &&  [ -n "$(grep -oE "^USE_ENTWARE_KERNEL_MODULE" ${INSTALL_DIR}WireguardVPN.conf)" ];then    # v4.12
        local USE_ENTWARE_KERNEL_MODULE="Y"
    fi

    if [ "$USE_ENTWARE_KERNEL_MODULE" == "Y" ];then
        rm ${INSTALL_DIR}*.ipk 2>/dev/null            # v4.12
        [ -n "$(opkg list-installed | grep "wireguard-kernel")" ] && opkg remove wireguard-kernel 1>/dev/null
        [ -n "$(opkg list-installed | grep "wireguard-tools")" ]  && opkg remove wireguard-tools  1>/dev/null
        rm ${INSTALL_DIR}*.ipk 2>/dev/null
    fi

    #local WEBFILE_NAMES=$(curl -${SILENT}fL https://www.snbforums.com/threads/experimental-wireguard-for-hnd-platform-4-1-x-kernels.46164/ | grep "<a href=.*odkrys.*wireguard" | grep -oE "wireguard.*" | sed 's/\"//g' | tr '\n' ' ')
    local WEBFILE_NAMES=$(curl -${SILENT}fL https://api.github.com/repos/odkrys/entware-makefile-for-merlin/git/trees/main | grep "\"path\": \"wireguard-.*\.ipk\"," | cut -d'"' -f 4)  # v4.11 @defung pull request https://github.com/MartineauUK/wireguard/pull/3

    # Allow use of Entware/3rd Party Kernel modules even if included in firmware
    if [ ! -f /usr/sbin/wg ] || [ "$USE_ENTWARE_KERNEL_MODULE" == "Y" ];then

        case "$ROUTER" in

            RT-AC86U|GT-AC2900)     # RT-AC86U, GT-AC2900 - 4.1.27          e.g. wireguard-kernel_1.0.20210606-k27_1_aarch64-3.10.ipk
                local WEBFILE_NAMES=$(curl -${SILENT}fL https://api.github.com/repos/ZebMcKayhan/Wireguard/git/trees/$FROM_REPOSITORY | grep "\"path\": \"wireguard-.*\.ipk\"," | cut -d'"' -f 4)   # v4.12 v4.11
                local REPOSITORY_OWNER="ZebMcKayhan"
                local MODULE="$(echo "$WEBFILE_NAMES" | awk "/$ROUTER/ {print}")"   # v4.13
                [ -z "$MODULE" ] && local MODULE=$(echo "$WEBFILE_NAMES" | awk "/k27/ {print}") # v4.13
                _Get_File "$MODULE" "$REPOSITORY_OWNER" "$FROM_REPOSITORY"
                ;;
            RT-AX88U|GT-AX11000)    # RT-AX88U, GT-AX11000 - 4.1.51         e.g. wireguard-kernel_1.0.20210219-k51_1_aarch64-3.10.ipk
                local WEBFILE_NAMES=$(curl -${SILENT}fL https://api.github.com/repos/ZebMcKayhan/Wireguard/git/trees/$FROM_REPOSITORY | grep "\"path\": \"wireguard-.*\.ipk\"," | cut -d'"' -f 4)   # v4.12
                local REPOSITORY_OWNER="ZebMcKayhan"
                local MODULE="$(echo "$WEBFILE_NAMES" | awk "/$ROUTER/ {print}")"   # v4.13
                [ -z "$MODULE" ] && local MODULE=$(echo "$WEBFILE_NAMES" | awk "/k51/ {print}") # v4.13
                _Get_File "$MODULE" "$REPOSITORY_OWNER" "$FROM_REPOSITORY"
                ;;
            RT-AX68U)               # RT-AX68U - 4.1.52                     e.g. wireguard-kernel_1.0.20210219-k52_1_aarch64-3.10.ipk
                _Get_File "$(echo "$WEBFILE_NAMES" | awk '/k52/ {print}')" "$REPOSITORY_OWNER" "$FROM_REPOSITORY"   # k52_1
                ;;
            RT-AX86U|GT-AC5700)     # v4.12 These models have wireguard in the firmware
                    # RT-AX68U, RT-AX86U - 4.1.52           e.g. wireguard-kernel_1.0.20210219-k52_1_aarch64-3.10.ipk
                    _Get_File "$(echo "$WEBFILE_NAMES" | awk '/k52/ {print}')" "$REPOSITORY_OWNER" "$FROM_REPOSITORY"   # k52_1
                ;;
            *)
                echo -e $cBRED"\a\n\t***ERROR: Unable to find 3rd-Party WireGuard® Kernel module for $ROUTER (v$BUILDNO)\n"$cRESET
                # Deliberately Download an incompatible file simply so that an error message is produced by 'opkg install*.ipk'
                #
                #       Unknown package 'wireguard-kernel'.
                #       Collected errors:
                #        * pkg_hash_fetch_best_installation_candidate: Packages for wireguard-kernel found, but incompatible with the architectures configured
                #        * opkg_install_cmd: Cannot install package wireguard-kernel.
                #
                #
                #_Get_File "$(echo "$WEBFILE_NAMES" | awk '{print $1}')" "$REPOSITORY_OWNER" "$FROM_REPOSITORY"
                ROUTER_COMPATIBLE="N"
                ;;
        esac
    else
        local FPATH=$(modprobe --show-depends wireguard | awk '{print $2}')
        local FVERSION=$(strings $FPATH | grep "^version" | cut -d'=' -f2)  # v4.12 @ZebMcKayhan
        echo -e $cBGRE"\n\t[✔]$cBWHT WireGuard® Kernel module/User Space Tools included in Firmware $ROUTER (v$BUILDNO)"$cRED" ($FVERSION)\n"$cRESET    # v4.12
        echo -e $cBYEL"\a\t\tWireGuard® exists in firmware       - use ${cRESET}'vx'${cBYEL} command to override with 3rd-Party/Entware (if available)"$cRESET
    fi

    # User Space Tools - Allow use of Entware/3rd Party modules even if Modules included in firmware
    if [ ! -f /usr/sbin/wg ] || [ "$USE_ENTWARE_KERNEL_MODULE" == "Y" ];then    # v4.12 Is the User Space Tools included in the firmware?
        if [ "$ROUTER_COMPATIBLE" != "N" ];then     # v4.13 HOTFIX
            WEBFILE=$(echo "$WEBFILE_NAMES" | awk '/wireguard-tools/ {print}')
            echo -e $cBCYA"\n\tDownloading WireGuard® User space Tool$cBWHT '$WEBFILE'$cBCYA for $ROUTER (v$BUILDNO) @$REPOSITORY_OWNER $FROM_RESPOSITORY_TXT"$cRESET  # v4.11
            _Get_File  "$WEBFILE" "$REPOSITORY_OWNER" "$FROM_REPOSITORY" "NOMSG"            # v4.12 v4.11
        fi
    else
        echo -e $cBYEL"\a\t\tUser Space tool exists in firmware - use ${cRESET}'vx'${cBYEL} command to override with 3rd-Party/Entware (if available)\n"$cRESET
    fi

}
Load_UserspaceTool() {

    local USE_ENTWARE_KERNEL_MODULE="N"                                     # v4.12
    if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -oE "^USE_ENTWARE_KERNEL_MODULE" ${INSTALL_DIR}WireguardVPN.conf)" ];then     # v4.12
        local USE_ENTWARE_KERNEL_MODULE="Y"
    fi

    if [ ! -d "${INSTALL_DIR}" ];then
        echo -e $cRED"\a\n\tNo modules found - '/${INSTALL_DIR} doesn't exist'\n"
        echo -e "\tPress$cBRED y$cRESET to$cBRED DOWNLOAD WireGuard® Kernel and Userspace Tool modules ${cRESET} or press$cBGRE [Enter] to SKIP."
            read -r "ANS"
            if [ "$ANS" == "y" ];then
                Download_Modules $HARDWARE_MODEL
            fi
    fi

    local ACTIVE_WG_INTERFACES=$(echo "$(wg show interfaces)" | tr " " "\n" | sort -r | tr "\n" " ")    # v4.13

    local STATUS=0
    if [ ! -f /usr/sbin/wg ] || [ "$USE_ENTWARE_KERNEL_MODULE" == "Y" ];then           # v4.12 Is the User Space Tools included in the firmware?
        echo -e $cBCYA"\n\tLoading WireGuard® Kernel module and Userspace Tool for $HARDWARE_MODEL (v$BUILDNO)"$cRESET
        if [ -n "$(ls /jffs/addons/wireguard/*.ipk 2>/dev/null)" ];then
            [ -n "$ACTIVE_WG_INTERFACES" ] && Manage_Wireguard_Sessions "stop" "$ACTIVE_WG_INTERFACES"  # v4.14
            for MODULE in $(ls /jffs/addons/wireguard/*.ipk)
                do
                    local MODULE_NAME=$(echo "$(basename $MODULE)" | sed 's/_.*$//')
                    SayT "Initialising WireGuard® module '$MODULE_NAME'"
                    echo -e $cBCYA"\tInitialising WireGuard® module $cRESET'$MODULE_NAME'"
                    opkg install $MODULE
                    if [ $? -eq 0 ];then
                        md5sum $MODULE > ${INSTALL_DIR}$MODULE_NAME".md5"
                        sed -i 's~/jffs/addons/wireguard/~~' ${INSTALL_DIR}$MODULE_NAME".md5"
                    else
                        local STATUS=1
                    fi
                done
        fi

        if [ "$STATUS" -eq 0 ];then
            insmod /opt/lib/modules/wireguard 2>/dev/null

            echo -e $cBGRA"\t"$(dmesg | grep -a "WireGuard" | tail -n 1)
            echo -e $cBGRA"\t"$(dmesg | grep -a "wireguard: Copyright" | tail -n 1)"\n"$cRESET
            local STATUS=0
        else
            echo -e $cBRED"\a\n\t***ERROR: Unable to LOAD Entware/3rd-party WireGuard® Kernel and Userspace Tool modules\n"
            local STATUS=1
        fi
    else

        local KERNEL_MODULE=$(find /lib/modules -name "wireguard.ko" | tr '\n' ' ' | awk '{print $1}')       # v4.14 v4.12

        if [ -n "$KERNEL_MODULE" ];then
            local FPATH=$(modprobe --show-depends wireguard | awk '{print $2}')
            local FVERSION=$(strings $FPATH | grep "^version" | cut -d'=' -f2)  # v4.12 @ZebMcKayhan
            echo -e $cBGRE"\n\t[✔]$cBWHT WireGuard® Kernel module/User Space Tools included in Firmware"$cRED" ($FVERSION)\n"$cRESET
            [ -n "$ACTIVE_WG_INTERFACES" ] && Manage_Wireguard_Sessions "stop" "$ACTIVE_WG_INTERFACES"  # v4.14
            SayT "Initialising WireGuard® Kernel module '$KERNEL_MODULE'"
            echo -e $cBCYA"\tInitialising WireGuard® Kernel module $cRESET'$KERNEL_MODULE'"
            rmmod  $KERNEL_MODULE 2>/dev/null                   # v4.12
            insmod $KERNEL_MODULE 2>/dev/null                   # v4.12
            echo -e $cBGRA"\t"$(dmesg | grep -a "WireGuard" | tail -n 1)
            echo -e $cBGRA"\t"$(dmesg | grep -a "wireguard: Copyright" | tail -n 1)"\n"$cRESET

            rm ${INSTALL_DIR}*.ipk 2>/dev/null            # v4.12
            [ -n "$(opkg list-installed | grep "wireguard-kernel")" ] && opkg remove wireguard-kernel 1>/dev/null
            [ -n "$(opkg list-installed | grep "wireguard-tools")" ]  && opkg remove wireguard-tools  1>/dev/null

        else
            logger -t "wireguard-server${VPN_ID:3:1}" "***ERROR Failure to Initialise WireGuard® Kernel module!"
            local STATUS=1
        fi
    fi

    [ -n "$ACTIVE_WG_INTERFACES" ] && Manage_Wireguard_Sessions "start" "$ACTIVE_WG_INTERFACES" # v4.13

    return $STATUS                                  # v4.14

}
Show_MD5() {

    local TYPE=$1

    if [ "$TYPE" == "script" ];then
        echo -e $cBCYA"\tMD5="$(awk '{print $0}' ${INSTALL_DIR}wg_manager.md5)
    else
        if [ ! -f /usr/sbin/wg ] || [ "$(which wg)" == "/opt/bin/wg" ];then           # v4.12
            echo -e $cBCYA"\tMD5="$(awk '{print $0}' ${INSTALL_DIR}wireguard-kernel.md5)
            echo -e $cBCYA"\tMD5="$(awk '{print $0}' ${INSTALL_DIR}wireguard-tools.md5)
        else
            #echo -e $cBYEL"\a\n\t***ERROR: MD5= ???? - WireGuard® exists in firmware for $ROUTER (v$BUILDNO)\n"$cRESET
            :
        fi
    fi
}
Check_Module_Versions() {

    local ACTION=$1

    local UPDATES="N"

    echo -e $cBGRA"\t"$(dmesg | grep -a "WireGuard" | tail -n 1)    # v4.12
    echo -e $cBGRA"\t"$(dmesg | grep -a "wireguard: Copyright" | tail -n 1)"\n"$cRESET  # v4.12

    if [ -n "$(lsmod | grep -i wireguard)" ];then
        if [ -n "$(opkg status wireguard-kernel | awk '/^Installed/ {print $2}')" ];then
            local LOADTIME=$(date -d @$(opkg status wireguard-kernel | awk '/^Installed/ {print $2}'))
        else
            local LOADTIME=
        fi
        echo -e $cBGRE"\t[✔] WireGuard® Module LOADED $LOADTIME\n"$cRESET
    else
        echo -e $cBRED"\t[✖] WireGuard® Module is NOT LOADED\n"$cRESET
    fi

    # Without a BOOT or 'loadmodule' command was issued, there may be a mismatch
    local BOOTLOADED=$(dmesg | grep -a WireGuard  | tail -n 1 | awk '{print $3}')
    local WGKERNEL=$(opkg list-installed | grep "wireguard-kernel" | awk '{print $3}' | sed 's/\-.*$//')
    local WGTOOLS=$(opkg list-installed | grep "wireguard-tools" | awk '{print $3}' | sed 's/\-.*$//')

    local USE_ENTWARE_KERNEL_MODULE="N"                                     # v4.12
    if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -oE "^USE_ENTWARE_KERNEL_MODULE" ${INSTALL_DIR}WireguardVPN.conf)" ];then
        local USE_ENTWARE_KERNEL_MODULE="Y"
    fi

    if [ -f /usr/sbin/wg ] && [ "$USE_ENTWARE_KERNEL_MODULE" == "N" ];then
        local FPATH=$(modprobe --show-depends wireguard | awk '{print $2}')
        local WGKERNEL=$(strings $FPATH | grep "^version" | cut -d'=' -f2)  # v4.12 @ZebMcKayhan
    fi

    #[ "$WGKERNEL" != "$BOOTLOADED" ] && echo -e $cRED"\a\n\tWarning: Reboot or 'loadmodule command' required for (dmesg) WireGuard® $WGKERNEL $BOOTLOADED\n"

    Show_MD5

    if [ "$ACTION" != "report" ];then

        # Check if Kernel and User Tools Update available
        echo -e $cBWHT"\tChecking for WireGuard® Kernel and Userspace Tool updates..."
        if [ "$HARDWARE_MODEL" != "RT-AC86U" ] && [ "$HARDWARE_MODEL" != "GT-AC2900" ];then                 # v4.12
            local REPOSITORY_OWNER="odkrys"                                                                 # v4.12
            local REPOSITORY_TITLE="entware-makefile-for-merlin"                                            # v4.12
        else
            local REPOSITORY_OWNER="ZebMcKayhan"                                                            # v4.12
            local REPOSITORY_TITLE="Wireguard"                                                              # v4.12
        fi

        local FILES=$(curl -${SILENT}fL https://api.github.com/repos/$REPOSITORY_OWNER/$REPOSITORY_TITLE/git/trees/main | grep "\"path\": \"wireguard-.*\.ipk\"," | cut -d'"' -f 4 | tr '\r\n' ' ')  # v4.12 v4.11 @defung pull request  https://github.com/MartineauUK/wireguard/pull/3

        if [ "$ACTION" == "force" ];then                                            # v4.12
            local UPDATES="Y"                                                       # v4.12
        else
            [ -z "$(echo "$FILES" | grep -F "$WGKERNEL")" ] && { echo -e $cBYEL"\t\tKernel UPDATE available" $FILE; local UPDATES="Y"; }
            [ -z "$(echo "$FILES" | grep -F "$WGTOOLS")" ] && { echo -e $cBYEL"\t\tUserspace Tool UPDATE available" $FILE; local UPDATES="Y"; }
        fi

        if [ "$UPDATES" == "Y" ];then
            if [ "$ACTION" != "force" ];then            # v4.12
                echo -e $cRESET"\n\tPress$cBRED y$cRESET to$cBRED Update WireGuard® Kernel and Userspace Tool${cRESET} or press$cBGRE [Enter] to SKIP."
                read -r "ANS"
            else
                local ANS="y"                           # v4.12
            fi

            if [ "$ANS" == "y" ];then
                Download_Modules $HARDWARE_MODEL
                #Load_UserspaceTool
            else
                echo -e $cBWHT"\n\tUpdate skipped\n"$cRESET
            fi
        else
            echo -e $cBGRE"\n\tWireGuard® Kernel and Userspace Tool up to date.\n"$cRESET
        fi
    fi
}
Create_Peer() {

    # Default subnet IPv4 only, but IPv4,IPv6 if applicable/specified or just IPv6

    # peer new                                  # IPv4 only

    # peer new ipv6[=[private_ipv6 subnet]]     # Multi IPv4 and IPv6
    # peer new ipv6 noipv4                      # no IPv4

    local ACTION=$1;shift

    local USE_IPV4="Y"              # v4.15
    local USE_IPV6="N"
    local VPN_POOL6=                # v4.15
    local IPV6_TXT=                 # v4.16 @archiel

    while [ $# -gt 0 ]; do          # v3.02
        case "$1" in
        auto*)
            local AUTO="$(echo "$@" | sed -n "s/^.*auto=//p" | awk '{print $1}')"
            ;;
        port*)
            local LISTEN_PORT="$(echo "$@" | sed -n "s/^.*port=//p" | awk '{print $1}')"
            local LISTEN_PORT_USER="Y"
            ;;
        ipv6|ipv6=*)
            local USE_IPV6="Y"
            local IPV6_TXT="(IPv6) "
            local SERVER_PEER=

            local VPN_POOL6="$(echo "$@" | sed -n "s/^.*ipv6=//p" | awk '{print $1}')"
            if [ "${1:0:5}" == "ipv6=" ] && [ -n "$VPN_POOL6" ];then
                # Ensure IPv6 address is in standard compressed format
                VPN_POOL6="$(IPv6_RFC "$VPN_POOL6")"        # v4.15
                local VPN_POOL_USER="Y"
                local USE_ULA=
            fi
            ;;
        ula4|ula)
            [ "$1" == "ula" ]  && local USE_ULA="Y"
            [ "$1" == "ula4" ] && local USE_ULA="4"         # v4.16
            ;;
        ip=*)
            local VPN_POOL4="$(echo "$@" | sed -n "s/^.*ip=//p" | awk '{print $1}')"
            local VPN_POOL_USER="Y"
            ;;
        noipv4|noIPv4)
            local USE_IPV4="N"                  # v4.15
            local IPV6_TXT="(IPv6 Only) "       # v4.15
            ;;
        *)
            local SERVER_PEER=$1
            case $SERVER_PEER in
                new)
                    local SERVER_PEER=
                ;;
            esac
            ;;
        esac
        shift
    done

    local INDEX=

    [ -z "$LISTEN_PORT" ] && local LISTEN_PORT=11500
    [ -z "$AUTO" ] && local AUTO="N" || AUTO=$(echo "$AUTO" | tr 'a-z' 'A-Z')

    if [ -z "$SERVER_PEER" ];then
        # Use the last IPv4 server as the VPN POOL
        local SERVER_PEER=$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers WHERE subnet LIKE '%.%';" | sort | tail -n 1)
        local AUTO_VPN_POOL="10.50.0.1/24"
        local INDEX=$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM servers;")
        local INDEX=$((INDEX+1))
        local SERVER_PEER="wg2"$INDEX
    else
        if [ "${SERVER_PEER:0:3}" == "wg2" ];then
            INDEX=${SERVER_PEER:3:1}
            local AUTO_VPN_POOL="10.50.$((INDEX-1)).1/24"       # v4.15
        else
            echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard® 'server' Peer prefix (wg2*) '$SERVER_PEER'\n"$cRESET
            return 1
        fi
    fi

    # User specified VPN Tunnel subnet?
    if [ -z "$VPN_POOL4" ] || [ -z "$VPN_POOL6" ];then
        [ -z "$AUTO_VPN_POOL" ] && local AUTO_VPN_POOL="10.50.1.1/24"
        local ONE_OCTET=$(echo "$AUTO_VPN_POOL" | cut -d'.' -f1)
        local TWO_OCTET=$(echo "$AUTO_VPN_POOL" | cut -d'.' -f2)
        local THIRD_OCTET=$(echo "$AUTO_VPN_POOL" | cut -d'.' -f3)
        local REST=$(echo "$AUTO_VPN_POOL" | cut -d'.' -f4-)
        local NEW_THIRD_OCTET=$((THIRD_OCTET+1))
        local SERVER_CNT=$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM servers;")
        [ $SERVER_CNT -ge $NEW_THIRD_OCTET ] && local NEW_THIRD_OCTET=$((SERVER_CNT+1))
        [ "$USE_IPV4" == "Y" ] && local VPN_POOL4=$(echo -e "$ONE_OCTET.$TWO_OCTET.$NEW_THIRD_OCTET.$REST")

        if [ "$USE_IPV6" == "Y" ] && [ -z "$VPN_POOL6" ];then
            [ -z "$TWO_OCTET" ] && local TWO_OCTET="50"
            [ -z "$NEW_THIRD_OCTET" ] && local NEW_THIRD_OCTET="1"

            case $USE_ULA in
                4)
                    local VPN_POOL6="fd00:${TWO_OCTET}:${NEW_THIRD_OCTET}::1/64"
                ;;
                *)
                    local VPN_POOL6=$(Generate_IPv6_ULA "$USE_ULA") # v4.16
                    [ "$VPN_POOL6" == "***ERROR Requires Entware module" ] && local VPN_POOL6="fd00:${TWO_OCTET}:${NEW_THIRD_OCTET}::1/64"
                ;;
            esac
        fi
    fi

    [ -n "$VPN_POOL4" ] && local VPN_POOL=$VPN_POOL4    # v4.15

    if [ -n "$VPN_POOL4" ] && [ -n "$VPN_POOL6" ];then  # v4.15
            local VPN_POOL=$VPN_POOL4","$VPN_POOL6
            local IPV6_TXT="(IPv4/IPv6) "               # v4.15
    fi

    if [ "$USE_IPV4" == "N" ];then                      # v4.15
        if [ -n "$VPN_POOL6" ];then                     # v4.15
            local VPN_POOL=$VPN_POOL6                   # v4.15
            local IPV6_TXT="(IPv6) "                    # v4.15
        else
            echo -e $cBRED"\a\n\t***ERROR Create new WireGuard® ${IPV6_TXT}'server' Peer has missing ${cRESET}IPv6 Private subnet${cBRED} - use $cRESET'ipv6[=]'$cBRED arg\n"$cRESET
            return 1
        fi
    fi

    # User specified Listen Port?
    [ -z "$LISTEN_PORT_USER" ] && LISTEN_PORT=$((LISTEN_PORT+INDEX))

    for THIS in $(echo "$VPN_POOL" | tr ',' ' ')        # v4.15
        do
            if [ -z "$(echo "$THIS" | grep -F ":")" ];then
                [ -z "$(echo "$THIS" | Is_IPv4_CIDR)" ] && { echo -e $cBRED"\a\n\t***ERROR: '$THIS' must be IPv4 CIDR"$cRESET; return 1; }                                  # v4.15
            else
                # ANY IPv6 but don't allow Link-Local IPv6 (i.e. fe80::/10 but in practice, only fe80::/64 is commonly used)                                                            # v4.16
                [ "$THIS{0:4}" == "fe80" ] && { echo -e $cBRED"\a\n\t***ERROR: IPv6 Link-Local address '$THIS' NOT allowed!"$cRESET; return 1; }                                    # v4.16
            fi
        done

    if [ -f ${CONFIG_DIR}${SERVER_PEER}.conf ] || [ -n "$(grep -E "^$SERVER_PEER" ${INSTALL_DIR}WireguardVPN.conf)" ];then
        echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard® 'server' Peer '$SERVER_PEER' already exists\n"$cRESET
        return 1
    fi

    local WANIPADDR=$(nvram get wan0_ipaddr)
    [ -n "$(echo "$WANIPADDR" | Is_Private_IPv4)" ] && echo -e ${cRESET}${cBRED}${aBOLD}"\a\n\t*** Ensure Upstream router Port Foward entry for port:${cBMAG}${LISTEN_PORT}${cRESET}${cBRED}${aBOLD} ***"$cRESET
    echo -e $cBWHT"\n\tPress$cBGRE y$cRESET to$cBGRE Create ${cBCYA}${IPV6_TXT}${cBGRE}'server' Peer (${cBMAG}${SERVER_PEER}${cBGRE}) ${cBCYA}${VPN_POOL}:${LISTEN_PORT}${cRESET} or press$cBGRE [Enter] to SKIP." # v4.15
    read -r "ANS"
    [ "$ANS" == "y" ] || return 1

    echo -e $cBCYA"\tCreating WireGuard® Private/Public key-pair for ${IPV6_TXT}'server' Peer ${cBMAG}${SERVER_PEER}${cBCYA} on $HARDWARE_MODEL (v$BUILDNO)"$cRESET
    if [ -n "$(which wg)" ];then
        wg genkey | tee ${CONFIG_DIR}${SERVER_PEER}_private.key | wg pubkey > ${CONFIG_DIR}${SERVER_PEER}_public.key
        local PRI_KEY=$(cat ${CONFIG_DIR}${SERVER_PEER}_private.key)
        local PRI_KEY=$(Convert_Key "$PRI_KEY")
        local PUB_KEY=$(cat ${CONFIG_DIR}${SERVER_PEER}_public.key)
        local PUB_KEY=$(Convert_Key "$PUB_KEY")                         # v4.14
        #sed -i "/^PrivateKey/ s~[^ ]*[^ ]~$PRI_KEY~3" ${CONFIG_DIR}${SERVER_PEER}.conf

        local ANNOTATE="# $HARDWARE_MODEL ${IPV6_TXT}Server $INDEX"

        # Create Server template
        cat > ${CONFIG_DIR}${SERVER_PEER}.conf << EOF
$ANNOTATE
[Interface]
PrivateKey = $PRI_KEY
Address = $VPN_POOL
ListenPort = $LISTEN_PORT

EOF
# e.g. Accept a WireGuard connection from say YOUR mobile device to the router
# see '${CONFIG_DIR}mobilephone_private.key'

# Peer Example
#[Peer]
#PublicKey = Replace_with_the_Public_Key_of_YOUR_mobile_device
#AllowedIPs = PEER.ip.xxx.xxx/32
#PresharedKey = Replace_with_the_Pre-shared_Key_of_YOUR_mobile_device
# Peer Example End

        chmod 600 ${CONFIG_DIR}${SERVER_PEER}.conf          # v4.15 Prevent wg-quick "Warning: '/opt/etc/wireguard.d/wg22.conf' is world accessible"
        sqlite3 $SQL_DATABASE "INSERT INTO servers values('$SERVER_PEER','$AUTO','${VPN_POOL}','$LISTEN_PORT','$PUB_KEY','$PRI_KEY','$ANNOTATE');"
    fi

    echo -e $cBWHT"\tPress$cBGRE y$cRESET to$cBGRE Start ${cBCYA}${IPV6_TXT}${cBGRE}'server' Peer (${cBMAG}${SERVER_PEER}$cBGRE)$cRESET or press $cBGRE[Enter] to SKIP."
    read -r "ANS"
    [ "$ANS" == "y" ] && Manage_Wireguard_Sessions "start" "$SERVER_PEER"
    Show_Peer_Status "show" # v3.03

    # Firewall rule to listen on multiple ports?
    #   e.g. iptables -t nat -I PREROUTING -i $WAN_IF -d <yourIP/32> -p udp -m multiport --dports 53,80,4444  -j REDIRECT --to-ports $LISTEN_PORT

}
Delete_Peer() {

    local FORCE=$2

    for WG_INTERFACE in $@
        do

            if [ -n "$FORCE" ] || [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then     # v3.05
                if [ "$WG_INTERFACE" != "force" ];then
                    #[ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ] && local Mode=$(Server_or_Client "$WG_INTERFACE") || local Mode="?"
                    local Mode=$(Server_or_Client "$WG_INTERFACE")
                    [ "$Mode" == "**ERROR**" ] && local Mode="?"
                    local SQL_COL="peer"
                    if [ "$Mode" == "?" ];then                  # v4.14
                        case $WG_INTERFACE in
                            wg2*) local Mode="server";;
                            wg1*) local Mode="client";;
                        esac
                    fi
                    [ "$Mode" == "server" ] && local TABLE="servers" || { local TABLE="clients"; local FORCE="FORCEDCLIENT" ;}  # v4.16b6
                    #[  "${WG_INTERFACE:0:2}" != "wg" ] && { TABLE="devices"; local SQL_COL="name"; Mode="device"; }

                    echo -e $cBWHT"\n\tDeleting '$Mode' Peer (${cBMAG}${WG_INTERFACE}${cBWHT})\n"$cBRED

                    if [ "$Mode" == "server" ];then
                            # Check how many 'client' Peers exist
                            [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ] && local CNT=$(grep -cE "^AllowedIPs" ${CONFIG_DIR}${WG_INTERFACE}.conf ) || local CNT=0   # v4.14
                            if [ $CNT -gt 0 ];then
                                echo -e $cBRED"\n\tWarning: 'server' Peer ${cBMAG}${WG_INTERFACE}${cBRED} has ${cBWHT}${CNT}${cBRED} 'client' Peer\n"$cBYEL
                                grep -E -B 3 -A 1 "^AllowedIPs" ${CONFIG_DIR}${WG_INTERFACE}.conf
                                echo -e $cBWHT"\n\tYou can manually reassign them to a different 'server' Peer by using command 'peer wg2x bind"    # v4.16
                            fi

                            # Site-to-Site identify remote site peer
                            # Extract '# Cabin LAN'
                            if [ "$(sqlite3 $SQL_DATABASE "SELECT auto FROM servers WHERE peer='$WG_INTERFACE';")" == "S" ];then    # v4.15
                                local SITE2SITE_PEER_LAN=$(awk '/^#.*LAN/ {print $2}' ${CONFIG_DIR}${WG_INTERFACE}.conf )           # v4.15
                            fi
                    fi

                    echo -e $cBWHT"\tPress$cBRED y$cRESET to ${aBOLD}CONFIRM${cRESET}${cBRED} or press$cBGRE [Enter] to SKIP."
                    read -r "ANS"

                    if [ "$ANS" == "y" ];then

                        [ -n "$(wg show $WG_INTERFACE 2>/dev/null)" ] && Manage_Wireguard_Sessions "stop" "$WG_INTERFACE"
                        sqlite3 $SQL_DATABASE "DELETE FROM $TABLE WHERE $SQL_COL='$WG_INTERFACE';"
                        [ -n "$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE name='$WG_INTERFACE';")" ] && sqlite3 $SQL_DATABASE "DELETE FROM devices WHERE name='$WG_INTERFACE';"

                        # Site-to-Site remove the remote Site from 'devices' table if it exists
                        if [ -n "$SITE2SITE_PEER_LAN" ];then
                            [ -n "$(sqlite3 $SQL_DATABASE "SELECT * FROM devices WHERE name='$SITE2SITE_PEER_LAN';")" ] && sqlite3 $SQL_DATABASE "DELETE FROM devices WHERE name='$SITE2SITE_PEER_LAN';"    # v4.15
                        fi

                        # ... and delete associated RPDB Selective Routing rule
                        sqlite3 $SQL_DATABASE "DELETE FROM policy WHERE peer='$WG_INTERFACE';"
                        # IPsets
                        sqlite3 $SQL_DATABASE "DELETE FROM ipset WHERE peer='$WG_INTERFACE';"
                        # Passthru
                        if [ "$Mode" == "server" ];then                                                 # v4.16
                            sqlite3 $SQL_DATABASE "DELETE FROM passthru WHERE server='$WG_INTERFACE';"  # v4.16
                        fi
                        if [ "$Mode" == "client" ];then                                                 # v4.16
                            sqlite3 $SQL_DATABASE "DELETE FROM passthru WHERE client='$WG_INTERFACE';"  # v4.16
                        fi
                        [ -n "$(sqlite3 $SQL_DATABASE "SELECT * FROM passthru WHERE ip_subnet='$WG_INTERFACE';")" ] && sqlite3 $SQL_DATABASE "DELETE FROM passthru WHERE ip_subnet='$WG_INTERFACE';"    # v4.16

                        #   DDNS martineau.homeip.net
                        #   Endpoint = martineau.homeip.net:51820
                        if [ -n "$FORCE" ] || [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                            if [ -n "$FORCE" ] || [ "$(awk -F '[ :]' '/^Endpoint/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf)" == "$(nvram get ddns_hostname_x)" ];then      # v4.02

                                # Remove the 'client' from any 'server' Peers
                                #   # SGS8
                                #   ..........
                                #   # SGS8 End

                                # Scan for 'server' Peer that accepts this 'client' connection
                                local MATCHTHIS="$(echo "$WG_INTERFACE" | sed 's/\"/\\\"/g')"

                                if [ -n "$(ls /opt/etc/wireguard.d/wg2*.conf 2>/dev/null)" ];then
                                    local SERVER_PEER_LIST=$(grep -HE "^#.*${MATCHTHIS}.*device" ${CONFIG_DIR}*.conf | tr '\n' ' ')    # v4.14 v4.11
                                fi
                                for SERVER_PEER in $SERVER_PEER_LIST
                                    do
                                        SERVER_PEER=$(echo "$SERVER_PEER" | awk -F '[\/:\._]' '{print $6}')
                                        if [ -n "$SERVER_PEER" ];then
                                            if [ "$WG_INTERFACE" != "$SERVER_PEER" ];then
                                                echo -e $cBGRE"\t'device' Peer ${cBMAG}${WG_INTERFACE}${cBGRE} removed from 'server' Peer (${cBMAG}${SERVER_PEER}${cBGRE})"     # 4.02
                                                sed -i "/^# ${MATCHTHIS} device/,/^# $WG_INTERFACE End$/d" ${CONFIG_DIR}${SERVER_PEER}.conf
                                                local RESTART_SERVERS=$RESTART_SERVERS" "$SERVER_PEER
                                            fi
                                        fi
                                    done
                            fi
                        fi

                        if [ "${WG_INTERFACE:0:3}" == "wgc" ] || [ "${WG_INTERFACE:0:3}" == "wgs" ];then
                            # Shouldn't be used on a Router with WireGuard installed in firmware?
                            #if [ "$(which wg)" != "/usr/sbin/wg" ];then

                                nvram unset ${WG_INTERFACE}_addr
                                nvram unset ${WG_INTERFACE}_aips
                                nvram unset ${WG_INTERFACE}_alive
                                nvram unset ${WG_INTERFACE}_dns
                                nvram unset ${WG_INTERFACE}_enable
                                nvram unset ${WG_INTERFACE}_ep_addr
                                nvram unset ${WG_INTERFACE}_ep_port
                                nvram unset ${WG_INTERFACE}_nat
                                nvram unset ${WG_INTERFACE}_ppub
                                nvram unset ${WG_INTERFACE}_priv

                                SayT "Debug: nvram_unset vpnc_clientlist="$(nvram get vpnc_clientlist)
                                #nvram unset vpnc_clientlist

                                SayT "Debug: nvram_unset vpnc_pptp_options_x_list="$(nvram get vpnc_pptp_options_x_list)
                                #nvram unset vpnc_pptp_options_x_list

                                SayT "Debug: nvram_unset wgc_unit="$(nvram get wgc_unit)
                                #nvram unset wgc_unit
                            #fi
                        fi
                        #echo -e $cBCYA"\tDeleting '${CONFIG_DIR}${WG_INTERFACE}*.*'"$cBRED
                        rm ${CONFIG_DIR}${WG_INTERFACE}* 2>/dev/null

                        echo -e $cBGRE"\t'$Mode' Peer ${cBMAG}${WG_INTERFACE}${cBGRE} ${cBRED}${aREVERSE}DELETED"$cRESET

                        # Do we need to restart any 'server' Peers?.....Remove duplicates from the restart list
                        RESTART_SERVERS=$(echo "$RESTART_SERVERS" | xargs -n1 | sort -u | xargs)        # v3.05
                        for SERVER_PEER in $RESTART_SERVERS
                            do
                                # Need to Restart the 'server' Peer if it is UP
                                if [ -n "$(wg show interfaces | grep "$SERVER_PEER")" ];then
                                    CMD="restart"
                                    echo -e $cBWHT"\a\n\tWireGuard® 'server' Peer needs to be ${CMD}ed to remove 'client' Peer ${cBMAG}$DEVICE_NAME $TAG"
                                    echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'server' Peer ($SERVER_PEER) or press$cBGRE [Enter] to SKIP."
                                    read -r "ANS"
                                    [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$SERVER_PEER"; Show_Peer_Status "show"; }  # v3.03
                                fi
                            done
                    fi
                fi
            else
                [ -n "$Mode" ] && TXT="'$Mode' " || TXT=            # v3.03
                SayT "***ERROR: WireGuard® VPN ${TXT}Peer ('$WG_INTERFACE') config NOT found?....skipping $ACTION request"
                echo -e $cBRED"\a\n\t***ERROR: WireGuard® ${TXT}Peer (${cBWHT}$WG_INTERFACE${cBRED}) config NOT found?....skipping delete Peer '${cBMAG}${WG_INTERFACE}${cBRED}' request\n"$cRESET   2>&1  # v1.09
            fi
        done

}
Import_Peer() {


    local ACTION=$1;shift
    local WG_INTERFACE=$1

    if [ "$1" == "?" ];then
        local CONFIGS=$(ls -1 ${CONFIG_DIR}*.conf 2>/dev/null | awk -F '/' '{print $5}' | grep -v "wg[1-2]" | sort )
        echo -e $cBYEL"\n\t Available Peer Configs for import:\n${cRESET}$CONFIGS"
        return 0
    fi

    if [ "$1" == "dir" ];then

        IMPORT_DIR=$2
        [ "${IMPORT_DIR:0:1}" != "/" ] && IMPORT_DIR="/opt/etc/"$IMPORT_DIR
        [  ${IMPORT_DIR#"${IMPORT_DIR%?}"} != "/" ] && IMPORT_DIR=$IMPORT_DIR"/"
        if [ -d $IMPORT_DIR ];then
            echo -e $cBGRE"\n\t[✔] Import directory set $IMPORT_DIR"$cRESET 2>&1
        else
            echo -e $cBRED"\a\n\t***ERROR: Invalid directory ${cBWHT}'$IMPORT_DIR'"$cRESET 2>&1
            return 1
        fi
        shift 2

        local WG_INTERFACE=$1
    fi

    # Allow detection of NVRAM (spoofing!)
    if [ -n "$(nvram dump 2>/dev/null | grep "wgc_unit")" ] || [ "$(which wg)" == "/usr/sbin/wg" ];then # v4.12
        local ASUS_NVRAM="Y"
    fi

    while [ $# -gt 0 ]; do
        #if [ "$ASUS_NVRAM" != "Y" ];then                                # v4.12
                if [ -n "$(echo "$1" | grep -F "name=")" ];then
                    local RENAME="Y"
                    local NEW_NAME=$(echo "$1" | sed -n "s/^.*name=//p" | awk '{print $0}')
                else
                    # v4.12 By default if 'name=' not specified import .config into next free 'wgxx' slot; unless 'wgxx' supplied
                    if [ -z "$(echo "$WG_INTERFACE" | grep -E "^wg[1-2]")" ];then           # v4.12
                        local RENAME="Y"
                    fi
                fi
                if [ "$1" == "tag=" ] || [ "$1" == "comment" ];then
                    local ANNOTATE="$(echo "$1" | sed -n "s/^.*tag=//p" | awk '{print $0}')"
                    [ -z "$ANNOTATE" ] && local ANNOTATE="$(echo "$@" | sed -n "s/^.*comment//p" | awk '{print $0}')"
                    break
                fi
                if [ -n "$(echo "$1" | grep -F "type=")" ];then
                    local FORCE_TYPE="$(echo "$1" | sed -n "s/^.*type=//p" | awk '{print $0}')"     # v4.03
                fi
        #fi

        shift

    done

    if [ "$RENAME" == "Y" ];then
            if [ "$FORCE_TYPE" != "server" ];then
                local CONFIGURED_IDS="11 12 13 14 15 16 17 18 19 111 112 113 114 115"   # v4.14
            else
                local CONFIGURED_IDS="21 22 23 24 25 26 27 28 29"                       # v4.15 v4.14
            fi

            if [ -z "$NEW_NAME" ] || [ "$NEW_NAME" == "?" ];then
                # Pick the next Peer name
                for I in $CONFIGURED_IDS                        # v4.14
                    do
                        [ -f ${CONFIG_DIR}wg${I}.conf ] && continue
                        local NEW_NAME="wg"$I
                        break
                    done
            else
                if [ -f ${CONFIG_DIR}${NEW_NAME}.conf ];then
                    echo -e $cBRED"\a\n\t***ERROR: Peer (${cBWHT}$NEW_NAME${cBRED}) ALREADY exists!"$cRESET
                    return 1
                fi
            fi
    fi

    for WG_INTERFACE in $WG_INTERFACE $@
        do
            [ "$WG_INTERFACE" = "comment" ] && break

            if [ "${WG_INTERFACE:0:1}" == "/" ];then        # v4.12
                local PATHNAME=$WG_INTERFACE
                IMPORT_DIR=${PATHNAME%/*}"/"                # v4.12 Directory
                WG_INTERFACE=${PATHNAME##*/}                # v4.12 Filename.Suffix i.e. strip Directory
                WG_INTERFACE=${WG_INTERFACE%.*}             # v4.12 Filename i.e. strip .Suffix
            else
                WG_INTERFACE=${WG_INTERFACE%.*}             # v4.12 v4.11
            fi

            if [ -f ${IMPORT_DIR}${WG_INTERFACE}.conf ];then
                [ -z "$FORCE_TYPE" ] && local MODE=$(Server_or_Client "$WG_INTERFACE" "$IMPORT_DIR")            # v4.14 v4.12
                [ -n "$FORCE_TYPE" ] && { MODE=$FORCE_TYPE; local FORCE_TYPE_TXT="(${cBRED}FORCED as '$MODE'${cRESET}) ${cBGRE}"; } # v4.03
                #if [ "$MODE" != "server" ];then
                    case $MODE in
                        client)
                            local TABLE="clients"
                            local AUTO="N"
                            local KEY="peer"
                        ;;
                        device)
                            local TABLE="devices"
                            local AUTO="X"
                            local KEY="name"
                        ;;
                        server)
                            local TABLE="servers"
                            local AUTO="N"
                            local KEY="peer"
                            [ -n "$(grep -E "^Endpoint" ${IMPORT_DIR}${WG_INTERFACE}.conf)" ] && AUTO="S"   # v.4.15 Site-to-Site
                        ;;
                        *)
                            SayT "***ERROR: WireGuard Peer TYPE ('$FORCE_TYPE') must be 'client'/'server' or 'device'....skipping import request"
                            echo -e $cBRED"\a\n\t***ERROR: WireGuard® Peer TYPE (${cBWHT}$FORCE_TYPE${cBRED}) must be 'client'/'server' or 'device'....skipping import Peer '${cBMAG}${WG_INTERFACE}${cBRED}' request\n"$cRESET   2>&1
                            return 1
                        ;;
                    esac

                    if [ -z "$(sqlite3 $SQL_DATABASE "SELECT $KEY FROM $TABLE WHERE $KEY='$WG_INTERFACE';")" ];then
                        if [ -z "$ANNOTATE" ];then
                            # Use comment line preceding the '[Interface]' directive
                            local ANNOTATE=$(grep -FB1 "[Interface]" ${IMPORT_DIR}${WG_INTERFACE}.conf | grep -vF "[Interface]")
                            [ -z "$ANNOTATE" ] && local ANNOTATE="# N/A" || local INSERT_COMMENT="N"    # v4.03
                        fi

                        local ANNOTATE=$(echo "$ANNOTATE" | sed "s/'/''/g")
                        local ANNOTATE=$(printf "%s" "$ANNOTATE" | sed 's/^[ \t]*//;s/[ \t]*$//')
                        [ "${ANNOTATE:0:1}" != "#" ] && ANNOTATE="# "$ANNOTATE

                        while IFS='' read -r LINE || [ -n "$LINE" ]; do

                            case "${LINE%% *}" in

                                PrivateKey) local PRI_KEY=${LINE##* };;
                                PublicKey) local PUB_KEY=${LINE##* };;
                                ListenPort) local LISTEN_PORT=${LINE##* }               # v4.17 v4.14
                                    # Torguard profile defines 51820 which will conflict with the wg21 'server' Peer default 51820
                                    # Check if port is already in use by a 'server' Peer; if so comment it out
                                    [ "$LISTEN_PORT" == "51820" ] && COMMENT_OUT="Y"    # v4.17
                                    [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM servers WHERE port='$LISTEN_PORT';") -gt 0 ] && COMMENT_OUT="Y"  # v4.17

                                ;;
                                AllowedIPs) local ALLOWIP=$(echo "$LINE" | sed 's/^AllowedIPs.*=//' | awk '{$1=$1};1')  # v4.12 strip leading/trailing spaces/tabs
                                ;;
                                Endpoint) local SOCKET=${LINE##* }
                                    local SOCKET=$(echo "$SOCKET" | awk '{$1=$1};1')    # v4.12  strip leading/trailing spaces/tabs
                                ;;
                                PreUp)                                          # v4.14
                                    # This must be commented out!
                                    if [ "$MODE" != "device" ];then
                                        COMMENT_OUT="Y"
                                    fi
                                ;;
                                "#"PostUp);;                                    # v4.14
                                PostUp)                                         # v4.14
                                    # This must be commented out!
                                    if [ "$MODE" != "device" ];then
                                        COMMENT_OUT="Y"
                                    fi
                                ;;
                                "#"PreDown);;                                   # v4.14
                                PreDown)                                        # v4.14
                                    # This must be commented out!
                                    if [ "$MODE" != "device" ];then
                                        COMMENT_OUT="Y"
                                    fi
                                ;;
                                "#"PostDown);;                                  # v4.14
                                PostDown)                                       # v4.14
                                    # This must be commented out!
                                    if [ "$MODE" != "device" ];then
                                        COMMENT_OUT="Y"
                                    fi
                                ;;
                                "#"SaveConfig);;                                  # v4.14
                                SaveConfig)                                       # v4.14
                                    # This must be commented out!
                                    if [ "$MODE" != "device" ];then
                                        COMMENT_OUT="Y"
                                    fi
                                ;;
                                MTU) local MTU=${LINE##* }                      # v4.09
                                ;;
                                DNS) local DNS=$(echo "$LINE" | sed 's/^DNS.*=//' | awk '{$1=$1};1')                # HOTFIX v4.16
                                ;;
                                Address) local SUBNET=$(echo "$LINE" | sed 's/^Address.*=//' | awk '{$1=$1};1')     # HOTFIX v4.16
                                ;;
                            esac
                        done < ${IMPORT_DIR}${WG_INTERFACE}.conf

                        [ -f ${IMPORT_DIR}${WG_INTERFACE}_public.key ] && local PUB_KEY=$(awk 'NR=1{print $0}' ${IMPORT_DIR}${WG_INTERFACE}_public.key)

                        [ -z "$DNS" ] && local DNS=$COMMENT_DNS             # v4.03
                        [ -z "$SUBNET" ] && local SUBNET=$COMMENT_SUBNET       # v4.03

                        if [ -d ${CONFIG_DIR} ];then
                            if [ "$MODE" != "device" ];then
                                if [ "$RENAME" != "Y" ];then
                                    IMPORTED_PEER_NAME=$WG_INTERFACE
                                    if [ "$MODE" == "client" ];then
                                        sqlite3 $SQL_DATABASE "INSERT INTO $TABLE values('$WG_INTERFACE','$AUTO','$SUBNET','$SOCKET','$DNS','$MTU','$PUB_KEY','$PRI_KEY','$ANNOTATE');"     # v4.09
                                    else
                                        sqlite3 $SQL_DATABASE "INSERT INTO servers values('$WG_INTERFACE','$AUTO','${SUBNET}','$LISTEN_PORT','$PUB_KEY','$PRI_KEY','$ANNOTATE');"
                                    fi
                                else
                                    IMPORTED_PEER_NAME=$NEW_NAME
                                    if [ "$MODE" == "client" ];then
                                        sqlite3 $SQL_DATABASE "INSERT INTO $TABLE values('$NEW_NAME','$AUTO','$SUBNET','$SOCKET','$DNS','$MTU','$PUB_KEY','$PRI_KEY','$ANNOTATE');"         # v4.09
                                    else
                                        sqlite3 $SQL_DATABASE "INSERT INTO servers values('$NEW_NAME','$AUTO','${SUBNET}','$LISTEN_PORT','$PUB_KEY','$PRI_KEY','$ANNOTATE');"
                                    fi
                                fi
                            else
                                IMPORTED_PEER_NAME=$WG_INTERFACE
                                sqlite3 $SQL_DATABASE "INSERT INTO $TABLE values('$WG_INTERFACE','$AUTO','$SUBNET','$DNS','$ALLOWIP','$PUB_KEY','$PRI_KEY','$ANNOTATE','');"
                            fi
                        fi

                        if [ "$ASUS_NVRAM" == "Y" ] && [ "$(/bin/uname -o)" != "ASUSWRT-Merlin" ];then       # v4.14 v4.12
                            # ASUS supported firmware, so use NVRAM
                            if [ $(nvram get wgc_unit) -ne 1 ];then
                                local INDEX=$(($(nvram get wgc_unit)-1))
                            else
                                local INDEX=5
                            fi
                            eval "nvram set wgc${INDEX}_addr='$SUBNET'"
                            eval "nvram set wgc${INDEX}_aips='$ALLOWIP'"
                            eval "nvram set wgc${INDEX}_alive=25"
                            eval "nvram set wgc${INDEX}_dns='$DNS'"
                            eval "nvram set wgc${INDEX}_enable=0"
                            # Split  Endpoint 'ip:port' for separate GUI fields
                            local SOCKET_IP=${SOCKET%:*}        # Endpoint IP address
                            local SOCKET_PORT=${SOCKET##*:}     # Endpoint Port
                            eval "nvram set wgc${INDEX}_ep_addr='$SOCKET_IP'"
                            eval "nvram set wgc${INDEX}_ep_port='$SOCKET_PORT'"
                            eval "nvram set wgc${INDEX}_nat=1"
                            eval "nvram set wgc${INDEX}_ppub='$PUB_KEY'"
                            eval "nvram set wgc${INDEX}_priv='$PRI_KEY'"

                            #vpnc_clientlist=Mullvad_USA_Los_Angeles>WireGuard>5>>>1>5>><Mullvad_Oz_Melbourne>WireGuard>4>>>1>6>>
                            local PREV=$(nvram get vpnc_clientlist)
                            local ANNOTATE=$(echo "$ANNOTATE" | sed 's/^# //' | sed 's/,/-/g')  # GUI doesn't allow certain characters in name

                            nvram set vpnc_clientlist="${PREV}${ANNOTATE}>WireGuard>${INDEX}>>>0>${INDEX}>>"

                            local PREV=$(nvram get vpnc_pptp_options_x_list)
                            nvram set vpnc_pptp_options_x_list="${PREV}<auto"

                            nvram set wgc_unit=$INDEX

                            nvram commit

                            # When connected
                            # fc_disable=1
                            # vpnc5_dns=193.138.218.74
                            # vpnc5_sbstate_t=0
                            # vpnc5_state_t=2
                            # vpnc_unit=0     <- does this mean you can't edit configs
                            # wgc5_ep_addr_r=89.45.90.2
                            # wgc5_enable=1
                            # vpnc_clientlist=Mullvad_USA_Los_Angeles>WireGuard>5>>>1>5>> <<- '5>>>0>5>>' ==> '5>>>1>5>>'

                        fi

                        [ -f ${IMPORT_DIR}${WG_INTERFACE}.conf ] && chmod 600 ${IMPORT_DIR}${WG_INTERFACE}.conf     # v4.15 Prevent wg-quick "Warning: '/opt/etc/wireguard.d/wg11.conf' is world accessible"
                        [ -d $CONFIG_DIR ] && cp ${IMPORT_DIR}${WG_INTERFACE}.conf ${CONFIG_DIR}${WG_INTERFACE}.conf_imported

                        if [ "$COMMENT_OUT" == "Y" ];then
                            # sed -i 's/^DNS/#DNS/' ${IMPORT_DIR}${WG_INTERFACE}.conf
                            # sed -i 's/^Address/#Address/' ${IMPORT_DIR}${WG_INTERFACE}.conf
                            # sed -i 's/^MTU/#MTU/' ${IMPORT_DIR}${WG_INTERFACE}.conf                   # v4.09
                            # sed -i 's/^PreUp/#PreUp/g' ${IMPORT_DIR}${WG_INTERFACE}.conf              # v4.14
                            # sed -i 's/^PostUp/#PostUp/g' ${IMPORT_DIR}${WG_INTERFACE}.conf            # v4.14
                            # sed -i 's/^PreDown/#PreDown/g' ${IMPORT_DIR}${WG_INTERFACE}.conf          # v4.14
                            # sed -i 's/^PostDown/#PostDown/g' ${IMPORT_DIR}${WG_INTERFACE}.conf        # v4.14
                            # sed -i 's/^SaveConfig/#SaveConfig/g' ${IMPORT_DIR}${WG_INTERFACE}.conf    # v4.14
                            sed -i 's/^ListenPort/#ListenPort/g' ${IMPORT_DIR}${WG_INTERFACE}.conf      # v4.17

                            # Insert the tag
                            if [ "$ANNOTATE" != "# N/A" ];then
                                if [ "$INSERT_COMMENT" != "N" ];then                    # v4.03
                                    local POS=$(awk '/^\[Interface\]/ {print NR}' ${IMPORT_DIR}${WG_INTERFACE}.conf)
                                    sed -i "$POS i $ANNOTATE" ${IMPORT_DIR}${WG_INTERFACE}.conf
                                fi
                            fi
                        fi

                        # Should 'Endpoint' be moved from the End of the config?
                        #LASTLINE=$(tail -n 1 ${IMPORT_DIR}${WG_INTERFACE}.conf)
                        #if [ "${LASTLINE:0:4}" == "Endp" ];then
                            #local POS=$(awk '/^\[Peer]/ {print NR}' ${IMPORT_DIR}${WG_INTERFACE}.conf)
                            #sed -i "$POS a $LASTLINE" ${IMPORT_DIR}${WG_INTERFACE}.conf
                        #fi
                        # or to the End?
                        #sed -n '/^Endpoint/{h;$p;$b;:a;n;p;$!ba;x};p' ${IMPORT_DIR}${WG_INTERFACE}.conf
                        if [ -d "$CONFIG_DIR" ];then
                            [ "$IMPORT_DIR" != "$CONFIG_DIR" ] && cp ${IMPORT_DIR}${WG_INTERFACE}.conf ${CONFIG_DIR}${WG_INTERFACE}.conf
                            [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ] && chmod 600 ${CONFIG_DIR}${WG_INTERFACE}.conf     # v4.15 Prevent wg-quick "Warning: '/opt/etc/wireguard.d/wg11.conf' is world accessible"
                            if [ "$RENAME" == "Y" ];then
                                mv ${CONFIG_DIR}${WG_INTERFACE}.conf ${CONFIG_DIR}${NEW_NAME}.conf
                                [ -f ${CONFIG_DIR}${NEW_NAME}.conf ] && chmod 600 ${CONFIG_DIR}${NEW_NAME}.conf         # v4.15 Prevent wg-quick "Warning: '/opt/etc/wireguard.d/wg11.conf' is world accessible"
                                local AS_TXT="as ${cBMAG}$NEW_NAME "$cRESET
                                if [ "$MODE" == "server" ];then                                                         # v4.14
                                    cp ${CONFIG_DIR}${WG_INTERFACE}_public.key ${CONFIG_DIR}${NEW_NAME}_public.key      # v4.14
                                    cp ${CONFIG_DIR}${WG_INTERFACE}_private.key ${CONFIG_DIR}${NEW_NAME}_private.key    # v4.14
                                fi

                            fi
                        fi

                        if [ "$ASUS_NVRAM" == "Y" ] && [ "$(/bin/uname -o)" != "ASUSWRT-Merlin" ];then
                            [ -z "$AS_TXT" ] && local AS_TXT="as ${cBMAG}wgc${INDEX} "$cRESET || local AS_TXT="$AS_TXT, ${cBMAG}wgc${INDEX} "$cRESET
                        fi

                        [ "$AUTO" == "S" ] && local FORCE_TYPE_TXT="Site-to-Site "$FORCE_TYPE_TXT   # v.4.15 Site-to-Site
                        echo -e $cBGRE"\n\t[✔] Config ${cBMAG}${WG_INTERFACE}${cBGRE} import ${AS_TXT}${FORCE_TYPE_TXT}success"$cRESET 2>&1

                        local COMMENTOUT=; local RENAME=; local AS_TXT=
                    else
                        SayT "***ERROR: WireGuard® VPN 'client' Peer ('$WG_INTERFACE') ALREADY exists in database?....skipping import request"
                        echo -e $cBRED"\a\n\t***ERROR: WireGuard® 'client' Peer (${cBWHT}$WG_INTERFACE${cBRED}) ALREADY exists in database?....skipping import Peer '${cBMAG}${WG_INTERFACE}${cBRED}' request\n"$cRESET   2>&1
                    fi
                #else
                    #SayT "***ERROR: WireGuard VPN Peer ('$WG_INTERFACE') must be 'client'....skipping import request"
                    #echo -e $cBRED"\a\n\t***ERROR: WireGuard Peer (${cBWHT}$WG_INTERFACE${cBRED}) must be 'client'....skipping import Peer '${cBMAG}${WG_INTERFACE}${cBRED}' request\n"$cRESET   2>&1
                #fi
            else
                SayT "***ERROR: WireGuard® VPN 'client' Peer ('${IMPORT_DIR}$WG_INTERFACE.conf') configuration file NOT found?....skipping import request"   # v4.12
                echo -e $cBRED"\a\n\t***ERROR: WireGuard® 'client' Peer (${cBWHT}${IMPORT_DIR}$WG_INTERFACE.conf${cBRED}) configuration file NOT found?....skipping import Peer '${cBMAG}${WG_INTERFACE}${cBRED}' request\n"$cRESET   2>&1   # v4.12
            fi
        done

}
Export_Peer(){

    local ACTION=$1;shift
    local WG_INTERFACE=$1

    # Show ACTIVE GUI Peers (so we know they are valid)
    # { export [? [wgm] |  wgs | wgcx | wg1x [nvram] }
    if [ "$1" == "?" ];then
        if [ -z $2 ];then
            local CONFIGS=$(wg show interfaces | grep -v "wg[1-2]" | sort )
            echo -e $cBYEL"\n\t Available GUI Peer Configs for export:\n${cRESET}$CONFIGS"
            return 0
        else
            local CONFIGS=$(wg show interfaces | grep -v "wg[cs]" | sort )
            echo -e $cBYEL"\n\t Available Peer Configs for export:\n${cRESET}$CONFIGS"
            return 0
        fi
    fi

    case $WG_INTERFACE in
        wg[cs]*)
            if [ -n "$(nvram get ${WG_INTERFACE}_addr)" ];then

                local FN="${WG_INTERFACE}.conf_exported"

                # Allow export of any GUI Peer (if you know it exists!)
                local TAG=$(nvram get vpnc_clientlist | sed "s/>>>//g" | sed 's/>>/|/g')
                (
                echo -e "# "$TAG
                echo -en "[Interface]\nPrivateKey = "
                echo -e "$(nvram get ${WG_INTERFACE}_priv)"
                echo -en "#Address = "
                echo -e "$(nvram get ${WG_INTERFACE}_addr)"
                echo -en "#DNS = "
                echo -e "$(nvram get ${WG_INTERFACE}_dns)"
                echo -en "\n[Peer]\nPublicKey = "
                echo -e "$(nvram get ${WG_INTERFACE}_ppub)"
                echo -en "AllowedIPs = "
                echo -e "$(nvram get ${WG_INTERFACE}_aips)"
                echo -e "Endpoint = $(nvram get ${WG_INTERFACE}_ep_addr)":"$(nvram get ${WG_INTERFACE}_ep_port)\n"
                echo -en "PersistentKeepalive = "
                echo -e "$(nvram get ${WG_INTERFACE}_alive)"


                ) > "${CONFIG_DIR}$FN"

                echo -e $cBGRE"\n\t[✔] Config ${cBMAG}${WG_INTERFACE}${cBGRE} export '${cRESET}${CONFIG_DIR}${FN}${cBGRE}' success"$cRESET 2>&1
            else
                SayT "***ERROR: WireGuard VPN GI Peer ('${IMPORT_DIR}$WG_INTERFACE.conf') NVRAM configuration NOT found?....skipping export request"   # v4.12
                echo -e $cBRED"\a\n\t***ERROR: WireGuard GUI Peer NVRAM configuration NOT found?....skipping export Peer '${cBMAG}${WG_INTERFACE}${cBRED}' request\n"$cRESET   2>&1
            fi
        ;;
        wg[12]*)

            [ "${WG_INTERFACE:2:1}" == "1" ] && local TYPE="c" || local TYPE="s"

            local INDEX=${WG_INTERFACE:3:1}

            local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM clients where peer='$WG_INTERFACE';")
            [ -z "$DESC" ] && local DESC=$(grep -FB1 "[Interface]" ${CONFIG_DIR}${WG_INTERFACE}.conf | grep -vF "[Interface]")    # v4.14
            local DESC=$(printf "%s" "$DESC" | sed 's/^[ \t]*//;s/[ \t]*$//')
            [ -z "$DESC" ] && local DESC="# Unidentified"
            local SOCKET=$(sqlite3 $SQL_DATABASE "SELECT socket FROM clients where peer='$WG_INTERFACE';")
            local SUBNET=$(sqlite3 $SQL_DATABASE "SELECT subnet FROM clients where peer='$WG_INTERFACE';")
            local DNS=$(sqlite3 $SQL_DATABASE "SELECT dns FROM clients where peer='$WG_INTERFACE';")
            local PUB_KEY=$(sqlite3 $SQL_DATABASE "SELECT pubkey FROM clients where peer='$WG_INTERFACE';")
            local PRI_KEY=$(sqlite3 $SQL_DATABASE "SELECT prikey FROM clients where peer='$WG_INTERFACE';")
            local ALLOWIP=$(awk '/^Allow/ {$1="";$2="";print $0}' ${CONFIG_DIR}${WG_INTERFACE}.conf | awk '{$1=$1};1')


            eval "nvram set wg${TYPE}${INDEX}_addr='$SUBNET'"
            eval "nvram set wg${TYPE}${INDEX}_aips='$ALLOWIP'"
            eval "nvram set wg${TYPE}${INDEX}_alive=25"
            eval "nvram set wg${TYPE}${INDEX}_dns='$DNS'"
            eval "nvram set wg${TYPE}${INDEX}_enable=0"
            # Split  Endpoint 'ip:port' for separate GUI fields
            local SOCKET_IP=${SOCKET%:*}        # Endpoint IP address
            local SOCKET_PORT=${SOCKET##*:}     # Endpoint Port
            eval "nvram set wg${TYPE}${INDEX}_ep_addr='$SOCKET_IP'"
            eval "nvram set wg${TYPE}${INDEX}_ep_port='$SOCKET_PORT'"
            eval "nvram set wg${TYPE}${INDEX}_nat=1"
            eval "nvram set wg${TYPE}${INDEX}_ppub='$PUB_KEY'"
            eval "nvram set wg${TYPE}${INDEX}_priv='$PRI_KEY'"

            #vpnc_clientlist=Mullvad_USA_Los_Angeles>WireGuard>5>>>1>5>><Mullvad_Oz_Melbourne>WireGuard>4>>>1>6>>
            local PREV=$(nvram get vpnc_clientlist)
            local ANNOTATE=$(echo "$ANNOTATE" | sed 's/^# //' | sed 's/,/-/g')  # GUI doesn't allow certain characters in name

            #nvram set vpnc_clientlist="${PREV}${ANNOTATE}>WireGuard>${INDEX}>>>0>${INDEX}>>"

            local PREV=$(nvram get vpnc_pptp_options_x_list)
            #nvram set vpnc_pptp_options_x_list="${PREV}<auto"
    esac
}
Manage_Peer() {

    local ACTION=$1;shift

    local ARGS="$@"

    WG_INTERFACE=$1;shift
    local CMD=$1

    if [ "$WG_INTERFACE" == "new" ] || [ "$WG_INTERFACE" == "newC" ] || [ "$WG_INTERFACE" == "new6" ] ;then
        CMD="$WG_INTERFACE";
        WG_INTERFACE=
    fi

    if [ "$WG_INTERFACE" == "del" ] || [ "$WG_INTERFACE" == "add" ] || [ "$WG_INTERFACE" == "rule" ];then
        echo -e $cBRED"\a\n\t***ERROR Missing Peer argument!\n"$cRESET
        return 1
    fi

    [ "$WG_INTERFACE" == "help" ] && { CMD="help"; WG_INTERFACE=; }
    [ "$WG_INTERFACE" == "import" ] && { CMD="import"; WG_INTERFACE=; }

    [ -z "$CMD" ] && CMD="list"

    [ -n "$(echo $@ | grep -iw "ipset")" ] && { local SUBCMD=$CMD;local CMD="ipset"; }
    [ -n "$(echo $@ | grep -iw "subnet")" ] && { local SUBCMD=$CMD;local CMD="subnet"; }    # v4.14

        case $CMD in
            list)

                if [ "$WG_INTERFACE" != "category" ];then                   # v3.04
                    Show_Peer_Config_Entry "$WG_INTERFACE"
                else
                    echo -e $cBWHT"\n\tPeer categories\n"$cBCYA
                    grep -E "^[[:alpha:]].*=wg" ${INSTALL_DIR}WireguardVPN.conf | tr ',' ' '
                    echo -e "\n"$cRESET
                fi
            ;;
            *)

                if [ "$CMD" == "help" ];then
                    echo -e "\n\tpeer help\t\t\t\t\t\t\t\t- This text"
                    echo -e "\tpeer\t\t\t\t\t\t\t\t\t- Show ALL Peers in database"
                    echo -e "\tpeer peer_name\t\t\t\t\t\t\t\t- Show Peer in database or for details e.g peer wg21 config"
                    echo -e "\tpeer peer_name {cmd {options} }\t\t\t\t\t\t- Action the command against the Peer"
                    echo -e "\tpeer peer_name del\t\t\t\t\t\t\t- Delete the Peer from the database and all of its files *.conf, *.key"
                    echo -e "\tpeer peer_name ip=xxx.xxx.xxx.xxx\t\t\t\t\t- Change the Peer VPN Pool IP"
                    echo -e "\tpeer category\t\t\t\t\t\t\t\t- Show Peer categories in database"
                    echo -e "\tpeer peer_name category [category_name {del | add peer_name[...]} ]\t- Create a new category with 3 Peers e.g. peer category GroupA add wg17 wg99 wg11"

                    echo -e "\tpeer new [peer_name [options]]\t\t\t\t\t\t- Create new server Peer             e.g. peer new wg27 ip=10.50.99.1/24 port=12345"
                    echo -e "\tpeer new [peer_name] {ipv6}\t\t\t\t\t\t- Create new Dual-stack server Peer with 'aa' prefix e.g. peer new ipv6"
                    echo -e "\tpeer new [peer_name] {ipv6}\t\t\t\t\t\t- Create new Dual-stack server Peer with 'fd' prefix  e.g. peer new ipv6 ula"
                    echo -e "\tpeer new [peer_name] {ipv6 noipv4 [ula[4]]}\t\t\t\t- Create new IPv6 Only server Peer   e.g. peer new ipv6 noipv4"
                    echo -e "\tpeer new [peer_name] {ipv6 noipv4}\t\t\t\t\t- Create new IPv6 Only server Peer   e.g. peer new ipv6 noipv4 ipv6=aaff:a37f:fa75:100:100::1/120"

                    echo -e "\tpeer import peer_conf [options]\t\t\t\t\t\t- Import '.conf' into SQL database e.g. import Mullvad_Dallas"
                    echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t\t   e.g. import SiteA type=server"

                    echo -e "\tpeer peer_name [del|add|upd] ipset {ipset_name[...]}\t\t\t- Selectively Route IPSets e.g. peer wg13 add ipset NetFlix Hulu"
                    echo -e "\t\t\t\t\t\t\t\t\t\t                                peer wg12 upd ipset MACs dstsrc src"
                    echo -e "\t\t\t\t\t\t\t\t\t\t                                peer wg12 upd ipset all enable n"

                    echo -e "\tpeer peer_name [add] subnet {IPSubnet[...]}\t\t\t\t- Configure downstream subnets e.g. peer wg13 add subnet 192.168.5.0/24"

                    echo -e "\tpeer peer_name {rule [del {id_num} |add [wan] rule_def]}\t\t- Manage Policy rules e.g. peer wg13 rule add 172.16.1.0/24 comment All LAN"
                    echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t   peer wg13 rule add wan 52.97.133.162 comment smtp.office365.com"
                    echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t   peer wg13 rule add wan 172.16.1.100 9.9.9.9 comment Quad9 DNS"
                    echo -e "\tpeer serv_peer_name {passthru client_peer {[add|del] [device|IP/CIDR]}} - Manage passthu' rules; 'server' peer devices/IPs/CIDR outbound via 'client' peer"
                    echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t   peer wg21 passthru add wg11 SGS8"
                    echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t   peer wg21 passthru add wg15 all"
                    echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t   peer wg21 passthru add wg12 10.100.100.0/27"
                    echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t   peer wg21 passthru del wg15 all"
                    echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t   peer wg21 passthru del SGS8"
                    echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t   peer wg21 passthru del all"
                    echo -e "\tpeer serv_peer_name {bind device_peer}\t\t\t\t\t- Bind a Road Warrior 'device' Peer to a 'server' Peer e.g. peer wg21 bind SGS20"

                    return
                fi

                local FN=${INSTALL_DIR}WireguardVPN.confXXX

                if [ "$WG_INTERFACE" == "new" ] || [ "$WG_INTERFACE" == "newC" ] || [ "$WG_INTERFACE" == "add" ] || [ "$WG_INTERFACE" == "new6" ] || [ "$WG_INTERFACE" == "bind" ];then     # v4.15
                    CMD=$WG_INTERFACE
                    shift
                    WG_INTERFACE=$1
                fi

                if [ "$WG_INTERFACE" != "category" ];then                   # v3.04

                    if [ "$CMD" == "import" ] || [ "$CMD" == "delX" ] || [ "$CMD" == "new" ] || [ "$CMD" == "add" ] || [ "$CMD" == "new6" ] || [ "$WG_INTERFACE" == "bind" ] || [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                        case $CMD in
                            new*)
                                # New 'server' Peer     [port=nnnnn] [ip=xxx.xxx.xxx.1/24] [auto={y|n}]
                                # New 'client' Peer     {ip=xxx.xxx.xxx.1/24  end=xxx.xxx.xxx.xxx:nnnnn pub=aaaaaaaaaaaaaa pri=aaaaaaaaaa [auto={y|n}]
                                Create_Peer $menu1
                            ;;
                            auto*)
                                #shift 1
                                local Mode=$(Server_or_Client "$WG_INTERFACE")      # v4.11

                                local AUTO=$(echo "$CMD" | sed -n "s/^.*auto=//p" | awk '{print $1}')   # v4.11

                                [ "$Mode" == "device" ] && { echo -e $cBRED"\a\n\t***ERROR 'device' Peer '$WG_INTERFACE' does not support $cBWHT'auto=$AUTO'\n"$cRESET; return ; }  # v4.11

                                if [ "$(echo "$AUTO" | grep "^[yYnNpPZWS]$" )" ];then       # v4.15
                                    FLAG=$(echo "$AUTO" | tr 'a-z' 'A-Z')
                                    if [ -z "$(echo "$CMD" | grep "autoX")" ];then
                                        # If Auto='P' then enforce existence of RPDB Selective Routing rules or IPSET fwmark for the 'client' Peer or Passthru gateway
                                        if [ "$FLAG" == "P" ];then
                                           if [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$WG_INTERFACE';") -eq 0 ] && \
                                              [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM ipset WHERE peer='$WG_INTERFACE';") -eq 0 ]  && \
                                              [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(client) FROM passthru WHERE client='$WG_INTERFACE';") -eq 0 ];then    # v4.12 v4.11 @ZebMcKayhan/@The Chief
                                              echo -e $cBRED"\a\n\t***ERROR No Policy (nor IPSET/Passthru) rules exist for ${cBMAG}$WG_INTERFACE ${cBRED}(${cBWHT} e.g. use 'peer $WG_INTERFACE rule add' command${cBRED} first)\n"$cRESET
                                              return 1
                                            fi
                                        fi
                                    fi

                                    [ "$Mode" == "server" ] && local TABLE="servers" || TABLE="clients" # v4.11 v4.10

                                    sqlite3 $SQL_DATABASE "UPDATE $TABLE SET auto='$FLAG' WHERE peer='$WG_INTERFACE';"
                                    echo -e $cBGRE"\n\t[✔] Updated '$WG_INTERFACE' AUTO=$FLAG\n"$cRESET
                                else
                                    echo -e $cBRED"\a\n\t***ERROR Invalid Peer Auto='$AUTO' $WG_INTERFACE'\n"$cRESET
                                fi
                            ;;
                            delX|del)

                                [ "$CMD" == "delX" ] && Delete_Peer "$WG_INTERFACE" "force" || Delete_Peer "$WG_INTERFACE"  # v3.05
                            ;;
                            comment)
                                shift 1
                                COMMENT="$@"
                                [ "${COMMENT:0:1}" != "#" ] && COMMENT="# "$COMMENT
                                COMMENT=$(echo "$COMMENT" | sed "s/'/''/g;s/\%n/$WG_INTERFACE/g")   # v4.16 %n is replaced by Peer name

                                local Mode=$(Server_or_Client "$WG_INTERFACE")      # v4.15
                                local SQL_COL="peer"                                # v4.15

                                case $Mode in                                       # v4.15
                                    server) local TABLE="servers";;
                                    client) local TABLE="clients";;
                                    device)
                                        local TABLE="devices"
                                        local SQL_COL="name"
                                    ;;
                                esac                                                # v4.15
                                sqlite3 $SQL_DATABASE "UPDATE $TABLE SET tag='$COMMENT' WHERE $SQL_COL='$WG_INTERFACE';"    # v4.15

                                echo -e $cBGRE"\n\t[✔] Updated Annotation tag "$COMMENT"\n"$cRESET
                            ;;
                            dump|config)

                                local Mode=$(Server_or_Client "$WG_INTERFACE")
                                if [ "$CMD" == "config" ] && [ "$Mode" == "server" ];then
                                    local TABLE="servers"
                                    echo -e $cBWHT"\n\t'$Mode' Peer ${cBMAG}${WG_INTERFACE}${cBWHT} Configuration Summary\n"$cBYEL
                                    Show_Peer_Config_Entry "$WG_INTERFACE"
                                    echo -en $cBYEL
                                    echo -e "Public Key = "$(cat ${CONFIG_DIR}${WG_INTERFACE}_public.key)
                                    grep -ivE "example" ${CONFIG_DIR}${WG_INTERFACE}.conf | awk '( $1=="PrivateKey" || $1=="ListenPort" || $3=="End") {print $0}' | sed 's/End//g; s/^#/Client Peer:/g'
                                else
                                    echo -e $cBWHT"\n\t'$Mode' Peer ${cBMAG}${WG_INTERFACE}${cBWHT} Configuration Detail\n"$cBYEL
                                    local ID="peer"                                     # v4.11
                                    case $Mode in                                       # v4.11
                                        server) local TABLE="servers";;
                                        client) local TABLE="clients";;                 # v4.11
                                        *) local TABLE="devices";local ID="name";;      # v4.11
                                    esac

                                    cat ${CONFIG_DIR}${WG_INTERFACE}.conf | grep .      # v4.11

                                    local AUTO="$(sqlite3 $SQL_DATABASE "SELECT auto FROM $TABLE WHERE $ID='$WG_INTERFACE';")"  # v4.11

                                    if [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$WG_INTERFACE';") -gt 0 ] || \
                                        [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(client) FROM passthru WHERE client='$WG_INTERFACE';")" -gt 0 ];then
                                        if [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$WG_INTERFACE';") -gt 0 ];then
                                            local COLOR=$cBCYA;local TXT=
                                            if [ "$Mode" == "client" ] && [ "$AUTO" != "P" ];then
                                                COLOR=$cRED;local TXT="DISABLED"
                                            fi
                                            echo -e $COLOR"\n\tSelective Routing RPDB rules $TXT\n"
                                            sqlite3 $SQL_DATABASE "SELECT rowid,peer,iface,srcip,dstip,tag FROM policy WHERE $ID='$WG_INTERFACE' ORDER BY iface DESC;" |column -t  -s '|' --table-columns ID,Peer,Interface,Source,Destination,Description # v4.08
                                        fi
                                    else
                                        if [ "$Mode" == "client" ];then
                                            [ "$AUTO" != "P" ] && local COLOR=$cBGRA || local COLOR=$cRED                    # v4.12 v4.11
                                            echo -e $COLOR"\n\tNo RPDB Selective Routing/Passthru rules for $WG_INTERFACE\n"$cRESET  # v4.11
                                        fi
                                    fi
                                fi

                                [ "$Mode" == "device" ] && { local HDR="Device"; local ID="name"; }  || { local HDR="Peer"; local ID="peer"; } # v4.02 Hotfix

                                echo -e $cBMAG
                                sqlite3 $SQL_DATABASE "SELECT $ID,tag FROM $TABLE WHERE $ID='$WG_INTERFACE';" | column -t  -s '|' --table-columns $HDR,'Annotation' # v4.02 Hotfix

                                echo -e $cBCYA"\nConnected Session duration: $cBGRE"$(Session_Duration "$WG_INTERFACE")$cRESET

                            ;;
                            import*)
                                Import_Peer $ARGS
                            ;;
                            rule*)
                                Manage_RPDB_rules $menu1
                                [ $? -eq 1 ] && Show_Peer_Config_Entry "$WG_INTERFACE"
                            ;;
                            passthru*)
                                Manage_PASSTHRU_rules $menu1            # v4.12
                                [ $? -eq 1 ] && Show_Peer_Config_Entry "$WG_INTERFACE"
                            ;;
                            allowedips=*)
                                shift
                                local Mode=$(Server_or_Client "$WG_INTERFACE")
                                local ALLOWEDIPSCMD="$(echo "$CMD" | sed -n "s/^.*allowedips=//p" | awk '{print $1}' | tr ',' ' ')" # v4.11
                                local ALLOWEDIPS=
                                for IP in $ALLOWEDIPSCMD
                                    do
                                        if [ "$IP" == "default" ] || [ "$IP" == "default6" ] [ "$IP" == "4" ] || [ "$IP" == "6" ]  ||[ -n "$(echo "$IP" | Is_IPv4_CIDR)" ] || [ -n "$(echo "$IP" | Is_IPv4)" ] || [ -n "$(echo "$IP" | Is_IPv6)" ];then       # v4.14 v4.11
                                            [ -n "$ALLOWEDIPS" ] && local ALLOWEDIPS=$ALLOWEDIPS","
                                            if [ "$IP" == "default" ] || [ "$IP" == "4" ];then  # v4.14
                                                local IP="0.0.0.0/0"                            # v4.14
                                            fi
                                            if [ "$IP" == "default6" ] || [ "$IP" == "6" ];then # v4.14
                                                local IP="::0/0"                                # v4.14
                                            fi
                                            ALLOWEDIPS=$ALLOWEDIPS""$IP
                                        else
                                            echo -e $cBRED"\n\a\t***ERROR: Invalid IP '${cBWHT}${IP}${cBRED}'"$RESET
                                            return
                                        fi
                                    done

                                [ -n "$ALLOWEDIPS" ] && sed -i "/^AllowedIPs/ s~[^ ]*[^ ]~$ALLOWEDIPS~3" ${CONFIG_DIR}${WG_INTERFACE}.conf  # v4.14

                                local SQL_MATCH="subnet"; local ID="peer"; IPADDR="subnet"
                                case $Mode in
                                    server) local TABLE="servers";;
                                    client) local TABLE="clients";;
                                    device) local TABLE="devices"; local ID="name"; local IPADDR="allowedip"; local SQL_MATCH="ip";;
                                esac

                                sqlite3 $SQL_DATABASE "UPDATE $TABLE SET $IPADDR='$ALLOWEDIPS' WHERE $ID='$WG_INTERFACE';"

                                [ "$Mode" == "device" ] && { DEVICE_NAME=$WG_INTERFACE; Display_QRCode "${CONFIG_DIR}${DEVICE_NAME}.conf"; }    # v4.11

                                # If 'client' Peer is up, then restart it
                                if [ "$Mode" == "client" ];then
                                    if [ -n "$(wg show interfaces | grep -ow "$WG_INTERFACE")" ];then
                                        CMD="restart"
                                        local TAG=$cBWHT"("${cBMAG}$(sqlite3 $SQL_DATABASE "select tag FROM $TABLE WHERE $ID='$WG_INTERFACE';")${cBWHT}")"
                                        echo -e $cBWHT"\a\n\tWireGuard® 'client' Peer ${cBMAG}${WG_INTERFACE} ${TAG}$cBWHT needs to be ${CMD}ed"
                                        echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'client' Peer ($WG_INTERFACE) or press$cBGRE [Enter] to SKIP."
                                        read -r "ANS"
                                        [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$WG_INTERFACE"; Show_Peer_Status "show"; }
                                    fi
                                fi

                                echo -e $cBGRE"\n\t[✔] Updated Allowed IPs\n"$cRESET
                            ;;
                            ip=*)
                                shift
                                local Mode=$(Server_or_Client "$WG_INTERFACE")
                                local IP_SUBNET="$(echo "$CMD" | sed -n "s/^.*ip=//p" | awk '{print $1}')"

                                # v4.11 Whilst convenient, the following isn't appropriate for Site-to-Site where '/24' is the norm, nor for IPv6 addresses
                                #if [ "${IP_SUBNET#${IP_SUBNET%???}}" != "/32" ] && [ "${IP_SUBNET#${IP_SUBNET%???}}" != "/24" ];then    # v4.02
                                    #local IP_SUBNET=$IP_SUBNET"/32"                     # v4.02
                                #fi
                                if [ -n "$(echo "$IP_SUBNET" | Is_IPv4_CIDR)" ] || [ -n "$(echo "$IP_SUBNET" | Is_IPv6)"  ];then    # v4.11 v4.02
                                    local CHECK_IP=$(echo "$IP_SUBNET" | sed s'~/.*$~~')
                                    local SQL_MATCH="subnet"; local ID="peer"; IPADDR="subnet"
                                    case $Mode in
                                        server) local TABLE="servers";;
                                        client) local TABLE="clients";;
                                        device) local TABLE="devices"; local ID="name"; local IPADDR="ip"; local SQL_MATCH="ip";;
                                    esac

                                    # If it's a 'server' Peer, then all of its current 'device' Peers would be invalidated
                                    if [ "$Mode" == "server" ];then             # v4.11
                                        # Check how many 'client' Peers exist
                                        local CNT=$(grep -cE "^AllowedIPs" ${CONFIG_DIR}${WG_INTERFACE}.conf )
                                        if [ $CNT -gt 0 ];then
                                            echo -e $cBRED"\n\a\t***ERROR: This will invalidate ${cBWHT}${CNT}$cBRED Road-Warrior 'device' Peers...request ABORTED"$RESET   # v4.11
                                            return
                                        fi
                                    fi

                                    # Can't be the server IP or already assigned                    # v4.02
                                    if [ "${CHECK_IP##*.}" != "1" ];then
                                            local DUPLICATE=$(sqlite3 $SQL_DATABASE "SELECT $ID FROM $TABLE WHERE $SQL_MATCH LIKE '$CHECK_IP%';")   # v4.02
                                            if [ -z "$DUPLICATE" ] ;then

                                                #[ "${WG_INTERFACE:0:2}" != "wg" ] && local TABLE="devices"; local ID="name"; local IPADDR="ip"

                                                [ "$Mode" == "device" ] && local OLD_IP=$(sqlite3 $SQL_DATABASE "select $IPADDR FROM devices WHERE $ID='$WG_INTERFACE';")

                                                # It may be that a 'device' Peer needs a static IP in its 'server' Peer Subnet?
                                                sqlite3 $SQL_DATABASE "UPDATE $TABLE SET $IPADDR='$IP_SUBNET' WHERE $ID='$WG_INTERFACE';"
                                                sed -i "/^Address/ s~[^ ]*[^ ]~$IP_SUBNET~3" ${CONFIG_DIR}${WG_INTERFACE}.conf

                                                echo -e $cBGRE"\n\t[✔] Updated IP/Subnet\n"$cRESET

                                                # v4.11 If it's a 'device' Peer, then its 'server' Peer needs to be updated, and the new QRCODE scanned into device @here1310
                                                if [ "$Mode" == "device" ];then
                                                    DEVICE_NAME=$WG_INTERFACE
                                                    # Find the 'server' Peer listening for the Road-Warrior 'device' Peer
                                                    local RESTART_SERVERS=$(grep -HE "^#.*$DEVICE_NAME$" ${CONFIG_DIR}wg2*.conf | awk -F '[\/:\._]' '{print $6}')
                                                    # Update the old VPN POOL IP with the new in the 'server' Peer config                   # v4.11
                                                    sed -i "/^# $DEVICE_NAME$/,/^# $DEVICE_NAME End$/ s~$OLD_IP~$IP_SUBNET~" ${CONFIG_DIR}${RESTART_SERVERS}.conf   # v4.11

                                                    Display_QRCode "${CONFIG_DIR}${DEVICE_NAME}.conf"                       # v4.11

                                                    # Do we need to restart any 'server' Peers?
                                                    local RESTART_SERVERS=$(echo "$RESTART_SERVERS" | xargs -n1 | sort -u | xargs)  # Remove duplicates from the restart list
                                                    for SERVER_PEER in $RESTART_SERVERS
                                                        do
                                                            # Need to Restart the 'server' Peer if it is UP
                                                            if [ -n "$(wg show interfaces | grep "$SERVER_PEER")" ];then
                                                                CMD="restart"
                                                                local TAG=$cBWHT"("${cBMAG}$(sqlite3 $SQL_DATABASE "select tag FROM devices WHERE $ID='$DEVICE_NAME';")${cBWHT}")"
                                                                echo -e $cBWHT"\a\n\tWireGuard® 'server' Peer needs to be ${CMD}ed to update 'client' Peer ${cBMAG}${DEVICE_NAME} $TAG"
                                                                echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'server' Peer ($SERVER_PEER) or press$cBGRE [Enter] to SKIP."
                                                                read -r "ANS"
                                                                [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$SERVER_PEER"; Show_Peer_Status "show"; }  # v3.03
                                                            fi
                                                        done
                                                fi
                                            else
                                                echo -e $cBRED"\n\a\t***ERROR: '$IP_SUBNET' already assigned to Peer ${cBMAG}$DUPLICATE"$RESET
                                            fi
                                    else
                                        echo -e $cBRED"\n\a\t***ERROR: '$IP_SUBNET' is not valid cannot be .1 "$RESET   # v4.02
                                    fi
                                else
                                    echo -e $cBRED"\n\a\t***ERROR: '$IP_SUBNET' is not a valid IPv4 CIDR or IPv6 address"$RESET # v4.11 v4.02
                                fi
                            ;;
                            dns*)
                                shift
                                local Mode=$(Server_or_Client "$WG_INTERFACE")
                                local DNS=$(echo "$CMD" | sed -n "s/^.*dns=//p" | awk '{print $1}')
                                local ID="peer"
                                case $Mode in
                                    client) local TABLE="clients";;
                                    device) local TABLE="devices"; local ID="name";;    # v4.06
                                esac

                                if [ "$Mode" != "server" ];then
                                    sqlite3 $SQL_DATABASE "UPDATE $TABLE SET dns='$DNS' WHERE $ID='$WG_INTERFACE';"
                                    if [ -n "$(grep -E "^DNS" ${CONFIG_DIR}${WG_INTERFACE}.conf )" ];then       # v4.16
                                        sed -i "/^DNS/ s~[^ ]*[^ ]~$DNS~3" ${CONFIG_DIR}${WG_INTERFACE}.conf
                                    else
                                        sed -i "/^Address/a DNS = $DNS" ${CONFIG_DIR}${WG_INTERFACE}.conf           # v4.16
                                    fi

                                    echo -e $cBGRE"\n\t[✔] Updated DNS\n"$cRESET
                                else
                                     echo -e $cBRED"\a\n\t***ERROR 'server' Peer '$WG_INTERFACE' cannot set DNS\n"$cRESET
                                fi
                            ;;
                            mtu*)                                                   # v4.09
                                shift
                                local Mode=$(Server_or_Client "$WG_INTERFACE")
                                local MTU=$(echo "$CMD" | sed -n "s/^.*mtu=//p" | awk '{print $1}')
                                local ID="peer"
                                case $Mode in
                                    client) local TABLE="clients";;
                                    device) local TABLE="devices"; local ID="name";;
                                esac

                                if [ "$Mode" != "server" ];then
                                    if [ "$MTU" -ge "1280" ] && [ "$MTU" -le "1500" ];then  # v4.12
                                        sqlite3 $SQL_DATABASE "UPDATE $TABLE SET mtu='$MTU' WHERE $ID='$WG_INTERFACE';"
                                        sed -i "/^MTU/ s~[^ ]*[^ ]~$MTU~3" ${CONFIG_DIR}${WG_INTERFACE}.conf

                                        echo -e $cBGRE"\n\t[✔] Updated MTU\n"$cRESET
                                    else
                                        echo -e $cBRED"\a\n\t***ERROR 'client' Peer'$WG_INTERFACE' MTU '$MTU' invalid; ONLY range 1280-1500 (Recommended Default 1420)\n"$cRESET    # v4.12
                                    fi
                                else
                                     echo -e $cBRED"\a\n\t***ERROR 'server' Peer '$WG_INTERFACE' cannot set MTU\n"$cRESET
                                fi
                            ;;
                            subnet*)                                # peer wg11 {[add | del ]} {xxx.xxx.xxx.0/24[...]}

                                local ARGS=$@
                                if [ "$SUBCMD" == "add" ] || [ "$SUBCMD" == "del" ] || [ "$SUBCMD" == "upd" ];then
                                    shift 2
                                    Manage_Custom_Subnets "$SUBCMD" "$WG_INTERFACE" "$@"
                                else
                                    echo -e $cBRED"\a\n\t***ERROR Invalid command '$SUBCMD' e.g. [add | del | upd]\n"$cRESET
                                fi
                            ;;
                            port*)                                  # v4.14 peer wg23 port=12345 (useful if Torguard Listenport = 51820)
                                shift
                                local Mode=$(Server_or_Client "$WG_INTERFACE")
                                local PORT=$(echo "$CMD" | sed -n "s/^.*port=//p" | awk '{print $1}')

                                if [ "$Mode" = "server" ];then

                                    if [ -n "$(echo "$PORT" | grep -E "^[0-9]{1,}$")" ] && [ "$PORT" -ge "1024" ] && [ "$PORT" -le "65365" ];then   # v4.14
                                        sqlite3 $SQL_DATABASE "UPDATE servers SET port='$PORT' WHERE peer='$WG_INTERFACE';"                         # v4.14
                                        sed -i "/^ListenPort/ s~[^ ]*[^ ]~$PORT~3" ${CONFIG_DIR}${WG_INTERFACE}.conf

                                        echo -e $cBGRE"\n\t[✔] Updated 'server' Peer Listen Port\n"$cRESET
                                    else
                                        echo -e $cBRED"\a\n\t***ERROR 'server' Peer '$WG_INTERFACE' Listen Port '$PORT' invalid!\n"$cRESET    # v4.14
                                    fi
                                else
                                     echo -e $cBRED"\a\n\t***ERROR 'client' Peer '$WG_INTERFACE' cannot set Listen Port\n"$cRESET
                                fi
                            ;;
                            add*|ipset*)                            # peer wg1x [add|del|upd] ipset Netflix[.....]

                                local ARGS=$@
                                if [ "$SUBCMD" == "add" ] || [ "$SUBCMD" == "del" ] || [ "$SUBCMD" == "upd" ];then
                                    shift 2
                                    Manage_IPSET "$SUBCMD" "$WG_INTERFACE" "$@"
                                else
                                    echo -e $cBRED"\a\n\t***ERROR Invalid command '$SUBCMD' e.g. [add | del | upd]\n"$cRESET
                                fi
                            ;;
                            bind*)                                  # peer wg2x bind SGS20 [new_allowed_IP]
                                local ARGS=$@
                                local SERVER_PEER=$WG_INTERFACE
                                local Mode=$(Server_or_Client "$SERVER_PEER")
                                if [ "$Mode" == "server" ];then
                                    local DEVICE=$2
                                    local NEW_ALLOWED_IP=$3
                                    if [ -f ${CONFIG_DIR}${DEVICE}.conf ];then
                                        local PUB_KEY=$(sqlite3 $SQL_DATABASE "SELECT pubkey FROM servers WHERE peer='$SERVER_PEER';")
                                        sed -i "/^PublicKey/ s~[^ ]*[^ ]~$PUB_KEY~3" ${CONFIG_DIR}${DEVICE}.conf
                                        sed -i "/^# ${DEVICE} device/,/^# $DEVICE End$/d" ${CONFIG_DIR}${SERVER_PEER}.conf
                                        sed -i -e :a -e '/^\n*$/{$d;N;};/\n$/ba' ${CONFIG_DIR}${SERVER_PEER}.conf   # v4.15 Delete all trailing blank lines from file
                                        echo -e >> ${CONFIG_DIR}${SERVER_PEER}.conf
                                        local PUB_KEY=$(cat ${CONFIG_DIR}${DEVICE}_public.key)
                                        local ALLOWIPS=$(awk '/^Address/ {print $3}' ${CONFIG_DIR}${DEVICE}.conf)

                                        if [ -n "$NEW_ALLOWED_IP" ];then
                                            local SERVER_SUBNET=$(awk '/^#Address/ {print $3}' ${CONFIG_DIR}${SERVER_PEER}.conf | grep -o '^.*\.')
                                            if [ -n "$(echo "$NEW_ALLOWED_IP" | Is_IPv4_CIDR )" ];then
                                                local ALLOWIPS=$NEW_ALLOWED_IP", "$ALLOWIPS
                                            else
                                                echo -e $cBRED"\a\n\t***ERROR NEW ${cRESET}'ALLOWED_IPS=$NEW_ALLOWED_IP'${cBRED} - must be a valid ${cRESET}IPv4/32${cBRED} e.g. ${cRESET}${SERVER_SUBNET}99/32$cRESET \n"$cRESET
                                                return 1
                                            fi
                                        fi

                                        local PRE_SHARED_KEY=$(awk '/^PresharedKey/ {print $3}' ${CONFIG_DIR}${DEVICE}.conf)
                                        [ -n "$PRE_SHARED_KEY" ] && local PRE_SHARED_KEY="PresharedKey = "$PRE_SHARED_KEY || local PRE_SHARED_KEY="#PresharedKey = "
                                        cat >> ${CONFIG_DIR}${SERVER_PEER}.conf << EOF
# $DEVICE device bind on $(date +%F)
[Peer]
PublicKey = $PUB_KEY
AllowedIPs = $ALLOWIPS
$PRE_SHARED_KEY
# $DEVICE End
EOF

                                        echo -e $cBGRE"\n\t[✔] Device '${DEVICE}' bind to 'server' Peer '$SERVER_PEER' success\n"$cRESET

                                        # Need to Restart the 'server' Peer if it is UP
                                        if [ -n "$(wg show interfaces | grep "$SERVER_PEER")" ];then    # v4.16
                                            local CMD="restart"                                         # v4.16
                                            echo -e $cBWHT"\a\n\tWireGuard® 'server' Peer needs to be ${CMD}ed to allow 'client' Peer ${cBMAG}$DEVICE"
                                            echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'server' Peer (${cBWHT}${SERVER_PEER}${cBRED}) or press$cBGRE [Enter] to SKIP."
                                            read -r "ANS"                                                                                       # v4.16
                                            [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$SERVER_PEER"; Show_Peer_Status "show"; }  # v4.16
                                        fi


                                    else
                                        echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard® 'device' Peer '$DEVICE'\n"$cRESET
                                    fi
                                else
                                    echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard® 'server' Peer '$SERVER_PEER'\n"$cRESET
                                fi
                            ;;
                            *)
                                echo -e $cBRED"\a\n\t***ERROR Invalid command '$CMD' e.g. [add | del | upd | bind]\n"$cRESET    # v4.15
                            ;;
                        esac
                    else
                        echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard® Peer '$WG_INTERFACE'\n"$cRESET
                    fi
                else

                    local CATEGORY_NAME=$1;shift                                    # v3.04

                    local CMD=$1;shift

                    case $CMD in
                        add*)
                            if [ -z "$(grep "^${CATEGORY_NAME}\=" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                                POS=$(awk '/^# Categories/ {print NR}' ${INSTALL_DIR}WireguardVPN.conf)
                                local PEERS=
                                echo -e
                                for PEER in $@
                                    do
                                        [ ${PEER:0:2} != "wg" ] && { echo -e $cRED"\a\tInvalid Peer prefix 'wg*' '${cBWHT}$PEER${cRED}' ignored"$cRESET; PEER=; }
                                        if [ -n "$PEER" ] && [ ! -f ${CONFIG_DIR}${PEER}.conf ];then
                                            echo -e $cRED"\a\tPeer '${cBWHT}$PEER${cRED}' not found... ignored"$cRESET
                                            PEER=
                                        fi
                                        [ -n "$PEER" ] && PEERS=$PEERS" "$PEER
                                    done

                                PEERS=$(printf "%s" "$PEERS" | sed 's/^[ \t]*//;s/[ \t]*$//')
                                if [ -n "$PEERS" ];then
                                    LINE="$CATEGORY_NAME="$PEERS
                                    sed -i "$POS a $LINE" ${INSTALL_DIR}WireguardVPN.conf
                                    echo -e $cBGRE"\n\t'Peer category '$CATEGORY_NAME' ${cBRED}created\n"$cRESET
                                else
                                    echo -e $cBRED"\a\n\t***ERROR Category name '$CATEGORY_NAME' must contain VALID Peers!\n"$cBYEL
                                fi
                            else
                                echo -e $cBRED"\a\n\t***ERROR Category name '$CATEGORY_NAME' already EXISTS!\n"$cBYEL
                                grep "^$CATEGORY_NAME\=" ${INSTALL_DIR}WireguardVPN.conf
                                echo -e $cBWHT
                            fi
                        ;;
                        del)
                            if [ -n "$(grep "^${CATEGORY_NAME}\=" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                                sed -i "/^$CATEGORY_NAME\=/d" ${INSTALL_DIR}WireguardVPN.conf
                                echo -e $cBGRE"\n\t'Peer category '$CATEGORY_NAME' ${cBRED}Deleted\n"$cRESET
                            else
                                echo -e $cBRED"\a\n\t***ERROR Invalid Category name '$CATEGORY_NAME'\n"$cRESET
                            fi
                        ;;
                    esac
                fi
            ;;
        esac
}
Manage_Wireguard_Sessions() {

    local ACTION=$1;shift
    local WG_INTERFACE=$1;shift
    local CATEGORY=
    local SHOWCMDS=         # v4.14
    local WG_QUICK=

    # ALL Peers?
    if [ -z "$WG_INTERFACE" ] || [ "$WG_INTERFACE" == "all" ];then
            local WG_INTERFACE=

            # If no specific Peer specified, for Stop/Restart retrieve ACTIVE Peers otherwise for Start use Peer configuration
            if [ "$ACTION" == "start" ];then                  # v2.02 v1.09
                WG_INTERFACE=$(sqlite3 $SQL_DATABASE "SELECT peer FROM clients WHERE auto='Y' OR auto='P' OR auto='W';" | tr '\n' ' ')                              # v4.15
                WG_INTERFACE=$WG_INTERFACE" "$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers WHERE auto='Y' OR auto='P' OR auto='W' OR auto='S';" | tr '\n' ' ')  # v4.15
                if [ -z "$WG_INTERFACE" ];then
                    echo -e $cRED"\a\n\t***ERROR: No WireGuard® Peers WHERE (${cBWHT}Auto='Y'${cBRED}) defined\n"$cRESET 2>&1
                    return 1
                fi
            else
                # Wot if there are Peers we don't control?
                WG_INTERFACE=$(wg show interfaces)                # v1.09
            fi
            WG_INTERFACE=$(echo "$WG_INTERFACE" | awk '{$1=$1};1')    # v4.15 Strip leading/trailing spaces/tabs
            SayT "$VERSION Requesting WireGuard® VPN Peer $ACTION ($WG_INTERFACE)"
    else
        echo -en $cBCYA
        # Allow category
        case "$WG_INTERFACE" in
            clients)
                WG_INTERFACE=$(sqlite3 $SQL_DATABASE "SELECT peer FROM clients WHERE auto='Y' OR auto='P' OR auto='W';" | tr '\n' ' ')  # v4.15
                local CATEGORY=" for Category 'Clients'"
                WG_INTERFACE=$(echo "$WG_INTERFACE" | awk '{$1=$1};1')    # v4.15 Strip leading/trailing spaces/tabs
                SayT "$VERSION Requesting WireGuard® VPN Peer ${ACTION}$CATEGORY ($WG_INTERFACE)"
                local TABLE="clients"
                if [ -z "$WG_INTERFACE" ];then
                    echo -e $cRED"\a\n\t***ERROR: No Peers$CATEGORY WHERE (${cBWHT}Auto='Y' or 'P'${cBRED}) defined\n"$cRESET 2>&1
                    return 1
                fi
            ;;
            servers)
                WG_INTERFACE=$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers WHERE auto='Y' OR auto='P' OR auto='W' OR auto='S';" | tr '\n' ' ')  # v4.15
                local CATEGORY=" for Category 'Servers'"
                WG_INTERFACE=$(echo "$WG_INTERFACE" | awk '{$1=$1};1')    # v4.15 Strip leading/trailing spaces/tabs
                SayT "$VERSION Requesting WireGuard® VPN Peer ${ACTION}$CATEGORY ($WG_INTERFACE)"
                local TABLE="servers"
                if [ -z "$WG_INTERFACE" ];then
                    echo -e $cRED"\a\n\t***ERROR: No Peers$CATEGORY WHERE (${cBWHT}Auto='Y'${cBRED}) defined\n"$cRESET 2>&1
                    return 1
                fi
            ;;
            force|all)
                case $ACTION in                                     # v4.16
                    stop)                                           # v4.16
                    local WG_INTERFACE=$(wg show interfaces)        # v4.16
                ;;
                    *)
                    echo -e $cRED"\a\n\t***ERROR: '$WG_INTERFACE' not valid with '$ACTION' command!\n"$cRESET 2>&1  # v4.16
                    return 1
                ;;
                esac
            ;;
            *)

                local PEERS=$WG_INTERFACE" "$@              # v3.04

                for PEER in $PEERS
                    do
                        [ "$PEER" == "debug" ] && { local SHOWCMDS="debug"; continue; }                 # v4.14
                        [ "$PEER" == "wg-quick" ] && { local WG_QUICK="wg-quick"; continue; }           # v4.14

                        [ "$PEER" == "policy" ] && { local FORCEPOLICY="forcepolicy"; local POLICY_MODE="Forced POLICY mode"; continue; }       # v4.14
                        [ "$PEER" == "nopolicy" ] && { local FORCEPOLICY="forcedefault"; local POLICY_MODE="Override POLICY mode"; continue; }  # v4.14
                        # Category  list (CSV or space delimited) ?     # v3.04
                        if [ "${PEER:0:2}" != "wg" ];then
                            if [ -z "$(wg show $PEER 2>/dev/null)" ];then
                                local VALID_CATEGORY_PEERS=$(grep -E "^[[:alpha:]].*=wg" ${INSTALL_DIR}WireguardVPN.conf | grep -F "$PEER" | tr ',' ' ')
                                if [ -n "$VALID_CATEGORY_PEERS" ];then
                                    local CATEGORY_PEERS=$CATEGORY_PEERS" "${VALID_CATEGORY_PEERS#*=}       # v3.04
                                    local CATEGORY=" expanded category..."                                  # v3.04
                                fi
                            fi
                            local INTERFACES=$INTERFACES" "$PEER
                        else
                            local INTERFACES=$INTERFACES" "$PEER
                        fi
                    done
                WG_INTERFACE=$INTERFACES" "$CATEGORY_PEERS              # v3.04
            ;;
        esac
    fi

    WG_INTERFACE=$(printf "%s" "$WG_INTERFACE" | sed 's/wgs[1-5]//g' | sed 's/wgc[1-5]//g' | sed 's/^[ \t]*//;s/[ \t]*$//')

    # v4.12 Ensure 'server' peers are initialised before 'client' peers e.g. this order:  wg21 wg22 wg11 wg12 wg13 wg14 wg15
    local TMP_SERVERS=
    local TMP_CLIENTS=
    for WGI in $WG_INTERFACE
        do
            case $WGI in
                wg2*) [ -z "$(echo "$TMP_SERVERS" | grep -w "$WGI")" ] && TMP_SERVERS=$TMP_SERVERS" "$WGI;;
                wg1*) [ -z "$(echo "$TMP_CLIENTS" | grep -w "$WGI")" ] && TMP_CLIENTS=$TMP_CLIENTS" "$WGI;;
            esac
        done

    local TMP_SERVERS=$(echo "$TMP_SERVERS" | tr " " "\n" | sort | tr "\n" " ")
    WG_INTERFACE=$TMP_SERVERS" "$TMP_CLIENTS

    WG_INTERFACE=$(echo "$WG_INTERFACE" | awk '{$1=$1};1')    # v4.13  strip leading/trailing spaces/tabs

    [ -n "$WG_INTERFACE" ] && echo -e $cBWHT"\n\tRequesting WireGuard® VPN Peer ${ACTION}$CATEGORY (${cBMAG}$WG_INTERFACE"$cRESET")" ${cWRED}${POLICY_MODE}$cRESET

    case "$ACTION" in
        start|restart)                                  # v1.09

            # Commandline request overrides entry in config file                            # v1.10 Hotfix
            #[ -n "$(echo "$@" | grep -w "policy")" ] && { Route="policy"; POLICY_MODE="Policy Mode"; } || Route="default"      # v2.01 @jobhax v1.09
            [ -n "$(echo "$@" | grep -w "nopolicy")" ] && Route="default"                   # v1.11 Hotfix

            echo -e

            LOOKAHEAD=$WG_INTERFACE

            for WG_INTERFACE in $WG_INTERFACE
                do

                    Mode=$(Server_or_Client "$WG_INTERFACE")

                    [ "$Mode" == "server" ] && local TABLE="servers" || local TABLE="clients"

                    if [ -z "$Route" ] || [ "$FORCEPOLICY" == "forcepolicy" ];then
                        if [ "$Mode" == "client" ];then
                            if [ "$(sqlite3 $SQL_DATABASE "SELECT auto FROM $TABLE WHERE peer='$WG_INTERFACE';")" == "P" ] || [ "$FORCEPOLICY" == "forcepolicy" ];then
                                if [ "$FORCEPOLICY" != "forcedefault" ];then
                                    if [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$WG_INTERFACE';")" -gt 0 ] || \
                                       [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM ipset WHERE peer='$WG_INTERFACE';")" -gt 0 ] || \
                                       [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(client) FROM passthru WHERE client='$WG_INTERFACE';")" -gt 0 ];then # v4.12 v4.11 @ZebMcKayhan/@The Chief
                                        Route="policy"
                                    else
                                        SayT "Warning: WireGuard® '$Mode' Peer ('$WG_INTERFACE') defined as Policy mode but no RPDB Selective Routing/Passthru rules found?"
                                        echo -e $cRED"\tWarning: WireGuard® '$Mode' Peer (${cBWHT}$WG_INTERFACE${cBRED}) defined as Policy mode but no RPDB Selective Routing/Passthru rules found?\n"$cRESET 2>&1
                                    fi
                                else
                                    Route="default"
                                fi
                            else
                                Route="default"
                            fi
                        fi
                    fi

                    if [ "$ACTION" == "restart" ];then                                      # v1.09
                        # If it is UP then terminate the Peer
                        if [ -n "$(ifconfig $WG_INTERFACE 2>/dev/null | grep inet)" ];then  # v1.09
                            echo -e $cBWHT"\tRestarting Wireguard '$Mode' Peer (${cBMAG}${WG_INTERFACE}${cBWHT})"$cBCYA 2>&1
                            SayT "$VERSION Restarting Wireguard '$Mode' Peer ($WG_INTERFACE)"
                            [ "$Mode" == "server" ] && /jffs/addons/wireguard/wg_server $WG_INTERFACE "disable" "$SHOWCMDS" "$WG_QUICK" || ${INSTALL_DIR}wg_client $WG_INTERFACE "disable" "$SHOWCMDS" "$WG_QUICK"                 # v1.09
                        fi
                    fi

                    echo -en $cBCYA
                    SayT "$VERSION Initialising Wireguard VPN '$Mode' Peer ($WG_INTERFACE) ${POLICY_MODE}"
                    if [ -n "$(ifconfig | grep -E "^$WG_INTERFACE")" ];then
                        SayT "Warning: WireGuard® '$Mode' Peer ('$WG_INTERFACE') ALREADY ACTIVE"
                        echo -e $cRED"\tWarning: WireGuard® '$Mode' Peer (${cBWHT}$WG_INTERFACE${cBRED}) ALREADY ACTIVE\n"$cRESET 2>&1
                    else                                                                    # v3.04 Hotfix
                        if [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                            if [ "$Mode" == "server" ] ; then

                                local TS=$(date +%s)
                                #sh ${INSTALL_DIR}wg_server $WG_INTERFACE   # v4.12 http://www.snbforums.com/threads/vpnclient1-up-down-scripts-openvpn-ac86u-help-needed.56500/post-489924
                                chmod +x ${INSTALL_DIR}wg_server            # v4.12
                                ${INSTALL_DIR}wg_server $WG_INTERFACE "$SHOWCMDS" "$WG_QUICK"       # v4.14 v4.12

#[ "$(wg show interfaces | tr ' ' '\n' | grep "wg2[1-9]" | wc -w)" -eq 1 ] && local UDP_MONITOR=$(Manage_UDP_Monitor "server" "enable")

                                # Reset all its 'client' Peers...well HACK until 'client' peer ACTUALLY connects...
                                # Update the Start time for ALL 'client' device Peers hosted by the server

                                # Use the 'device' Peers Public Key rather than rely on a comment!
                                local DEVICE_PUB_KEYS=$(awk '/^PublicKey/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf | tr '\n' ' ')
                                local TIMESTAMP=$(date +%s)
                                for PUB_KEY in $DEVICE_PUB_KEYS
                                    do
                                        DEVICE=$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE pubkey='$PUB_KEY';")
                                        sqlite3 $SQL_DATABASE "INSERT into session values('$DEVICE','Start','$TIMESTAMP');"
                                        sqlite3 $SQL_DATABASE "UPDATE devices SET conntrack='$TIMESTAMP' WHERE name='$DEVICE';"
                                    done

                            elif [ "$Mode" == "client" ] && [ "$Route" != "policy" ] ; then
                                    #sh ${INSTALL_DIR}wg_client $WG_INTERFACE   # v4.12 http://www.snbforums.com/threads/vpnclient1-up-down-scripts-openvpn-ac86u-help-needed.56500/post-489924
                                    chmod +x ${INSTALL_DIR}wg_client            # v4.12
                                    ${INSTALL_DIR}wg_client $WG_INTERFACE "$SHOWCMDS"   # v4.14 v4.12
                            else
                                    #sh ${INSTALL_DIR}wg_client $WG_INTERFACE "policy"  # v4.12 http://www.snbforums.com/threads/vpnclient1-up-down-scripts-openvpn-ac86u-help-needed.56500/post-489924
                                    chmod +x ${INSTALL_DIR}wg_client                    # v4.12
                                    ${INSTALL_DIR}wg_client $WG_INTERFACE "policy" "$SHOWCMDS"      # v4.14 v4.12

                            fi
                        else
                            [ -n "$Mode" ] && TXT="'$Mode' " || TXT=            # v1.09
                            SayT "***ERROR: WireGuard® VPN ${TXT}Peer ('$WG_INTERFACE') config NOT found?....skipping $ACTION request"
                            echo -e $cBRED"\a\n\t***ERROR: WireGuard® ${TXT}Peer (${cBWHT}$WG_INTERFACE${cBRED}) config NOT found?....skipping $ACTION request\n"$cRESET   2>&1  # v1.09
                        fi
                    fi
                    # Reset the Policy flags/text
                    Route=                                  # v2.02
                    local FORCEPOLICY=                      # v4.14
                    local POLICY_MODE=                      # v4.14
                done
            WG_show
            ;;
        stop)
            # Default is to terminate ALL ACTIVE Peers,unless a list of Peers belonging to a category has been provided
            if [ -z "$WG_INTERFACE" ];then
                WG_INTERFACE=$(wg show interfaces | sed s'/wgc[1-5] //g' | sed s'/wgs[1-5] //g')      # v4.12 ACTIVE Peers excluding firmware managed peers e.g. wgs1 or wgc5
                if [ -n "$WG_INTERFACE" ];then
                    WG_INTERFACE=
                    SayT "$VERSION Requesting termination of ACTIVE WireGuard® VPN Peers ($WG_INTERFACE)"
                    echo -e $cBWHT"\tRequesting termination of ACTIVE WireGuard® VPN Peers ($WG_INTERFACE)"$cRESET 2>&1
                else
                    echo -e $cRED"\n\tNo WireGuard® VPN Peers ACTIVE for Termination request\n" 2>&1
                    SayT "No WireGuard® VPN Peers ACTIVE for Termination request"
                    echo -e 2>&1
                    return 0
                fi
            fi

            echo -e

            for WG_INTERFACE in $WG_INTERFACE
                do
                   [ "$WG_INTERFACE" == "debug" ] && { local SHOWCMDS="debug"; continue; }      # v4.14
                   if [ -n "$(wg show $WG_INTERFACE 2>/dev/null)" ] || [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then

                       Mode=$(Server_or_Client "$WG_INTERFACE")         # v4.14
                       [ "$Mode" == "server" ] && local TABLE="servers" || local TABLE="clients"   # v4.11

                        if [ -n "$(wg show $WG_INTERFACE 2>/dev/null | grep -F "interface:")" ] && [ ! -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then                                                  # v4.11
                            local FORCE="force"
                        fi
                        local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM $TABLE WHERE peer='$WG_INTERFACE';")
                        echo -en $cBCYA
                        SayT "$VERSION Requesting termination of WireGuard® VPN '$Mode' Peer ('$WG_INTERFACE')"

                        if [ -z "$(wg show interfaces | grep -w "$WG_INTERFACE")" ] && [ -z "$(ifconfig | grep -E "^$WG_INTERFACE")" ];then     # v4.12
                            echo -e $cRED"\a\t";Say "WireGuard® VPN '$Mode' Peer ('$WG_INTERFACE') NOT ACTIVE";echo -e
                        else
                            if [ "$Mode" == "server" ]; then

                                # Update the end time for ALL 'client' device Peers hosted by the server

                                # Use the 'device' Peers Public Key rather than rely on a comment!
                                local DEVICE_PUB_KEYS=$(awk '/^PublicKey/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf | tr '\n' ' ')
                                local TIMESTAMP=$(date +%s)
                                for PUB_KEY in $DEVICE_PUB_KEYS
                                    do
                                        DEVICE=$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE pubkey='$PUB_KEY';")
                                        sqlite3 $SQL_DATABASE "INSERT into session values('$DEVICE','End','$TIMESTAMP');"
                                    done

                                #sh ${INSTALL_DIR}wg_server $WG_INTERFACE "disable" "$SHOWCMDS" "$WG_QUICK"
                                ${INSTALL_DIR}wg_server $WG_INTERFACE "disable" "$SHOWCMDS" "$WG_QUICK"     # v4.16

                                # If there are no 'server' Peers ACTIVE then terminate UDP monitoring
                                # Will require REBOOT to reinstate! or 'wgm init'
                                [ "$(wg show interfaces | tr ' ' '\n' | grep "wg2[1-9]" | wc -w)" -eq 0 ] && local UDP_MONITOR=$(Manage_UDP_Monitor "server" "disable") # v4.12

                            else
                                # Dump the stats
                                Show_Peer_Status "generatestats" "$WG_INTERFACE" "ToFile"   # v4.16 v4.04
                                if [ "$Mode" == "client" ] && [ "$Route" != "policy" ] ; then
                                    wg show $WG_INTERFACE >/dev/null 2>&1 && ${INSTALL_DIR}wg_client $WG_INTERFACE "disable" "$FORCE" "$SHOWCMDS" "$WG_QUICK" || Say "WireGuard® $Mode service ('$WG_INTERFACE') NOT running."                       # v4.16
                                else
                                    wg show $WG_INTERFACE >/dev/null 2>&1 && ${INSTALL_DIR}wg_client $WG_INTERFACE "disable" "policy" "$FORCE" "$SHOWCMDS" "$WG_QUICK" || Say "WireGuard® $Mode (Policy) service ('$WG_INTERFACE') NOT running."     # v4.16
                                fi
                                [ -f /tmp/metrics.wg ] && { cat /tmp/metrics.wg; rm /tmp/metrics.wg ;}          # v4.16
                            fi

                        fi
                    else
                        SayT "***ERROR: WireGuard® VPN ${TXT}Peer ('$WG_INTERFACE') config NOT found?....skipping $ACTION request"
                        echo -e $cBRED"\a\n\t***ERROR: WireGuard® ${TXT}Peer (${cBWHT}$WG_INTERFACE${cBRED}) config NOT found?....skipping $ACTION request\n"$cRESET   2>&1  # v1.09
                    fi
                done

            WG_show
            ;;
    esac
}
Manage_alias() {
                [ ! -f /jffs/configs/profile.add ] && true > /jffs/configs/profile.add      # v4.12

    local ALIASES="start stop restart show diag"

    case "$1" in
        del)
            echo -e $cBCYA"\tDeleted aliases for '$SCRIPT_NAME'"$cRESET
            sed -i "/$SCRIPT_NAME/d" /jffs/configs/profile.add
            rm -rf "/opt/bin/wg_manager" 2>/dev/null                                   # v4.15 v2.01
        ;;
        "?")
            echo -e $cRESET"\tAlias info\n"
            for ALIAS in $ALIASES
                do
                    type "wg"$ALIAS
                done

        ;;
        *)
        # Create Alias

            rm -rf "/opt/bin/wg_manager" 2>/dev/null                                        # v2.01
            if [ -d "/opt/bin" ] && [ ! -L "/opt/bin/wg_manager" ]; then
                echo -e $cBCYA"\n\tCreating 'wg_manager' alias for '$SCRIPT_NAME'" 2>&1
                ln -s /jffs/addons/wireguard/wg_manager.sh /opt/bin/wg_manager              # v2.01
            fi

            if [ -z "$(grep "$SCRIPT_NAME" /jffs/configs/profile.add)" ];then
                # echo -e $cBCYA"\n\tCreating aliases and shell functions for '$SCRIPT_NAME'"$cRESET
                # alias wgstart='/jffs/addons/wireguard/$SCRIPT_NAME start'
                # echo "alias wgstart='/jffs/addons/wireguard/$SCRIPT_NAME start'"               >>/jffs/configs/profile.add

                # alias wgstop='/jffs/scripts/addons/wireguard/$SCRIPT_NAME stop'
                # echo "alias wgstop='/jffs/addons/wireguard/$SCRIPT_NAME stop'"                 >>/jffs/configs/profile.add

                # alias wgrestart='/jffs/addons/wireguard/$SCRIPT_NAME restart'
                # echo "alias wgrestart='/jffs/addons/wireguard/$SCRIPT_NAME restart'"           >>/jffs/configs/profile.add

                # alias wgshow='/jffs/addons/wireguard/$SCRIPT_NAME show'
                # echo "alias wgshow='/jffs/addons/wireguard/$SCRIPT_NAME show'"                 >>/jffs/configs/profile.add

                # alias wgdiag='/jffs/scripts/wireguard/$SCRIPT_NAME diag'
                # echo "alias wgdiag='/jffs/addons/wireguard/$SCRIPT_NAME diag'"                 >>/jffs/configs/profile.add

                # Shell function!
                echo -e "wgm()  { ${INSTALL_DIR}$SCRIPT_NAME \$@; }          # WireGuard Session Manager"   >>/jffs/configs/profile.add
            else
                echo -e $cRED"\n\tWarning: Aliases and shell functions for $SCRIPT_NAME already exist\n"$cRESET
            fi
        ;;
    esac
}
Manage_Event_Scripts() {

    local ACTION=$2

    if [ "$ACTION" != "backup" ];then
        if [ ! -d ${INSTALL_DIR}Scripts ];then                              # v4.01
            # Restore from backup if one exists
            if [ -d ${CONFIG_DIR}Scripts ];then
                mv ${CONFIG_DIR}Scripts ${INSTALL_DIR}
            else
                mkdir ${INSTALL_DIR}Scripts
            fi
        fi
        echo -e $cBYEL"\n\tEvent scripts\n"$cBWHT
        ls -1 ${INSTALL_DIR}Scripts
    else
        # Backup...perhaps user has elected to uninstall WireGuard Session Manager but wants to preserve the data directory ${CONFIG_DIR}
        mv ${INSTALL_DIR}Scripts ${CONFIG_DIR}                              # v4.09
    fi
}
Manage_RPDB_rules() {
    # v4.08
    local REDISPLAY=1
    local SRC=
    local DST=
    local ALLOW_SRCDST_SWITCH="Y"
    local SRCDST_SWITCHED=
    local ACTION=$1
    shift
    local WG_INTERFACE=$1
    shift 2
    local CMD=$1
    shift
    [ -z "$CMD" ] && local CMD="list"
    [ "$CMD" == "del" ] && { local ROW=$1; shift; }

    if [ ! -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
        echo -e $cBRED"\a\n\t***ERROR: Peer (${cBWHT}$WG_INTERFACE${cBRED}) doesn't exist!"$cRESET
        return 1
    fi

    while [ $# -gt 0 ]; do
        case $1 in
            wan|vpn|wg2*)
                local IFACE=$1
            ;;
            src=*)
                local SRC=$(echo "$1" | sed 's/src=//')
            ;;
            dst=*)
                local DST=$(echo "$1" | sed 's/dst=//')
            ;;
            "?"|list)
                local CMD="list"
            ;;
            tag=*|comment)
                if [ "$1" == "tag=" ] || [ "$1" == "comment" ];then
                    local ANNOTATE="$(echo "$1" | sed -n "s/^.*tag=//p" | awk '{print $0}')"
                    [ -z "$ANNOTATE" ] && local ANNOTATE="$(echo "$@" | sed -n "s/^.*comment//p" | awk '{print $0}')"
                    local ANNOTATE=$(printf "%s" "$ANNOTATE" | sed 's/^[ \t]*//;s/[ \t]*$//')
                    break
                fi
            ;;
            *)
                [ -z "$SRC" ] && local SRC=$1 || local DST=$1
            ;;
        esac
        shift
    done

    case $SRC in
        [aA][nN][yY]) local SRC="Any";;
    esac
    case $DST in
        [aA][nN][yY]) local DST="Any";;
    esac

    # Don't perform validation if BOTH SRC and DST are EXPLICITLY supplied
    if { [ -z "$SRC" ] && [ -z "$DST" ] ;} || { [ -n "$SRC" ] && [ -z "$DST" ] ;} ;then                                 # v4.12

        # By default, any DST IP that is    deemed LOCAL, is switched to be the SRC, similarly
        #             any SRC IP that ISN'T deemed LOCAL, is switched to be the DST

        # Wait!, for WireGuard it is indeed perfectly acceptable to access LOCAL IPs over the tunnel?

        if [ -n "$SRC" ];then
                if [ "$SRC" != "Any" ];then
                    if [ -z "$(echo "$SRC" | grep -F ":")" ];then               # v4.12
                        if [ -z "$(echo "$SRC" | Is_IPv4_CIDR)" ] && [ -z "$(echo "$SRC" | Is_Private_IPv4)" ];then
                            if [ "$ALLOW_SRCDST_SWITCH" == "Y" ];then
                                if [ "$DST" != "Any" ];then
                                    local SRCDST_SWITCHED="${cRESET}***Source $SRC switched to destination!"
                                    local DST=$SRC
                                    local SRC=
                                fi
                            fi
                        fi
                    else
                        if [ -z "$(echo "${SRC%/*}" | Is_Private_IPv6)" ];then
                            if [ "$ALLOW_SRCDST_SWITCH" == "Y" ];then
                                local SRCDST_SWITCHED="${cRESET}***Source $SRC switched to destination!"
                                local DST=$SRC
                                local SRC=
                            fi
                        fi
                    fi
                fi
        fi

        if [ -n "$DST" ];then
            if [ "$DST" != "Any" ];then
                if [ -n "$(echo "$DST" | grep -F ":")" ];then
                    if [ -n "$(echo "${DST%/*}" | Is_Private_IPv6)" ];then
                        if [ "$ALLOW_SRCDST_SWITCH" == "Y" ];then
                            if [ "$SRC" != "Any" ];then
                                local SRCDST_SWITCHED="${cRESET}***Destination $DST switched to source!"
                                local SRC=$DST
                                local DST=
                            fi
                        fi
                    fi
                else
                    if [ -n "$(echo "$DST" | Is_IPv4_CIDR)" ] || [ -n "$(echo "$DST" | Is_Private_IPv4)" ];then
                        if [ "$ALLOW_SRCDST_SWITCH" == "Y" ];then
                            if [ "$SRC" != "Any" ];then
                                local SRCDST_SWITCHED="${cRESET}***Destination $DST switched to source!"
                                local SRC=$DST
                                local DST=
                            fi
                        fi
                    fi
                fi
            fi
        fi

        [ -z "$IFACE" ] && IFACE="VPN"
        [ -z "$SRC" ] && SRC="Any"
        [ -z "$DST" ] && DST="Any"
    else
        #Check if valid SRC/DST format
        [ -z "$IFACE" ] && IFACE="VPN"
        [ -z "$SRC" ] && SRC="Any"
        [ -z "$DST" ] && DST="Any"

        case $SRC in
            Any)
            ;;
            *.*)
                 if [ -z "$(echo "$SRC" | Is_IPv4_CIDR)" ] && [ -z "$(echo "$SRC" | Is_Private_IPv4)" ];then
                    echo -e $cBRED"\a\n\t***ERROR: Source IP address (${cBWHT}$SRC${cBRED}) is NOT a valid IPv4/CIDR address!"$cRESET
                    return 1
                 fi
            ;;
            *:*)
                 if [ -z "$(echo "${SRC%/*}" | Is_IPv6)" ];then
                    echo -e $cBRED"\a\n\t***ERROR: Source IP address (${cBWHT}$SRC${cBRED}) is NOT a valid IPv6 address!"$cRESET
                    return 1
                 fi
            ;;
            *)
                echo -e $cBRED"\a\n\t***ERROR: Source IP address (${cBWHT}$SRC${cBRED}) - must be valid IPv4/IPv6 address or 'Any'!"$cRESET
                return 1
            ;;
        esac

        case $DST in
            Any)
            ;;
            *.*)
                 if [ -z "$(echo "$DST" | Is_IPv4_CIDR)" ] && [ -z "$(echo "$DST" | Is_IPv4)" ];then
                    echo -e $cBRED"\a\n\t***ERROR: Destination IP address (${cBWHT}$DST${cBRED}) is NOT a valid IPv4/CIDR address!"$cRESET
                    return 1
                 fi
            ;;
            *:*)
                 if [ -z "$(echo "${DST%/*}" | Is_IPv6)" ];then
                    echo -e $cBRED"\a\n\t***ERROR: Destination IP address (${cBWHT}$DST${cBRED}) is NOT a valid IPv6 address!"$cRESET
                    return 1
                 fi
            ;;
            *)
                echo -e $cBRED"\a\n\t***ERROR: Destination IP address (${cBWHT}$DST${cBRED}) - must be valid IPv4/IPv6 address or 'Any'!"$cRESET
                return 1
            ;;
        esac
    fi

    local IFACE=$(echo "$IFACE" | tr 'a-z' 'A-Z')

    case "$CMD" in
        add)
            if [ -z "$(sqlite3 $SQL_DATABASE "SELECT * FROM policy WHERE peer='$WG_INTERFACE' AND iface='$IFACE' AND srcip='$SRC' AND dstip='$DST';")" ];then
                sqlite3 $SQL_DATABASE "INSERT INTO policy values('$WG_INTERFACE','$IFACE','$SRC','$DST','$ANNOTATE');"
                echo -e $cBGRE"\n\t[✔] Updated RPDB Selective Routing rule for $WG_INTERFACE $SRCDST_SWITCHED\n"$cRESET  2>&1
                SayT "Updated RPDB Selective Routing rule for $WG_INTERFACE $SRCDST_SWITCHED"
            else
                echo -e $cRED"\a\n\t***ERROR Peer ${cBCYA}${WG_INTERFACE} ${cRESET}$IFACE${cRED} rule already exists!\n"$cRESET
                REDISPLAY=0
            fi
        ;;
        del)
            if [ "$ROW" != "all" ];then
                sqlite3 $SQL_DATABASE "DELETE FROM policy WHERE rowid='$ROW';"
                echo -e $cBGRE"\n\t[✔] Deleted RPDB Selective Routing rule for $WG_INTERFACE \n"$cRESET  2>&1
            else
                echo -e $cBCYA"\a\n\tDo you want to DELETE ALL Selective Routing RPDB rules for ${cBMAG}$WG_INTERFACE?"$cRESET
                echo -e "\tPress$cBRED y$cRESET to$cBRED CONFIRM${cRESET} or press$cBGRE [Enter] to SKIP."
                read -r "ANS"
                if [ "$ANS" == "y" ];then
                    sqlite3 $SQL_DATABASE "DELETE FROM policy WHERE peer='$WG_INTERFACE';"
                    echo -e $cBGRE"\n\t[✔] Deleted ALL RPDB Selective Routing rules for $WG_INTERFACE \n"$cRESET  2>&1
                else
                    REDISPLAY=0
                fi
            fi

        ;;
        upd)
            echo -e $cBGRE"\n\t[✔] Updated RPDB Selective Routing rule for $WG_INTERFACE \n"$cRESET
        ;;
        list)
            if [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$WG_INTERFACE';") -gt 0 ];then
                echo -e $cBCYA"\n"
                sqlite3 $SQL_DATABASE "SELECT rowid,peer,iface,srcip,dstip,tag FROM policy WHERE peer='$WG_INTERFACE' ORDER BY iface DESC;" | column -t  -s '|' --table-columns ID,Peer,Interface,Source,Destination,Description
            else
                echo -e $cRED"\n\tNo RPDB Selective Routing/Passthru rules for $WG_INTERFACE\n"$cRESET
            fi

            REDISPLAY=0
        ;;
    esac

    return $REDISPLAY
}
Manage_PASSTHRU_rules() {
    # v4.12
    # v4.16     del { 'all' | wg1x [ 'all' | IP/CIDR ] }
    #           add { 'all' | IP/CIDR }
    local REDISPLAY=1
    local ACTION=$1
    shift
    local WG_INTERFACE=$1
    shift 2
    local CMD=$1
    shift
    local IFACE=$1
    shift
    local IP_SUBNET=$1

    if [ "$IFACE" != "wan" ] && [ ! -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
        echo -e $cBRED"\a\n\t***ERROR: Peer (${cBWHT}$WG_INTERFACE${cBRED}) doesn't exist!"$cRESET
        return 1
    fi

    local MODE=$(Server_or_Client "$WG_INTERFACE")

    if [ "$MODE" != "server" ];then
        echo -e $cBRED"\a\n\t***ERROR: Peer (${cBWHT}$WG_INTERFACE${cBRED}) must be 'server' peer e.g. 'wg21'"$cRESET
        return 1
    fi

    if [ -n "$CMD" ] && [ "$CMD" != "list" ];then

        local Route=
        if [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$IFACE';")" -gt 0 ] || \
           [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM ipset WHERE peer='$IFACE';")" -gt 0 ] || \
           [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(client) FROM passthru WHERE client='$IFACE';")" -gt 0 ];then
            Route="policy"
        fi

        case "$CMD" in
            add)

                if [ "$IFACE" != "wan" ] && [ ! -f ${CONFIG_DIR}${IFACE}.conf ];then
                    echo -e $cBRED"\a\n\t***ERROR: 'client' Peer (${cBWHT}$IFACE${cBRED}) doesn't exist!"$cRESET
                    return 1
                fi

                if [ "$IFACE" == "wan" ];then
                    :
                else
                    local MODE=$(Server_or_Client "$IFACE")
                    if [ "$MODE" == "server" ];then
                        echo -e $cBRED"\a\n\t***ERROR: Peer (${cBWHT}$IFACE${cBRED}) must be 'client' peer e.g. 'wg13'"$cRESET
                        return 1
                    fi
                fi

                if [ "$IP_SUBNET" == "all" ];then
                    local IP_SUBNET=$(sqlite3 $SQL_DATABASE "SELECT subnet FROM servers WHERE peer='$WG_INTERFACE';")
                fi

                for THIS in "$(echo "$IP_SUBNET" | tr ',' ' ')"
                    do
                        if [ -n "$(echo "$THIS" | Is_IPv4)" ] || [ -n "$(echo "$THIS" | Is_IPv4_CIDR)" ] || [ -n "$(echo "$THIS" | grep -F ":")" ];then  # v4.16
                            :
                        else
                            if [ -z "$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE name='$THIS';")" ];then           # v4.16
                                [ -n "$THIS" ] && echo -e $cBRED"\a\n\t***ERROR: 'device' Peer (${cBWHT}$THIS${cBRED}) doesn't exist!"$cRESET || echo -e $cBRED"\a\n\t***ERROR: 'device' Peer missing ${cRESET}(or use 'all') e.g add $IFACE MyPhone"
                                return 1
                            fi
                        fi
                    done

                sqlite3 $SQL_DATABASE "INSERT INTO passthru values('$WG_INTERFACE','$IFACE','$IP_SUBNET');"

                echo -e $cBGRE"\n\t[✔] Updated Passthru Routing rule for $WG_INTERFACE \n"$cRESET  2>&1
                if [ "$IFACE" == "wan" ];then
                   # Need to Restart the 'server' Peer if it is UP
                    if [ -n "$(wg show interfaces | grep "$WG_INTERFACE")" ];then
                        CMD="restart"
                        echo -e $cBWHT"\a\n\tWireGuard® 'server' Peer needs to be ${CMD}ed to implement 'wan' passthru"
                        echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'server' Peer ($WG_INTERFACE) or press$cBGRE [Enter] to SKIP."
                        read -r "ANS"
                        [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$WG_INTERFACE"; REDISPLAY=1; }  # v4.12
                    fi
                else
                    # Need to Restart the 'client' Peer if it is UP
                    if [ -n "$(wg show interfaces | grep "$IFACE")" ];then
                        local Route=
                        if [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$IFACE';")" -gt 0 ] || \
                           [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM ipset WHERE peer='$IFACE';")" -gt 0 ] || \
                           [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(client) FROM passthru WHERE client='$IFACE';")" -gt 0 ];then
                            Route="policy"
                        fi
                        CMD="restart"
                        echo -e $cBWHT"\a\n\tWireGuard® 'client' Peer needs to be ${CMD}ed to implement '$IP_SUBNET' passthru RPDB rules"
                        echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'client' Peer ($IFACE) or press$cBGRE [Enter] to SKIP."
                        read -r "ANS"
                        [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$IFACE" "$Route"; REDISPLAY=1; }
                    fi
                fi
            ;;
            del)
                if [ "$IFACE" != "all" ];then

                    [ -z "$IP_SUBNET" ] && local IP_SUBNET="all"        # v4.16

                    if [ "$IP_SUBNET" != "all" ];then                   # v4.16
                        if [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(server) FROM passthru WHERE server='$WG_INTERFACE' AND client='$IFACE' AND ip_subnet='$IP_SUBNET';") -gt 0 ];then    # v4.16
                            sqlite3 $SQL_DATABASE "DELETE FROM passthru WHERE server='$WG_INTERFACE' AND client='$IFACE' AND ip_subnet='$IP_SUBNET';"
                            echo -e $cBGRE"\n\t[✔] Deleted Passthru Routing rule for $WG_INTERFACE via $IFACE\n"$cRESET  2>&1   # v4.16
                        else
                            echo -e $cBRED"\a\n\t***ERROR: No matching Passthru Routing rule?!"$cRESET 2>&1     # v4.16
                            return 1
                        fi
                    else
                        if [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(server) FROM passthru WHERE server='$WG_INTERFACE' AND client='$IFACE';") -gt 0 ];then   # v4.16
                            sqlite3 $SQL_DATABASE "DELETE FROM passthru WHERE server='$WG_INTERFACE' AND client='$IFACE';"  # v4.16
                            echo -e $cBGRE"\n\t[✔] Deleted ALL Passthru Routing rules for $WG_INTERFACE via $IFACE\n"$cRESET  2>&1
                        else
                            if [ -n "$IFACE" ];then
                                echo -e $cBRED"\a\n\t***ERROR: No matching Passthru Routing rules for $WG_INTERFACE via $IFACE\n"$cRESET 2>&1       # v4.16
                            else
                                echo -e $cBRED"\a\n\t***ERROR: No matching Passthru Routing rules for $WG_INTERFACE\n"$cRESET 2>&1      # v4.16
                            fi
                            return 1
                        fi
                    fi

                    if [ "$IFACE" == "wan" ];then
                        # Need to Restart the 'server' Peer if it is UP
                        if [ -n "$(wg show interfaces | grep "$WG_INTERFACE")" ];then
                            CMD="restart"
                            echo -e $cBWHT"\a\n\tWireGuard® 'server' Peer needs to be ${CMD}ed to remove 'wan' passthru"
                            echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'server' Peer ($WG_INTERFACE) or press$cBGRE [Enter] to SKIP."
                            read -r "ANS"
                            [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$WG_INTERFACE"; REDISPLAY=1; }  # v4.12
                        fi
                    else
                        #if [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(server) FROM passthru WHERE server='$WG_INTERFACE' AND client='$IFACE';") -gt 0 ];then
                            # Need to Restart the 'client' Peer if it is UP
                            if [ -n "$(wg show interfaces | grep "$IFACE")" ];then
                                CMD="restart"
                                echo -e $cBWHT"\a\n\tWireGuard® 'client' Peer needs to be ${CMD}ed to remove '$IP_SUBNET' passthru RPDB rules"
                                echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'client' Peer ($IFACE) or press$cBGRE [Enter] to SKIP."
                                read -r "ANS"
                                [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$IFACE" "$Route"; REDISPLAY=1; }
                            fi
                        #else
                            # Delete ALL Passthru RPDB rules in flight.....
                            #${INSTALL_DIR}wg_client $IFACE "passthru_rules" "del"
                            #echo -e $cGRE"\a\n\tALL Passthru RPDB Routing rules for $WG_INTERFACE via $IFACE removed\n"$cRESET 2>&1
                        #fi
                    fi
                else
                    echo -e $cBCYA"\a\n\tDo you want to DELETE ALL Passthru Routing rules for ${cBMAG}$WG_INTERFACE?"$cRESET
                    echo -e "\tPress$cBRED y$cRESET to$cBRED CONFIRM${cRESET} or press$cBGRE [Enter] to SKIP."
                    read -r "ANS"
                    if [ "$ANS" == "y" ];then
                        local RESTART_CLIENTS=$(sqlite3 $SQL_DATABASE "SELECT client FROM passthru WHERE server='$WG_INTERFACE';")  # v4.16
                        local RESTART_CLIENTS=$(echo "$RESTART_CLIENTS" | xargs -n1 | sort -u | xargs)  # Remove duplicates from the restart list

                        if [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(server) FROM passthru WHERE server='$WG_INTERFACE';") -gt 0 ];then   # v4.16
                            sqlite3 $SQL_DATABASE "DELETE FROM passthru WHERE server='$WG_INTERFACE';"
                            echo -e $cBGRE"\n\t[✔] Deleted ALL Passthru Routing rules for $WG_INTERFACE \n"$cRESET  2>&1
                            # Do we need to restart any 'client' Peers?                                                     # v4.16
                            for CLIENT_PEER in $RESTART_CLIENTS
                                do
                                    # Need to Restart the 'client' Peer if it is UP
                                    if [ -n "$(wg show interfaces | grep "$CLIENT_PEER")" ];then
                                        CMD="restart"
                                        echo -e $cBWHT"\a\n\tWireGuard® 'client' Peer needs to be ${CMD}ed to remove 'passthru' rules"
                                        echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'client' Peer ($CLIENT_PEER) or press$cBGRE [Enter] to SKIP."
                                        read -r "ANS"
                                        [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$CLIENT_PEER" "$Route"; REDISPLAY=1; }
                                    fi
                                done
                        else
                            echo -e $cGRE"\a\n\tWarning: No matching Passthru Routing rules for $WG_INTERFACE\n"$cRESET 2>&1        # v4.16
                            REDISPLAY=1
                        fi
                    else
                        REDISPLAY=0
                    fi
                fi
            ;;
            *)
                echo -e $cBRED"\a\n\t***ERROR: command '$CMD' invalid - use 'add' or 'del' ONLY"$cRESET
                return 1
            ;;
        esac

    fi

    return $REDISPLAY
}
Manage_VPNDirector_rules() {

    local REDISPLAY=0

    local ACTION=$2             # vpndirector [ clone [ 'wan' | 'ovpnc'n [ changeto_vpn_num]]| delete | list]

    local FILTER=$3
    if [ -n "$FILTER" ];then
        local FILTER=$(echo "$FILTER" | tr 'a-z' 'A-Z')
        [ "$FILTER" != "WAN" ] && local FILTER="OVPN"$FILTER
    fi

    local WG_INTERFACE=$4

    [ -z "$ACTION"  ] && local ACTION="list"

    case $ACTION in
        clone|copy)
            if [ -s /jffs/openvpn/vpndirector_rulelist ];then
                sed -E 's/(>OVPN[1-5]|>WAN)/\1\n/g' /jffs/openvpn/vpndirector_rulelist > /tmp/VPNDirectorRules.txt
                [ -n "$FILTER" ] && local FILTER_TXT="(ONLY ${FILTER}) "                    # v4.14
                echo -e $cRESET"\n\tAuto clone VPN Director ${FILTER_TXT}rules\n" 2>&1      # v4.14
                while read -r LINE || [ -n "$LINE" ]; do
                    #local ACTIVE=$(echo "$LINE" | awk -F '>' '{print $1}' VPNDIrector.txt)
                    local COMMENT=$(echo "$LINE"        | awk -F '>' '{print $2}')
                    local SRC=$(echo "$LINE"            | awk -F '>' '{print $3}')
                    local DST=$(echo "$LINE"            | awk -F '>' '{print $4}')
                    local TARGET_IFACE=$(echo "$LINE"   | awk -F '>' '{print $NF}')

                    if [ -n "$FILTER" ];then
                        if [ "$FILTER" != "$TARGET_IFACE" ];then
                            echo -e $cBRED"\tVPN Director clone Filter: '$FILTER' skipping '$TARGET_IFACE ($COMMENT)'"$cRESET
                            continue
                        fi
                    fi

                    if [ -z "$SRC" ] && [ -n "$DST" ];then
                        local DST="dst="$DST
                    fi

                    local VPN_NUM=${TARGET_IFACE#"${TARGET_IFACE%?}"}
                    if [ "$VPN_NUM" != "N" ];then
                        [ -z "$4" ] && local WG_INTERFACE="wg1"$VPN_NUM || local WG_INTERFACE="wg1"$4
                    else
                        local WG_INTERFACE="wg11"
                    fi

                    [ "$TARGET_IFACE" == "WAN" ] && local TARGET_IFACE="wan" || local TARGET_IFACE="vpn"
                    echo -en "\tpeer" $WG_INTERFACE" rule add "$TARGET_IFACE $SRC $DST "comment" "$COMMENT" 2>&1
                    Manage_RPDB_rules peer $WG_INTERFACE rule add $TARGET_IFACE $SRC $DST comment VPN Director: $COMMENT    # v4.13

                    local IFACE=
                    local SRC=
                    local COMMENT=

                done < /tmp/VPNDirectorRules.txt

                #rm /tmp/VPNDirectorRules.txt
            else
                echo -en $cRED"\a\n\t***ERROR: No VPN Director Policy rules configured in firmware!\n"$cRESET 2>&1
                return 0
            fi

            local REDISPLAY=1
        ;;
        list)
            if [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(tag) FROM policy WHERE tag LIKE 'VPN Director:%';")" -gt 0 ];then
                echo -e $cBCYA"\n\tVPN Director Selective Routing RPDB rules\n"$cRESET 2>&1
                sqlite3 $SQL_DATABASE "SELECT rowid,peer,iface,srcip,dstip,tag FROM policy WHERE tag LIKE 'VPN Director:%' ORDER BY iface DESC;" |column -t  -s '|' --table-columns ID,Peer,Interface,Source,Destination,Description 2>&1 # v4.13
            else
                echo -en $cRED"\a\n\tNo WirGuard VPN Director Policy rules found\n"$cRESET 2>&1
            fi
        ;;
        delete|flush)
            if [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(tag) FROM policy WHERE tag LIKE 'VPN Director:%';")" -gt 0 ];then
                echo -e $cBCYA"\a\n\tDo you want to DELETE ALL VPN Director Policy rules?"$cRESET 2>&1
                echo -e "\tPress$cBRED y$cRESET to$cBRED CONFIRM${cRESET} or press$cBGRE [Enter] to SKIP." 2>&1
                read -r "ANS"
                if [ "$ANS" == "y" ];then
                    sqlite3 $SQL_DATABASE "DELETE FROM policy WHERE tag LIKE 'VPN Director:%';"
                    echo -e $cBGRE"\n\t[✔] Deleted ALL VPN Director Policy rules\n"$cRESET  2>&1
                fi
            else
                echo -en $cRED"\a\n\t***ERROR: No VPN Director Policy rules found to delete'\n"$cRESET 2>&1
            fi
        ;;
    esac

    return $REDISPLAY

}
Manage_FC() {

    local STATUS=

    if [ "$(which fc)" == "/bin/fc" ];then

        case "$1" in
            disable|off)

                if [ -n "$(fc status | grep "Flow Learning Enabled")" ];then
                    echo -en $cBRED"\t"
                    fc disable
                    echo -en $cBGRE"\t"
                    fc flush
                    SayT "Broadcom Packet Flow Cache learning via BLOG (Flow Cache) DISABLED"   # v4.11 @Torson
                    nvram set fc_disable=1      # v4.12
                    nvram commit                # v4.12
                fi
                local STATUS="\n\t${cBRED}Flow Cache Disabled"
            ;;
            enable|off)

                if [ -z "$(fc status | grep "Flow Learning Enabled")" ];then
                    echo -en $cBGRE"\t"
                    fc enable
                    echo -en $cBGRE"\t"
                    fc flush
                    SayT "Broadcom Packet Flow Cache learning via BLOG (Flow Cache) ENABLED"   # v4.11 @Torson
                    nvram set fc_disable=0      # v4.12
                    nvram commit                # v4.12
                fi
                local STATUS="\n\t${cBGRE}Flow Cache Enabled"
            ;;
            *)
                [ -n "$(fc status | grep "Flow Learning Enabled")" ] && local STATUS="\tFlow Cache Enabled" || local STATUS="\tFlow Cache Disabled"
            ;;
        esac
    fi

    echo "$STATUS"

}
Initialise_SQL() {

    local ACTION=$1                 # v4.14
    local FORCE=$2
    local STATUS="Initialised"      # v4.14

    [ "$(sqlite3 -version | awk 'BEGIN { FS = "." } {printf("%03d%02d",$1,$2)}')" -le 325 ] && opkg install sqlite3-cli # v4.14

    local TS=$(date +"%Y%m%d-%H%M%S")    # current date and time 'yyyymmdd-hhmmss'

    local FCNT=$(ls -lah ${CONFIG_DIR}*.conf 2>/dev/null | wc -l)
    [ -f ${INSTALL_DIR}WireguardVPN.conf ] && local CCNT=$(grep -E "^wg[1-2]" ${INSTALL_DIR}WireguardVPN.conf | wc -l) || local CCNT=0

    if [ $CCNT -eq 0 ];then
        echo -e $cBRED"\a\n\tNo Peer entries to auto-migrate ${cBCYA}from '${cBWHT}${INSTALL_DIR}WireguardVPN.conf${cBCYA}', but you will need to manually import the 'device' Peer '*.conf' files:\n\n"$cRESET

        ls -1 ${CONFIG_DIR}*.conf 2>/dev/null | awk -F '/' '{print $5}' | grep -v "wg[1-2]" | sed 's/\.conf$//' | sort
        [ "$ACTION" == "migrate" ] && return 0
    fi

    if [ -f $SQL_DATABASE ] && [ "$ACTION" == "keep" ];then
        mv $SQL_DATABASE ${SQL_DATABASE}.$TS 2>/dev/null
        local STATUS="Retained/Upgraded"
    fi

    # v4.09 Modify policy
    # v4.11 Modify traffic
    cat > /tmp/sql_cmds.txt << EOF
CREATE TABLE IF NOT EXISTS servers (peer varchar(5) PRIMARY KEY, auto varchar(1) NOT NULL, subnet varchar(19) NOT NULL, port integer(5), pubkey varchar(55), prikey varchar(55) NOT NULL, tag varchar(40));
CREATE TABLE IF NOT EXISTS clients (peer varchar(5) PRIMARY KEY, auto varchar(1) NOT NULL, subnet varchar(19) NOT NULL, socket varchar(25), dns varchar(19), mtu integer(4),pubkey varchar(55), prikey varchar(55), tag varchar(40));
CREATE TABLE IF NOT EXISTS devices (name varchar(15) PRIMARY KEY, auto varchar(1) NOT NULL, ip varchar(19)  NOT NULL, dns varchar(15)  NOT NULL, allowedip varchar(100), pubkey varchar(55)  NOT NULL, prikey varchar(55), tag varchar(40), conntrack UNSIGNED BIG INT );
CREATE TABLE IF NOT EXISTS policy  (peer varchar(5), iface varchar(4), srcip varchar(19), dstip varchar(19), tag varchar(30), PRIMARY KEY(peer,iface,srcip,dstip));
CREATE TABLE IF NOT EXISTS fwmark  (fwmark varchar(10), peer varchar(15) NOT NULL, PRIMARY KEY(fwmark,peer));
CREATE TABLE IF NOT EXISTS ipset   (ipset PRIMARY KEY, use varchar(1), peer varchar(5),fwmark varchar(10) NOT NULL, dstsrc varchar (11) NOT NULL);
CREATE TABLE IF NOT EXISTS traffic (peer NOT NULL,timestamp UNSIGNED BIG INT NOT NULL,rx UNSIGNED BIG INT NOT NULL,tx UNSIGNED BIG INT NOT NULL,rxtotal UNSIGNED BIG INT NOT NULL,txtotal UNSIGNED BIG INT NOT NULL);
CREATE TABLE IF NOT EXISTS session (peer NOT NULL,state varchar(1), timestamp UNSIGNED BIG INT NOT NULL);
CREATE TABLE IF NOT EXISTS passthru (server varchar(5) NOT NULL, client varchar(5) NOT NULL, ip_subnet varchar(19) NOT NULL, PRIMARY KEY(server,client,ip_subnet));
EOF
    echo -en $cBRED

    sqlite3 $SQL_DATABASE < /tmp/sql_cmds.txt
    if [ $? -eq 0 ];then
        if [ "$STATUS" != "Initialised" ];then                                          # v4.14
            rm $SQL_DATABASE
            mv  ${SQL_DATABASE}.$TS $SQL_DATABASE 2>/dev/null                           # v4.14
        fi
        echo -e $cBGRE"\n\t[✔] WireGuard® Peer SQL Database $STATUS OK\n"$cRESET     # v4.12
    fi

    Manage_Peer                                                                         # v4.14

    echo -en $cRESET

    if [ "$INSTALL_MIGRATE" == "Y" ] || [ -n "$FORCE" ];then
        if [ $CCNT -gt 0 ];then
            echo -e $cBCYA"\tDo you want to auto-migrate the ${cBWHT}${CCNT}${cBCYA} Peer entries?"
            echo -e "\n\tPress$cBRED y$cRESET to$cBRED migrate${cRESET} or press$cBGRE [Enter] to skip"
            read -r "ANS"
            if [ "$ANS" == "y" ];then

                for WG_INTERFACE in $(grep -E "^wg2" ${INSTALL_DIR}WireguardVPN.conf | awk '{print $1}' | tr '\n' ' ')
                    do
                        #if [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                            local AUTO=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $2}' ${INSTALL_DIR}WireguardVPN.conf)
                            local SUBNET=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $3}' ${INSTALL_DIR}WireguardVPN.conf)

                            [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ] && local PORT=$(awk '/^ListenPort/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf)

                            local ANNOTATE=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {$1="";$2="";$3="";print $0}' ${INSTALL_DIR}WireguardVPN.conf | sed 's/\t//g')
                            local ANNOTATE=$(printf "%s" "$ANNOTATE" | sed 's/^[ \t]*//;s/[ \t]*$//')
                            local ANNOTATE=$(echo "$ANNOTATE" | sed "s/'/''/g")
                            [ -f ${CONFIG_DIR}${WG_INTERFACE}_public.key ]  && local PUB_KEY=$(cat ${CONFIG_DIR}${WG_INTERFACE}_public.key)
                            [ -f ${CONFIG_DIR}${WG_INTERFACE}_private.key ] && local PRI_KEY=$(cat ${CONFIG_DIR}${WG_INTERFACE}_private.key)

                            sqlite3 $SQL_DATABASE "INSERT INTO servers values('$WG_INTERFACE','$AUTO','$SUBNET','$PORT','$PUB_KEY','$PRI_KEY','$ANNOTATE');"
                            echo -e $cBGRE"\t[✔] Peer ${cBMAG}${WG_INTERFACE},'$AUTO','$SUBNET','$PORT','$ANNOTATE'${cBGRE} migrate success"$cRESET 2>&1

                            local AUTO=;local SUBNET=;local ANNOTATE=;local PUB_KEY=;local PRI_KEY=
                        #fi
                    done
                echo -e
                for WG_INTERFACE in $(grep -E "^wg1" ${INSTALL_DIR}WireguardVPN.conf | awk '{print $1}' | tr '\n' ' ')
                    do
                        #if [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                            local AUTO=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $2}' ${INSTALL_DIR}WireguardVPN.conf)
                            local SUBNET=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $3}' ${INSTALL_DIR}WireguardVPN.conf)
                            local SOCKET=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $4}' ${INSTALL_DIR}WireguardVPN.conf)   # v4.01 @Torson Beta testing
                            local DNS=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $5}' ${INSTALL_DIR}WireguardVPN.conf)       # v4.01 @Torson Beta testing

                            if [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                                local PRI_KEY=$(awk '/^PrivateKey/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf)
                            fi
                            local ANNOTATE=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {$1="";$2="";$3="";$4="";$5="";print $0}' ${INSTALL_DIR}WireguardVPN.conf | sed 's/\t//g')
                            local ANNOTATE=$(printf "%s" "$ANNOTATE" | sed 's/^[ \t]*//;s/[ \t]*$//')
                            local ANNOTATE=$(echo "$ANNOTATE" | sed "s/'/''/g")
                            local PUB_KEY=

                            sqlite3 $SQL_DATABASE "INSERT INTO clients values('$WG_INTERFACE','$AUTO','$SUBNET','$SOCKET','$DNS','$PUB_KEY','$PRI_KEY','$ANNOTATE');"
                            echo -e $cBGRE"\t[✔] Peer ${cBMAG}${WG_INTERFACE},'$AUTO','$SUBNET','$SOCKET','$DNS','$ANNOTATE'${cBGRE} migrate success"$cRESET 2>&1

                            local AUTO=;local SUBNET=;local ANNOTATE=;local PUB_KEY=;local PRI_KEY=;local SOCKET=;local DNS=
                        #fi
                    done
                echo -e
                for WG_INTERFACE in $(awk '($2=="X") {print $1}' ${INSTALL_DIR}WireguardVPN.conf | tr '\n' ' ')
                    do
                        #if [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                            local AUTO=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $2}' ${INSTALL_DIR}WireguardVPN.conf)
                            if [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                                local IP=$(awk '/^Address/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf)
                                local DNS=$(awk '/^DNS/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf)
                                local ALLOWED=$(awk '/^AllowedIPs/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf)
                            fi
                            local ANNOTATE=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {$1="";$2="";$3="";$4="";print $0}' ${INSTALL_DIR}WireguardVPN.conf | sed 's/\t//g')
                            local ANNOTATE=$(printf "%s" "$ANNOTATE" | sed 's/^[ \t]*//;s/[ \t]*$//')
                            local ANNOTATE=$(echo "$ANNOTATE" | sed "s/'/''/g")
                            local PRI_KEY=;local PUB_KEY=
                            [ -f ${CONFIG_DIR}${WG_INTERFACE}_public.key ] && local PUB_KEY=$(awk 'NR=1{print $0}' ${CONFIG_DIR}${WG_INTERFACE}_public.key)

                            sqlite3 $SQL_DATABASE "INSERT INTO devices values('$WG_INTERFACE','$AUTO','$IP','$DNS','$ALLOWED','$PUB_KEY','$PRI_KEY','$ANNOTATE');"
                            echo -e $cBGRE"\t[✔] Peer ${cBMAG}${WG_INTERFACE},'$AUTO','$IP','$DNS','$ALLOWED','$ANNOTATE'${cBGRE} migrate success"$cRESET 2>&1

                            local AUTO=;local IP=;local ANNOTATE=;local PUB_KEY=;local PRI_KEY=;local ALLOWED=;local DNS=
                        #fi
                    done

                [ $(grep -E "^wg[1-2]" ${INSTALL_DIR}WireguardVPN.conf | wc -l) -gt 0 ] && mv ${INSTALL_DIR}WireguardVPN.conf ${INSTALL_DIR}WireguardVPN.conf_migrated

                Create_Sample_Config

                Manage_Peer

                echo -en $cBCYA"\n\tUse the ${aBOLD}${cBWHT}import${cRESET}${cBCYA} command to add the Road-Warrior Peer devices to the database.'\n\n\t\timport "$cRESET
                ls -1 ${CONFIG_DIR}*.conf 2>/dev/null | awk -F '/' '{print $5}' | grep -v "wg[1-2]" | sed 's/\.conf$//' | sort | column
            fi
        fi
    fi

    # fwmark 0x8000/0x8000 WAN
    # fwmark 0x7000/0x7000 wg14
    # fwmark 0x3000/0x3000 wg15
    # fwmark 0x1000/0x1000 wg11
    # fwmark 0x2000/0x2000 wg12
    # fwmark 0x4000/0x4000 wg13
    if [ -z "$(sqlite3 $SQL_DATABASE "SELECT * FROM fwmark;")" ];then

        sqlite3 $SQL_DATABASE "INSERT INTO fwmark values('0x1000','wg11');"
        sqlite3 $SQL_DATABASE "INSERT INTO fwmark values('0x2000','wg12');"
        sqlite3 $SQL_DATABASE "INSERT INTO fwmark values('0x4000','wg13');"
        sqlite3 $SQL_DATABASE "INSERT INTO fwmark values('0x7000','wg14');"
        sqlite3 $SQL_DATABASE "INSERT INTO fwmark values('0x3000','wg15');"
        sqlite3 $SQL_DATABASE "INSERT INTO fwmark values('0x8000','wan');"

    fi
}
Create_Sample_Config() {
    if [ -f ${INSTALL_DIR}WireguardVPN.conf ];then
        echo -e $cBYEL"\a\n\tWarning: WireGuard® configuration file '${INSTALL_DIR}WireguardVPN.conf' already exists!...renamed to 'WireguardVPN.conf$TS'"
        mv ${INSTALL_DIR}WireguardVPN.conf ${INSTALL_DIR}WireguardVPN.conf.$TS
    fi
    echo -e $cBCYA"\a\n\tCreating/Updating WireGuard® configuration file '${INSTALL_DIR}WireguardVPN.conf'"

    cat > ${INSTALL_DIR}WireguardVPN.conf << EOF
# WireGuard® Session Manager v4.12

# Categories - Group several WireGuard peers for ease of starting/stopping
#     NOTE: The default categories 'clients' and 'servers' represent ALL 'client' peers and 'server' peers respectively
#     e.g. Create the category 'usa',  use command 'peer category usa wg12 wg13' then command 'start usa' will start both 'client' peers.
None=

# WAN KILL-Switch - Prevents WAN access if there are no ACTIVE WireGuard 'client' peers.
#     Use command 'vx' to edit this setting.
#     (You can temporarily override this by using menu command 'killswitch off')
#KILLSWITCH

# Statistics Gathering
#     Use command 'vx' to edit this setting.
STATS

# Global IPv6 Override
#     Use command 'vx' to edit this setting.
#     If IPv6 is configured on the router (nvram get ipv6_service != "disabled") then
#        a 'client' peer may be assigned an IPv6 IP address by the WireGuard ISP and may subsequently include "::/0" in its AllowedIPs list etc.
#        This setting basically ignores any IPv6 settings for the WireGuard interfaces.
#NOIPV6

# Global Menu Display Override
#     Use command 'vx' to edit this setting.
#     If using SSH shortcuts on iPhone/Android, the menu text with word wrap is annoying, and made worse with the ASCII escape sequeces
#NOMENU

# Global ANSI/ASCII Display ATTRIB Override
#     Use command 'vx' to edit this setting.
#     Suppress ANSI/ASCII control sequences for display items such as highlighted/coloured Error messages or underline/reverse attibutes.
#NOCOLOR

# For Routers that include WireGuard Kernel/User Space tools, allow overriding with supported 3rd-Party/Entware versions
#     Use command 'vx' to edit this setting.
#USE_ENTWARE_KERNEL_MODULE

# Override setting of the -t mangle FORWARD/PREROUTING '-j MARK --set-xmark 0x01/0x7' fwmarks
# (NOT the user Selective Routing fwmarks for Ports/IPSETs etc.)
#     Use command 'vx' to edit this setting.
#NOSETXMARK

# Override setting of the TCP MSS clamping of -t mangle FORWARD chain '-p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu'
#     Use command 'vx' to edit this setting.
#     https://www.linuxtopia.org/Linux_Firewall_iptables/x4700.html
#NOTCPMSS

# Override use of 'Pg-Up' key to retrieve previous commands
#     Use command 'vx' to edit this setting.
#NOPG_UP

# URL to check Endpoint Server; apply to ALL interfaces unless excluded, or named interfaces
#     FULL URL https://mullvad.net/en/check/ which checks DNS Leak etc.
#     API CHK_ENDPOINT = curl https://am.i.mullvad.net/connected  , wg14-
#     Use command 'vx' to edit this setting.
#CHK_ENDPOINT = curl -s https://am.i.mullvad.net/connected , * wg14-
#CHK_ENDPOINT = curl -s https://am.i.mullvad.net/connected , wg11
#CHK_ENDPOINT = curl -s https://Torguard, wg14

# Disable Flow Cache Permanently. (Checked each time wireguard_manager is INITialised or command 'wgm start' is issued)
#     Use command 'vx' to edit this setting or command 'fc {disable | enable}'
#DISABLE_FLOW_CACHE

# **EXPERIMENTAL** Enable UDP Monitoring of 'server' Peer client connections when WireGuard_manager is INITialised
#     Use command 'vx' to edit this setting
#ENABLE_UDPMON

# Enable debugging messages to Syslog
#     Use command 'vx' to edit this setting
#PRINT_DDNS_RERESOLV_MSGS

# Enable Weekly 07:00 every Sunday cron job to trim SQL database older than xx days (0 - no trimming!)
#     Use command 'vx' to edit this setting
#     (You can temporarily override this by using menu command 'trimdb cron xx')
TrimDB 99

EOF

    return 0
}
_quote() {
  echo "$1" | sed 's/[]\/()$*.^|[]/\\&/g'
}
Convert_Key() {
    local KEY="$1"
    #[ -n "$(echo "$1" | grep -F "/" )" ] && local KEY=$(_quote "$KEY")

    echo "$KEY"
}
Display_QRCode() {

    local FN=$1
    local ANS=$2

    if [ -f $FN ];then                                          # v1.05
        if [ -z "$ANS" ];then
            echo -e $cBWHT"\tPress$cBRED y$cRESET to Display QR Code for Scanning into WireGuard® App on device $cBMAG'$DEVICE_NAME' ${cRESET}or press$cBGRE [Enter] to SKIP."
            read -r "ANS"
        fi
        [ "$ANS" == "y" ] && { clear; qrencode -t ANSIUTF8 < $FN; }             # v1.05
    fi
}
Edit_firewall_start() {
# v4.11 'nat'-start references changed to 'firewall'-start
    if [ "$1" != "del" ];then

        [ ! -f /jffs/scripts/firewall-start ] && { echo -e "#!/bin/sh\n\n"    > /jffs/scripts/firewall-start; chmod +x /jffs/scripts/firewall-start; }
        if [ -z "$(grep "WireGuard" /jffs/scripts/firewall-start)" ];then
            echo -e "/jffs/addons/wireguard/wg_firewall            # WireGuard" >> /jffs/scripts/firewall-start
            cat > /jffs/addons/wireguard/wg_firewall << EOF                     # v2.04
#!/bin/sh
VERSION="$TS"
# Reinstate WireGuard firewall rules by restarting WireGuard as firewall-start has executed
#
Get_WAN_IF_Name() {

    local IF_NAME=\$(nvram get wan0_ifname)              # DHCP/Static ?

    # Usually this is probably valid for both eth0/ppp0e ?
    if [ "\$(nvram get wan0_gw_ifname)" != "\$IF_NAME" ];then
        local IF_NAME=\$(nvram get wan0_gw_ifname)
    fi

    if [ ! -z "$(nvram get wan0_pppoe_ifname)" ];then
        local IF_NAME="\$(nvram get wan0_pppoe_ifname)"      # PPPoE
    fi

    echo \$IF_NAME
}

WAN_IF=\$(Get_WAN_IF_Name)

logger -st "(\$(basename "\$0"))" \$\$ "Checking if WireGuard® VPN Peer KILL-Switch is required....."
if [ -n "\$(grep -E "^KILLSWITCH" /jffs/addons/wireguard/WireguardVPN.conf)" ];then
    iptables -D FORWARD -i br0 -o \$WAN_IF -j REJECT -m comment --comment "WireGuard KILL-Switch" 2>/dev/null
    iptables -I FORWARD -i br0 -o \$WAN_IF -j REJECT -m comment --comment "WireGuard KILL-Switch" 2>/dev/null
    logger -st "(\$(basename "\$0"))" \$\$ "WireGuard® VPN Peer KILL-Switch ENABLED"
fi

if [ -n "\$(wg show interfaces)" ];then
    logger -st "(\$(basename "\$0"))" \$\$ "Restarting WireGuard® to reinstate RPDB/firewall rules"
    /jffs/addons/wireguard/wg_manager.sh stop
    /jffs/addons/wireguard/wg_manager.sh start

fi
EOF

            chmod +x /jffs/addons/wireguard/wg_firewall
        fi
        echo -e $cBCYA"\n\tfirewall-start updated to protect WireGuard® firewall rules"$cRESET
        SayT "firewall-start updated to protect WireGuard® firewall rules"
    else
        sed -i '/WireGuard/d' /jffs/scripts/firewall-start          # v4.11
        echo -e $cBCYA"\n\tfirewall-start updated - no longer protecting WireGuard® firewall rules"$cRESET
        SayT "firewall-start updated - no longer protecting WireGuard® firewall rules"
    fi

}
Server_or_Client() {

    local WG_INTERFACE=$1
    local PEER_TYPE="**ERROR**"                                                         # v4.05

    local SOURCE_DIR=$CONFIG_DIR                                                        # v4.12
    [ -n "$2" ] && SOURCE_DIR=$2                                                        # v4.12

        case "$WG_INTERFACE" in
            wgs*|wgc*)                              # ASUS Internal GUI peer...
                case "$WG_INTERFACE" in
                    wgc*) local PEER_TYPE="client";;
                    wgs*) local PEER_TYPE="server";;
                esac
                ;;
            *)

                # Check the definitive SQL database categorisation first....                                # v4.16b6
                if [ "$PEER_TYPE" == "**ERROR**" ];then
                    [ -n "$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers WHERE peer='$WG_INTERFACE';")" ] && local PEER_TYPE="server"
                fi
                if [ "$PEER_TYPE" == "**ERROR**" ];then
                    [ -n "$(sqlite3 $SQL_DATABASE "SELECT peer FROM clients WHERE peer='$WG_INTERFACE';")" ] && local PEER_TYPE="client"
                fi
                if [ "$PEER_TYPE" == "**ERROR**" ];then
                    [ -n "$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE name='$WG_INTERFACE';")" ] && local PEER_TYPE="device"
                fi

                # Alternatively determine if it's a 'client','server' or 'device' Peer from its config file
                if [ "$PEER_TYPE" == "**ERROR**" ] && [ -f ${SOURCE_DIR}${WG_INTERFACE}.conf ];then         # v4.16b6 v4.12 v1.03

                    if [ -z "$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers WHERE peer='$WG_INTERFACE';")" ] && [ -n "$(grep -iE "^Endpoint" ${SOURCE_DIR}${WG_INTERFACE}.conf)" ];then  # v4.14 v4.12 v1.03
                        local PEER_TYPE="client"
                        if [ -n "$(nvram get ddns_hostname_x)" ];then                           # v4.05
                            [ -n "$(grep -iF "$(nvram get ddns_hostname_x)" ${SOURCE_DIR}${WG_INTERFACE}.conf)" ] && PEER_TYPE="device" # v4.12
                        else
                            if [ -n "$(nvram get wan0_realip_ip)" ];then
                                [ -n "$(grep -iF "$(nvram get wan0_realip_ip)" ${SOURCE_DIR}${WG_INTERFACE}.conf)" ] && PEER_TYPE="device"  # v4.12
                            fi
                        fi
                    else
                        local PEER_TYPE="server"
                    fi
                fi

                ;;
        esac

    echo "$PEER_TYPE"
}
WG_show() {

    local SHOW=$1

    if [ "$SHOW" == "Y" ];then
        echo -e $cBCYA"\tStatus:\n"$cRESET
        wg show all
    fi
}
DNSmasq_Listening_WireGuard_Status() {
    # Check if DNSmasq is listening on ALL wg* interfaces               # v1.07
    if [ -z "$(grep -F "wg*" /etc/dnsmasq.conf)" ];then
        echo -e $cBRED"\t[✖]${cBWHT} DNSmasq ${cRED}is not listening on any WireGuard® interfaces 'wg*'\n"$cRESET 2>&1
    else
        echo -e $cBGRE"\t[✔]${cBWHT} DNSmasq ${cBGRE}is listening on ALL WireGuard® interfaces 'wg*'\n"$cRESET 2>&1
    fi
}
Edit_DNSMasq() {

    if [ -z "$1"  ];then                           # v2.01
        # Allow dnmsasq to listen on Wireguard interfaces for DNS
        [ ! -f /jffs/configs/dnsmasq.conf.add ] && true > /jffs/configs/dnsmasq.conf.add # v2.03
        if [ -z "$(grep -E "^interface=wg\*" /jffs/configs/dnsmasq.conf.add)" ];then
            echo -e $cBCYA"\tRestarting DNSmasq to add 'wg*' interfaces"$cRESET 2>&1
            echo -e "interface=wg*     # WireGuard" >> /jffs/configs/dnsmasq.conf.add
            service restart_dnsmasq 2>/dev/null
        fi
    else
        if [ -f /jffs/configs/dnsmasq.conf.add ];then
            if [ -n "$(grep "WireGuard" /jffs/configs/dnsmasq.conf.add)" ];then
                echo -e $cBCYA"\tRestarting DNSMASQ to remove 'wg*' interfaces"$cRESET 2>&1
                sed -i '/WireGuard/d' /jffs/configs/dnsmasq.conf.add     # v1.12
                service restart_dnsmasq 2>/dev/null
            fi
        fi
    fi

    sleep 1
}
Manage_KILL_Switch() {

    local ACTION=$1

    local SILENT="N"
    local TEMP_PERM="temporarily"
    local WAN_IF=$(Get_WAN_IF_Name)

    if [ -n "$ACTION" ];then
        if [ "$ACTION" != "off" ];then
                iptables -D FORWARD -i br0 -o $WAN_IF -j REJECT -m comment --comment "WireGuard KILL-Switch" 2>/dev/null
                iptables -I FORWARD -i br0 -o $WAN_IF -j REJECT -m comment --comment "WireGuard KILL-Switch" 2>/dev/null
                [ -z "$(grep -oE "^#KILLSWITCH" ${INSTALL_DIR}WireguardVPN.conf)" ] && local TEMP_PERM="permanently"             # v4.12
                #[ "$SILENT" == "N" ] && echo -e $cBGRE"\n\t[✔] WireGuard WAN KILL-Switch "${cBRED}${aREVERSE}"$TEMP_PERM ENABLED"$cRESET" (use 'vx' command for info)" 2>&1         # v4.12
        else
                iptables -D FORWARD -i br0 -o $WAN_IF -j REJECT -m comment --comment "WireGuard KILL-Switch" 2>/dev/null
                [ -z "$(grep -oE "^KILLSWITCH" ${INSTALL_DIR}WireguardVPN.conf)" ] && local TEMP_PERM= "permanently"              # v4.12
                #[ "$SILENT" == "N" ] && echo -e $cBRED"\n\t[✖] ${cBGRE}WireGuard WAN KILL-Switch "${cBRED}${aREVERSE}"$TEMP_PERM DISABLED"$cRESET" (use 'vx' command for info)" 2>&1    # v4.12
        fi
    fi

    [ -n "$(iptables -nvL FORWARD | grep "WireGuard KILL-Switch")" ] && STATUS="Y" || STATUS="N"    # v4.14

    echo "${STATUS}_${TEMP_PERM}"      # Y/N_[temporarily/Permanently]
}
Manage_Stats() {

    local ACTION=$2
    local STATUS=0

    case $ACTION in
        disable|off)
            cru d WireGuard 2>/dev/null
        ;;
        enable|on)
            cru d WireGuard 2>/dev/null
            cru a WireGuard 59 "* * * *" /jffs/addons/wireguard/wg_manager.sh generatestats
        ;;
    esac

    if [ -n "$(cru l | grep "WireGuard")" ];then
        local TXT="${cBGRE}\t[✔] ${cBWHT}Statistics gathering is ${cBGRE}ENABLED"$cRESET
        STATUS=1
    else
        local TXT="${cBRED}\t[✖] ${cBWHT}Statistics gathering is ${cRED}DISABLED"$cRESET
    fi

    echo -e "$TXT"

    return $STATUS

}
Get_scripts() {
    local BRANCH="$1"

    echo -e $cBCYA"\tDownloading scripts"$cRESET 2>&1

    # Allow use of custom script for debugging
    [ "$(WireGuard_Installed)" == "Y" ] && download_file ${INSTALL_DIR} wg_manager.sh martineau $BRANCH dos2unix 777
    download_file ${INSTALL_DIR} wg_client martineau $BRANCH dos2unix 777
    download_file ${INSTALL_DIR} wg_server martineau $BRANCH dos2unix 777
    download_file ${INSTALL_DIR} UDP_Updater.sh martineau $BRANCH dos2unix 777
    download_file ${INSTALL_DIR} wg_ChkEndpointDDNS.sh martineau $BRANCH dos2unix 777           # v4.15

    chmod +x ${INSTALL_DIR}wg_manager.sh
    chmod +x ${INSTALL_DIR}wg_client
    chmod +x ${INSTALL_DIR}wg_server
    chmod +x ${INSTALL_DIR}UDP_Updater.sh                                               # v4.01
    chmod +x ${INSTALL_DIR}wg_ChkEndpointDDNS.sh                                                # v4.15

    md5sum ${INSTALL_DIR}wg_manager.sh      > ${INSTALL_DIR}"wg_manager.md5"
    md5sum ${INSTALL_DIR}wg_client          > ${INSTALL_DIR}"wg_client.md5"
    md5sum ${INSTALL_DIR}wg_server          > ${INSTALL_DIR}"wg_server.md5"
    md5sum ${INSTALL_DIR}UDP_Updater.sh     > ${INSTALL_DIR}"UDP_Updater.md5"          # v4.01
    md5sum ${INSTALL_DIR}wg_ChkEndpointDDNS.sh     > ${INSTALL_DIR}"wg_ChkEndpointDDNS.md5"     # v4.15
}
Read_INPUT() {

# shellcheck disable=SC2120,SC2154
_GetKEY() {

        #local OLDIFS=$IFS

        # Doesn't require user also hitting ENTER
        IFS= read -rsn1  "${@:-char}"

        #IFS=$OLDIFS

        echo -en $char 2>&1
}

        local ESC=$(printf "\x1b")
        local ENTER=$(printf "\x0a")
        local BACKSPACE_VT220=$(printf "\x7e")                  # Xshell6 Del VT220 aka Esc[3~
        local BACKSPACE_ASCII=$(printf "\x7f")                  # Xshell6 CTRL+? ASCII 127
        local BACKSPACE=$(printf "\x08")                        # Xshell6 CTRL+H

        local DEL=$(printf "\x7e")

        local JUNK=

        local CHAR=
        local LBUF=
        local RBUF=
        local KEY_CNT=0

        local X=0
        local RECALLINDEX=0
        local MAX_RECALLINDEX=6

        if [ -n "$CMDLINE" ];then                             # Only save last command if it's non-blank
            CMD5="$CMD4";CMD5=$CMD5
            CMD4="$CMD3"
            CMD3="$CMD2"
            CMD2="$CMD1"
            CMD1="$CMDLINE"
        fi

        local OLDIFS=$IFS

        while true;do

            #local CHAR=$(_GetKEY)
            IFS= read -rsn1 "CHAR"

            if [ "$CHAR" == "$ESC" ]; then
                read -rsn2 JUNK # Read 2 more CTRL chars
                case "$JUNK" in                              # A-UP;B-DOWN;C-RIGHT;D-LEFT
                    "[A")                                     # CSR_UP
                       local RECALLINDEX=$((RECALLINDEX+1))
                       [ $RECALLINDEX -eq $MAX_RECALLINDEX ] && RECALLINDEX=1

                       eval local LBUF_TMP="\$CMD$RECALLINDEX"     # Retrieve last cmd from 'buffer stack'
                       if [ -z "$LBUF_TMP" ];then
                            if [ $RECALLINDEX -gt 1 ];then
                                local RECALLINDEX=1
                                local LBUF="$CMD1"
                            fi
                       else
                            local LBUF=$LBUF_TMP
                       fi
                       if [ -n "$LBUF" ];then
                            echo -en ${xPOSCSR}${xERASEEOL}$LBUF
                            local KEY_CNT=${#LBUF}
                       else
                            local RECALLINDEX=0
                       fi
                        ;;
                    "[D")                                    # CSR_LEFT
                        if [ ${#LBUF} -gt 0 ];then
                            echo -en "\e[D"
                            local X=$((${#LBUF}-1))
                            [ -z "$RBUF" ] && local RBUF=${LBUF:$X} || local RBUF=${LBUF:$X}${RBUF}
                            local LBUF=${LBUF:0:$X}
                        fi
                        ;;
                    "[C")                                    # CSR_RIGHT
                        if [ ${#RBUF} -gt 0 ];then
                            echo -en "\e[C"
                            local LBUF=${LBUF}${RBUF:0:1}
                            local RBUF=$(echo "$RBUF" | sed 's/^.//')
                        fi;;
                    *)
                        :
                        ;;
                esac
                continue
            fi

            if [ "$CHAR" == "$BACKSPACE" ] || [ "$CHAR" == "$BACKSPACE_ASCII" ]  || [ "$CHAR" == "$BACKSPACE_VT220" ];then
               if [ $((KEY_CNT+PROMPT_SIZE)) -gt $PROMPT_SIZE ];then
                   echo -en ${CHAR}$xERASEEOL
                   LBUF=$(echo "$LBUF" | sed 's/.$//')
                   local KEY_CNT=$((KEY_CNT-1))
                   [ -n "$RBUF" ] && echo -en ${xCSRPOS}${xERASEEOL}${RBUF}$xPOSCSR
               fi
               continue
            fi

            if [ -n "$RBUF" ] && [ "$CHAR" == "$DEL" ];then
                local RBUF="$(echo "$RBUF" | sed 's/^.//')"
                local KEY_CNT=$((KEY_CNT-1))
                echo -en ${xCSRPOS}${xERASEEOL}${RBUF}$xPOSCSR
                continue
            fi

            [ "$CHAR" == "$ENTER" ] && break

            [ "$CHAR" == " " ] && echo -en " "

            echo -en ${CHAR}${xCSRPOS}${xERASEEOL}${RBUF}$xPOSCSR
            LBUF=${LBUF}${CHAR}
            local KEY_CNT=$((KEY_CNT+1))
        done

        IFS=$OLDIFS

        CMDLINE="${LBUF}$RBUF"

        echo -e 2>&1

}
WireGuard_Installed() {

    local KERNEL_LOADED="N"     # v4.12 Check the current Kernel module rather than inconclusive 'which wg' User Tools module

    if [ -n "$(lsmod | grep -i wireguard)" ] || [ -n "$(opkg status wireguard-kernel 2>/dev/null | awk '/^Installed/ {print $2}')" ];then   # v4.12
       local KERNEL_LOADED="Y"  # v4.12
    fi

    if [ -f "${INSTALL_DIR}WireguardVPN.conf" ] && [ "$KERNEL_LOADED" == "Y" ];then # v4.12 v2.02
        echo "Y"
        return 0
    else
        echo "N"
        return 1
    fi
}
Peer_Status_Summary() {

    local TYPE=
    local CLIENT_PEERS=0
    local SERVER_PEERS=0
    local GUI_CLIENT_PEERS=0        # v4.12
    local GUI_SERVER_PEERS=0        # v4.12
    local PEER_STATUS=

    [ -n "$(which wg)" ] && ACTIVE_PEERS="$(wg show interfaces)"

    for PEER in $ACTIVE_PEERS
        do
            case $PEER in
                wgc*|wgs*)
                    case $PEER in
                        wgc*) GUI_CLIENT_PEERS=$((GUI_CLIENT_PEERS+1));;
                        wgs*) GUI_SERVER_PEERS=$((GUI_SERVER_PEERS+1));;
                    esac
                ;;
                *)
                    TYPE=$(Server_or_Client "$PEER")
                    case $TYPE in
                        client)
                            CLIENT_PEERS=$((CLIENT_PEERS+1))
                        ;;
                        server)
                            SERVER_PEERS=$((SERVER_PEERS+1))
                        ;;
                    esac
                ;;
            esac
        done

    if [ $GUI_CLIENT_PEERS -gt 0 ] || [ $GUI_CLIENT_PEERS -gt 0 ];then  # v4.12
        local GUI_PEERS="${cBMAG}\n\t\t      ${cRESET}ASUS GUI Peers:${cBMAG} Clients ${cBWHT}$GUI_CLIENT_PEERS${cBMAG}, Servers ${cBWHT}$GUI_SERVER_PEERS${cBMAG}" # v4.12
    fi
    PEER_STATUS="Clients ${cBWHT}$CLIENT_PEERS${cBMAG}, Servers ${cBWHT}$SERVER_PEERS $GUI_PEERS"
    echo -e "$PEER_STATUS" 2>&1

    [ -n "$1" ] && SayT "$PEER_STATUS"
}
Show_credits() {
    printf '\n+======================================================================+\n'
    printf '|  Welcome to the %bWireGuard® Manager/Installer script (Asuswrt-Merlin)%b |\n' "$cBGRE" "$cRESET"
    printf '|                                                                      |\n'
    local local CNT=23;VERSION_LENGTH=${#VERSION}
    [ $VERSION_LENGTH -gt 4 ] && CNT=$((CNT-(VERSION_LENGTH-4)))
    local BLANKS=$(Repeat $CNT " ")
    printf '|                      Version %b%s%b by Martineau%b' "$cBMAG" "$VERSION" "${cRESET}" "${BLANKS}|\n"    # v3.22
    printf '|                                                                      |\n'
}
Show_Info_HDR() {

    local ACTION="$(echo "$menu1"| awk '{print $1}')"

    local CHANGELOG="$cRESET(${cBCYA}Change Log: ${cBYEL}https://github.com/MartineauUK/wireguard/commits/main/wg_manager.sh$cRESET)"   #v2.01
    [ -n "$(echo $VERSION | grep "b")" ] && local CHANGELOG="$cRESET(${cBCYA}Change Log: ${cBYEL}https://github.com/MartineauUK/wireguard/commits/dev/wg_manager.sh$cRESET)" #v2.01

    echo -e $cBWHT"\n\tRouter$cBMAG $HARDWARE_MODEL ${cBRESET}Firmware ${cBMAG}(v$BUILDNO)"             # v4.12
    if [ -f "$ENTWARE_INFO" ] || [ -f /opt/etc/opkg.conf ];then
        if [ -f "$ENTWARE_INFO" ];then
            echo -e $cBGRE"\n\t[✔]${cBWHT} Entware Architecture${cBMAG} $(grep -E "^arch" $ENTWARE_INFO)\n"$cRESET     # v4.01 @Torson
        else
            echo -e $cBGRE"\n\t[✔]${cBWHT} Entware Architecture${cBMAG} $(grep -E "^arch.*\." /opt/etc/opkg.conf)\n"$cRESET
        fi
    else
        echo -e $cBRED"\n\t[✖] Entware Architecture unknown!\n"$cRESET
    fi

    echo -e $cBMAG"\n\t${VERSION}$cBWHT WireGuard® Session Manager" ${CHANGELOG}$cRESET  # v2.01

    [ -d ${INSTALL_DIR} ] && Show_MD5 "script"

}
Show_Info() {

    if [ -f /usr/sbin/wg ];then             # v4.12
        local FPATH=$(modprobe --show-depends wireguard | awk '{print $2}')
        local FVERSION=$(strings $FPATH | grep "^version" | cut -d'=' -f2)  # v4.12 @ZebMcKayhan
        if [ "$(which wg)" != "/opt/bin/wg" ];then
            echo -e $cBGRE"\n\t[✔]$cBWHT WireGuard® Kernel module/User Space Tools included in Firmware"$cRED" ($FVERSION)\n"$cRESET    # v4.12
        else
            echo -e $cBGRE"\n\t[ℹ ]$cBGRA WireGuard® Kernel module/User Space Tools included in Firmware"$cBWHT" ($FVERSION)${cBGRA} but 3rd-Party modules installed...\n"$cRESET    # v4.12
        fi
    fi

    [ "$(which wg)" == "/opt/bin/wg" ] && Check_Module_Versions "report"

    echo -e $cRESET
    DNSmasq_Listening_WireGuard_Status

    if [ -f /jffs/scripts/firewall-start ];then
        if [ -z "$(grep -i "wireguard" /jffs/scripts/firewall-start)" ];then     # v1.11
            echo -e $cBRED"\t[✖]${cBWHT} firewall-start$${cBRED} is NOT monitoring WireGuard® Firewall rules - ${cBWHT}use 'firewallstart' to ENABLE\n"$cRESET   # v4.12
        else
            echo -e $cBGRE"\t[✔]${cBWHT} firewall-start ${cBGRE}is monitoring WireGuard® Firewall rules\n"$cRESET
        fi
    else
        echo -e $cBRED"\t[✖]${cBWHT} firewall-start${cBRED} is NOT monitoring WireGuard® Firewall rules - ${cBWHT}use 'firewallstart' to ENABLE\n"$cRESET
    fi

    if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^NOMENU" ${INSTALL_DIR}WireguardVPN.conf)" ];then     # v4.15
        echo -e $cBRED"\t[✖]${cBWHT} NOMENU specified\n"                                                                # v4.15
    fi

    if [ -f ${INSTALL_DIR}WireguardVPN.conf ];then
        if [ -n "$(echo "$(Manage_KILL_Switch)" | grep -F "Y_")" ];then
            local TEMP_PERM="temporarily "                                      # v4.12
            [ -z "$(grep -oE "^#KILLSWITCH" ${INSTALL_DIR}WireguardVPN.conf)" ] && local TEMP_PERM=             # v4.12
            echo -e $cBGRE"\t[✔]$cBWHT WAN ${cBGRE}KILL-Switch is ${TEMP_PERM}ENABLED"$cRESET" (use 'vx' command for info)" # v4.12
        else
            local TEMP_PERM="temporarily "                                      # v4.12
            [ -z "$(grep -oE "^KILLSWITCH" ${INSTALL_DIR}WireguardVPN.conf)" ] && local TEMP_PERM=              # v4.12
            echo -e $cRED"\t[✖]$cBWHT WAN ${cBGRE}KILL-Switch is "${cBRED}${aREVERSE}"${TEMP_PERM}DISABLED"$cRESET" (use 'vx' command for info)"    # v4.12
        fi
    else
        echo -e $cRED"\t[✖]$cBWHT WAN ${cBGRE}KILL-Switch ${cBRED}STATUS N/A (${cRESET}${INSTALL_DIR}WireguardVPN.conf${cBRED} not found?)"$cRESET
    fi

    if [ "$(Manage_UDP_Monitor)" == "Y" ];then                          # v4.01
        echo -e $cBGRE"\t[✔]${cBWHT} UDP ${cBGRE}monitor is ENABLED$cRESET"
    else
        echo -e $cRED"\t[✖]${cBWHT} UDP ${cBGRE}monitor is ${cBRED}DISABLED$cRESET"
    fi

    local FC_STATUS=$(Manage_FC "?")                          # v4.14
    case "$FC_STATUS" in
        *[Ee]nabled*)
            echo -e $cBGRE"\n\t[✔]${cBWHT} Flow Cache ${cBGRE}is ENABLED$cRESET"
        ;;
        *[Dd]isabled*)
            echo -e $cRED"\n\t[✖]${cBWHT} Flow Cache ${cBGRE}is ${cBRED}DISABLED$cRESET"
        ;;
        *)
            echo -e $cBGRE"\n\t[✔]${cBWHT} Flow Cache status ${cBGRE} N/A$cRESET"
        ;;
    esac

    if [ "$(nvram get ipv6_service)" == "disabled" ];then
        echo -e $cBRED"\n\t[✖]${cBWHT} IPv6 Service is ${cBRED}DISABLED$cRESET"
        echo -e $cBGRE"\t[ℹ ] ${cBWHT}$(wget -O - -q http://ip4.me/api | sed 's/,Remain.*$//')"
    else
        echo -e $cBGRE"\n\t[✔]${cBWHT} IPv6 Service is ${cBRED}$(nvram get ipv6_service)"$cRESET    # v4.16
        echo -e $cBGRE"\t[ℹ ] ${cBWHT}$(wget -O - -q http://ip6.me/api | sed 's/,Remain.*$//')"
    fi

    local WAN_IF=$(Get_WAN_IF_Name)                                             # v4.11
    local VAL=$(cat /proc/sys/net/ipv4/conf/$WAN_IF/rp_filter)                  # v4.11
    [ "$VAL" == "1" ] && STATE="ENABLED" || STATE="${cBRED}DISABLED${cBGRE}"    # v4.11
    echo -e $cBGRE"\n\t[ℹ ] ${cBWHT}Reverse Path Filtering${cBGRE} $STATE\n"$cRESET            # v4.11

    if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^NOTCPMSS" ${INSTALL_DIR}WireguardVPN.conf)" ];then   # v4.12 v4.11
        echo -e $cBRED"\t[✖]${cBWHT} 'NOTCPMSS' specified, TCP clamping to PMTU (-t mangle '--tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu')$cBRED DISABLED$cRESET" # v4.12
    fi
    if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^NOSETXMARK" ${INSTALL_DIR}WireguardVPN.conf)" ];then   # v4.12 v4.11
        echo -e $cBRED"\t[✖]${cBWHT} 'NOSETXMARK' specified, (-t mangle  '-j MARK --set-xmark 0x01/0x7')$cBRED  DISABLED" # v4.12
    fi

    # Override IPv6 ?
    if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^NOIP[Vv]6" ${INSTALL_DIR}WireguardVPN.conf)" ];then   # v4.11
        [ "$(nvram get ipv6_service)" != "disabled" ] && echo -e $cBRED"\t[✖]${cBWHT} 'NOIPV6' specified, IPv6 ${cRED} is not allowed  - IPv4 configs ONLY$cRESET" # v4.11
    fi

    # Allow use of 3rd-Party Entware Kernel/Userspace Tools
    if [ -f ${INSTALL_DIR}WireguardVPN.conf ] &&  [ -n "$(grep -oE "USE_ENTWARE_KERNEL_MODULE" ${INSTALL_DIR}WireguardVPN.conf)" ];then
            if [ -f /usr/sbin/wg ];then
                if [ -n "$(grep -oE "^USE_ENTWARE_KERNEL_MODULE" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                    echo -e $cBGRE"\t[✔]Use 3rd-party Entware/Userspace Tools ${cBGRE}modules is ALLOWED\n$cRESET"
                else
                    echo -e $cBRED"\t[✖]${cBWHT} Use 3rd-party Entware/Userspace Tools ${cBGRE}modules is ${cBRED}DENIED\n$cRESET"
                fi
            fi
    fi

    [ $(cru l | grep ChkDDNS | wc -l) -gt 0 ] && echo -e $cBGRE"\t[✔] ${cBWHT}Endpoint DDNS$cBGRE re-fresh monitor ACTIVE\n$cRESET"        # v4.15

    [ $(cru l | grep -E "wireguard_manager.*trimdb" | wc -l) -gt 0 ] && echo -e $cBGRE"\t[✔] ${cBWHT}Cron schedule ${cBGRE}$(cru l | awk '/wireguard_manager.sh trimdb/ {print $9}') ($(cru l | awk '/wireguard_manager.sh trimdb/ {print $1" "$2" "$3" "$4" "$5}'))$cBWHT to trim older than ${cBGRE}$(cru l | awk '/wireguard_manager.sh trimdb/ {print $8}') days$cBWHT from WireGuard® SQL Database ${cBGRE}ENABLED\n"$cRESET

    [ "$READLINE" == "ReadLine" ] && echo -e $cBGRE"\t[✔]$cBWHT Use of 'Pg-Up' Key ${cBGRE}for command retrieval is ENABLED\n$cRESET" || echo -e $cBRED"\t[✖]${cBWHT} Use of 'Pg-Up' Key for command retrieval is ${cBRED}DISABLED\n$cRESET" # v4.14

    Manage_Stats

    echo -e $cBGRE"\n\t[ℹ ] ${cRESET}Speedtest link${cBYEL} https://fast.com/en/gb/ \n"$cRESET              # v4.12

    echo -e $cBGRE"\t[ℹ ] ${cRESET}IPv6 Test link${cBYEL} https://ipv6-test.com/ \n"$cRESET             # v4.16

    echo -e $cBGRE"\t[ℹ ] ${cRESET}WireGuard© Official Site ${cBYEL}https://www.wireguard.com/ \n"$cRESET   # v4.15

    echo -e $cBGRE"\t[ℹ ] ${cRESET}@ZebMcKayhan's$cBGRE Hint's and Tips Guide${cBYEL} https://github.com/ZebMcKayhan/WireguardManager/blob/main/README.md#table-of-content \n"$cRESET   # v4.13


}
exit_message() {

        local CODE=0
        [ -n "$1" ] && local CODE=$1

        rm -rf /tmp/wg.lock

        if [ -n "$1" ] && [ $CODE -eq 0 ];then
            clear
            echo -e $cBWHT"Bye!"
        fi
        echo -e $cRESET
        exit $CODE
}
Install_WireGuard_Manager() {

    local NOPULL_SCRIPTS=$1

    echo -en $cBWHT"\n\tInstalling WireGuard® Manager - Router$cBMAG $HARDWARE_MODEL (v$BUILDNO)"
    [ -f "$ENTWARE_INFO" ] && echo -e " $(grep -E "^arch" $ENTWARE_INFO)\n"$cRESET

    if [ "$(Is_AX)" == "N" ] && [ "$(Is_HND)" == "N" ];then
        echo -e $cBRED"\a\n\t***ERROR: Router$cRESET $HARDWARE_MODEL (v$BUILDNO)$cBRED is not currently compatible with WireGuard®!\n"
        exit 93
    else
        if [ ! -f "$ENTWARE_INFO" ] || [ "$(grep  "^arch" $ENTWARE_INFO | awk -F'=' '{print $2}' )" != "aarch64" ];then     # v4.12 v4.11 Hotfix
            if [ ! -f /usr/sbin/wg ];then
                echo -e $cBRED"\a\n\n\t***ERROR: ${cRESET}3rd-Party Entware${cBRED} version not compatible with ${cRESET}WireGuard®!\n"       # v4.13 v4.11
                exit 94        # v4.12
            fi
        fi
    fi

    echo -en $cBRED

    # Amtm
    # mkdir -p /jffs/addons/wireguard
    if [ -d /opt/etc/ ];then
        # Legacy pre v2.03 install?
        if [ -d /opt/etc/wireguard ];then
            echo -e $cRED"\a\n\tWarning: obsolete WireGuard® Session Manager v1.xx config directory Found!!! (${cBWHT}'/opt/etc/wireguard'{$cBRED})\n"$cRESET
            SayT "Warning obsolete WireGuard® Session Manager config directory Found!!! ('/opt/etc/wireguard')"
        fi
        [ ! -d ${CONFIG_DIR} ] && mkdir -p ${CONFIG_DIR}
    else
        echo -e $cBRED"\a\n\t***ERROR: Entware directory '${cRESET}/opt/etc/${cBRED}' not found? - Please install ${cRESET}Entware${cBRED} (${cRESET}amtm Diversion${cBRED})\n"$cRESET
        exit 95
    fi

    # Scripts
    if [ "$NOPULL_SCRIPTS" != "noscripts" ];then
        if [ -d "${INSTALL_DIR}" ];then
            Get_scripts "$2"
            Manage_Addon "wgmExpo.sh"       # v4.15 @ZeMcKayhan's Addon
            echo -e
        fi
    else
        echo -e $cBRED"\tBypass GitHub script retrieval ('noscripts')\n"$cRESET
    fi

    echo -en $cBGRA
    modprobe xt_comment
    opkg install column                     # v2.02
    opkg install coreutils-mkfifo
    opkg install p7zip                      # v4.15

    # Kernel module in firmware?
    if [ "$(which wg)" == "/usr/sbin/wg" ];then # v4.12
        ROUTER_COMPATIBLE="Y"                   # v4.13
    else
        # SEe if 3rd-Party Entware Kernel module exists
        echo -e $cBCYA"\tDownloading Wireguard® Kernel module for $HARDWARE_MODEL (v$BUILDNO)"$cRESET

        ROUTER_COMPATIBLE="Y"

        Download_Modules $HARDWARE_MODEL

        Load_UserspaceTool
    fi

    # Create the Sample/template parameter file '${INSTALL_DIR}WireguardVPN.conf'
    Create_Sample_Config

    Manage_alias

    if [ ! -f $SQL_DATABASE ];then                      # v4.14 v4.12 v3.04

        Initialise_SQL

        # Create 'Server' Peer
        echo -e $cBCYA"\tCreating WireGuard® 'Server' Peer ${cBMAG}(wg21)${cBCYA}'"$cRESET

        # Create Server template
        local PEER_LIST="1"

        echo -e $cBCYA"\tCreating WireGuard® Private/Public key-pairs for ${cBMAG}$HARDWARE_MODEL (v$BUILDNO)"$cRESET
        if [ -n "$(which wg)" ];then

                # do
                    # wg genkey | tee ${CONFIG_DIR}wg1${I}_private.key | wg pubkey > ${CONFIG_DIR}wg1${I}_public.key
                # done
            for I in $PEER_LIST
                do
                    wg genkey | tee ${CONFIG_DIR}wg2${I}_private.key | wg pubkey > ${CONFIG_DIR}wg2${I}_public.key

                    PRIV_KEY=$(cat ${CONFIG_DIR}wg2${I}_private.key)
                    PRIV_KEY=$(Convert_Key "$PRIV_KEY")

                    local WG_INTERFACE="wg2"${I}
                    local AUTO="Y"
                    local SUBNET="10.50.1.1/24"
                    local PORT=51820
                    local ANNOTATE="# $HARDWARE_MODEL Server #1"
                    local PUB_KEY=$(cat ${CONFIG_DIR}${WG_INTERFACE}_public.key)
                    local PRI_KEY=$(cat ${CONFIG_DIR}${WG_INTERFACE}_private.key)

                    cat > ${CONFIG_DIR}wg2${I}.conf << EOF
# $HARDWARE_MODEL 'server' Peer #1 (wg2$I)
[Interface]
PrivateKey = $PRIV_KEY
#Address = $SUBNET
ListenPort = 51820

EOF
# e.g. Accept a WireGuard connection from say YOUR mobile device to the router

# DeviceExample
#[Peer]
#PublicKey = This_should_be_replaced_with_the_Public_Key_of_YOUR_mobile_device
#AllowedIPs = 0.0.0.0/0 # All Access or [192.168.1.0/24,10.8.0.21/32] i.e. List of IP/Subnet/networks YOUR mobile device may access.
# DeviceExample End

                    chmod 600 ${CONFIG_DIR}wg2${I}.conf         # v4.15 Prevent wg-quick "Warning: '/opt/etc/wireguard.d/wg21.conf' is world accessible"
                    sqlite3 $SQL_DATABASE "INSERT INTO servers values('$WG_INTERFACE','$AUTO','$SUBNET','$PORT','$PUB_KEY','$PRIV_KEY','$ANNOTATE');"
                done
        fi

        if  [ -n "$(which wg)" ] && [ "$ROUTER_COMPATIBLE" == "Y" ];then

            # Test 'wg' and this script - (well actually the one used @BOOT) against the 'server' Peers e.g. wg21
            echo -e $cBCYA"\tInitialising WireGuard® VPN 'server' Peer"$cRESET
            Manage_Wireguard_Sessions "start" "wg21"
        else
            echo -e $cBRED"\a\n\t***ERROR: WireGuard® install FAILED!\n"$cRESET
            exit 96
        fi
    else
        echo -e $cBCYA"\tExisting WireGuard.db exists; Reusing existing Peer definitions"$cRESET    # v4.14
        Initialise_SQL "keep"
        Manage_Wireguard_Sessions "start"                                                           # v4.14
    fi

    Manage_Stats "init" "enable"

    Edit_firewall_start                                 # v1.07

    Edit_DNSMasq                                        # v1.12

    Manage_Event_Scripts                                # v4.01 @ZebMcKayhan

    # Auto start ALL defined WireGuard Peers @BOOT
    # Use post-mount
    echo -e $cBCYA"\tAdding Peer Auto-start @BOOT"$cRESET
    if [ -z "$(grep -i "WireGuard" /jffs/scripts/post-mount)" ];then
        echo -e "/jffs/addons/wireguard/wg_manager.sh init \"$@\" & # WireGuard Manager" >> /jffs/scripts/post-mount
    fi

    echo -e $cBCYA"\tInstalling QR rendering module"$cBGRA
    opkg install qrencode

    if [ -z "$(which tee)" ] || [ "$(which tee)" == "/opt/bin/tee" ];then
        echo -e $cBCYA"\tInstalling tee module"$cBGRA
        opkg install coreutils-tee      # v4.12
    fi

    if [ -z "$(which dos2unix)" ] || [ "$(which dos2unix)" == "/opt/bin/dos2unix" ];then
        echo -e $cBCYA"\tInstalling dos2unix module"$cBGRA
        opkg install dos2unix           # v4.12
    fi

    if [ -z "$(which xargs)" ] || [ "$(which xargs)" == "/opt/bin/xargs" ];then
        echo -e $cBCYA"\tInstalling xargs module"$cBGRA
        opkg install findutils          # v4.12
    fi

    if [ ! -f /opt/bin/sqlite3 ];then   # Support SQL schema directive
        echo -e $cBCYA"\tInstalling sqlite3 module"$cBGRA
        opkg install sqlite3-cli        # v4.14
    fi

    # Create a sample Road-Warrior device and QR code for import into WireGuard App on the say an iPhone
    echo -e $cBWHT"\tDo you want to create a 'device' Peer for 'server' Peer (${cBMAG}wg21${cBWHT}) ?\n\t${cBWHT}Press ${cBGRE}y$cRESET to ${cBWHT}create 'device' Peer ${cRESET}or press$cBGRE [Enter] to skip"
    read -r "ANS"
    if [ "$ANS" == "y" ];then
        echo -e $cBWHT"Enter the device name e.g. ${cBGRE}iPhone"$cBWHT
        read -r "ANS"
        if [ -n "$ANS" ];then
            Create_RoadWarrior_Device "create" "$ANS"         # v4.01 v3.01
        fi
    else
        echo -e $cBCYA"\tWireGuard® Peer Status"
        Show_Peer_Status
    fi

    echo -e $cBGRE"\n\t${aREVERSE}$VERSION WireGuard® Session Manager install COMPLETED.\n"$cRESET

}
Uninstall_WireGuard() {

    echo -e $cBCYA"\n\tUninstalling WireGuard® Session Manager"$cRESET
    [ -n "$(wg show interfaces)" ] && Manage_Wireguard_Sessions "stop"      # v4.14
    echo -en $cBRED
    [ -f ${INSTALL_DIR}WireguardVPN.conf ] && rm ${INSTALL_DIR}WireguardVPN.conf
        # legacy tidy-up!
        [ -f ${CONFIG_DIR}WireguardVPN_map ] && rm ${CONFIG_DIR}WireguardVPN_map

    # Only remove WireGuard Entware packages if user DELETES '/opt/etc/wireguard'
    echo -e "\n\tPress$cBRED Y$cRESET to$cBRED delete ALL WireGuard® DATA files (Peer *.config etc.) $cRESET('${CONFIG_DIR}') or press$cBGRE [Enter] to keep custom WireGuard DATA files."
    read -r "ANS"
    if [ "$ANS" == "Y" ];then
       echo -e $cBCYA"\n\tDeleting $cRESET'${CONFIG_DIR}'"
       [ -d "${CONFIG_DIR}" ] && rm -rf ${CONFIG_DIR}

       echo -e $cBCYA"\tUninstalling Wireguard® Kernel module and Userspace Tool for $HARDWARE_MODEL (v$BUILDNO)"$cBGRA
       opkg remove wireguard-kernel wireguard-tools
       rm -rf /opt/etc/wireguard/
    else
        Manage_Event_Scripts "backup"                           # v4.01
        [ -f ${INSTALL_DIR}WireguardVPN.conf ] && mv ${INSTALL_DIR}WireguardVPN.conf ${CONFIG_DIR}
    fi

    Manage_Addon "wgmExpo.sh" "del"     # v4.15 @ZeMcKayhan's Addon

    rm -rf ${INSTALL_DIR}

    echo -e $cBCYA"\tDeleted Peer Auto-start @BOOT\n"$cRESET
    [ -n "$(grep -i "WireGuard" /jffs/scripts/post-mount)" ] && sed -i '/WireGuard/d' /jffs/scripts/post-mount  # v2.01

    cru d "WireGuard"

    Manage_Stats "DISABLE" "disable"

    if [ -f /jffs/scripts/nat-start ];then
        [ -n "$(grep -o "WireGuard" /jffs/scripts/nat-start)" ] && sed -i '/WireGuard/d' /jffs/scripts/nat-start    # v4.11 Legacy use of nat-start
    fi
    Edit_firewall_start "del"

    Manage_alias "del"                  # v1.11

    Edit_DNSMasq "del"                  # v1.12

    Unmount_WebUI $SCRIPT_NAME".asp"    # v4.15

    echo -e $cBGRE"\n\tWireGuard® Uninstall complete for $HARDWARE_MODEL (v$BUILDNO)\n"$cRESET

    exit 0
}
Session_Duration() {

    local WG_INTERFACE=$1

    local LAST_START=$(sqlite3 $SQL_DATABASE "SELECT timestamp FROM session WHERE (peer='$WG_INTERFACE' AND state='Start') order by timestamp desc limit 1;")
    local LAST_END=$(sqlite3 $SQL_DATABASE "SELECT timestamp FROM session WHERE (peer='$WG_INTERFACE' AND state='End') order by timestamp desc limit 1;")

    local MODE=$(Server_or_Client "$WG_INTERFACE")

    case "$WG_INTERFACE" in
        wgc*|wgs*)
            echo -e "${cBRED}***Session statistics (Duration/data transferred) N/A ***"$cRESET
            ;;
        *)
            if [ "$MODE" == "device" ];then
                LAST_START=$(sqlite3 $SQL_DATABASE "SELECT conntrack FROM devices WHERE name='$WG_INTERFACE';")
                BEGINTAG=${cBGRE}$(EpochTime "$LAST_START" "FULL")
                LAST_END=$(date +%s)
            else

                if [ -n "$LAST_START" ];then
                    if [ -n "$LAST_END" ];then
                        if [ $LAST_START -lt $LAST_END ];then
                            BEGINTAG=${cBGRE}$(EpochTime "$LAST_START" "FULL")
                        else
                            BEGINTAG=${cBGRE}$(EpochTime "$LAST_START" "FULL")
                            LAST_END=
                        fi
                    fi
                fi

                if [ -z "$LAST_END" ];then
                    [ -n "$(wg show "$WG_INTERFACE" 2>/dev/null)" ] && local LAST_END=$(date +%s) || local LAST_START=$LAST_END
                    local ENDTAG=${cRESET}" >>>>>>"
                else
                    [ "$CRON_PERIOD" != "Y" ] && local ENDTAG=${RESET}" to $c{BRED}"$(EpochTime "$LAST_END" "FULL") # v4.16
                fi
            fi

            if [ -z "${LAST_START##[0-9]*}" ] && [ -z "${LAST_END##[0-9]*}" ];then
                local DURATION=$((LAST_END-LAST_START))
                echo -e $(Convert_SECS_to_HHMMSS "$DURATION" "Days")" since "${BEGINTAG}${ENDTAG}
            else
                echo -e "<$(EpochTime "$LAST_START" "Human")> to <$(EpochTime "$LAST_START" "Human")>"
            fi
            ;;
    esac

    return 0
}
Show_Peer_Status() {

    local DETAIL=
    local WG_INTERFACE=
    local MINS=0

    while [ $# -gt 0 ]; do          # v3.02
        case "$1" in
        detail*|full*)
            DETAIL="FULL"
            ;;
        generatestats)
            local STATS="Y"
            ;;
        list*|show*)
            ;;
        ToFile)
            local STATS_FILE="/tmp/metrics.wg"          # v4.15
            ;;
        *)
            WG_INTERFACE=$WG_INTERFACE" "$1
            ;;
        esac
        shift
    done

    #[ -z "$WG_INTERFACE" ] && WG_INTERFACE=$(wg show interfaces | sed s'/wgc[1-5] //g' | sed s'/wgs[1-5] //g')      # v4.12 ACTIVE Peers excluding firmware managed peers e.g. wgs1 or wgc5
    [ -z "$WG_INTERFACE" ] && WG_INTERFACE=$(wg show interfaces)
    for WG_INTERFACE in $WG_INTERFACE           # v3.02
        do
            [ -f "/tmp/WireGuard.txt" ] && rm /tmp/WireGuard.txt

            wg show $WG_INTERFACE >> /tmp/WireGuard.txt

            #echo -e
            if [ -f /tmp/WireGuard.txt ] && [ $(wc -l < /tmp/WireGuard.txt) -ne 0 ];then

                while IFS='' read -r LINE || [ -n "$LINE" ]; do

                    if [ "${LINE:0:1}" == "#" ];then
                        local menu1="$(echo "$LINE" | sed 's/#//')"
                        continue
                    fi

                    local COLOR=$cBCYA

                    if [ -n "$(echo "$LINE" | grep -E "latest handshake:")" ];then

                        # If latest Hand-shake more than 30 mins ago, then assume dormant connection?
                        #   latest handshake: 1 hour, 18 minutes, 8 seconds ago
                        if [ -n "$(echo "$LINE" | grep -E "minutes|hour")" ];then
                            local MINS=$(echo "$LINE" | sed 's/ minutes.*$//')
                            [ -z "$(echo "$LINE" | grep -E "hour")" ] && local MINS=${MINS##* } || MINS=999

                            [ $MINS -gt 30 ] && COLOR=$cBGRA
                        fi
                    fi

                    # interface: wg1? or wg2?
                    if [ -n "$(echo "$LINE" | grep -E "interface:")" ];then
                        echo -e
                        local TAB="\t"
                        local COLOR=$cBMAG
                        local MINS=0
                        local WG_INTERFACE=$(echo $LINE | awk '{print $2}')

                        local VPN_ADDR=                                 # v3.01
                        local VPN_IP_TXT=
                        local MODE=$(Server_or_Client "$WG_INTERFACE")
                        if [ "$MODE" == "server" ];then
                            local TYPE="server"
                            local TABLE="servers"
                            local VPN_ADDR=$(ip addr | grep $WG_INTERFACE | awk '/inet/ {print $2}')

                            [ "${WG_INTERFACE:0:3}" != "wgs" ] && local LISTEN_PORT=$(awk '/^ListenPort/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf) || local LISTEN_PORT=$(nvram get ${WG_INTERFACE}_port)

                            local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM $TABLE WHERE peer='$WG_INTERFACE';")
                            local DESC=$(printf "%s" "$DESC" | sed 's/^[ \t]*//;s/[ \t]*$//')
                            local TABS="\t\t\t"                                                                                                     # v4.15
                            if [ "$(sqlite3 $SQL_DATABASE "SELECT auto FROM servers WHERE peer='$WG_INTERFACE';")" != "S" ];then
                                local TABS="\t\t\t" # v4.15
                                local VPN_IP_TXT="Port:${LISTEN_PORT}\t${VPN_ADDR} ${cBYEL}${TABS}VPN Tunnel Network"
                            else
                                local SOCKET=$(wg show $WG_INTERFACE endpoints | awk '{print $2}')
                                [ -n "$SOCKET" ] && TABS="\t" || TABS="\t\t\t\t"
                                local VPN_IP_TXT="Port:${LISTEN_PORT} Endpoint=${SOCKET} ${cBYEL}${TABS}VPN Tunnel Network"
                            fi

                            [ "$WG_INTERFACE" == "wgs1" ] && DESC="${cBRED}***ASUS Internal GUI 'server' Peer***"
                        else
                            if [ "$MODE" == "client" ];then
                                local TYPE="client"
                                local TABLE="clients"
                            else
                                local TYPE="device"         # v4.15
                                local TABLE="devices"
                            fi

                            # Tag it on screen if this is the default route
                            local DEFAULT_ROUTE=$(ip route | grep -Em 1 "^0.0.|128.0" | awk '{print $3}')       # v4.07
                            [ "$DEFAULT_ROUTE" == "$WG_INTERFACE" ] && DEF="$aREVERSE" || DEF=                  # v4.14

                            local LOCALIP=$(sqlite3 $SQL_DATABASE "SELECT subnet FROM $TABLE WHERE peer='$WG_INTERFACE';")

                            #local LOCALIPS=$(sqlite3 $SQL_DATABASE "SELECT subnet FROM $TABLE WHERE peer='$WG_INTERFACE';" | tr ',' ' ')   # v4.14
                            # for LOCALIP in $LOCALIPS
                                # do
                                    # if [ "$USE_IPV6" == "Y" ] && [ -n "$(echo "$LOCALIP" | grep -F ":")" ];then   # v4.14
                                        # continue
                                        # SayT "Warning: IPv6 'client' Peer '$LOCALIP' ('$WG_INTERFACE') skipped as IPv6 not ENABLED"
                                    # else
                                        # if [ -n "$(echo "$LOCALIP" | Is_IPv4_CIDR)" ] || [ -n "$(echo "$LOCALIP" | Is_IPv4)" ];then
                                            # break
                                        # else
                                            # echo -e $cBRED"\a\n\t***ERROR: Invalid IPv4 local address for 'client' Peer '$LOCALIP'"
                                        # fi
                                    # fi
                                # done

                            case "$WG_INTERFACE" in
                                wgc*|wgs*)
                                    local DESC="${cBRED}***ASUS Internal GUI 'client' Peer***"$cRESET
                                    ;;
                                *)
                                    local SOCKET=$(wg show $WG_INTERFACE endpoints | awk '{print $2}')          # 4.14

                                    local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM $TABLE WHERE peer='$WG_INTERFACE';")
                                ;;
                            esac

                            local DESC=$(printf "%s" "$DESC" | sed 's/^[ \t]*//;s/[ \t]*$//')

                            # Cosmetic IPv4 three tabs; IPv6 two tabs
                            [ -n "$(echo "$SOCKET" | grep -F ".")" ] && local TABS="\t\t\t" || TABS="\t\t"

                            local VPN_IP_TXT=${cBGRA}"EndPoint="${cRESET}${SOCKET}"${TABS}${cBYEL}${LOCALIP}\t"

                        fi

                        local LINE=${DEF}${COLOR}${LINE}${cRESET}" ${cBMAG}   ${cBWHT}${VPN_IP_TXT}\t${cBMAG}${DESC}"$cRESET  # v 4.14 v3.05 v3.01
                    else
                        local TAB="\t\t"
                        if [ -n "$(echo "$LINE" | grep -E "transfer:")" ];then

                            #   transfer: 3.79 KiB received, 4.54 KiB sent
                            # Current Hand-shake dormant?
                            [ $MINS -gt 30 ] && COLOR=$cBGRA || COLOR=$cBWHT

                            if [ "$STATS" == "Y" ];then
                                local RX=
                                local RXU=
                                local TX=
                                local TXU=
                                Parse "$LINE" " " junk RX RXU junk TX TXU junk
                                RX=$(Convert_1024KMG "$RX" "$RXU")
                                TX=$(Convert_1024KMG "$TX" "$TXU")

                                # Need to get the last logged RX/TX Total values for the Peer, and only add to SQL if total > 0
                                Parse "$(sqlite3 $SQL_DATABASE "SELECT rxtotal,txtotal FROM traffic WHERE peer='$WG_INTERFACE' order by timestamp desc limit 1;")" "|" RX_OLD TX_OLD    # v4.11

                                if [ "$RX_OLD" != "*" ] && [ -n "$RX" ] && [ -n "$RX_OLD" ];then
                                    local RX_DELTA=$RX
                                    local TX_DELTA=$TX
                                    local INIT_TRAFFIC="Y"                          # v4.15
                                fi

                                if [ -n "$RX_OLD" ] && [ -n "$TX_OLD" ];then
                                    #local RX_DELTA=$((RX-RX_OLD))
                                    #local TX_DELTA=$((TX-TX_OLD))
                                    # Old-skool - slower but doesn't create negative result
                                    #   WTF!!! echo $((1191071409+2037987240))
                                    if [ "$RX_OLD" != "*" ] && [ -n "$RX" ] && [ -n "$RX_OLD" ];then    # v4.11 @Torson
                                        local RX_DELTA=$(expr "$RX" - "$RX_OLD")    # v4.11 @ZebMcKayhan
                                    else
                                        local RX_DELTA=0
                                    fi
                                    if [ "$TX_OLD" != "*" ] && [ -n "$TX" ] && [ -n "$RX_OLD" ];then    # v4.11 @Torson
                                        local TX_DELTA=$(expr "$TX" - "$TX_OLD")    # v4.11 @ZebMcKayhan
                                    else
                                        local TX_DELTA=0
                                    fi
                                else
                                    local RX_DELTA=$RX
                                    local TX_DELTA=$TX
                                fi
                                #if [ $((RX_DELTA+TX_DELTA)) -gt 0 ];then
                                [ -z "$RX_DELTA" ] && local RX_DELTA=0          # v4.12 @Dreaz
                                [ -z "$TX_DELTA" ] && local TX_DELTA=0          # v4.12 @Dreaz

                                if [ "$INIT_TRAFFIC" == "Y" ] || [ $(expr "$RX_DELTA" + "$TX_DELTA") -gt 0 ];then # v4.15 @JGrana v4.11 @ZebMcKayhan
                                    local TIMESTAMP=$(date +%s)
                                    sqlite3 $SQL_DATABASE "INSERT into traffic values('$WG_INTERFACE','$TIMESTAMP','$RX_DELTA','$TX_DELTA','$RX','$TX');"       # 4.11 v3.05
                                fi

                                local INIT_TRAFFIC="N"                          # v4.15
                            fi
                            local TABS="\t\t"
                            [ "${#LINE}" -lt 40 ] && local TABS="\t\t\t"

                            LINE=${COLOR}${LINE}"${TABS}${COLOR}$(Session_Duration "$WG_INTERFACE")"
                        fi
                    fi

                    if [ -n "$(echo "$LINE" | grep -iE "peer:" )" ];then

                        if [ "$TYPE" == "server" ];then
                            local PUB_KEY=$(echo "$LINE" | awk '{print $2}')
                            local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM devices WHERE pubkey='$PUB_KEY';")
                            if [ -z "$DESC" ];then
                                # Site2Site maybe?                          # v4.14
                                local MATCH_PEER=$(grep -F "$PUB_KEY" ${CONFIG_DIR}*_public.key | awk -F '[\/:\._]' '{print $6}')
                                if [ -z "$MATCH_PEER" ];then
                                    local DESC="# Unidentified"
                                else
                                    local DESC=$(grep -FB1 "[Interface]" ${CONFIG_DIR}${MATCH_PEER}.conf | grep -vF "[Interface]")  # v4.14
                                    [ -z "$DESC" ] && DESC="# "$DESC
                                fi
                            fi

                            WG_INTERFACE=$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE pubkey='$PUB_KEY';")

                            [ -z "$WG_INTERFACE" ] && WG_INTERFACE=$(grep -F "$PUB_KEY" ${CONFIG_DIR}*_public.key | awk -F '[\/:\._]' '{print $6}')

                            [ -n "$WG_INTERFACE" ] && local VPN_ADDR=$(awk '/^Address/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf ) || local DESC=${cBRED}$DESC" owner of this Public key:"

                            local LINE=${COLOR}$LINE" \t${cBWHT}${VPN_ADDR}\t\t${cBMAG}${DESC}\t"
                        fi
                    fi

                    if [ -z "$DETAIL" ];then
                        # For dormant (after 30 mins) Road-Warrior 'clients', don't display obvious redundant RX=0/TX=0 metrics
                        if [ $MINS -lt 30 ];then        # v4.11
                            if [ "$STATS" == "Y" ];then     # v4.11
                                if [ -n "$(echo "$LINE" | grep -E "transfer:")" ];then
                                    if [ "$CRON_PERIOD" != "Y" ];then                   # v4.16
                                        SayT ${WG_INTERFACE}":"${LINE}"$cBRED "$(EpochTime "$(date +%s)" "FULL")" "${cRESET}
                                        SayT ${WG_INTERFACE}": period : $(Size_Human $RX_DELTA) received, $(Size_Human $TX_DELTA) sent (Rx=$RX_DELTA;Tx=$TX_DELTA)"
                                        [ -z "$STATS_FILE" ] && echo -e "\t\t"${WG_INTERFACE}":"${LINE}$cRESET || echo -e "\t\t$cRESET"${WG_INTERFACE}":"${LINE}$cBRED" "$(EpochTime "$(date +%s)" "FULL")$cRESET > $STATS_FILE
                                    else
                                        local LINE="$(echo "$LINE" | sed 's/\\t\\t/; /')"
                                        SayT ${WG_INTERFACE}":"${LINE}${cRESET}        # v4.16
                                        SayT ${WG_INTERFACE}": period : $(Size_Human $RX_DELTA) received, $(Size_Human $TX_DELTA) sent (Rx=$RX_DELTA;Tx=$TX_DELTA)"
                                        [ -z "$STATS_FILE" ] && echo -e "\t\t"${WG_INTERFACE}":"${LINE}$cRESET || echo -e "\t\t$cRESET"${WG_INTERFACE}":"${LINE}$cBRED$cRESET > $STATS_FILE
                                    fi
                                    [ -z "$STATS_FILE" ] && echo -e "\t\t"${WG_INTERFACE}": period : $(Size_Human $RX_DELTA) received, $(Size_Human $TX_DELTA) sent (Rx=$RX_DELTA;Tx=$TX_DELTA)"$cBCYA  || echo -e "\t\t$cRESET"${WG_INTERFACE}": period : $(Size_Human $RX_DELTA) received, $(Size_Human $TX_DELTA) sent (Rx=$RX_DELTA;Tx=$TX_DELTA)"$cBCYA >> $STATS_FILE
                                fi
                            else
                                [ -n "$(echo "$LINE" | grep -E "interface:|peer:|transfer:|latest handshake:")" ] && echo -e ${TAB}${COLOR}$LINE
                            fi
                        fi
                    else
                        echo -e ${TAB}${COLOR}$LINE
                    fi

                    DEFAULT_ROUTE=;DEF=

                done < /tmp/WireGuard.txt

                rm /tmp/WireGuard.txt
            else
                SayT "No WireGuard Peers active"
                echo -e "\tNo WireGuard Peers active\n" 2>&1
            fi
        done
}
Show_Peer_Config_Entry() {

    local WG_INTERFACE=$1

    case ${WG_INTERFACE:0:3} in

        "")
            echo -e $cBWHT"\n\tPeers (Auto start: Auto=P - Policy, Auto=S - Site-to-Site)"$cBCYA

            COLUMN_TXT="Server,Auto,Subnet,Port,Annotate"
            sqlite3 $SQL_DATABASE "SELECT peer,auto,subnet,port,tag from servers ORDER BY peer ASC;" | column -t  -s '|' --table-columns "$COLUMN_TXT"
            echo -e
            COLUMN_TXT="Client,Auto,IP,Endpoint,DNS,MTU,Annotate"           # v4.09
            sqlite3 $SQL_DATABASE "SELECT peer,auto,subnet,socket,dns,mtu,tag from clients ORDER BY peer ASC;" | column -t  -s '|' --table-columns "$COLUMN_TXT"
            echo -e $cBWHT"\n\tPeers (Auto=X - External i.e. Cell/Mobile/Site)"$cBCYA
            COLUMN_TXT="Device,Auto,IP,DNS,Allowed IPs,Annotate"            # v4.09
            sqlite3 $SQL_DATABASE "SELECT name,auto,ip,dns,allowedip,tag from devices ORDER BY ip ASC;" | column -t  -s '|' --table-columns "$COLUMN_TXT"   # v4.11

            [ -n "$(sqlite3 $SQL_DATABASE "SELECT * from passthru;" 2>/dev/null)" ] && { echo -e; sqlite3 $SQL_DATABASE "SELECT * from passthru;" | column -t  -s '|' --table-columns Server,Client,Passthru ; }    # v4.12
        ;;
        *)
            local Mode=$(Server_or_Client "$WG_INTERFACE")

            [ "$Mode" == "**ERROR**" ] && { echo -e $cBRED"\n\a\t***ERROR Invalid WireGuard® Peer '$WG_INTERFACE'";return;  }    # v4.14

            case "$Mode" in
                server)
                    local TABLE="servers"; local ID="peer"; local SQL_COL="server"
                    local COLUMN_TXT="Server,Auto,Subnet,Port,Annotate"         # v4.16
                    local COLS="peer,auto,subnet,port,tag"                      # v4.16
                    ;;
                client)
                    local TABLE="clients"; local ID="peer"; local SQL_COL="client"
                    local COLUMN_TXT="Client,Auto,IP,Endpoint,DNS,MTU,Annotate" # v4.16 v4.09 v4.04
                    local COLS="peer,auto,subnet,socket,dns,mtu,tag"            # v4.16
                    ;;
                *)
                    local TABLE="devices"; local ID="name"
                    local COLUMN_TXT="Device,Auto,IP,DNS,Allowed IPs,Annotate,Conntrack"    # v4.16 v4.09
                    local COLS="name,auto,ip,dns,allowedip,tag,conntrack"                   # v4.16
                    ;;
            esac

            local AUTO="$(sqlite3 $SQL_DATABASE "SELECT auto FROM $TABLE WHERE $ID='$WG_INTERFACE';")"  # v4.11

            echo -e
            sqlite3 $SQL_DATABASE "SELECT $COLS from $TABLE WHERE $ID='$WG_INTERFACE';" | column -t  -s '|' --table-columns "$COLUMN_TXT"   # v4.16

            if [ "$ID" == "peer" ];then                                                        # v4.09
                if [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$WG_INTERFACE';")" -gt 0 ] || [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(client) FROM passthru WHERE client='$WG_INTERFACE';")" -gt 0 ];then
                   if [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$WG_INTERFACE';")" -gt 0 ];then
                        echo -e $cBCYA"\n\tSelective Routing RPDB rules"
                        sqlite3 $SQL_DATABASE "SELECT rowid,peer,iface,srcip,dstip,tag FROM policy WHERE peer='$WG_INTERFACE' ORDER BY iface DESC;" |column -t  -s '|' --table-columns ID,Peer,Interface,Source,Destination,Description # v4.08
                   fi
                else
                    if [ "$Mode" == "client" ];then
                        [ "$AUTO" != "P" ] && local COLOR=$cBGRA || local COLOR=$cRED                    # v4.12 v4.11
                        echo -e $COLOR"\n\tNo RPDB Selective Routing/Passthru rules for 'client' Peer ${cBMAG}${WG_INTERFACE}\n"$cRESET  # v4.11
                    fi
                fi
                echo -e
                if [ "$(sqlite3 $SQL_DATABASE "SELECT * FROM ipset WHERE peer='$WG_INTERFACE';")" ] ;then
                    sqlite3 $SQL_DATABASE "SELECT * FROM ipset WHERE peer='$WG_INTERFACE';" | column -t  -s '|' --table-columns IPSet,Enable,Peer,FWMark,DST/SRC
                fi
            fi

            case "$Mode" in                                         # v4.12
                server|client)
                    [ -n "$(sqlite3 $SQL_DATABASE "SELECT * FROM passthru WHERE $SQL_COL='$WG_INTERFACE';" 2>/dev/null)" ] && { echo -e $cBCYA; sqlite3 $SQL_DATABASE "SELECT * from passthru WHERE $SQL_COL='$WG_INTERFACE';" | column -t  -s '|' --table-columns Server,Client,Passthru ; }   # v4.12
                    ;;
                *)
                    [ -n "$(sqlite3 $SQL_DATABASE "SELECT * FROM passthru WHERE ip_subnet LIKE '$WG_INTERFACE';" 2>/dev/null)" ] && { echo -e $cBCYA; sqlite3 $SQL_DATABASE "SELECT * from passthru WHERE ip_subnet LIKE '$WG_INTERFACE';" | column -t  -s '|' --table-columns Server,Client,Passthru ; }   # v4.12
                    ;;
            esac

            if [ -n "$(grep -E "^#Pre|^#Post" ${CONFIG_DIR}${WG_INTERFACE}.conf )" ];then           # v4.14
                echo -e $COLOR"\n\tConfiguration rules for Peer ${cBMAG}${WG_INTERFACE}\n"$cRESET   # v4.14
                grep -E "^#Pre|#Post" ${CONFIG_DIR}${WG_INTERFACE}.conf | sed 's/^#//'              # v4.14
                echo -e
            fi

        ;;
    esac

    echo -en $cRESET
}
Show_VPN_Pool() {

    #local SERVERS=$(awk '/^wg2/ {print $1}' ${INSTALL_DIR}WireguardVPN.conf | tr '\n' ' ')                  # v3.03
    local SERVERS=$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers;" | tr '\n' ' ')
    for WG_INTERFACE in $SERVERS
        do
            #local VPN_POOL_CIDR=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $3}' ${INSTALL_DIR}WireguardVPN.conf)
            local VPN_POOL_CIDR=$(sqlite3 $SQL_DATABASE "SELECT subnet FROM servers WHERE peer='$WG_INTERFACE';")
            local VPN_POOL_PREFIX=${VPN_POOL_CIDR%.*}
            echo -e $cBYEL"\n\t\t${cBMAG}$WG_INTERFACE IP Pool allocation\t\t  ${cBWHT}$VPN_POOL_CIDR"$cBCYA
            if [ -n "$(echo "$VPN_POOL_CIDR" | Is_IPv4_CIDR)" ];then
                sqlite3 $SQL_DATABASE "SELECT name, ip FROM devices WHERE ip LIKE '$VPN_POOL_PREFIX%';" | column -t  -s '|' --table-columns 'Device Name','IP address'
            else
                echo -e $cBRED"\a\n\t***ERROR: Invalid IPv4 CIDR '$VPN_POOL_CIDR'"
            fi
        done



}
Diag_Dump() {

    local IPV6ONLY="N"
    [ "$1" == "noipv4" ] && { local IPV6ONLY="Y"; shift; }

    local TYPE=$1
    [ "$TYPE" == "diag" ] && TYPE=
    local TABLE=$2;shift 2
    local REST=$@

    if [ -z "$TYPE" ] || [ "$TYPE" == "route" ] || [ "$TYPE" == "rpdb" ];then

        echo -e $cBYEL"\n\tWireGuard® VPN Peers"$cRESET
        Show_Peer_Config_Entry

        [ "$IPV6ONLY" == "N" ] && Diag_Routes "4"
        [ "$(nvram get ipv6_service)" != "disabled" ] && Diag_Routes "6"

        [ "$IPV6ONLY" == "N" ] && Diag_Rules "4"
        [ "$(nvram get ipv6_service)" != "disabled" ] && Diag_Rules "6"


        echo -e $cBYEL"\n\tDEBUG: Netstat\n"$cRESET
        netstat -rn | grep -E "wg.|Kernel|irtt"
        [ "$(nvram get ipv6_service)" != "disabled" ] && netstat -arn | grep -F ":"

        if [ -z "$TYPE" ] || [ "$TYPE" == "udp" ] || [ "$TYPE" == "sockets" ];then
            echo -e $cBYEL"\n\tDEBUG: UDP sockets.\n"$cBCYA 2>&1
            netstat -lnp | grep -e "^udp\s.*\s-$"
        fi
    fi


    if [ -z "$TYPE" ] || [ "$TYPE" == "firewall" ];then
        [ "$IPV6ONLY" == "N" ] && Diag_IPTables "4"
        [ "$(nvram get ipv6_service)" != "disabled" ] && Diag_IPTables "6"
    fi

    if [ -z "$TYPE" ] || [ "$TYPE" == "sql" ];then
        echo -e $cBWHT"\n\nUse command 'diag sql [ table_name ]' to see the SQL data (might be many lines!)\n"
        echo -e $cBWHT"       Valid SQL Database tables: "$cBCYA 2>&1

        # Requires opkg list sqlite3-cli
        if [ "$(sqlite3 -version | awk 'BEGIN { FS = "." } {printf("%03d%02d",$1,$2)}')" -gt 325 ];then     # v4.14
            sqlite3 $SQL_DATABASE "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%';" | while read -r THIS; do
                    sqlite3 $SQL_DATABASE "SELECT sql FROM sqlite_schema WHERE name='$THIS';"
                    echo -e
                done
        fi

        echo -e $cRESET
        echo -e "             e.g. ${cBGRE}diag sql traffic${cBWHT} will show the traffic stats SQL table"$cRESET
    fi

    if [ "$TYPE" == "sql" ] || [ "$TYPE" == "cmd" ];then

        if [ "$TABLE" != "cmd" ];then
            # Probably not a good idea for * - last couple of days maybe?
            if [ -z "$TABLE" ];then
                echo -e $cBYEL"\n\tDEBUG: SQL '$SQL_DATABASE'\n"$cBCYA 2>&1
                sqlite3 $SQL_DATABASE "SELECT * FROM servers;"
                sqlite3 $SQL_DATABASE "SELECT * FROM clients;"
                sqlite3 $SQL_DATABASE "SELECT * FROM fwmark;"
                sqlite3 $SQL_DATABASE "SELECT * FROM policy;"
                sqlite3 $SQL_DATABASE "SELECT * FROM devices;"
                sqlite3 $SQL_DATABASE "SELECT * FROM session;"
                sqlite3 $SQL_DATABASE "SELECT * FROM traffic;"
            else

                echo -e $cBYEL"\n\tDEBUG: SQL '$SQL_DATABASE'\n"$cBCYA 2>&1
                case $TABLE in
                    tra*)
                        TABLE="traffic"
                        echo -e $cBYEL"\tTable:$TABLE"$cBCYA 2>&1
                        sqlite3 $SQL_DATABASE "SELECT peer, datetime(timestamp, 'unixepoch', 'localtime') AS time, rx, tx, rxtotal, txtotal FROM $TABLE;" | column -t  -s '|' --table-columns Peer,Timestamp,RX,TX,"RX Total","TX Total"    # v4.11
                    ;;
                    sess*)
                        TABLE="session"
                        echo -e $cBYEL"\tTable:$TABLE"$cBCYA 2>&1
                        sqlite3 $SQL_DATABASE "SELECT peer, state, datetime(timestamp, 'unixepoch', 'localtime') AS time FROM $TABLE;" | column -t  -s '|' --table-columns Peer,State,Timestamp
                    ;;
                    pol*)
                        TABLE="policy"
                        echo -e $cBYEL"\tTable:$TABLE"$cBCYA 2>&1
                        sqlite3 $SQL_DATABASE "SELECT * FROM $TABLE;" | column -t  -s '|' --table-columns Peer,Interface,Source,Destination,Description
                    ;;
                    dev*)
                        TABLE="devices"
                        echo -e $cBYEL"\tTable:$TABLE"$cBCYA 2>&1
                        sqlite3 $SQL_DATABASE "SELECT * FROM $TABLE ORDER BY ip ASC;" | column -t  -s '|' --table-columns Device,Auto,IPADDR,DNS,'Allowed',Public,Private,Description,Conntrack # v4.12 v4.11
                    ;;
                    ips*)
                        TABLE="ipset"
                        echo -e $cBYEL"\tTable:$TABLE"$cBCYA 2>&1
                        sqlite3 $SQL_DATABASE "SELECT * FROM $TABLE;" | column -t  -s '|' --table-columns IPSet,Use,Peer,FWMark,DST/SRC
                    ;;
                    fwm*)
                        TABLE="fwmark"
                        echo -e $cBYEL"\tTable:$TABLE"$cBCYA 2>&1
                        sqlite3 $SQL_DATABASE "SELECT * FROM $TABLE;" | column -t  -s '|' --table-columns FWMark,Peer
                    ;;
                    serv*)
                        TABLE="servers"
                        echo -e $cBYEL"\tTable:$TABLE"$cBCYA 2>&1
                        sqlite3 $SQL_DATABASE "SELECT * FROM $TABLE;" | column -t  -s '|' --table-columns Peer,Auto,Subnet,Port,Public,Private,Description  # v4.12
                    ;;
                    client*)
                        TABLE="clients"
                        echo -e $cBYEL"\tTable:$TABLE"$cBCYA 2>&1
                        sqlite3 $SQL_DATABASE "SELECT * FROM $TABLE;" | column -t  -s '|' --table-columns Peer,Auto,IP,Endpoint,DNS,MTU,Public,Private,Description  # v4.12
                    ;;
                    passthru*)                                      # v4.12
                        TABLE="passthru"
                        echo -e $cBYEL"\tTable:$TABLE"$cBCYA 2>&1
                        sqlite3 $SQL_DATABASE "SELECT * FROM $TABLE;" | column -t  -s '|' --table-columns Server,Client,Passthru    # v4.12
                    ;;
                    *)
                        [ "$TABLE" != "?" ] && echo -en $cBRED"\a\tInvalid SQL table ${cBWHT}'$TABLE'\n\n"
                        echo -en $cBWHT"\tValid tables:\t"$cBCYA 2>&1
                        echo -e ".tables" > /tmp/sql_cmds.txt
                        sqlite3 $SQL_DATABASE < /tmp/sql_cmds.txt
                        echo -e $cRESET
                    ;;
                esac
            fi
        else
            CMD=$TABLE
            shift
            QUICK_CMD=$@

            case $QUICK_CMD in

                DelZero)
                    sqlite3 $SQL_DATABASE "DELETE FROM traffic WHERE rx='0' AND tx='0';"
                ;;
                *)
                sqlite3 $SQL_DATABASE "$@"
                ;;
            esac

        fi
    fi

    if [ "$TYPE" == "sqlX" ];then

        echo -en $cBYEL"\n\tDEBUG: Interactive SQL '$SQL_DATABASE'\n\tTables:\t"$cBCYA 2>&1
        echo -e ".tables" > /tmp/sql_cmds.txt
        sqlite3 $SQL_DATABASE < /tmp/sql_cmds.txt
        echo -e $cRESET
        sqlite3 $SQL_DATABASE

    fi

    echo -e $cRESET 2>&1
}
Diag_IPTables() {

    if [ "$1" == "4" ];then
        local IPT="iptables"
        local DASH6=
        local IPVER=
    else
        local IPT="ip6tables"
        local DASH6="-6"
        local IPVER="IPv6"
    fi

    echo -e $cBYEL"\n\tDEBUG: $IPVER Firewall rules \n"$cBCYA 2>&1
    echo -e $cBYEL"\n\tDEBUG: $IPVER -t filter \n"$cBCYA 2>&1
    $IPT --line -nvL FORWARD | grep -iE "WireGuard|Chain|pkts"
    echo -e
    $IPT --line -nvL WGM_ACL_F | grep -iE "WireGuard|Chain|pkts"
    echo -e
    $IPT --line -nvL INPUT | grep -iE "WireGuard|Chain|pkts"
    echo -e
    $IPT --line -nvL OUTPUT | grep -iE "WireGuard|Chain|pkts"

    echo -e $cBYEL"\n\tDEBUG: $IPVER -t nat \n"$cBCYA 2>&1
    $IPT --line -t nat -nvL PREROUTING | grep -iE "WireGuard|Chain|pkts"
    echo -e
    $IPT --line -t nat -nvL POSTROUTING | grep -iE "WireGuard|Chain|pkts"

    for WG_INTERFACE in $(wg show interfaces)
        do
            case $WG_INTERFACE in
                wg1*)

                    local I=$(echo "$WG_INTERFACE" | grep -oE "[1-9]*$")
                    [ ${#I} -gt 2 ] && local I=${I#"${I%??}"} || local I=${I#"${I%?}"}
                    if [ "$(Chain_exists "WGDNS${I}" "nat")" == "Y" ];then
                        echo -e
                        $IPT --line -t nat -nvL WGDNS${I} | grep -iE "WireGuard|Chain|pkts"
                    fi
                ;;
                *)
                ;;
            esac

        done

    echo -e $cBYEL"\n\tDEBUG: $IPVER -t mangle \n"$cBCYA 2>&1
    $IPT --line -t mangle -nvL FORWARD | grep -iE "WireGuard|Chain|pkts"
    echo -e
    $IPT --line -t mangle -nvL PREROUTING | grep -iE "WireGuard|Chain|pkts"

}
Diag_Routes() {

    local WG_INTERFACE=

    if [ "$1" == "4" ];then
        local DASH6=
        local IPVER=
    else
        local DASH6="-6"
        local IPVER="IPv6"
    fi

    echo -e $cBYEL"\n\tDEBUG: $IPVER Routing info MTU etc.\n"$cBCYA 2>&1      # v1.07
    ip $DASH6 a l $WG_INTERFACE                                # v1.07

    echo -e $cBYEL"\n\tDEBUG: $IPVER Routing Table main\n"$cBCYA 2>&1
    ip $DASH6 route | grep -E "wg."

    echo -e $cBYEL"\n\tDEBUG: $IPVER Routing Cache\n"$cBCYA 2>&1    # v4.16
    ip $DASH6 -s route show cache                                   # v4.16

}
Diag_Rules() {

    if [ "$1" == "4" ];then
        local IPT="iptables"
        local DASH6=
        local IPVER=
    else
        local IPT="ip6tables"
        local DASH6="-6"
        local IPVER="IPv6"
    fi

    echo -e $cBYEL"\n\tDEBUG: $IPVER RPDB rules\n"$cBCYA 2>&1
    ip $DASH6 rule

    for WG_INTERFACE in $(wg show interfaces)
        do
            local I=${WG_INTERFACE:3:1}
            if [ "${WG_INTERFACE:0:3}" != "wg2" ];then
                local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM clients WHERE peer='$WG_INTERFACE';")
                local DESC=$(printf "%s" "$DESC" | sed 's/^[ \t]*//;s/[ \t]*$//')
                echo -e $cBYEL"\n\tDEBUG: $IPVER Routing Table 12$I (wg1$I) ${cBMAG}$DESC\n"$cBCYA 2>&1
                ip $DASH6 route show table 12$I
            fi
        done
}
Check_Version_Update() {

    GITHUB_DIR=$GITHUB_MARTINEAU

    local localmd5="$(md5sum "$0" | awk '{print $1}')"

    if [ "$1" != "nochk" ];then
        local REMOTE_VERSION_NUMDOT="$(curl -${SILENT}fLN --retry 3 --connect-timeout 3 "${GITHUB_DIR}/wg_manager.sh" | grep -E "^VERSION\=" | tr -d '"' | sed 's/VER.*\=//')" || REMOTE_VERSION_NUMDOT="?.??"   # v3.23
        if [ -z "$REMOTE_VERSION_NUMDOT" ] || [ "$REMOTE_VERSION_NUMDOT" == "?.??" ];then
            echo -e ${cRESET}$cRED_"\a\t***ERROR Unable to verify Github version...check DNS/Internet access!\n\n"$cRESET
            local REMOTE_VERSION_NUMDOT=
        else
            [ "$1" != "nochk" ] && remotemd5="$(curl -${SILENT}fL  --retry 3 --connect-timeout 3 "${GITHUB_DIR}/wg_manager.sh" | md5sum | awk '{print $1}')"
            local REMOTE_VERSION_NUM=$(echo $REMOTE_VERSION_NUMDOT | sed 's/[^0-9]*//g')
        fi
    fi

    local LOCAL_VERSION_NUMDOT=$VERSION                                     # v1.03
    local LOCAL_VERSION_NUM=$(echo $VERSION | sed 's/[^0-9]*//g')

    local CHANGELOG="$cRESET(${cBCYA}Change Log: ${cBYEL}https://github.com/MartineauUK/${GIT_REPO}/commits/main/wg_manager.sh$cRESET)"
    [ -n "$(echo $VERSION | grep "b")" ] && local CHANGELOG="$cRESET(${cBCYA}Change Log: ${cBYEL}https://github.com/MartineauUK/${GIT_REPO}/commits/dev/wg_manager.sh$cRESET)"

    # As the developer, I need to differentiate between the GitHub md5sum hasn't changed, which means I've tweaked it locally
    if [ -n "$REMOTE_VERSION_NUMDOT" ];then
        [ ! -f ${INSTALL_DIR}wg_manager.sh.md5 ] && echo $remotemd5 > ${INSTALL_DIR}wg_manager.sh.md5
    fi

    [ -z "$REMOTE_VERSION_NUM" ] && REMOTE_VERSION_NUM=0

    # Local Version higher than GitHub version or MD5 Mismatch due to local development?
    if [ ${REMOTE_VERSION_NUM:0:3} -lt ${LOCAL_VERSION_NUM:0:3} ] || [ "$(echo "$VERSION" | grep -om1 "b")" == "b" ] || [ $REMOTE_VERSION_NUM -lt $LOCAL_VERSION_NUM ] || { [ "$(awk '{print $1}' ${INSTALL_DIR}wg_manager.sh.md5)" == "$remotemd5" ]; } && [ "$localmd5" != "$remotemd5" ];then  # v1.03
        local VERSION=$LOCAL_VERSION_NUMDOT                             # v1.03
        if [ $REMOTE_VERSION_NUM -lt $LOCAL_VERSION_NUM ];then
            ALLOWUPGRADE="N"
            UPDATE_SCRIPT_ALERT="$(printf '%b[✔] Push to Github PENDING for %b(Major) %b%s%b UPDATE %b%s%b >>>> %b%s\n' "${cGRE}" "${cBGRE}" "$cRESET" "$(basename $0)" "$cBRED" "$cBMAG" "$VERSION" "$cRESET" "$cBGRE" "$REMOTE_VERSION_NUMDOT")"
        else
            ALLOWUPGRADE="N"
            UPDATE_SCRIPT_ALERT="$(printf '%b[✔] Push to Github PENDING for %b(Minor Hotfix) %b%s update >>>> %b%s %b%s\n' "${cGRE}" "$cBRED" "$cBGRE" "$cRESET" "$(basename $0)" "$cRESET" "$cBMAG" "$VERSION")"
        fi
    else
        if [ "$localmd5" != "$remotemd5" ]; then
            if [ $REMOTE_VERSION_NUM -ge $LOCAL_VERSION_NUM ];then
                if [ $REMOTE_VERSION_NUM -gt $LOCAL_VERSION_NUM ];then
                    local UPDATE_SCRIPT_ALERT="$(printf '%bu%b  = %bUpdate (Major) %b%s %b%s -> %b %s\n' "${cBYEL}" "${cRESET}" "$cBGRE" "$cRESET" "$(basename $0)" "$cBMAG" "$VERSION" "$REMOTE_VERSION_NUMDOT" "$CHANGELOG")"
                else
                    local UPDATE_SCRIPT_ALERT="$(printf '%bu%b  = %bUpdate (Minor Hotfix) %b%s %b%s -> %b %s\n' "${cBYEL}" "${cRESET}" "$cBGRE" "$cRESET" "$(basename $0)" "$cBMAG" "$VERSION" "$REMOTE_VERSION_NUMDOT" "$CHANGELOG")"
                fi
            fi
        fi
    fi


    if [ -n "$UPDATE_SCRIPT_ALERT" ];then   # v1.03
        [ -z "$(echo "$UPDATE_SCRIPT_ALERT" | grep -F "Push to Github")" ] && local BEL="\a" || local BEL=
        echo -e "${BEL}\n\t"$UPDATE_SCRIPT_ALERT"\n"
        [ -n "$(echo "$UPDATE_SCRIPT_ALERT" | grep -o "Push to Github")" ] && return 2 || return 1 # v1.03
    else
        echo -e $cBGRE"\n\t$VERSION - No WireGuard® Manager updates available - you have the latest version\n"              # v1.03
        return 0
    fi

}
Display_SplashBox() {
    printf '| Requirements: %bHND %bor%b AX %brouter with Kernel %b4.1.xx%b or later           |\n' "$cBMAG" "$cRESET" "$cBMAG" "$cRESET" "$cBMAG" "$cRESET"
    printf '|                         e.g. %bRT-AC86U%b or %bRT-AX86U%b etc.               |\n' "$cBMAG" "$cRESET" "$cBMAG" "$cRESET"
    printf '|                                                                      |\n'
    printf '|               USB drive with %bEntware%b installed                       |\n' "$cBYEL" "$cRESET"
    printf '|                                                                      |\n'
    if [ "$EASYMENU" == "N" ];then
        printf '|   i = Install WireGuard Advanced Mode                     |\n'
    else
        printf '|   1 = Install WireGuard                                              |\n'
    fi
    local YES_NO="   "                              # v2.07
    [ "$EASYMENU" == "Y" ] && local YES_NO="${cBGRE}   ";   printf '|       o1. Enable firewall-start protection for Firewall rules%b    %b |\n' "$YES_NO" "$cRESET"
    [ "$EASYMENU" == "Y" ] && local YES_NO="${cBGRE}   ";   printf '|       o2. Enable DNS                                         %b    %b |\n' "$YES_NO" "$cRESET"
    printf '|                                                                      |\n'

    if [ "$EASYMENU" == "N" ];then                  # v2.07
        printf '|   z  = Remove WireGuard/Wireguard_manager                                |\n'
        printf '|   ?  = About Configuration                                           |\n'
        printf '|   3  = Advanced Tools                                                |\n'
    fi
    printf '|                                                                      |\n'
    printf '+======================================================================+\n'
}
Manage_UDP_Monitor() {

    # v4.01
    local TYPE=$1
    local ACTION=$2

    local WATCH=$3
    [ -z "$WATCH" ] && WATCH="&"

    local TS=$(date +"%Y%m%d-%H%M%S")    # current date and time 'yyyymmdd-hhmmss'

    if [ -n "$ACTION" ];then

        if [ "$ACTION" == "disable" ] || [ "$ACTION" == "off" ];then
            killall "$(pidof conntrack)" 2>/dev/null
            killall "$(pidof UDP_Monitor.sh)"  2>/dev/null
            killall "$(pidof UDP_Updater.sh)" 2>/dev/null
            rm /tmp/UDP_Updater.pid  2>/dev/null
            rm /tmp/UDP_Monitor.pid  2>/dev/null
            rm /tmp/WireGuard_UDP.log 2>/dev/null
            rm ${INSTALL_DIR}UDP_Monitor.sh 2>/dev/null
        else

            if [ ! -f ${INSTALL_DIR}UDP_Monitor.sh ];then

                cat > ${INSTALL_DIR}UDP_Monitor.sh << EOF
#!/bin/sh
VERSION="$TS"
#============================================================================================ © 2021 Martineau v1.01

SayT() {
   echo -e \$\$ \$@ | logger -t "(\$(basename \$0))"
}
LOCKFILE="/tmp/\${0##*/}.pid"

echo \$\$ > \$LOCKFILE

SayT "WireGuard UDP monitor Started"

FN=\$1
[ -z "\$FN" ] && FN="/tmp/WireGuard_UDP.log"

conntrack -E --event-mask UPDATE -p udp -o timestamp | tee > /tmp/WireGuard_UDP.log

SayT "WireGuard UDP monitor Terminated"

rm \$LOCKFILE
EOF

                chmod +x ${INSTALL_DIR}UDP_Monitor.sh

            fi

            if [ -z "$(pidof UDP_Monitor.sh)" ];then
                ( ${INSTALL_DIR}UDP_Monitor.sh ) &
            fi


            if [ -z "$(pidof UDP_Updater.sh)" ];then
               ( ${INSTALL_DIR}UDP_Updater.sh ) &
            fi

        fi

    fi

    if [ -n "$(pidof UDP_Monitor.sh)" ] || [ -n "$(pidof UDP_Updater.sh)" ];then
        echo -e "Y"
    else
        echo -e "N"
    fi

}
Manage_IPSET() {

    local ACTION=$1
    local WG_INTERFACE=$2

    case $ACTION in
        add|del|upd|new|""|list|ipset)
            shift
        ;;
        *)
            echo -e $cBRED"\a\n\t***ERROR IPSet cmd '$ACTION' e.g. [new | add | del | upd | ipset]\n"$cRESET
            return 1
        ;;
    esac

    if [ "$ACTION" == "ipset" ] && [ -z "$2" ];then
        local ACTION="summary"
        local IPSET="*"
    fi

    if [ "$ACTION" == "add" ] || [ "$ACTION" == "del" ];then
        local WG_INTERFACE=$1
        [ "$ACTION" == "add" ] && local SQL_ACTION="INSERT" || { SQL_ACTION="DELETE"; ACTION="delet"; }
        if [ -n "$(echo "$WG_INTERFACE" | grep -e "^wg[0-2]")" ];then
            shift
            echo -e
            for IPSET in $@
                do
                    local USE="Y"
                    local FWMARK=$(sqlite3 $SQL_DATABASE "SELECT fwmark FROM fwmark WHERE peer='$WG_INTERFACE';")
                    [ -z "$DSTSRC" ] && local DSTSRC="dst"

                    # IPSets containing MACs can only be 'src'!
                    #   hash:mac
                    #
                    #   Can only be 'src,src' or 'dst,src'
                    #   hash:ip,mac
                    #   bitmap:ip,mac
                    #if [ "$(ipset list $IPSET -t | awk -F ',' '/^Type/ {print $NF}')" == "mac" ];then
                        [ -n "$(ipset list $IPSET -t | grep -F "hash:mac")" ] && DSTSRC="src"  # v4.16
                    #fi

                    if [ "$ACTION" == "add" ];then
                        ipset list $IPSET -n >/dev/null 2>&1;if [ $? -eq 0 ]; then
                            if [ -z "$(sqlite3 $SQL_DATABASE "SELECT * FROM ipset WHERE peer='$WG_INTERFACE' AND ipset='$IPSET';")" ];then
                                sqlite3 $SQL_DATABASE "INSERT into ipset values('$IPSET','$USE','$WG_INTERFACE','$FWMARK','$DSTSRC');"
                                echo -e $cBGRE"\n\t[✔] Ipset ${cBWHT}'$IPSET'${cBGRE} Selective Routing ${ACTION}ed ${cBMAG}$WG_INTERFACE"$cRESET
                            else
                                echo -e $cRED"\tWarning: IPSet ${cBWHT}'$IPSET'${cBGRE} already exists for Peer ${cBMAG}$WG_INTERFACE"$cRESET
                            fi
                        else
                            echo -e $cRED"\a\t***ERROR: IPSet '$IPSET' does not EXIST! for routing via ${cBMAG}$WG_INTERFACE"$cRESET
                        fi
                    else
                        if [ -n "$(sqlite3 $SQL_DATABASE "SELECT * FROM ipset WHERE peer='$WG_INTERFACE' AND ipset='$IPSET';")" ];then
                            sqlite3 $SQL_DATABASE "DELETE FROM ipset WHERE ipset='$IPSET' AND peer='$WG_INTERFACE';"
                            echo -e $cBGRE"\n\t[✔] Ipset ${cBWHT}'$IPSET'${cBGRE} Selective Routing ${ACTION}ed ${cBMAG}$WG_INTERFACE"$cRESET
                        else
                            echo -e $cRED"\tWarning: IPSet '$IPSET' not used by Peer ${cBMAG}$WG_INTERFACE"$cRESET
                        fi
                    fi

                    local DSTSRC=
                done
        else
            # Direct manipulation of the IPSET ?
            if [ "$ACTION" == "add" ];then
                local IPSET=$WG_INTERFACE
                local WG_INTERFACE="none"
                local USE="N"
                local DSTSRC="dst"
                local FWMARK=

                sqlite3 $SQL_DATABASE "INSERT into ipset values('$IPSET','$USE','$WG_INTERFACE','$FWMARK','$DSTSRC');"
            else
                sqlite3 $SQL_DATABASE "DELETE FROM ipset WHERE ipset='$IPSET';"
            fi

        fi
        [ "${WG_INTERFACE:0:3}" == "wg1" ] && Manage_Peer "list" "$WG_INTERFACE"        # v4.16
        return 0
    fi

    [ -z "$ACTION" ] && local ACTION="list"

    if [ "$ACTION" == "upd" ];then
        shift
        local IPSET=$1
        shift
        local ACTION=$1
        shift
    else
        if [ "$ACTION" != "summary" ];then
            if [ "$ACTION" == "new" ];then
                if  [ -z "$(sqlite3 $SQL_DATABASE "SELECT * FROM ipset WHERE ip='$WG_INTERFACE'";)" ];then
                    local USE="Y"
                    local FWMARK=$(sqlite3 $SQL_DATABASE "SELECT fwmark FROM fwmark WHERE peer='$WG_INTERFACE';")
                    local DSTSRC="dst"
                    # IPSets containing MACs can only be 'src'!
                    #   hash:mac
                    #
                    #   Can only be 'src,src' or 'dst,src'
                    #   hash:ip,mac
                    #   bitmap:ip,mac
                    #if [ "$(ipset list $IPSET -t | awk -F ',' '/^Type/ {print $NF}')" == "mac" ];then
                        [ -n "$(ipset list $IPSET -t | grep -F "hash:mac")" ] && DSTSRC="src"  # v4.16
                    #f
                    sqlite3 $SQL_DATABASE "INSERT into ipset values('$IPSET','$USE','$WG_INTERFACE','$FWMARK','$DSTSRC');"
                fi
            else
                if [ -z "$(sqlite3 $SQL_DATABASE "SELECT * FROM ipset WHERE ipset='$IPSET';")" ];then
                    echo -e $cBRED"\a\n\t***ERROR IPSet '$IPSET' does not exist!\n"$cRESET
                    return 1
                fi
            fi
        fi
    fi

    case $ACTION in
        list)
            echo -e $cBYEL"\tTable:ipset"$cBCYA 2>&1
            sqlite3 $SQL_DATABASE "SELECT * FROM ipset;" | column -t  -s '|' --table-columns IPSet,Enable,Peer,FWMark,DST/SRC
        ;;
        fwmark)
            local FWMARK=$1
            [ "$IPSET" != "all" ] && local SQL_WHERE="ipset='$IPSET' AND" || SQL_WHERE=
            sqlite3 $SQL_DATABASE "UPDATE ipset SET fwmark='$FWMARK' WHERE $SQL_WHERE peer='$WG_INTERFACE';"
            echo -e $cBGRE"\n\t[✔] Updated IPSet Selective Routing FWMARK for ${cBMAG}$WG_INTERFACE \n"$cRESET
        ;;
        dstsrc)
            local DSTSRC=$1
            [ "$IPSET" == "all" ] && local SQL_WHERE="ipset='$IPSET' AND" || SQL_WHERE=
            DSTSRC=$(printf "%s" "$DSTSRC" | sed 's/^[ \t]*//;s/[ \t]*$//')
            local DSTSRC=$(echo "$DSTSRC" | tr 'A-Z' 'a-z')
            local VALID="Y"
            case $DSTSRC in
                dst|src);;
                dst","src);;
                src","dst);;
                src","src);;        # v4.16
                dst","dst);;
                *)
                    VALID="N"
                ;;
            esac

            # IPSets containing MACs can only be 'src'!
            #   hash:mac
            #
            #   Can only be 'src,src' or 'dst,src'
            #   hash:ip,mac
            #   bitmap:ip,mac
            #if [ "$(ipset list $IPSET -t | awk -F ',' '/^Type/ {print $NF}')" == "mac" ];then # v4.16
                #local DIMENSION=$(ipset list $IPSET -t | grep -E "^TYPE" | sed 's/^.*://')        # v4.16
                #[ "$DIMENSION" == "mac" ] && DSTSRC="src"                                  # v4.16
                [ -n "$(ipset list $IPSET -t | grep -F "hash:mac")" ] && DSTSRC="src"  # v4.16
            #fi

            if [ "$VALID" == "Y" ];then
                [ "$IPSET" != "all" ] && local SQL_WHERE="ipset='$IPSET' AND" || SQL_WHERE=
                sqlite3 $SQL_DATABASE "UPDATE ipset SET dstsrc='$DSTSRC' WHERE $SQL_WHERE peer='$WG_INTERFACE';"    # v4.12 @ZebMcKayhan
                echo -e $cBGRE"\n\t[✔] Updated IPSet ${cBWHT}'$IPSET'${cBGRE} DST/SRC for ${cBMAG}$WG_INTERFACE \n"$cRESET
                [ "${WG_INTERFACE:0:3}" == "wg1" ] && Manage_Peer "list" "$WG_INTERFACE"        # v4.16
            else
                echo -e $cBRED"\a\n\t***ERROR IPSet DST/SRC ${cBWHT}'$DSTSRC'${cBRED} INVALID! use { dst | src | dst,src | src,dst | src,src | dst,dst }\n"$cRESET          # v4.16
            fi
        ;;
        enable)
            local USE=$1
            [ "$IPSET" != "all" ] && local SQL_WHERE="ipset='$IPSET'" || SQL_WHERE=
            if [ -n $(echo "$USE" | grep -iE "Y|N") ];then
                local USE=$(echo "$USE" | tr 'a-z' 'A-Z')
                sqlite3 $SQL_DATABASE "UPDATE ipset SET use='$USE' WHERE $SQL_WHERE peer='$WG_INTERFACE';"
                echo -e $cBGRE"\n\t[✔] Updated IPSet ${cBWHT}'$IPSET'${cBGRE} Enable for ${cBMAG}$WG_INTERFACE \n"$cRESET
                [ "${WG_INTERFACE:0:3}" == "wg1" ] && Manage_Peer "list" "$WG_INTERFACE"        # v4.16
            fi
        ;;
        summary)
            echo -e $cBYEL"\n\tTable:ipset Summary\n"$cBCYA 2>&1
            sqlite3 $SQL_DATABASE "SELECT COUNT(ipset),ipset FROM ipset GROUP BY ipset;" | column -t  -s '|' --table-columns Total,IPSet
            echo -e
            sqlite3 $SQL_DATABASE "SELECT COUNT(ipset),ipset,peer FROM ipset GROUP BY ipset,peer;" | column -t  -s '|' --table-columns Total,IPSet,Peer
            echo -e
            sqlite3 $SQL_DATABASE "SELECT * FROM fwmark;" | column -t  -s '|' --table-columns FWMark,Interface
        ;;
        *)

            #echo -e $cBGRE"\n\t[✔] Updated IPSet Selective Routing for $WG_INTERFACE \n"$cRESET
            #Request to update FWMark table for Peer??
            if [ "$IPSET" == "fwmark" ];then
                sqlite3 $SQL_DATABASE "UPDATE fwmark SET fwmark='$ACTION' WHERE peer='$WG_INTERFACE';"
                echo -e $cBGRE"\n\t[✔] Updated FWMARK for ${cBMAG}$WG_INTERFACE \n"$cBCYA
                sqlite3 $SQL_DATABASE "SELECT * FROM fwmark;" | column -t  -s '|' --table-columns FWMark,Interface
            fi
        ;;
    esac
}
Manage_Custom_Subnets() {

    local ACTION=$1
    local WG_INTERFACE=$2
    local EDIT=0

    case $ACTION in
        add|del)
            shift 2
        ;;
        *)
            echo -e $cBRED"\a\n\t***ERROR Subnet cmd '$ACTION' e.g. [new | add | del ]\n"$cRESET
            return 1
        ;;
    esac

    # Simply open the appropriate scripts for editing?
    FN="${INSTALL_DIR}/Scripts/${WG_INTERFACE}-route-up.sh"
    if [ ! -f $FN ];then
        cat > $FN << EOF
#!/bin/sh

# Add Downstream IP/Subnets such as WiFi IoT
#     iptables -t nat -I PREROUTING -s xxx.xxx.xxx.xxx/24 -o $VPN_ID -j MASQUERADE -m comment --comment "WireGuard 'client'" 2>/dev/null

EOF
    for SUBNET in $@
        do
            if [ -n "$(echo "$SUBNET" | Is_IPv4_CIDR)" ] || [ -n "$(echo "$SUBNET" | Is_IPv4)" ];then
                echo -e "iptables -t nat -I PREROUTING -s $SUBNET -o $WG_INTERFACE -j MASQUERADE -m comment --comment \"WireGuard 'client'\" 2>/dev/null" >> $FN
            else
                echo -e $cBRED"\n\a\t***ERROR: Invalid IP/Subnet '${cBWHT}${SUBNET}${cBRED}'"$RESET
                echo -e "# ==> Invalid IP/Subnet iptables -t nat -I PREROUTING -s $SUBNET -o $WG_INTERFACE -j MASQUERADE -m comment --comment \"WireGuard 'client'\" 2>/dev/null" >> $FN
                local EDIT=1
            fi
        done
    fi
    [ $EDIT -eq 1 ] && nano --unix $FN
    echo -e $cRESET"\n\t'$FN'$cBGRE modified for custom Subnet management"$cRESET
    FN="${INSTALL_DIR}/Scripts/${WG_INTERFACE}-route-down.sh"
    if [ ! -f $FN ];then
        cat > $FN << EOF
#!/bin/sh

# Remove Downstream IP/Subnets such as WiFi IoT
#     iptables -t nat -D PREROUTING -s xxx.xxx.xxx.xxx/24 -o $WG_INTERFACE -j MASQUERADE -m comment --comment "WireGuard 'client'" 2>/dev/null

EOF
    for SUBNET in $@
        do
            echo -e "iptables -t nat -D PREROUTING -s $SUBNET -o $VPN_ID -j MASQUERADE -m comment --comment \"WireGuard 'client'\" 2>/dev/null" >> $FN
        done
    fi
    #nano --unix $FN
    echo -e $cRESET"\t'$FN'$cBGRE modified for custom Subnet management"$cRESET
}
Create_Site2Site() {

    # [ [name1] [name2] ['ip='ip_for_name1] ['port='listen_port_for_name1] ['lan='siteb_subnet] ]

    # [ add wgxx name2 ['lan='siteC_subnet] ]

    shift

    local I=1
    while [ $# -gt 0 ]; do
        case "$1" in
        full*)
            local ALLRULES="Y"
            ;;
        ip=*)                               # Tunnel VPN Pool SiteA e.g. 10.10.10.0 (SiteB will be assigned +1)
            local VPN_POOL4="$(echo "$1" | sed -n "s/^.*ip=//p" | awk '{print $1}')"
            [ "$I" -ge 1 ] && local I=$((I-1))      # Retain Positional parameter
            ;;
        ipv6|ipv6=*)
            local VPN_POOL6="$(echo "$1" | sed -n "s/^.*ipv6=//p" | awk '{print $1}')"
            # Ensure IPv6 address is in standard compressed format
            [ -n "$VPN_POOL6" ] && VPN_POOL6="$(IPv6_RFC "$VPN_POOL6")" # v4.15
            local USE_IPV6="Y"                      # v4.16 v4.15
            [ "$I" -ge 1 ] && local I=$((I-1))      # Retain Positional parameter
            ;;
        noipv4|noIPv4)
            local USE_IPV4="N"                  # v4.15
            local IPV6_TXT="(IPv6 Only) "       # v4.15
            ;;
        port*)                              # SiteA ListenPort (SiteB will be assigned +1)
            local LISTEN_PORT="$(echo "$1" | sed -n "s/^.*port=//p" | awk '{print $1}')"
            [ "$I" -ge 1 ] && local I=$((I-1))      # Retain Positional parameter
            ;;
        lan*)
            local SITE_TWO_LAN="$(echo "$1" | sed -n "s/^.*lan=//p" | awk '{print $1}')"
            [ "$I" -ge 1 ] && local I=$((I-1))      # Retain Positional parameter
            ;;
        lanipv6*)
            local SITE_TWO_LAN6="$(echo "$1" | sed -n "s/^.*lanipv6=//p" | awk '{print $1}')"
            # Ensure IPv6 address is in standard compressed format
            local SITE_TWO_LAN6="$(IPv6_RFC "$SITE_TWO_LAN6")"    # v4.15
            local USE_IPV6="Y"                              # v4.15
            [ "$I" -ge 1 ] && local I=$((I-1))              # Retain Positional parameter
            ;;
        allowips*)
            local SITE_TWO_ALLOWIPS="$(echo "$1" | sed -n "s/^.*allowips=//p" | awk '{print $1}' | sed 's~,\([1-2]\)~, \1~')"
            [ "$I" -ge 1 ] && local I=$((I-1))      # Retain Positional parameter
            ;;
        add)
            local ADD_SITE="Y"
            ;;
        *)
            case $I in
                1)
                    NAME_ONE=$1
                ;;
                2)
                    NAME_TWO=$1
                ;;
            esac
            ;;
        esac

        shift

        I=$((I+1))
    done

    if [ -z "$ADD_SITE" ];then
        [ -z "$NAME_ONE" ] && local NAME_ONE="SiteA"
        [ -z "$NAME_TWO" ] && local NAME_TWO="SiteB"

        if [ -n "$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE name='$NAME_ONE';")" ];then    # v4.15
            echo -e $cBRED"\a\n\t***ERROR: '$NAME_ONE' Peer already exists"$cRESET
            return 1
        fi
    else
        local NAME_ONE=
        [ -z "$NAME_TWO" ] && local NAME_TWO="SiteC"
    fi

    if [ -n "$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE name='$NAME_TWO';")" ];then    # v4.15
        echo -e $cBRED"\a\n\t***ERROR: '$NAME_TWO' remote 'device' Peer already exists"$cRESET
        return 1
    fi

    if [ -z "$ADD_SITE" ];then
        [ -z "$VPN_POOL4" ] && local VPN_POOL4="10.9.8.0"                 # VPN Tunnel Network
        local TWO_OCTET=$(echo "$VPN_POOL4" | cut -d'.' -f2)
        local THIRD_OCTET=$(echo "$VPN_POOL4" | cut -d'.' -f3)
        local IPV6_TXT=
        [ -z "$LISTEN_PORT" ] && local LISTEN_PORT="61820"              # Site $NAME_ONE
        local LAN_ADDR=$(nvram get lan_ipaddr)
        local LAN_SUBNET=${LAN_ADDR%.*}
        local SITE_ONE_LAN=$LAN_SUBNET".0/24"

        if [ "$USE_IPV6" == "Y" ] && [ -z "$VPN_POOL6" ];then
            [ -z "$TWO_OCTET" ] && local TWO_OCTET="9"
            [ -z "$NEW_THIRD_OCTET" ] && local NEW_THIRD_OCTET="8"
            local VPN_POOL6="fd10:${TWO_OCTET}:${NEW_THIRD_OCTET}::1"
            local IPV6_TXT="(IPv4/IPv6) "
        fi
    fi

    [ -n "$VPN_POOL4" ] && local VPN_POOL=$VPN_POOL4    # v4.15

    if [ -n "$VPN_POOL4" ] && [ -n "$VPN_POOL6" ];then  # v4.15
            local VPN_POOL=$VPN_POOL4","$VPN_POOL6
            local IPV6_TXT="(IPv4/IPv6) "               # v4.15
    fi

    if [ "$USE_IPV4" == "N" ];then                      # v4.15
        if [ -n "$VPN_POOL6" ];then                     # v4.15
            local VPN_POOL=$VPN_POOL6                   # v4.15
            local IPV6_TXT="(IPv6) "                    # v4.15
        else
            echo -e $cBRED"\a\n\t***ERROR Create new WireGuard® ${IPV6_TXT}'server' Peer has missing ${cRESET}IPv6 Private subnet${cBRED} - use $cRESET'ipv6[=]'$cBRED arg\n"$cRESET
            return 1
        fi
    fi

    for THIS in $(echo "$VPN_POOL" | tr ',' ' ')        # v4.15
        do
            if [ -z "$(echo "$THIS" | grep -F ":")" ];then
                [ -z "$(echo "$THIS" | Is_IPv4)" ] && { echo -e $cBRED"\a\n\t***ERROR: '$THIS' must be IPv4 "$cRESET; return 1; }                                  # v4.15
            else
                [ -z "$(echo "$THIS" | sed 's~/.*$~~' | Is_Private_IPv6)" ] && { echo -e $cBRED"\a\n\t***ERROR: '$THIS' must be Private IPv6 address"$cRESET; return 1; }   # v4.15
            fi
        done

    if [ -z "$ADD_SITE" ];then
        local LAST_OCTET=${VPN_POOL4##*.}
        if [ "$LAST_OCTET" == "0" ];then
            local SITE_ONE_IP=$(echo "$VPN_POOL4" | grep -o '^.*\.')"1/32"
            local SITE_TWO_IP=$(echo "$VPN_POOL4" | grep -o '^.*\.')"2/32"
        else
            local SITE_ONE_IP=$VPN_POOL"/32"
            local SITE_TWO_IP=$(echo "$VPN_POOL4" | grep -o '^.*\.')$((LAST_OCTET+1))/32
        fi
        if [ "$USE_IPV6" == "Y" ] && [ -n "$VPN_POOL6" ];then
            local SITE_ONE_IP=$SITE_ONE_IP", "$VPN_POOL6"/128"
        fi
    fi

    if [ -z "$SITE_TWO_LAN" ];then
        local SITE_TWO_THIRD_OCTET=$(($(echo "$SITE_ONE_LAN" | cut -d'.' -f3) + 1))
        local SITE_TWO_LAN=$(echo "$SITE_ONE_LAN" | grep -oE '^(.{1,3}\.){2}')${SITE_TWO_THIRD_OCTET}.0/24
        if [ "$USE_IPV6" == "Y" ];then
            [ -z "$SITE_TWO_LAN6" ] && local SITE_TWO_LAN6="fd20:${TWO_OCTET}:${SITE_TWO_THIRD_OCTET}::1/64"
            local VPN_POOL_IP=${SITE_TWO_LAN6%/*}
            local VPN_POOL_MASK=${SITE_TWO_LAN6##*/}                    # v4.15
            local VPN_SUBNET=${VPN_POOL_IP%:*}
            local VPN_IP_EXPANDED=$(Expand_IPv6 "${VPN_POOL_IP%/*}")    # v4.15
            local VPN_IP_COMPRESSED=$(Compress_IPv6 "${VPN_IP_EXPANDED}")
            local VPN_POOL_PREFIX_EXPANDED=${VPN_IP_EXPANDED%:*}        # v4.15
            local VPN_POOL_PREFIX_COMPRESSED=$(Compress_IPv6 "${VPN_POOL_PREFIX_EXPANDED}")

            local IP=2

            while true
                do
                    local MATCH="$(sqlite3 $SQL_DATABASE "SELECT ip FROM devices WHERE ip LIKE '%${VPN_POOL_PREFIX_COMPRESSED}${IP}/128%';" | tr ',' ' ')"  # v4.15 v4.11 v4.02
                    local DUPLICATE=$(echo "$MATCH" | grep -ow "${VPN_POOL_PREFIX_COMPRESSED}${IP}/128")
                    [ -z "$DUPLICATE" ] && break || local IP=$((IP+1))

                    if [ $IP -ge 255 ];then
                        echo -e $cBRED"\a\t***ERROR: 'server' Peer ($SERVER_PEER) IPv6 subnet MAX 254 imposed!'"
                        exit 98
                    fi

                    [ -z "$MATCH" ] && break

                done

            #local SITE_TWO_LAN=$SITE_TWO_LAN", "${VPN_POOL_PREFIX_COMPRESSED}$IP"/128"
        fi

    else
        if [ -n "$(echo "$SITE_TWO_LAN" | Is_IPv4)" ] || [ -n "$(echo "$SITE_TWO_LAN" | Is_IPv4_CIDR)" ];then
            if [ -z "$(echo "$SITE_TWO_LAN" | Is_IPv4_CIDR)" ];then
                local SITE_TWO_LAN=${SITE_TWO_LAN}/24
            fi
        else
            echo -e $cBRED"\a\n\t***ERROR: '$SITE_TWO_LAN' must be IPv4 IP/IP CIDR"$cRESET
            return 1
        fi
    fi

    if [ -z "$SITE_TWO_ALLOWIPS" ];then
        local SITE_TWO_ALLOWIPS="$SITE_TWO_IP, $SITE_TWO_LAN"
    else
        local SITE_TWO_ALLOWIPS="$SITE_TWO_IP, $SITE_TWO_ALLOWIPS"
    fi

    [ -n "$NAME_ONE" ] && local SLASH="/" || local SLASH=
    echo -e $cBCYA"\n\tCreating WireGuard® Private/Public key-pair for Site-to-Site ${IPV6_TXT}Peers ${cBMAG}${NAME_ONE}/${NAME_TWO}${cBCYA}"$cRESET

    for SITE in $NAME_ONE $NAME_TWO
        do
            if [ -n "$(which wg)" ];then
                wg genkey | tee ${CONFIG_DIR}${SITE}_private.key | wg pubkey > ${CONFIG_DIR}${SITE}_public.key
            fi
        done

    local SITE_ONE_PRI_KEY=$(cat ${CONFIG_DIR}${NAME_ONE}_private.key)
    local SITE_TWO_PRI_KEY=$(cat ${CONFIG_DIR}${NAME_TWO}_private.key)
    local SITE_ONE_PUB_KEY=$(cat ${CONFIG_DIR}${NAME_ONE}_public.key)
    local SITE_TWO_PUB_KEY=$(cat ${CONFIG_DIR}${NAME_TWO}_public.key)

    echo -e $cRESET"\a\n\tEnter ${cBMAG}${NAME_TWO} ${cRESET}Endpoint remote IP, or ${cBMAG}${NAME_TWO}$cRESET DDNS name or press$cBGRE [Enter] to SKIP."
    read -r "ANS"

    [ -n "$ANS" ] && local DDNS=$ANS || local DDNS=$NAME_TWO".DDNS"

    if [ -z "$ADD_SITE" ];then
        cat > ${CONFIG_DIR}${NAME_ONE}.conf << EOF
# $NAME_ONE - $SITE_ONE_LAN
[Interface]
PrivateKey = $SITE_ONE_PRI_KEY
Address = $SITE_ONE_IP
ListenPort = $LISTEN_PORT

# $NAME_TWO LAN
[Peer]
PublicKey = $SITE_TWO_PUB_KEY
AllowedIPs = $SITE_TWO_ALLOWIPS
Endpoint = $DDNS:$((LISTEN_PORT+1))
#PresharedKey = $PRE_SHARED_KEY
PersistentKeepalive = 25
EOF

        chmod 600 ${CONFIG_DIR}${NAME_ONE}.conf         # v4.15 Prevent wg-quick "Warning: '/opt/etc/wireguard.d/Home.conf' is world accessible"
    fi

    if [ -n "$ADD_SITE" ];then
        # Determine WG interface if user doesn't explicitly specify the 'server' Peer
        echo -e $cRESET"\tEnter the name of interface or descriptive name e.g. ${cBMAG}'Home'${cRESET} to bind site '${cBMAG}${NAME_TWO}${cRESET}' or press$cBGRE [Enter] to SKIP."
        read -r "ANS"
        if [ -n "$ANS" ];then
            if [ "${ANS:0:3}" == "wg2" ];then
                local WG_INTERFACE=$ANS
            else
                local MATCHTHIS="$ANS"
                if [ -n "$(ls /opt/etc/wireguard.d/wg2*.conf 2>/dev/null)" ];then
                    local SERVER_PEER_LIST=$(grep -HEi "^#.*${MATCHTHIS} " ${CONFIG_DIR}*.conf | grep "wg2" | tr '\n' ' ')    # v4.15
                fi
                [ -n "$SERVER_PEER_LIST" ] && local WG_INTERFACE=$(echo "$SERVER_PEER_LIST" | grep -Eo "wg2[1-9]")
            fi
        fi
        if [ -n "$SERVER_PEER_LIST" ];then
            NAME_ONE=$MATCHTHIS
            SITE_ONE_IP=$(awk '/^[#]*Address/ {print $3}' /opt/etc/wireguard.d/$WG_INTERFACE.conf)
            SITE_ONE_LAN=$('NR==1{print $NF}' /opt/etc/wireguard.d/$WG_INTERFACE.conf)
            LISTEN_PORT=$(awk '/^ListenPort/ {print $3}' /opt/etc/wireguard.d/$WG_INTERFACE.conf)
        fi
    fi

    # If no formal DDNS...ask what to do, so $NAME_TWO can connect to this $NAME_ONE router
    local ROUTER_DDNS=$(nvram get ddns_hostname_x)
    if [ -z "$ROUTER_DDNS" ];then
        echo -e $cRED"\n\a\tWarning: No DDNS is configured! to reach local ${cBMAG}${NAME_ONE}${cRED} Endpoint from remote ${cBMAG}$NAME_TWO"$cRESET
        echo -e $cRESET"\tPress$cBRED y$cRESET to use the current ${cBRED}WAN IP ${cRESET}or enter ${cBMAG}$NAME_ONE${cRESET} Endpoint IP or DDNS name or press$cBGRE [Enter] to SKIP."
        read -r "ANS"
        if [ "$ANS" == "y" ];then
            if [ -z "$(ip route show table main | grep -E "^0\.|^128\.")" ];then
                local ROUTER_DDNS=$(curl -${SILENT} ipecho.net/plain)                     # v3.01
            else
                echo -e $cRED"\a\n\tWarning: VPN is ACTIVE...cannot determine public WAN IP address!!!"
            fi
            [ -z "$ROUTER_DDNS" ] && ROUTER_DDNS="${NAME_ONE}_DDNS_$HARDWARE_MODEL"
        else
            if [ -n "$ANS" ] && [ ${#ANS} -gt 1 ] && [ $(echo "$ANS" | tr -cd "." | wc -c ) -ge 1 ];then
                local ROUTER_DDNS="$ANS"
            fi
        fi

        [ -z "$ROUTER_DDNS" ] && local ROUTER_DDNS=$NAME_ONE".DDNS"

    fi

    cat > ${CONFIG_DIR}${NAME_TWO}.conf << EOF
# $NAME_TWO - $SITE_TWO_LAN
[Interface]
PrivateKey = $SITE_TWO_PRI_KEY
Address = $SITE_TWO_IP
ListenPort = $((LISTEN_PORT+1))

# $NAME_ONE LAN
[Peer]
PublicKey = $SITE_ONE_PUB_KEY
AllowedIPs = $SITE_ONE_IP, $SITE_ONE_LAN
Endpoint = $ROUTER_DDNS:$LISTEN_PORT
#PresharedKey = $PRE_SHARED_KEY
PersistentKeepalive = 25
EOF

    chmod 600 ${CONFIG_DIR}${NAME_TWO}.conf         # v4.15 Prevent wg-quick "Warning: '/opt/etc/wireguard.d/Cabin.conf' is world accessible"

    if [ -n "$ADD_SITE" ];then
        # Bind the remote site to the host
        [ -n "$WG_INTERFACE" ] && Manage_Peer "peer" "$WG_INTERFACE" "bind" "$NAME_TWO"
    fi

    echo -e "\n========== $NAME_ONE configuration =====================================================\n"$cRESET
    cat ${CONFIG_DIR}${NAME_ONE}.conf

    echo -e "\n========== $NAME_TWO configuration =====================================================\n"
    cat ${CONFIG_DIR}${NAME_TWO}.conf

    echo -e "\n=======================================================================================\n"

    [ -n "$ADD_SITE" ] && local NAME_ONE=

    for FN in $NAME_ONE $NAME_TWO
        do
            LISTEN_PORT=$(awk '/^ListenPort/ {print $3}' /opt/etc/wireguard.d/$FN.conf)

            #echo -e $cBCYA"\tAdding WireGuard Site-to-Site Peer ${cBMAG}${FN}.conf PreUP/PostDown ${cBCYA}"$cRESET

            cat > /tmp/Site2Site.txt << EOF

# WireGuard (%p - ListenPort; %wan - WAN interface; %lan - LAN subnet; %net - IPv4 Tunnel subnet ONLY recognised by Martineau's WireGuard Manager/wg-quick2)

PostUp =   iptables -I INPUT -p udp --dport %p -j ACCEPT; iptables -I INPUT -i %i -j ACCEPT; iptables -I FORWARD -i %i -j ACCEPT
PostDown = iptables -D INPUT -p udp --dport %p -j ACCEPT; iptables -D INPUT -i %i -j ACCEPT; iptables -D FORWARD -i %i -j ACCEPT

EOF

            if [ "$ALLRULES" == "Y" ];then
                cat > /tmp/Site2Site.txt << EOF

# WireGuard (%p - ListenPort; %wan - WAN interface; %lan - LAN subnet; %net - IPv4 Tunnel subnet ONLY recognised by Martineau's WireGuard Manager/wg-quick2)
PreUp = iptables -I INPUT -p udp --dport %p -j ACCEPT
PreUp = iptables -I INPUT -i %i -j ACCEPT
PreUp = iptables -t nat -I PREROUTING -p udp --dport %p -j ACCEPT
PreUp = iptables -t nat -I POSTROUTING -s %net/24 -o br0 -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport %p -j ACCEPT
PostDown = iptables -D INPUT -i %i -j ACCEPT
PostDown = iptables -t nat -D PREROUTING -p udp --dport %p -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s %net/24 -o br0 -j MASQUERADE

# Firewall
PreUp = iptables -I INPUT   -i %i -j ACCEPT
PreUp = iptables -I FORWARD -i %i -j ACCEPT
PreUp = iptables -I FORWARD -o %i -j ACCEPT
PreUp = iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

PostDown = iptables -D INPUT   -i %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
PostDown = iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

EOF
            fi

            sed -i '/^ListenPort/r /tmp/Site2Site.txt' /opt/etc/wireguard.d/$FN.conf

        done

    [ -n "$NAME_ONE" ] && local JOIN_TXT=" and " || JOIN_TXT=
    echo -e $cBGRE"\n\tWireGuard Site-to-Site Peers ${cBMAG}${NAME_ONE}${JOIN_TXT}${NAME_TWO}${cBGRE} created\n"$cRESET

    echo -en "\n\tCopy ${cBMAG}${NAME_TWO}/${NAME_ONE}${cRESET} files: "$cBCYA

    if [ -n "$(which 7z)" ];then                                                                        # v4.15
        cd ${CONFIG_DIR}
        rm ${CONFIG_DIR}WireGuard_${NAME_TWO}.7z 2>/dev/null
        local FILES=$(ls ${CONFIG_DIR} | grep -E "${NAME_TWO}*\.*|${NAME_ONE}*\.*" | tr '\n' ' ')

        for FILE in $FILES
            do
                7z a -bso0 ${CONFIG_DIR}WireGuard_$NAME_TWO "$FILE"                                     # v4.15
            done

        echo -e "${cRESET}(included in ZIP ${cBMAG}'"${CONFIG_DIR}WireGuard_${NAME_TWO}.7z"')\n"        # v4.15
        7z l ${CONFIG_DIR}WireGuard_${NAME_TWO}.7z | grep -F "....A"
        #echo -e "\t\t$cBMAG"$FILES "${cRESET}included in ZIP $cBMAG '"${CONFIG_DIR}WireGuard_${NAME_TWO}.7z"'"
    else
        echo -e $cBMAG"\n"
        ls -l ${CONFIG_DIR} | grep -v "7z" | grep -E "${NAME_TWO}*\.*|${NAME_ONE}*\.*"                  # v4.15
    fi

    echo -e ${cBCYA}${cRESET}"\n\tto remote location\n"
    echo -e ${cBCYA}${cRESET}"\n\tImport ${cBMAG}${NAME_ONE}.conf${cRESET} on remote site using 'import ${NAME_ONE} type=device'\n\n"    # v4.15

    echo -e $cRESET"\tPress$cBRED y$cRESET to import ${cBMAG}$NAME_ONE${cRESET} or press$cBGRE [Enter] to SKIP."
    read -r "ANS"
    if [ "$ANS" == "y" ];then
        Import_Peer "import" $NAME_ONE "type=server"
        sqlite3 $SQL_DATABASE "UPDATE servers SET auto='S' WHERE peer='$IMPORTED_PEER_NAME';"   # v4.15
        # Create a 'device' for SiteB so the IP is recorded
        sqlite3 $SQL_DATABASE "INSERT into devices values('$NAME_TWO','X','$SITE_TWO_IP','','$SITE_ONE_IP, $SITE_ONE_LAN','$SITE_TWO_PUB_KEY','$SITE_TWO_PRI_KEY','# $NAME_TWO Site-to-Site LAN $SITE_TWO_LAN','0');"
    fi

}
Build_Menu() {
    if [ -z "$SUPPRESSMENU" ];then
        # Generate dynamically context aware menu
        if [ "$(WireGuard_Installed)" == "Y" ];then
            # Currently using 3rd-Party/Entware Kernel module or intention in 'WireguardVPN.conf' to do so? then Highlight 'Update' option...
            if [ -n "$(opkg list-installed | grep "wireguard-kernel")" ] || [ -n "$(grep -oE "^USE_ENTWARE_KERNEL_MODULE" ${INSTALL_DIR}WireguardVPN.conf)" ];then  # v4.12
                MENU_I="$(printf '%b1 %b = %bUpdate%b WireGuard® modules' "${cBYEL}" "${cRESET}" "${cBGRE}" "${cRESET}")"
            else
                # lowlight but don't disable option if firmware contains WireGuard module.
                MENU_I="$(printf '%b1 %b = %bUpdate%b WireGuard® modules' "${cBYEL}" "${cRESET}" "${cBGRA}" "${cBGRA}")"
            fi

            if [ -n "$(opkg list-installed | grep "wireguard-kernel")" ] || [ -n "$(opkg status wireguard-kernel | awk '/^Installed/ {print $2}')" ];then   # v4.12
                MENU_Z="$(printf '%b2 %b = %bRemove%b WireGuard®/(wg_manager)\n' "${cBYEL}" "${cRESET}" "${cBRED}" "${cRESET}")"
            else
                MENU_Z="$(printf '%b2 %b = %bRemove%b WireGuard®/%b(wg_manager)\n' "${cBYEL}" "${cRESET}" "${cBRED}" "${cBGRA}" "${cRESET}")"
            fi
        else
            MENU_I="$(printf '%b1 %b = %bBegin%b WireGuard® Installation Process' "${cBYEL}" "${cRESET}" "${cBGRE}" "${cRESET}")"
        fi

        if [ "$(WireGuard_Installed)" == "Y" ];then

            MENU_VX="$(printf '%bv %b = View %b%s\n' "${cBYEL}" "${cRESET}" "$cBGRE" "('${INSTALL_DIR}WireguardVPN.conf')")"
            MENU_RS="$(printf '%brs%b = %bRestart%b (or %bStart%b) WireGuard® Sessions(%b)\n' "${cBYEL}" "${cRESET}" "$cBGRE" "${cRESET}" "$cBGRE" "${cRESET}" )"

            if [ -n "$(wg show interfaces)" ];then
                MENU_S="$(printf '%b4 %b = %bStart%b   [ [Peer [nopolicy]...] | category ] e.g. start clients \n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"        # v2.02
                MENU_L="$(printf '%b3 %b = %bList%b ACTIVE Peers Summary [Peer...] [full]\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
                MENU_T="$(printf '%b5 %b = %bStop%b    [ [Peer... ] | category ] e.g. stop clients\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
            else
                MENU_S="$(printf '%b4 %b = %bStart%b   [ [Peer [nopolicy]...] | category ] e.g. start clients \n' "${cBYEL}" "${cRESET}" "${cBGRE}" "${cRESET}")"        # v2.02
                MENU_L="$(printf '%b3 %b = %bList%b ACTIVE Peers Summary [Peer...] [full]\n' "${cBYEL}" "${cRESET}" "${cBGRA}" "${cBGRA}")"   # v2.03
                MENU_T="$(printf '%b5 %b = %bStop%b    [ [Peer... ] | category ] e.g. stop clients\n' "${cBYEL}" "${cRESET}" "${cBGRA}" "${cBGRA}")"
            fi
            MENU_R="$(printf '%b6 %b = %bRestart%b [ [Peer... ] | category ]%b e.g. restart servers\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
            MENU_Q="$(printf '%b7 %b = %bQRcode%b display for a Peer {device} e.g. iPhone%b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}" "${cRESET}")"   # v4.12
            MENU_P="$(printf '%b8 %b = %bPeer%b management [ "help" | "list" | "new" ] | [ {Peer | category} [ 'del' | 'show' | 'add' [{"auto="[y|n|p]}] ]%b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}" "${cRESET}")"
            MENU_C="$(printf '%b9 %b = %bCreate[split]%b Road-Warrior 'device' Peer for 'server' Peer {device [server]} e.g. create myPhone wg21%b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}" "${cRESET}")"
            MENU_IPS="$(printf '%b10 %b= %bIPSet%b management [ "upd" { ipset [ "fwmark" {fwmark} ] | [ "enable" {"y"|"n"}] | [ "dstsrc"] {src} ] }] %b' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}" "${cRESET}")"
            MENU_ISPIMP="$(printf '%b11 %b= %bImport%b WireGuard® configuration { [ "?" | [ "dir" directory ] | [/path/]config_file [ "name="rename_as ] ]} %b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}" "${cRESET}")"
            MENU_VPNDIR="$(printf '%b12 %b= %bvpndirector%b Clone VPN Director rules [ "clone" [ "wan" | "ovpn"n [ changeto_wg1n ]] | "delete" | "list" ] %b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}" "${cRESET}")" # v4.14
        fi

        MENU__="$(printf '%b? %b = About Configuration\n' "${cBYEL}" "${cRESET}")"
        echo -e ${cWGRE}"\n"$cRESET      # Separator line

        echo -e
        printf "%s\t\t\t\t\t\t%s\n"                 "$MENU_I" "$MENU_Q"

        if [ "$(WireGuard_Installed)" == "Y" ];then
            printf "%s\t\t\t\t\t%s\n"                   "$MENU_Z" "$MENU_P"
            printf "\t\t\t\t\t\t\t\t\t%s\n"                       "$MENU_C"
            printf "%s\t\t\t\t%s\n"                     "$MENU_L" "$MENU_IPS"       # v4.12
            printf "%s\t%s\n"                           "$MENU_S" "$MENU_ISPIMP"    # v4.12
            printf "%s\t\t%s\n"                         "$MENU_T" "$MENU_VPNDIR"    # v4.14
            printf "%s\t\t\t\t\t\t\t\t\t%s\n"           "$MENU_R"
            printf "\n%s\t\t\t\t\t\n"                   "$MENU__"
            printf "%s\t\t\n"                           "$MENU_VX"
        fi

        printf '\n%be %b = Exit Script [?]\n' "${cBYEL}" "${cRESET}"
    fi
}
Validate_User_Choice() {

    local menu1=$@

    # Translate v3.00 (restricted) Easy menu but Advanced mode commands remain for consistency backward compatibility.
    if [ "$EASYMENU" == "Y" ];then
        case "$menu1" in
            0) ;;
            10*|ipset*) menu1=$(echo "$menu1" | awk '{$1="ipset"}1') ;;
            11*|import*) menu1=$(echo "$menu1" | awk '{$1="import"}1') ;;
            12*|vpndirector*) menu1=$(echo "$menu1" | awk '{$1="vpndirector"}1') ;; # v4.14 v4.13
            13*|export*) menu1=$(echo "$menu1" | awk '{$1="export"}1') ;;
            1*|i)
                [ -z "$(ls ${INSTALL_DIR}*.ipk 2>/dev/null)" ]  && menu1="install "$(echo "$menu1" | awk '{print $2}') || menu1="getmodules";;
            2|z|remove) menu1="uninstall";; # v4.14
            3*|list*|show*) menu1=$(echo "$menu1" | awk '{$1="list"}1');;
            4*|start|start" "*) menu1=$(echo "$menu1" | awk '{$1="start"}1') ;;
            5*|stop|stop" "*) menu1=$(echo "$menu1" | awk '{$1="stop"}1') ;;
            6*|restart|restart" "*) menu1=$(echo "$menu1" | awk '{$1="restart"}1') ;;
            7*|qrcode*) menu1=$(echo "$menu1" | awk '{$1="qrcode"}1') ;;
            8*|peer|peer" "*) menu1=$(echo "$menu1" | awk '{$1="peer"}1') ;;
            9*) menu1=$(echo "$menu1" | awk '{$1="create"}1') ;;

            u|uf|uf" "*) ;;                           # v3.14
            "?") ;;
            v|vx) ;;
            createsplit*|create*) ;;
            ip) ;;                         # v3.03
            getmod*) ;;
            loadmod*) ;;
            dns*) ;;                       # v2.01
            firewallstart*) ;;             # v4.11
            alias*) ;;
            diag*) ;;
            debug) ;;
            initdb*|migrate*);;            # v4.01
            stats*);;
            wg|wg" "*) ;;
            scripts*) ;;                    # v4.01
            udpmon*) ;;                     # v4.01
            jump*|geo*|livin*) ;;           # v4.08 v4.07
            generatestats) ;;
            killsw*) ;;             # v2.03
            killinter*) ip link del dev $(echo "$menu1" | awk '{print $2}'); menu1=;;
            rpfilter*|rp_filter*);; # v4.11
            useentware*|allowentware*);;    # v4.14
            fc*);;      # v4.14
            pgup*);;    # v4.14
            site2site*);; # v4.14
            raw" "*|print" "*|config" "*);; # v4.15
            "") ;;
            e*) ;;
            www*);;         # v4.15
            menu*);;        # v4.15
            color*|colour*);;        # v4.15
            addon*);;        # v4.15
            zip|zipinstall);;        # v4.15
            trimdb*);;        # v4.15
            ipv6*);;        # v4.16
            formatwg-quick*|formatwgquick*);;   # v4.16
            ipmon*);;                           # v4.16
            *)
               :
            ;;
        esac

        echo "$menu1"
    fi
}
Process_User_Choice() {

        local menu1=$@

        case "$menu1" in
            "")
                continue
            ;;
            0)
                Show_credits
                printf '|                                                                      |\n'
                printf '+======================================================================+\n'
            ;;
            e|exit)                                         # v3.23
                [ -n "$(echo "$menu1" | grep -E "e.*\?")" ] && exit_message "0" || exit_message
                break
                ;;
            diag*|list*|show*)

                local ACTION="$(echo "$menu1"| awk '{print $1}')"

                local ARG=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                fi

                if [ -n "$(which wg)" ];then

                    if [ "$ACTION" == "diag" ];then
                        #[ -z "$ARG" ] && Show_Peer_Status "full"             # v3.04 Hotfix
                        [ -z "$ARG" ] && { echo -e $cBYEL"\n\tWireGuard® VPN Peer Status"$cRESET; wg show all; }
                        Diag_Dump ${menu1#* }
                    else
                        Show_Peer_Status                    # v3.04 Hotfix
                    fi
                else
                    echo -en $cRED"\a\n\t";Say "Wireguard® VPN module 'wg' NOT installed\n"$cRESET
                    echo -e
                fi
                ;;
            install*)                                               # ['noscript']

                if [ -z "$(grep -i "WireGuard" /jffs/scripts/post-mount)" ];then        # v4.14
                    local ACTION="$(echo "$menu1"| awk '{print $2}')"
                    Install_WireGuard_Manager $ACTION                                   # v4.14
                else

                    Download_Modules $HARDWARE_MODEL
                    Load_UserspaceTool
                fi

                ;;

            alias*)                                                  # ['del']

                local ARG=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                fi
                Manage_alias "$ARG"                                     # v1.05

                ;;
            getmod*)                                                    # [dev]

                local ARG=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)" # v4.12
                fi

                Download_Modules $HARDWARE_MODEL "$ARG"                 # v4.12
                ;;
            loadmod*)

                Load_UserspaceTool
                ;;
            dns*)

                local ARG=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                fi

                Edit_DNSMasq "$ARG"                                   # v1.12
                DNSmasq_Listening_WireGuard_Status

                ;;
            createconfig)

                Create_Sample_Config

                ;;
            qrcode*)                                                    # {interface[.conf]}

                local ARG=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                fi

                if [ -n "$ARG" ];then
                    [ -z "$(echo "$ARG" | grep -E "\.conf$")" ] && SUFFIX=".conf"
                    [ -f  ${CONFIG_DIR}${ARG}${SUFFIX} ] && Display_QRCode "${CONFIG_DIR}${ARG}${SUFFIX}" "y" || echo -e $cBRED"\a\n\t***ERROR Invalid Peer config '${CONFIG_DIR}${ARG}${SUFFIX}'\n"$cRESET       # v1.05
                else
                    echo -e $cBRED"\a\n\t***ERROR Missing/invalid Peer config\n"$cRESET
                fi

                ;;
            z|uninstall)

                local ANS=
                local WG_TXT="WireGuard/WireGuard Manager"
                [ -f /usr/sbin/wg ] && local WG_TXT="WireGuard Manager"     # WireGuard's in firmware; can't be removed
                echo -e "\n\tPress$cBRED Y$cRESET to$cBRED Remove $WG_TXT ${cRESET}or press$cBGRE [Enter] to cancel request." # v4.14  @ZebMcKayhan
                read -r "ANS"
                if [ "$ANS" == "Y" ];then       # v4.14 @ZebMcKayhan
                    Uninstall_WireGuard
                else
                    echo -e $cBYEL"\n\a\tUninstall...request ABORTED (${cBRED}'Y'$cRESET response not confirmed.)"$RESET
                fi

                ;;
            createsplit*|create*)                                                            # {name} [{tag="desciption{"}}]     # v1.11 v1.03
                # Create a Private/Public key-pair for your mobile phone etc.
                #           e.g. create   Nokia6310 tag="Best phone ever!"
                #
                #  Default Allowed IP is '0.0.0.0/0, ::/0' which forces ALL traffic via the remote 'server' Peer
                #  but 'createlanonly' routes only the 'server' Per LAN e.g. LAN 192.68.0.0/24

                local ACTION="$(echo "$menu1"| awk '{print $1}')"

                local ARG=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                fi

                if [ "$ARG" == "help" ];then
                    echo -e "\n\tcreate help\t\t\t\t\t\t\t\t- This text"
                    echo -e "\tcreate[split] {device_name [server_name] [options]}\t\t\t- Create 'device' Peer and bind to 'server' Peer wg21 e.g. create SGS22 tag=\"My Samsung phone\""
                    echo -e "\tcreate device_name ipv6\t\t\t\t\t\t\t- Create 'device' Peer and include IPv6 'AllowedIPs = ::/0' e.g. create iPhone12 ipv6"
                    echo -e "\tcreate device_name ipv6 ips=ipv4/ipv6_ip_subnet\t\t\t\t- Override 'AllowedIPs = 0.0.0.0/0, ::/0' e.g. create iPhone ipv6 ips=192.168.5.0/24,fdaa:abcd:cdef::/64"
                    echo -e "\tcreate device_name server_name dns=local\t\t\t\t- Create 'device' Peer with local (private) DNS e.g. create Pixel6 wg24 dns=local"
                    echo -e "\tcreatesplit device_name\t\t\t\t\t\t\t- Create 'device' Peer with LAN access ONLY (say 192.168.1.0/24) e.g. createsplit Pixel6"
                else
                    if [ -z "$(echo "$ARG" | tr -cd \"\')" ];then   # v4.14 Peer name can't contain single/double quotes
                        Create_RoadWarrior_Device $menu1
                    else
                        echo -e $cBRED"\a\n\t***ERROR Peer '$ARG' contains quotes\n"$cRESET
                    fi
                fi
                ;;
            "?"|u|u" "*|uf|uf" "*)

                local ACTION="$(echo "$menu1"| awk '{print $1}')"

                Show_Info_HDR

                case "$ACTION" in
                    "?")
                        Show_Info
                        ;;
                    *)
                        [ "$2" == "dev" ] && DEV="dev" || DEV="main"
                        DOWNLOAD="N"

                        echo -e
                        if [ -z "$(echo "$ACTION" | grep -E "^uf")" ];then          # v4.12
                            Check_Module_Versions
                        else
                            Check_Module_Versions "force"                           # v4.12
                        fi

                        if [ "$ACTION" == "uf" ];then
                            echo -e ${cRESET}$cWRED"\n\tForced Update"$cRESET"\n"
                            DOWNLOAD="Y"
                        else
                            Check_Version_Update
                            [ $? -eq 1 ] && DOWNLOAD="Y"        # '2' means 'Push to GitHub' pending! ;-;
                        fi

                        if [ "$DOWNLOAD" == "Y" ];then
                            # Protect against curl download failures i.e. Github DOWN
                            cp $0 $0.u                                             # v3.03
                            Get_scripts "$DEV"

                            Manage_Addon "wgmExpo.sh"       # v4.15 @ZeMcKayhan's Addon

                            [ -f ${INSTALL_DIR}$SCRIPT_NAME ] && { rm $0.u; sleep 1; exec "$0"; } || mv $0.u $0     # v4.14

                            # Never get here!!!
                            echo -e $cRESET
                        fi
                        ;;
                esac
                ;;
            firewallstart*)

                local ARG=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                fi

                if [ -f /jffs/scripts/nat-start ];then
                    [ -n "$(grep -o "WireGuard" /jffs/scripts/nat-start)" ] && sed -i '/WireGuard/d' /jffs/scripts/nat-start    # v4.11 Legacy use of nat-start
                fi
                Edit_firewall_start "$ARG"      # v4.11

                ;;
            "-h"|help)

                    ShowHelp
                ;;
            vx|v)                                                                   # v1.10

                    FN="${INSTALL_DIR}WireguardVPN.conf"

                    [ "$menu1" == "v" ] && ACCESS="--view" || ACCESS="--unix"
                    if [ -f $FN ];then
                        #PRE_MD5="$(md5sum $FN | awk '{print $1}')"
                        nano $ACCESS $FN
                    else
                        echo -e $cBRED"\a\n\t***ERROR WireGuard® Peer Configuration '$FN' NOT found\n"$cRESET
                    fi

            ;;
            peer|peer" "*)                                           # peer [ 'list' | interface { [auto y|n|p ] 'del' | 'add' | 'comment' {'#'comment}'} | 'bind' {peer} ]  # v1.10

                Manage_Peer $menu1

                ;;
            restart|restart" "*|stop|stop" "*|start|start" "*)       # start [ Peer [policy] | [client|server]] ]

                Manage_Wireguard_Sessions $menu1

            ;;
            debug)

                if [ -z "$DEBUGMODE" ];then
                    DEBUGMODE="$(echo -e ${cRESET}$cWRED"Debug mode enabled"$cRESET)"
                else
                    DEBUGMODE=
                fi
            ;;
            wg|wg" "*)                                              # v4.04
                # Expose the WireGuard Userspace Tool
                echo -e $cBWHT"\n\tWireGuard® Userspace Tool:\n"
                $menu1
            ;;
            killsw*)

                local ARG=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                fi

                Parse "$(Manage_KILL_Switch "$ARG")" "_" RC TEMP_PERM

                [ "$RC" == "Y" ] && echo -e $cBGRE"\n\t[✔] WireGuard® WAN KILL-Switch "${cBGRE}${aREVERSE}"${TEMP_PERM} ENABLED"$cRESET" (use 'vx' command for info)" || echo -e $cBRED"\n\t[✖] ${cBGRE}WireGuard WAN KILL-Switch "${cBRED}${aREVERSE}"${TEMP_PERM} DISABLED"$cRESET" (use 'vx' command for info)"
            ;;
            ip)

                Show_VPN_Pool                       # v3.03

            ;;
            initdb*|migrate*)                                                  # v4.01

                Initialise_SQL $menu1

            ;;
            stats*)                                                             # stats [ enable | disable ]    # v4.01

                echo -e
                Manage_Stats $menu1

            ;;
            udpmon*)                                                            # udpmon [ enable | disable ]   # v4.01

                if [ "$(Manage_UDP_Monitor $menu1)" == "Y" ];then
                    echo -e $cBGRE"\n\t[✔]${cBWHT} UDP ${cBGRE}monitor is ENABLED$cRESET"
                else
                    echo -e $cRED"\n\t[✖]${cBWHT} UDP ${cBGRE}monitor is ${cBRED}${aREVERSE}DISABLED$cRESET"
                fi

            ;;
            import*)

                Import_Peer $menu1                                              # v4.01
                Manage_Peer
            ;;
            export*)
                # Internal GUI peers ONLY - generate .conf from NVRAM variables
                Export_Peer $menu1                                              # v4.12
                #Manage_Peer
            ;;
            scripts*)

                Manage_Event_Scripts $menu1                                     # v4.01
            ;;
            ipset*)

                Manage_IPSET $menu1

            ;;
            generatestats*)
                CRON_PERIOD="Y"                     # v4.16
                Show_Peer_Status "generatestats"
                CRON_PERIOD=                        # v4.16
            ;;
            jump*|geo*|livin*)                                                         # livin { @home | * | {[France | wg14]} {LAN device}     # v4.07
                shift
                local LOCATION=$1
                shift
                local IP=$1

                [ -z "$IP" ] && { echo -en $cRED"\a\n\t***ERROR: LAN Host name or LAN IP address required'\n"$cRESET ; return 1; }

                if [ -z "$(echo "$IP" | Is_IPv4)" ] && [ -z "$(echo "$IP" | Is_IPv4_CIDR)" ];then
                    # Assume Hostname... so does it have a DHCP Reserved LAN IP?
                    [ -f /etc/dnsmasq.conf ] && local IP=$(grep -i "$IP" /etc/dnsmasq.conf | awk -F',' '{print $4}')    # v4.15
                else
                    # Allow known IPs / CIDR
                    local LAN_SUBNET=$(nvram get lan_ipaddr | grep -o '^.*\.')                          # v4.15
                    local MATCH_SUBNET=$(echo "$IP" | grep -o '^.*\.')                                  # v4.15
                    if [ "$MATCH_SUBNET" == "$LAN_SUBNET" ] || \
                       [ "$(nvram get vpn_server1_sn | grep -o '^.*\.')" == "$MATCH_SUBNET" ] || \
                       [ "$(nvram get vpn_server2_sn | grep -o '^.*\.')" == "$MATCH_SUBNET" ] || \
                       [ -n "$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers WHERE subnet LIKE '$MATCH_SUBNET%';")" ] || \
                       [ -n "$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE ip LIKE '$MATCH_SUBNET%';")" ];then        # v4.15 WireGuard
                        :
                    else
                        IP=
                    fi
                fi

                [ -z "$IP" ] && { echo -en $cRED"\a\n\t***ERROR: $cRESET'$1'$cBRED Invalid IPv4 address! - must be $cRESET'$LAN_SUBNET*'$cBRED or local VPN Server/client IP\n"$cRESET ; return 1; }

                if [ "$LOCATION" != "@home" ] && [ "$LOCATION" != "*" ];then
                    local WG_INTERFACE=$LOCATION
                    # If a Peer wasn't specified, scan the Policy Peers for a description match?
                    [ ! -f ${CONFIG_DIR}${WG_INTERFACE}.conf ] && local WG_INTERFACE=$(sqlite3 $SQL_DATABASE "SELECT peer FROM clients WHERE tag LIKE '%$WG_INTERFACE%';")   # v4.02

                    if [ -n "$WG_INTERFACE" ];then
                        if [ "$(sqlite3 $SQL_DATABASE "SELECT auto FROM clients WHERE peer='$WG_INTERFACE';")" == "P" ];then
                            if [ -n "$(wg show interfaces | grep -o "$WG_INTERFACE")" ];then    # v4.12
                                # v4.12 Remove the DNS redirection if it exists .....
                                local I=$(iptables-save -t nat | grep -m 1 -F "$IP" | grep -o "WGDNS[1-5]" | grep -o "[1-5]")
                                local DNS=$(iptables-save -t nat | grep -F "$IP" | grep WGDNS | awk '{print $NF}')
                                [ -n "$I" ] && iptables -t nat -D WGDNS${I} -s $IP -j DNAT --to-destination $DNS -m comment --comment "WireGuard 'client${I} DNS'"  # v4.12 @ZebMcKayhan
                                # Remove 'livin' from Policy database
                                sqlite3 $SQL_DATABASE "DELETE FROM policy WHERE srcip='$IP' AND tag LIKE '%Expat livin%' ;"

                                local I=$(echo "$WG_INTERFACE" | grep -oE "[1-9]*$")
                                [ ${#I} -gt 2 ] && local I=${I#"${I%??}"} || local I=${I#"${I%?}"}
                                local DNS=$(sqlite3 $SQL_DATABASE "SELECT dns FROM clients WHERE peer='$WG_INTERFACE';")
                                local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM clients WHERE peer='$WG_INTERFACE';")
                                local PRIO=$(ip rule | awk -v pattern="$IP" 'match($0, pattern) {print $1}')
                                ip rule del from $IP prio $PRIO 2>/dev/null
                                # Live in......
                                ip rule add from $IP table 12${I}
                                # Add 'livin' to Policy database
                                sqlite3 $SQL_DATABASE "INSERT INTO policy values('$WG_INTERFACE','VPN','$IP','Any','## Expat livin temporarily $DESC ##');"
                                iptables -t nat -A WGDNS${I} -s $IP -j DNAT --to-destination $DNS -m comment --comment "WireGuard 'client${I} DNS'"
                                echo -e $cBGRE"\n\t[✔] Welcome Expat to '$DESC'\n"$cRESET
                            else
                                echo -en $cRED"\a\n\t***ERROR: ${cBMAG}${WG_INTERFACE}${cRED} not ACTIVE\n"$cRESET
                            fi
                        else
                            echo -en $cRED"\a\n\t***ERROR: ${cBMAG}${WG_INTERFACE} not in Policy mode\n"$cRESET
                        fi
                    else
                        echo -en $cRED"\a\n\t***ERROR: No match for destination '$LOCATION'\n"$cRESET
                    fi
                else
                    # Return to wherever...
                    local PRIO_LIST=$(ip rule | grep -w "$IP" | awk -F '[:]' '{print $1}' | tr '\n' ' ')            # v4.08
                    for PRIO in $PRIO_LIST
                        do
                            ip rule del from $IP prio $PRIO 2>/dev/null
                        done

                    # v4.12 Remove the DNS redirection.....
                    # Remove 'livin' from Policy database
                    sqlite3 $SQL_DATABASE "DELETE FROM policy WHERE srcip='$IP' AND tag LIKE '%Expat livin%' ;"
                    local DNS=$(iptables-save -t nat | grep -F "$IP" | grep WGDNS | awk '{print $NF}')
                    local I=$(iptables-save -t nat | grep -m 1 -F "$IP" | grep -o "WGDNS[1-5]" | grep -o "[1-5]")
                    [ -n "$I" ] && iptables -t nat -D WGDNS${I} -s $IP -j DNAT --to-destination $DNS -m comment --comment "WireGuard 'client${I} DNS'"  # v4.12 @ZebMcKayhan
                    echo -e $cBGRE"\n\t[✔] Welcome home Sir!!!\n"$cRESET
                fi
            ;;
            rpfilter*|rp_filter*)                                               # v4.11 as per OpenVPN allow source to reply over different interface if route defined
                local ARG=
                local ACTION=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ACTION="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                fi
                case $ACTION in
                    1|2|disable|enable|""|"?")
                        local WAN_IF=$(Get_WAN_IF_Name)
                        if [ "$ACTION" != "?" ];then
                            [ "$ACTION" == "disable" ] && { local VAL=2; local TXT="DISABLED"; }
                            [ "$ACTION" == "enable" ]  && { local VAL=1; local TXT="ENABLED";  }
                            [ -z "$ACTION" ] && local VAL=1             # default is to re-enable the router's Reverse Path Filtering feature

                            local TXT=$TXT" ($VAL)"
                            echo $VAL> /proc/sys/net/ipv4/conf/$WAN_IF/rp_filter
                            echo -e $cBGRE"\n\t [✔] Reverse Path Filtering $TXT\n"$cRESET
                        else
                            local VAL=$(cat /proc/sys/net/ipv4/conf/$WAN_IF/rp_filter)
                            [ "$VAL" == "1" ] && STATE="ENABLED" || STATE="DISABLED"
                            local TXT="value is "$VAL" ("$STATE")"
                            echo -e $cBGRE"\n\t [ℹ ] Reverse Path Filtering $TXT\n"$cRESET
                        fi
                    ;;
                    *)
                        echo -en $cRED"\a\n\t***ERROR: Invalid Reverse Path Filter request $cBWHT'"$ARG"'$cBRED - use 'disable|enable'\n"$cRESET
                    ;;
                esac
            ;;
            vpndirector*)                   # v4.13 'vpndirector [ clone [ 'wan' | ovpnc_num [ changeto_vpn_num]]| delete | list]'

                Manage_VPNDirector_rules $menu1
                [ $? -eq 1 ] && Manage_VPNDirector_rules list   # Show VPN Director rules for successful 'clone'

            ;;
            useentware*|allowentware*)      # v4.14 'allowentware [on | off | yes | no]'

                local ACTION="$(echo "$menu1"| awk '{print $2}')"

                if [ -f ${INSTALL_DIR}WireguardVPN.conf ] &&  [ -n "$(grep -oE "USE_ENTWARE_KERNEL_MODULE" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                case $ACTION in
                    on|yes)
                        sed -i 's/^#USE_ENTWARE_KERNEL_MODULE/USE_ENTWARE_KERNEL_MODULE/' ${INSTALL_DIR}WireguardVPN.conf
                        echo -e $cBGRE"\n\t[✔] Use 3rd-party Entware Kernel/Userspace Tools modules ALLOWED\n"$cRESET
                ;;
                    off|no)
                        sed -i 's/^USE_ENTWARE_KERNEL_MODULE/#USE_ENTWARE_KERNEL_MODULE/' ${INSTALL_DIR}WireguardVPN.conf
                        echo -e $cRED"\n\t[✖]${cBGRE}  Use 3rd-party Entware Kernel/Userspace Tools modules ${cBRED}DENIED\n"$cRESET
                ;;
                    *)
                    echo -en $cRED"\a\n\t***ERROR: Invalid arg $cBWHT'"$ACTION"'$cBRED for 'Use Entware Module' request  - valid 'on' or 'off' only!\n"$cRESET
                ;;
                esac
                else
                    echo -en $cRED"\a\n\t***ERROR: Use Entware Module request $cBWHT'"$ACTION"'$cBRED feature not available!\n"$cRESET
                fi
            ;;
            fc*)                            # v4.14 ALlow management of Flow Cache setting
                local ACTION="$(echo "$menu1"| awk '{print $2}')"

                case "$ACTION" in

                    enable|disable|"?")
                        echo -e "\n$(Manage_FC "$ACTION")"
                        [ "$ACTION" == "disable" ] && echo -e $cBWHT"\t(Use '${cBCYA}vx$cBWHT' command to uncomment config option '${cBCYA}DISABLE_FLOW_CACHE$cBWHT' to DISABLE permanently)\n"$cRESET  # v4.16
                    ;;
                    *)
                        echo -e $cRED"\a\n\t***ERROR: Flow Cache arg $cBWHT'"$ACTION"'$cBRED invalid - 'enable' or 'disable' or '?' ONLY"$cRESET
                    ;;
                esac
            ;;
            pgup*)                            # v4.14 Allow management of Pg-Up key command retrieval
                local ACTION="$(echo "$menu1"| awk '{print $2}')"

                case $ACTION in
                    on|yes)
                        [ -f ${INSTALL_DIR}WireguardVPN.conf ] && sed -i 's/^NOPG_UP/#NOPG_UP/' ${INSTALL_DIR}WireguardVPN.conf
                        echo -e $cBGRE"\n\t[✔] Use of 'PG-Up' key for command retrieval ENABLED\n"$cRESET
                        READLINE="Readline"
                        # Restart wireguard_manager ?
                        exec "$0" "$@"
                ;;
                    off|no)
                        [ -f ${INSTALL_DIR}WireguardVPN.conf ] && sed -i 's/^#NOPG_UP/NOPG_UP/' ${INSTALL_DIR}WireguardVPN.conf
                        echo -e $cRED"\n\t[✖]${cBGRE}  Use of 'PG-Up' key for command retrieval ${cBRED}DISABLED\n"$cRESET
                        READLINE=
                ;;
                    *)
                    echo -en $cRED"\a\n\t***ERROR: Invalid arg $cBWHT'"$ACTION"'$cBRED for 'Use Pg-Up key command retrieval - valid 'on' or 'off' only!\n"$cRESET
                ;;
                esac
            ;;
            site2site*)                     # v4.14

                Create_Site2Site $menu1     # [ [name1] [name2] ['ip='ip_for_name1] ['port='listen_port_for_name1] ['lan='siteb_subnet] ]
            ;;
            raw" "*|print" "*|config" "*)   # v4.15             {['raw' | 'print' | 'config']' peer} ['all']

                shift
                local WG_INTERFACE=$1
                local ACTION=$2

                if [ -n "ls ${CONFIG_DIR}${WG_INTERFACE}*" ];then

                     [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ]        && { echo -e "\n\t================Config==============="; cat ${CONFIG_DIR}${WG_INTERFACE}.conf; }
                     if [ -n "$ACTION" ];then
                         [ -f ${CONFIG_DIR}${WG_INTERFACE}_public.key ]  && { echo -e "\n\t================Public==============="; cat ${CONFIG_DIR}${WG_INTERFACE}_public.key; }
                         [ -f ${CONFIG_DIR}${WG_INTERFACE}_private.key ] && { echo -e "\n\t================Private=============="; cat ${CONFIG_DIR}${WG_INTERFACE}_private.key; }
                     fi
                else
                    echo -en $cRED"\a\n\t***ERROR: ${cBMAG}${WG_INTERFACE}${cRED} not found\n"$cRESET
                fi
            ;;
            www" "*|www)                        # v4.15       www [ [ {on | off | mount | unmount} ] [rom] ]

                local PAGE=$SCRIPT_NAME".asp"

                local ACTION=$2
                local PAGES=$3

                [ -z "$ACTION" ] && local ACTION="debug"

                [ "$PAGES" == "rom" ] && { local PAGES="Advanced_WireguardClient_Content.asp Advanced_WireguardServer_Content.asp Advanced_VPN_OpenVPN.asp"; local INTERNAL_PAGE="internal ROM"; }

                case "$ACTION" in
                    mount|on)
                        echo -e $cBGRE
                        if [ -z "$INTERNAL_PAGE" ];then
                            Mount_WebUI "${PAGE}"
                        else

                            LOCKFILE=/tmp/addonwebui.lock
                            FD=386
                            eval exec "$FD>$LOCKFILE"
                            flock -x "$FD"

                            for PAGE in $PAGES
                                do
                                    umount /www/${PAGE} 2>/dev/null
                                    echo -en $cBRED
                                    mount -o bind ${INSTALL_DIR}${PAGE} /www/${PAGE}
                                    if [ $? -eq 0 ];then
                                        echo -e $cBGRE"\tCustom '$PAGE' mounted"$cRESET
                                        SayT "Custom '${INSTALL_DIR}${PAGE}' page mounted"
                                    fi
                                done

                            # ************************************** Temporary *********************************************
                            sed -i '/Advanced_WireguardClient_Content.asp/s~__INHERIT__.*$~WireGuard© Client"},\t/\*Martineau Hack\*/~' /tmp/menuTree.js
                            sed -i '/Advanced_WireguardServer_Content.asp/s~__INHERIT__.*$~WireGuard© Server"},\t/\*Martineau Hack\*/~'  /tmp/menuTree.js
                            echo -e $cBRED"\tAdvancedWireGuard[Client|Server] /tmp/menuTree.js Martineau Hack!"$cRESET
                            SayT "AdvancedWireGuard[Client|Server] /tmp/menuTree.js Martineau Hack!"
                            # ************************************** Temporary *********************************************

                            flock -u "$FD"
                        fi
                        echo -e $cRESET
                    ;;
                    unmount|off)
                        echo -e $cBGRE
                        if [ -z "$INTERNAL_PAGE" ];then
                            Unmount_WebUI "${PAGE}"
                        else
                            LOCKFILE=/tmp/addonwebui.lock
                            FD=386
                            eval exec "$FD>$LOCKFILE"
                            flock -x "$FD"

                            for PAGE in $PAGES
                                do
                                    umount /www/${PAGE} 2>/dev/null
                                    if [ $? -eq 0 ];then
                                        echo -e $cBGRE"\tCustom '$PAGE' page unmounted"$cRESET
                                        SayT "Custom '${INSTALL_DIR}${PAGE}' page unmounted"
                                    fi
                                done

                            sed -i '/Advanced_WireguardClient_Content.asp/s/WireGuard© Client\"\},.*$/__INHERIT__\"},/' /tmp/menuTree.js
                            sed -i '/Advanced_WireguardServer_Content.asp/s/WireGuard© Server\"\},.*$/__INHERIT__\"},/' /tmp/menuTree.js
                            echo -e $cBGRE"\tAdvancedWireGuard[Client|Server] /tmp/menuTree.js Martineau Hack ${cBRED}DELETED!"$cRESET
                            SayT "AdvancedWireGuard[Client|Server] /tmp/menuTree.js Martineau Hack DELETED"

                            flock -u "$FD"
                        fi
                        echo -e $cRESET
                    ;;
                    debug)
                        echo -e $cRESET
                        df | grep -E "/www/|File"
                        echo -e $cBCYA
                        ls -lh /www/ext/user*.* | sort -k 8 ;echo -e $cRESET;grep -THE "user[1-9]\." /tmp/menuTree.js | sort -k 3
                    ;;
                    *)
                        echo -en $cRED"\a\n\t***ERROR: Invalid arg $cBWHT'"$ACTION"'$cBRED for GUI TAB - valid 'mount' or 'unmount' only!\n"$cRESET
                    ;;
                esac

            ;;
            menu" "*|menu)                          # v4.15         menu { [show|on] | [hide|off] }

                local ACTION=$2

                case "$ACTION" in
                    show|on)
                        SUPPRESSMENU=
                    ;;
                    hide|off)
                        SUPPRESSMENU="Suppress"
                    ;;
                esac
            ;;
            colour" "*|color" "*)                   # v4.15         {colour|color}  { [show|on] | [hide|off] }

                local ACTION=$2

                case "$ACTION" in
                    show|on)
                        ANSIColours
                        if [ -f ${INSTALL_DIR}WireguardVPN.conf ] &&  [ -n "$(grep -oE "^NOCOLOUR" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                            sed -i 's/^NOCOLOUR/#NOCOLOUR/' ${INSTALL_DIR}WireguardVPN.conf
                        fi
                    ;;
                    hide|off)
                        ANSIColours "disable"
                        if [ -f ${INSTALL_DIR}WireguardVPN.conf ] &&  [ -n "$(grep -oE "^#NOCOLOUR" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                            sed -i 's/^#NOCOLOUR/NOCOLOUR/' ${INSTALL_DIR}WireguardVPN.conf
                        fi
                    ;;
                esac
            ;;
            addon|addon*)                           # v4.15         {script_name [ dev | remove | del ] }

                shift

                local FN=$1
                local ACTION=$2;local BRANCH=$2

                echo -e

                case $ACTION in
                    del|remove)

                        if [ -f ${INSTALL_DIR}${FN} ];then
                            Manage_Addon "$FN" "$ACTION"
                            echo -e $cBGRE"\tAddon $cRESET'$FN'$cBGRE removed"$cRESET
                            SayT "Addon '${INSTALL_DIR}${FN}' removed"
                        else
                            echo -en $cRED"\a\t***ERROR: Addon $cRESET'$FN'$cBRED NOT found!\n"$cRESET
                        fi
                    ;;
                    *)
                        Manage_Addon "$FN" "$BRANCH"        # v4.15
                    ;;
                esac

            ;;
            zip|zip" "install)
                echo -e "\n\t"$cBGRA
                opkg install p7zip      # v4.15
            ;;
            trimdb*)                                                # trimdb { '?' | days [ 'traffic' | 'sessions'] ['auto']  } | [cron {number_of_days}]
                if [ "$2" == "cron" ];then                          # v4.16
                    [ -z "$3" ] && local DAYS=90 || DAYS=$3         # v4.16
                    cru d WireGuard_DB 2>/dev/null                  # v4.16
                    if [ $DAYS -gt 0 ];then
                        cru a WireGuard_DB "0 7 * * 6 /jffs/addons/wireguard/wireguard_manager.sh trimdb $DAYS"     # v4.16
                        echo -e $cBGRE"\n\t[✔] Cron schedule to trim WireGuard® SQL Database created $cBWHT(07:00 every Sunday)$cBGRE older than ${cBWHT}$DAYS${cBGRE} days)\n"$cRESET   # v4.16
                    else
                        echo -e $cBRED"\n\t[✖] ${cBGRE}Cron schedule to trim WireGuard® SQL Database ${cBRED}DELETED\n"$cRESET
                    fi
                else
                    Purge_Database $menu1   # v4.15
                fi
            ;;
            ipv6|ipv6" "*)                                          # ipv6 [ '?' | 'spoof' | 'simulate' | 'disable'  | {'gen' [['un]loadmodule'] ['ula']}]

                local ARG=$2
                local TYPE=$3
                local TMPMODULE=

                [ "$TYPE" = "loadmodule" ] && { echo -en $cBGRA"\n";opkg install coreutils-date; shift; local TYPE=$3 ;}
                [ "$TYPE" = "unloadmodule" ] && { echo -en $cBGRA"\n\t";opkg remove coreutils-date; return ;}

                if [ "$ARG" != "ula" ] && [ "$ARG" != "gen" ] && [ "$ARG" != "generate" ];then # v4.16
                    case $ARG in
                        spoof|simulate)
                            $(nvram set ipv6_service="$ARG")            # v4.16
                            echo -e $cBGRE"\n\t[✔] IPv6 Service SET $cBGRE'$ARG'"$cRESET
                        ;;
                        "?")
                            :
                        ;;
                        6to4|6in4|6rd|native|ipv6pt|dhcp6)
                            :
                        ;;
                        "disable")
                            if [ "$(nvram get ipv6_service)" == "spoof" ] || [ "$(nvram get ipv6_service)" == "simulate" ];then
                                $(nvram set ipv6_service="disabled")    # v4.16
                                echo -e $cBGRE"\n\t[✔] IPv6 Service SET ${cRED}DISABLED!"$cRESET
                            fi
                        ;;
                        *)
                             [ -n "$ARG" ] && echo -en $cBRED"\n\a\t***ERROR: Arg invalid! $cBWHT'$ARG' - specify  '?', 'spoof' or 'disable'!\n"$cRESET
                        ;;
                    esac

                    [ "$(nvram get ipv6_service)" == "disabled" ] && echo -e $cBRED"\n\t[✖]${cBWHT} IPv6 Service is ${cBRED}DISABLED$cRESET" || echo -e $cBGRE"\n\t[✔]${cBWHT} IPv6 Service is ${cBRED}$(nvram get ipv6_service)"$cRESET    # v4.16
                else
                    if [ ! -f /opt/bin/date ];then
                        SayT "Warning IPv6 ULA generate function requires Entware 'date' module (coreutils-date)...temporarily loading"
                        echo -e $cRED"\n\tWarning IPv6 ULA generate function requires Entware 'date' module.....')"
                        echo -en $cBGRA;opkg install coreutils-date
                        local TMPMODULE="Y"
                    fi

                    local IPV6_ULA=$(Generate_IPv6_ULA "ula")   # ALWAYS request true ULA 'fdxx'
                    [ "$TMPMODULE" == "Y" ] && { echo -en $cBGRA"\t";opkg remove coreutils-date ;}
                    [ -n "$(echo "$IPV6_ULA" | grep -F ":")" ] && echo -e ${cGRE}"\n\tOn $(date +%c), Your IPv6 ULA is $cBWHT'"${IPV6_ULA}"'$cBYEL (Use $cBWHT'$(echo $IPV6_ULA | sed 's/^../aa/')'$cBYEL for Dual-stack IPv4+IPv6)"${cRESET} || echo -e ${cBRED}"\a\n\t*** ERROR.. $(which date)"${cRESET}
                fi
            ;;
            formatwg-quick*|formatwgquick*)                     # formatwg-quick [ config_file[.conf] ]

                local CONFIGS=$2

                if [ -z "$CONFIGS" ];then
                    local CONFIGS=$(ls -1 ${CONFIG_DIR}*.conf 2>/dev/null | awk -F '/' '{print $5}' | grep "wg[1-2]" | sort )
                else
                    if [ ! -f ${CONFIG_DIR}$CONFIGS ] && [ -f ${CONFIG_DIR}${CONFIGS}.conf ];then
                        local CONFIGS=$CONFIGS.conf
                    fi
                fi

                echo -e $cRESET"\n\tChecking Peer Config for conversion to wg-quick format:\n\n${cBCYA}$CONFIGS\n"

                local CONVERTED="N"
                for CONF in ${CONFIGS//,/ }
                    do
                        local FN=${CONFIG_DIR}$CONF

                        if [ -f $FN ];then
                            if [ $(grep -cE "^#Address" $FN) -eq 1 ];then
                                sed -i 's/^#Address/Address/' $FN; local CONVERTED="Y"
                            else
                                if [ $(grep -cE "^#Address" $FN) -gt 1 ];then
                                    echo -en $cRESET"\tPress$cBRED y$cRESET to$cBRED convert $cBCYA'$CONF' multiple $cBRED'#Address' ${cBWHT}directives${cRESET} or press$cBGRE [Enter] to SKIP: "
                                    read -r "ANS"
                                    [ "$ANS" == "y" ] && sed -i 's/^#Address/Address/' $FN; local CONVERTED="Y"
                                fi
                            fi
                            if [ $(grep -cE "^#DNS" $FN) -eq 1 ];then
                                sed -i 's/^#DNS/DNS/' $FN; local CONVERTED="Y"
                            else
                                if [ $(grep -cE "^#DNS" $FN) -gt 1 ];then
                                    echo -en $cRESET"\tPress$cBRED y$cRESET to$cBRED convert $cBCYA'$CONF' multiple $cBRED'#DNS' ${cBWHT}directives${cRESET} or press$cBGRE [Enter] to SKIP: "
                                    read -r "ANS"
                                    [ "$ANS" == "y" ] && sed -i 's/^#DNS/DNS/' $FN; local CONVERTED="Y"
                                fi
                            fi

                            if [ $(grep -cE "^#Pre[UD]" $FN) -eq 1 ] || [ $(grep -cE "^#Post" $FN) -eq 1 ];then
                                sed -i 's/^#PreU/PreU/; s/^#PreD/PreD/; s/^#Post/Post/' $FN; local CONVERTED="Y"
                            else
                                if [ $(grep -cE "^#Pre[UD]" $FN) -gt 1 ] || [ $(grep -cE "^#Post" $FN) -gt 1 ];then
                                    echo -en $cRESET"\tPress$cBRED y$cRESET to$cBRED convert $cBCYA'$CONF' multiple $cBRED'#Pre/#Post' ${cBWHT}directives${cRESET} or press$cBGRE [Enter] to SKIP: "
                                    read -r "ANS"
                                    [ "$ANS" == "y" ] && { sed -i 's/^#Post/Post/; s/^#PreU/PreU/; s/^#PreD/PreD/' $FN; local CONVERTED="Y" ;}
                                fi
                            fi

                            [ "$CONVERTED" == "Y" ] && { local CONVERTED="N"; echo -e $cBGRE"\t[✔] $cBCYA'$CONF'$cBGRE converted to $cBWHT'wg/wg-quick' format"$cRESET  ;}
                        else
                            echo -en $cRED"\n\a\t***ERROR: $cRESET'$FN'$cBRED NOT found!\n"$cRESET
                        fi
                    done

            ;;
            ipmon*)                                 #   ipmon [wg_interface]

                local ARG=$2
                [ -n "$(wg show interfaces | grep -wo "$ARG")" ] && THIS="dev "$ARG || THIS=
                echo -e "\n\t\t${cBGRE}Press CTRL-C to stop iproute2 monitor\n"$cRESET
                trap 'Process_User_Choice' INT
                ip -ts monitor label $THIS
            ;;
            *)
                printf '\n\a\t%bInvalid Option%b "%s"%b Please enter a valid option\n' "$cBRED" "$cRESET" "$menu1" "$cBRED"    # v4.03 v3.04 v1.09
            ;;
        esac

}
Purge_Database() {

    # trimdb { '?' | days [ 'traffic' | 'sessions'] ['auto']  }

    local ANS=
    [ -n "$(echo "$@" | grep -io "auto")" ] && local AUTOREPLY="Y"

    local DAYS=$2

    local TABLES_TXT="(traffic and sessions)"

    local TABLE=$3
    [ "$TABLE" == "auto" ] && TABLE=

    [ -z "$TABLE" ] && TABLE="All"

    case $TABLE in
        traffic|session|All)
        :
        ;;
        *)
         echo -e $cBRED"\a\n\t***ERROR: SQL database table $cRESET'$TABLE'$cBRED NOT found! - use 'traffic' or 'session'\n"$cRESET
         return 1
        ;;
    esac

    if [ "$DAYS" == "?" ];then

        [ "$TABLE" == "All" ] && TABLE="traffic session"

        echo -e

        for THIS in $TABLE

            do
                local OCNT=$(sqlite3 $SQL_DATABASE "SELECT Count(*) FROM $THIS;")
                local OLDEST_EPOCH_SECS=$(sqlite3 $SQL_DATABASE "SELECT timestamp FROM $THIS order by timestamp limit 1;")
                echo -e $cRESET"\tTable ${cBCYA}${THIS}$cRESET: oldest "${cBCYA}$(date -d @"$OLDEST_EPOCH_SECS" "+%c")$cRESET" records ${cBCYA}${OCNT}${cRESET}"
            done

        return
    fi

    if [ -n "$DAYS" ] && [ -n "$(echo "$DAYS" | grep -Eo "[[:digit:]]*")" ];then

        local TABLES_TXT="($TABLE)"

        local NOW=$(date "+%s")
        local EPOCH_SECS=$((DAYS*86400))
        local OLDEST_EPOCH_SECS=$((NOW-EPOCH_SECS))

        echo -e "\n\t$TABLES_TXT statistics Records older than "${cBCYA}$(date -d @"$OLDEST_EPOCH_SECS" "+%c")${cRESET}" will be erased from SQL database"
        [ "$TABLE" == "All" ] && TABLE="traffic session"

        if [ -z "$AUTOREPLY" ];then
            echo -e "\tPress$cBRED y$cRESET to$cBRED DELETE database records${cRESET} or press$cBGRE [Enter] to SKIP."
            read -r "ANS"
        else
            local ANS="y"
        fi

        if [ "$ANS" == "y" ];then
            echo -e
            for THIS in $TABLE
                do
                    local OCNT=$(sqlite3 $SQL_DATABASE "SELECT Count(*) FROM $THIS;")
                    sqlite3 $SQL_DATABASE "DELETE FROM $THIS WHERE timestamp <='$OLDEST_EPOCH_SECS';"
                    local NCNT=$(sqlite3 $SQL_DATABASE "SELECT Count(*) FROM $THIS;")
                    [ $OCNT -eq $NCNT ] && echo -e "$cRED\t $((OCNT-NCNT)) $THIS records deleted" || echo -e "$cBGRE\t $((OCNT-NCNT)) $THIS records deleted"
                done
        fi
    else
        echo -en $cBRED"\a\n\t***ERROR: Numbers of days $cRESET'$DAYS'$cBRED invalid!\n"$cRESET
    fi

}
Get_WebUI_Installed() {
    md5_installed="0"
    if [ -f $installedMD5File ]; then
        md5_installed="$(cat $installedMD5File)"
    fi
}
Get_WebUI_Page(){
    MyPage="none"
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        page="/www/user/user$i.asp"
        if [ -f "$page" ] && [ "$(md5sum < "$1")" = "$(md5sum < "$page")" ]; then
            MyPage="user$i.asp"
            return
        elif [ "$MyPage" = "none" ] && [ ! -f "$page" ]; then
            MyPage="user$i.asp"
        fi
    done
}
Mount_WebUI(){
    if nvram get rc_support | grep -qF "am_addons"; then

        local PAGE=$1                                                       # Martineau Hack

        ### locking mechanism code credit to Martineau (@MartineauUK) ###
        LOCKFILE=/tmp/addonwebui.lock
        FD=386
        eval exec "$FD>$LOCKFILE"
        flock -x "$FD"

        Get_WebUI_Installed
        Get_WebUI_Page "$SCRIPT_DIR/$PAGE" "$md5_installed"                         # Martineau Hack
        if [ "$MyPage" = "none" ]; then
            echo -e $cBRED"\aUnable to mount $SCRIPT_NAME WebUI page, exiting"$cRESET
            flock -u "$FD"
            return 1                                                                # Martineau Hack
        fi

        echo -en $cBRED                                                             # Martineau Hack

        cp -f "$SCRIPT_DIR/$PAGE" "$SCRIPT_WEBPAGE_DIR/$MyPage"                     # Martineau Hack
        #echo "Saving MD5 of installed file $SCRIPT_DIR/$PAGE to $installedMD5File" # Martineau Hack
        md5sum < "$SCRIPT_DIR/$PAGE" > $installedMD5File                            # Martineau Hack

        if [ ! -f "/tmp/index_style.css" ]; then
            cp -f "/www/index_style.css" "/tmp/"
        fi

        if ! grep -q '.menu_Addons' /tmp/index_style.css ; then
            echo ".menu_Addons { background: url(ext/shared-jy/addons.png); }" >> /tmp/index_style.css
        fi

        umount /www/index_style.css 2>/dev/null
        mount -o bind /tmp/index_style.css /www/index_style.css

        if [ ! -f "/tmp/menuTree.js" ]; then
            cp -f "/www/require/modules/menuTree.js" "/tmp/"
        fi

        sed -i "\\~$MyPage~d" /tmp/menuTree.js

        if ! grep -q 'menuName: "Addons"' /tmp/menuTree.js ; then
            lineinsbefore="$(( $(grep -n "exclude:" /tmp/menuTree.js | cut -f1 -d':') - 1))"
            sed -i "$lineinsbefore"'i,\n{\nmenuName: "Addons",\nindex: "menu_Addons",\ntab: [\n{url: "ext/shared-jy/redirect.htm", tabName: "Help & Support"},\n{url: "NULL", tabName: "__INHERIT__"}\n]\n}' /tmp/menuTree.js
        fi

        if grep -q "javascript:window.open('/ext/shared-jy/redirect.htm'" /tmp/menuTree.js ; then
            sed -i "s~javascript:window.open('/ext/shared-jy/redirect.htm','_blank')~javascript:var helpwindow=window.open('/ext/shared-jy/redirect.htm','_blank')~" /tmp/menuTree.js
        fi
        if ! grep -q "javascript:var helpwindow=window.open('/ext/shared-jy/redirect.htm'" /tmp/menuTree.js ; then
            sed -i "s~ext/shared-jy/redirect.htm~javascript:var helpwindow=window.open('/ext/shared-jy/redirect.htm','_blank')~" /tmp/menuTree.js
        fi
        sed -i "/url: \"javascript:var helpwindow=window.open('\/ext\/shared-jy\/redirect.htm'/i {url: \"$MyPage\", tabName: \"WireGuard Manager\"}," /tmp/menuTree.js

        umount /www/require/modules/menuTree.js 2>/dev/null
        mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js

        echo -e $cBGRE"\t$SCRIPT_NAME WebUI page mounted as $cRESET'"$MyPage"'"     # Martineau Hack
        SayT "$SCRIPT_NAME WebUI page mounted as $cRESET'"$MyPage"'"                # Martineau Hack

        flock -u "$FD"
    fi
}
Unmount_WebUI(){

    local PAGE=$1                                                       # Martineau Hack

    ### locking mechanism code credit to Martineau (@MartineauUK) ###
    LOCKFILE=/tmp/addonwebui.lock
    FD=386
    eval exec "$FD>$LOCKFILE"
    flock -x "$FD"

    Get_WebUI_Installed
    Get_WebUI_Page "$SCRIPT_DIR/$PAGE" "$md5_installed"                 # Martineau Hack
    if [ "$md5_installed" != "0" ];then                                 # Martineau Hack
        #echo "$MyPage"                                                 # Martineau Hack
        if [ -n "$MyPage" ] && [ "$MyPage" != "none" ] && [ -f "/tmp/menuTree.js" ]; then
            sed -i "\\~$MyPage~d" /tmp/menuTree.js
            umount /www/require/modules/menuTree.js
            mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js
            rm -rf "$SCRIPT_WEBPAGE_DIR/$MyPage"
            rm -rf "$SCRIPT_WEB_DIR"
            echo -e $cBGRE"\t$SCRIPT_NAME WebUI page $cRESET'"$MyPage"'${cBGRE} unmounted${cRESET}"     # Martineau Hack
            SayT "$SCRIPT_NAME WebUI page $cRESET'"$MyPage"' unmounted" # Martineau Hack
        fi
    else
        echo -e $cRED"\a\t$SCRIPT_NAME WebUI page not mounted! $cRESET" # Martineau Hack
    fi

    rm "$installedMD5File" 2>/dev/null                                  # Martineau Hack

    flock -u "$FD"
}
Show_Main_Menu() {

        Show_credits

        if [ "$(WireGuard_Installed)" == "Y" ];then
            HDR="N"
            printf '+======================================================================+'   # 2.13
        fi

        #
        while true; do

            # If WireGuard already installed then no need to display FULL HDR - stops confusing idiot users ;-:
            if [ "$HDR" == "ForceDisplay" ];then
                HDR=                                        # Show the header Splash box in FULL
                Show_credits
            fi

            # No need to display the Header box every time....
            if [ -z "$HDR" ];then
                Display_SplashBox
                HDR="N"
            fi

            local STATUS_LINE="WireGuard® ACTIVE Peer Status: "$(Peer_Status_Summary)                  # v3.04 v2.01
            [ -n "$(echo "$(Manage_KILL_Switch)" | grep -F "Y_")" ] && local KILL_STATUS="${cBGRE}${aREVERSE}KILL-Switch ACTIVE$cRESET" || local KILL_STATUS="                 " # v4.12
            echo -e $cRESET"\n"${KILL_STATUS}"\t${cRESET}${cBMAG}${STATUS_LINE}"$cRESET

            if [ -z "$NOCHK" ];then
                [ "$CHECK_GITHUB" != "N" ] && Check_Version_Update      # v2.01
                CHECK_GITHUB="N"
            fi

            if [ "$1" = "uninstall" ]; then
                menu1="z"
            else
                Build_Menu
            fi

            # Show 'E[asy]'/'A[dvanced]' mode, and does the selection require ENTER?
            if [ "$EASYMENU" == "N" ];then
               TXT="A:"
               #printf '\n%b%s%bOption ==>%b ' "$cBCYA" "$TXT" "${cBYEL}" "${cRESET}"
            else
               TXT="E:"
               #printf '\n%b%s%bPress desired Option key (no ENTER key reqd.) %bOption ==>%b ' "$cBCYA" "$TXT" "${cBYEL}" "${cRESET}" "${cBYEL}"
            fi
            local PROMPT=${TXT}$DEBUGMODE"Option ==> "
            local PROMPT_SIZE=${#PROMPT}
            printf '\n%b%s%bOption ==>%b ' "$cBCYA" "${TXT}$DEBUGMODE" "${cBYEL}" "${cRESET}"
            echo -en $xCSRPOS

            [ "$READLINE" == "ReadLine" ] && Read_INPUT || read -r "CMDLINE"

            menu1="$CMDLINE"

            local TXT=
            unset $TXT
            HDR="N"

            [ -n "$DEBUGMODE" ] && set -x

            menu1=$(printf "%s" "$menu1" | sed 's/^[ \t]*//;s/[ \t]*$//')       #  Old-skool strip leading/trailing spaces

            menu1=$(Validate_User_Choice $menu1)

            Process_User_Choice $menu1

            #echo -en ${cWGRE}"\n"$cRESET      # Separator line
set +x
        done
}
Create_RoadWarrior_Device() {

    local DEVICE_NAME=$2

    local DEVICE_USE_IPV6="N"                      # v4.16

    local TAG="$(echo "$@" | sed -n "s/^.*tag=//p" | awk '{print $0}')"
    local ADD_ALLOWED_IPS="$(echo "$@" | sed -n "s/^.*ips=//p" | awk '{print $0}')"

    # use dns=local or dns=push to use LAN DNS
    local DNS_RESOLVER="$(echo "$@" | sed -n "s/^.*dns=//p" | awk '{print $0}')"        # v3.04 Hotfix
    if [ "$DNS_RESOLVER" == "push" ] || [ "$DNS_RESOLVER" == "local" ];then             # v4.16
        local PUSHDNS="Y"                                                               # v4.16
        local DNS_RESOLVER=                                                             # v4.16
    fi

    local REMOTE_LISTEN_PORT="$(echo "$@" | sed -n "s/^.*port=//p" | awk '{print $0}')" # v4.14

    local SERVER_PEER=
    local PEER_TOPOLOGY="device"    # 4.14

    while [ $# -gt 0 ]; do          # v3.03
        case "$1" in
            create*)
                ACTION=$1
            ;;
            wg*)
                SERVER_PEER=$1
            ;;
            peer*)
                local ALLOW_TUNNEL_PEERS="Y"        # v4.11
            ;;
            site=*)
                local SITE2SITE="$(echo "$@" | sed -n "s/^.*site=//p" | awk '{print $0}')"  # v4.14
                case $SITE2SITE in                                                          # v4.15
                    [nN])
                        local SITE2SITE=$(echo "$SITE2SITE" | tr 'a-z' 'A-Z')               # v4.15 disable device Multi Site-to-Site
                    ;;
                    remoteonly)
                        local SITE2SITE_PEER_LAN=$SITE2SITE                                 # v4.15
                    ;;
                    *)
                        echo -e $cBRED"\a\n\t***ERROR: Invalid 'site=$SITE2SITE' arg - 'n' or 'remoteonly' "$cRESET
                        return 1
                    ;;
                esac
            ;;
            ipv6|ipv6=*)
                #local VPN_POOL6="$(echo "$1" | sed -n "s/^.*ipv6=//p" | awk '{print $1}')"
                # Ensure IPv6 address is in standard compressed format
                #[ -n "$VPN_POOL6" ] && VPN_POOL6="$(IPv6_RFC "$VPN_POOL6")" # v4.15
                local DEVICE_USE_IPV6="Y"                      # v4.16
            ;;
        esac
        shift
    done

    # If user did not specify 'server' Peers, use the oldest 'server' Peer found ACTIVE or the first (usually wg21) defined in the SQL database
    [ -z "$SERVER_PEER" ] && SERVER_PEER=$(wg show interfaces | grep -vE "wg1" | grep -vE "wgs")    # v4.12
    [ -z "$SERVER_PEER" ] && SERVER_PEER=$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers order by peer;" | head -n 1)
    [ -z "$SERVER_PEER" ] && { echo -e $cBRED"\a\n\t***ERROR: no 'server' Peers specified or found (wg2*)"$cRESET; return 1; }
    for SERVER_PEER in $SERVER_PEER
        do
            # Is it ACTUALLY a 'server' Peer?                       # v1.08
            # A Site-to-Site 'server' Peer can have an Endpoint"    # v4.14
            if [ -f ${CONFIG_DIR}${SERVER_PEER}.conf ];then         # v4.14
                continue
            else
                echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard® 'server' Peer '$SERVER_PEER'\n"$cRESET
                return 1
            fi
        done

    if [ "$SITE2SITE" != "N" ] && [ "$(sqlite3 $SQL_DATABASE "SELECT auto FROM servers WHERE peer='$SERVER_PEER';")" == "S" ];then  # v4.15
        local SITE2SITE="Y"                                 # v4.14
        local PEER_TOPOLOGY="device Multi Site-to-Site"     # v4.14
        local TAG=$PEER_TOPOLOGY
        local SITE_PEER=$(awk '/^#.*LAN/ {print $2}' ${CONFIG_DIR}${SERVER_PEER}.conf )     # v4.15
    fi

    if [ "$SITE2SITE" == "Y" ];then
        [ -z "$SITE_PEER" ] && SITE_PEER="SiteB"
        [ ! -f ${CONFIG_DIR}${SITE_PEER}.conf ] && { echo -e $cBRED"\a\n\t***ERROR: $PEER_TOPOLOGY 'server' Peer $cRESET'$SITE_PEER'$cBRED NOT found!"$cRESET; return 1; }
    fi

    # createsplit xxxxx 'peers'
    [ "$ACTION" == "createsplit" ] && SPLIT_TUNNEL="Y" || SPLIT_TUNNEL="Q. Split Tunnel"                       # v1.11 v1.06

    if [ -n "$DEVICE_NAME" ];then

        if [ ! -f ${CONFIG_DIR}${DEVICE_NAME} ] && [ -z "$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE name='$DEVICE_NAME';")" ];then
                echo -e $cBCYA"\n\tCreating Wireguard Private/Public key pair for $PEER_TOPOLOGY '${cBMAG}${DEVICE_NAME}${cBCYA}'"$cBYEL
                wg genkey | tee ${CONFIG_DIR}${DEVICE_NAME}_private.key | wg pubkey > ${CONFIG_DIR}${DEVICE_NAME}_public.key
                echo -e $cBYEL"\t$PEER_TOPOLOGY '"${cBMAG}${DEVICE_NAME}${cBYEL}"' Peer ${cBCYA}Public${cBYEL}     key="$(cat ${CONFIG_DIR}${DEVICE_NAME}_public.key)$cRESET
                umask 077
                wg genpsk > ${CONFIG_DIR}${DEVICE_NAME}_pre-shared.key                  # v4.12 or openssl rand -base64 32 > ${CONFIG_DIR}${SERVER_PEER}_pre-shared.key
                local PRE_SHARED_KEY=$(cat ${CONFIG_DIR}${DEVICE_NAME}_pre-shared.key)  # v4.12
                echo -e $cBYEL"\t$PEER_TOPOLOGY '"${cBMAG}${DEVICE_NAME}${cBYEL}"' Peer ${cBCYA}Pre-shared${cBYEL} key="$(cat ${CONFIG_DIR}${DEVICE_NAME}_pre-shared.key)$cRESET   # v4.14 v4.12

                #local PRE_SHARED_KEY=$(Convert_Key "$PRE-SHARED_KEY")                  # v4.12

                # Generate the Peer config to be imported into the device
                local PUB_KEY=$(cat ${CONFIG_DIR}${DEVICE_NAME}_public.key)

                local PUB_SERVER_KEY=
                # Use the Public key of the designated 'server' Peer
                # For instant testing the 'server' Peer needs to be restarted? # v1.06
                if [ -n "$SERVER_PEER" ];then
                    local PUB_SERVER_KEY=$(cat ${CONFIG_DIR}${SERVER_PEER}_public.key)                  # v1.06
                    [ "$SITE2SITE_PEER_LAN" != "remoteonly" ] && echo -e $cBCYA"\tUsing Public key for 'server' Peer '"${cBMAG}${SERVER_PEER}${cBCYA}

                    # Use the 'server' Peer LISTEN_PORT rather than default to 51820
                    local LISTEN_PORT=$(awk '/^ListenPort/ {print $3}' ${CONFIG_DIR}${SERVER_PEER}.conf)                # v3.04
                fi

                local PRI_KEY=$(cat ${CONFIG_DIR}${DEVICE_NAME}_private.key)
                local ROUTER_DDNS=$(nvram get ddns_hostname_x)

                # If no formal DDNS...ask what to do
                if [ -z "$ROUTER_DDNS" ];then
                    echo -e $cRED"\a\tWarning: No DDNS is configured!"
                    echo -e $cRESET"\tPress$cBRED y$cRESET to$cBRED use the current WAN IP or enter DDNS name or press$cBGRE [Enter] to SKIP."
                    read -r "ANS"
                    if [ "$ANS" == "y" ];then
                        if [ -z "$(ip route show table main | grep -E "^0\.|^128\.")" ];then
                            ROUTER_DDNS=$(curl -${SILENT} ipecho.net/plain)                     # v3.01
                        else
                            echo -e $cRED"\a\tWarning: VPN is ACTIVE...cannot determine public WAN IP address!!!"
                        fi
                        [ -z "$ROUTER_DDNS" ] && ROUTER_DDNS="YOUR_DDNS_$HARDWARE_MODEL"
                    else
                        if [ -n "$ANS" ] && [ ${#ANS} -gt 1 ] && [ $(echo "$ANS" | tr -cd "." | wc -c ) -ge 1 ];then
                            ROUTER_DDNS="$ANS"
                        fi
                    fi

                fi

                local CREATE_DEVICE_CONFIG="Y"
                if [ -f ${CONFIG_DIR}${DEVICE_NAME}.conf ];then
                    echo -e $cRED"\a\tWarning: Peer device '${cBMAG}${DEVICE_NAME}${cRED}' WireGuard® config already EXISTS!"
                    echo -e $cRESET"\tPress$cBRED y$cRESET to$cBRED ${aBOLD}CONFIRM${cRESET}${cBRED} Overwriting Peer device '${cBMAG}$DEVICE_NAME.config${cRESET}' or press$cBGRE [Enter] to SKIP."
                    read -r "ANS"
                    [ "$ANS" != "y" ] && CREATE_DEVICE_CONFIG="N"
                fi

                #[ -z "$VPN_POOL_IP" ] && local VPN_POOLS=$(sqlite3 $SQL_DATABASE "SELECT subnet FROM servers WHERE peer='$SERVER_PEER';")
                local VPN_POOLS=$(sqlite3 $SQL_DATABASE "SELECT subnet FROM servers WHERE peer='$SERVER_PEER';")

                for VPN_POOL in $(echo "$VPN_POOLS" | tr ',' ' ')       # v4.15
                    do
                        if [ -z "$(echo "$VPN_POOL" | grep -F ":")" ];then      # v4.15 Hotfix @ZebMcKayhan
                            #local VPN_POOL_PREFIX=$(echo "$VPN_POOL" | sed 's/\:\:.*$//')
                            #if [ -z "$VPN_POOL_IP" ];then
                                if [ -n "$VPN_POOL" ];then
                                    local VPN_POOL_IP=${VPN_POOL%/*}
                                    local VPN_POOL_SUBNET=${VPN_POOL%.*}

                                    local IP=$((${VPN_POOL_IP##*.}+1))     # v4.16 Use the 'server' (BASE IP)+1 rather than assume '.2' @ZebMcKayhan

                                    while true
                                        do
                                            local MATCHES="$(sqlite3 $SQL_DATABASE "SELECT ip FROM devices WHERE ip LIKE '%${VPN_POOL_SUBNET}.${IP}/32%';" | tr '\n' ' ')"  # v4.15 v4.11 v4.02
                                            for MATCH in $MATCHES
                                                do
                                                    MATCH=$(echo "$MATCH" | tr ',' ' ')
                                                    local DUPLICATE=$(echo "$MATCH" | grep -ow "${VPN_POOL_SUBNET}.${IP}/32")
                                                    [ -z "$DUPLICATE" ] && break || local IP=$((IP+1))
                                                done

                                            if [ $IP -ge 255 ];then
                                                echo -e $cBRED"\a\t***ERROR: 'server' Peer ($SERVER_PEER) subnet MAX 254 reached '${INSTALL_DIR}WireguardVPN.conf'"
                                                exit 97
                                            fi

                                            [ -z "$MATCHES" ] && break
                                        done

                                        local VPN_POOL_IP4=$VPN_POOL_SUBNET"."$IP"/32"  # v4.15
                                else
                                    echo -e $cBRED"\a\t***ERROR: 'server' Peer ($SERVER_PEER) subnet NOT defined 'device' Peers?"
                                    return 1
                                fi
                            #fi
                        else
                            local DEVICE_USE_IPV6="Y"
                            local VPN_POOL_IP=${VPN_POOL%/*}
                            local VPN_POOL_MASK=${VPN_POOL##*/}                     # v4.15
                            local VPN_SUBNET=${VPN_POOL_IP%:*}
                            local VPN_IP_EXPANDED=$(Expand_IPv6 "${VPN_POOL%/*}")   # v4.15
                            local VPN_IP_COMPRESSED=$(Compress_IPv6 "${VPN_IP_EXPANDED}")
                            local VPN_POOL_PREFIX_EXPANDED=${VPN_IP_EXPANDED%:*}    # v4.15
                            local VPN_POOL_PREFIX_COMPRESSED=$(Compress_IPv6 "${VPN_POOL_PREFIX_EXPANDED}")

                            local IP=$((${VPN_POOL_IP##*:}+1))        # v4.16 Use the 'server' (BASE IP)+1 rather than assume '.2' @ZebMcKayhan

                            while true
                                do
                                    local MATCH="$(sqlite3 $SQL_DATABASE "SELECT ip FROM devices WHERE ip LIKE '%${VPN_POOL_PREFIX_COMPRESSED}${IP}/128%';" | tr ',' ' ')"  # v4.15 v4.11 v4.02
                                    local DUPLICATE=$(echo "$MATCH" | grep -ow "${VPN_POOL_PREFIX_COMPRESSED}${IP}/128")
                                    [ -z "$DUPLICATE" ] && break || local IP=$((IP+1))

                                    if [ $IP -ge 255 ];then
                                        echo -e $cBRED"\a\t***ERROR: 'server' Peer ($SERVER_PEER) IPv6 subnet MAX 254 imposed!'"
                                        exit 98
                                    fi

                                    [ -z "$MATCH" ] && break

                                done

                            local VPN_POOL_IP6=${VPN_POOL_PREFIX_COMPRESSED}$IP"/128"   # v4.15

                        fi
                    done

                VPN_POOL_IP=$VPN_POOL_IP4                                       # v4.15
                if [ "$DEVICE_USE_IPV6" == "Y" ] && [ -n "$VPN_POOL_IP6" ];then        # v4.16 v4.15
                    [ "$SPLIT_TUNNEL" != "Y" ] && local IPV6=", ::/0"                                         # v4.15
                    if [ -n "$VPN_POOL_IP" ];then                               # v4.15
                        local VPN_POOL_IP=$VPN_POOL_IP","$VPN_POOL_IP6          # v4.15
                        local IPV6_TXT="(IPv4/IPv6) "                           # v4.15
                    else
                        local VPN_POOL_IP=$VPN_POOL_IP6                         # v4.15
                        local IPV6_TXT="(IPv6) "                                # v4.15
                    fi
                fi

                # Should the Peer ONLY have access to LAN ? e.g. 192.168.1.0/24         # v1.06
                # NOTE: These are routes, so a savvy user could simply tweak the Allowed IPs to 0.0.0.0/0 on his Peer device!!!
                #       Allowed IPs - outbound is routing table; inbound is ACL
                #
                if [ "$SPLIT_TUNNEL" == "Y" ];then

                    local LAN_ADDR=$(nvram get lan_ipaddr)
                    local LAN_SUBNET=${LAN_ADDR%.*}

                    # Any other custom routes say to a specific server on the LAN?
                    [ -z "$ADD_ALLOWED_IPS" ] && local IP=$LAN_SUBNET".0/24" || local IP=$LAN_SUBNET".0/24,"$ADD_ALLOWED_IPS

                    local SPLIT_TXT="# Split Traffic LAN Only"

                    # Should we EXPLICITLY allow access to ALL other VPN Tunnel Peers?
                    if [ "$ALLOW_TUNNEL_PEERS" == "Y" ];then            # v4.11
                        local TUNNEL_PEERS=$VPN_POOL_SUBNET".0/24, "    # v4.11
                        [ "$DEVICE_USE_IPV6" == "Y" ] && local TUNNEL_PEERS=$TUNNEL_PEERS", "$(nvram get ipv6_rtr_addr) # v4.16
                        SPLIT_TXT=$SPLIT_TXT", but Road-Warrior Peer-to-Peer allowed"   # v4.11
                    fi

                else
                    # Default route ALL traffic via the remote 'server' Peer
                    local IP="0.0.0.0/0"
                    [ "$DEVICE_USE_IPV6" == "Y" ] && local IPV6=", ::/0"
                    local SPLIT_TXT="# ALL Traffic"
                fi

                local ALLOWED_IPS=${TUNNEL_PEERS}${IP}${IPV6}           # v4.11

                # User specifed DNS ?
                if [ -z "$DNS_RESOLVER" ];then                                                      # v3.04 Hotfix
                    if [ "$SITE2SITE" != "Y" ];then
                        if [ -z "$PUSHDNS" ];then
                            local DNS_RESOLVER=$(nvram get wan0_dns | awk '{print $1}')                     # v3.04 Hotfix @Sh0cker54 #v3.04 Hotfix
                            if [ -z "$DNS_RESOLVER" ];then                                                  # v4.12 @underdose
                                echo -e $cRED"\a\tWarning: No DNS (${cBWHT}nvram get wan0_dns${cRED}) is configured! - will use ${cBWHT}${VPN_POOL_SUBNET}.1"   # v4.12 @underdose
                                local DNS_RESOLVER="${VPN_POOL_SUBNET}.1"                                   # v4.12 @underdose
                            fi
                            [ "$DEVICE_USE_IPV6" == "Y" ] && DNS_RESOLVER=$DNS_RESOLVER","$(nvram get ipv6_dns1)   # v4.16 v3.04 Hotfix
                        else
                            if [ "$PUSHDNS" == "Y" ];then
                                if [ -z "$IPV6_TXT" ] || [ -n "$(echo "$IPV6_TXT" | grep "IPv4")" ];then
                                    local DNS_RESOLVER="${VPN_POOL_SUBNET}.1"
                                fi

                                if [ "$DEVICE_USE_IPV6" == "Y" ] && [ -n "$VPN_POOL_IP6" ];then     # v4.16
                                    [ -n "$DNS_RESOLVER" ] && local DNS_RESOLVER=$DNS_RESOLVER", "$VPN_IP_COMPRESSED || DNS_RESOLVER=$VPN_IP_COMPRESSED     # v4.16
                                fi
                                local ALLOWED_IPS=$ALLOWED_IPS", "$DNS_RESOLVER                     # v4.16
                            fi
                        fi
                    else
                        local DNS_RESOLVER=${VPN_POOL_IP%.*}".1,1.1.1.1"                # v4.15
                        [ "$DEVICE_USE_IPV6" == "Y" ] && DNS_RESOLVER="2606:4700:4700::1111"                    # v4.16
                    fi
                fi

                [ -z "$DNS_RESOLVER" ] && local DNS_RESOLVER="${VPN_POOL_SUBNET}.1"

                # NOTE: A Road-Warrior Peer .config may have multiple '[PEER]' clauses to connect to several 'server' Peers concurrently!
                #       ( Will also need to define the appropriate additional 'server' Peer /24 subnets in the single 'Address' directive)
                if [ "$CREATE_DEVICE_CONFIG" == "Y" ];then
                    cat > ${CONFIG_DIR}${DEVICE_NAME}.conf << EOF
# $DEVICE_NAME $TAG
[Interface]
PrivateKey = $PRI_KEY
Address = $VPN_POOL_IP
DNS = $DNS_RESOLVER

# $HARDWARE_MODEL ${IPV6_TXT}'server' ($SERVER_PEER)
[Peer]
PublicKey = $PUB_SERVER_KEY
AllowedIPs = $ALLOWED_IPS     ${SPLIT_TXT}
# DDNS $ROUTER_DDNS
Endpoint = $ROUTER_DDNS:$LISTEN_PORT
PresharedKey = $PRE_SHARED_KEY
PersistentKeepalive = 25
# $DEVICE_NAME End
EOF

                    # Add device IP address and identifier to config
                    [ -z "$TAG" ] && TAG=$(echo -e "\"Device\"")                                   # v1.03
                    LINE=$(echo "$DEVICE_NAME\tX\t\t$VPN_POOL_IP\t\t$PUB_KEY\t\t# $DEVICE_NAME $TAG")
                    TAG=$(echo "$TAG" | sed "s/'/''/g")

                    if [ "$SITE2SITE_PEER_LAN" != "remoteonly" ];then
                        sqlite3 $SQL_DATABASE "INSERT into devices values('$DEVICE_NAME','X','$VPN_POOL_IP','$DNS_RESOLVER','$ALLOWED_IPS','$PUB_KEY','$PRI_KEY','# $DEVICE_NAME $TAG','0');"

                        echo -e $cBGRE"\n\tWireGuard® config for $PEER_TOPOLOGY Peer '${cBMAG}${DEVICE_NAME}${cBGRE}' (${cBWHT}${VPN_POOL_IP}${cBGRE}) created ${cBWHT}(Allowed IP's ${ALLOWED_IPS} ${SPLIT_TXT})\n"$cRESET
                    fi
                fi
                if [ "$SITE2SITE_PEER_LAN" != "remoteonly" ];then
                    echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED ADD $PEER_TOPOLOGY Peer '${cBMAG}${DEVICE_NAME}${cBRED}' ${cRESET}to 'server' Peer (${cBMAG}${SERVER_PEER}${cRESET}) or press$cBGRE [Enter] to SKIP."
                    read -r "ANS"
                    if [ "$ANS" == "y" ];then

                        local PUB_KEY=$(Convert_Key "$PUB_KEY")
                        sed -i -e :a -e '/^\n*$/{$d;N;};/\n$/ba' ${CONFIG_DIR}${SERVER_PEER}.conf       # v4.15 Delete all trailing blank lines from file
                        echo -e >> ${CONFIG_DIR}${SERVER_PEER}.conf
                        for SERVER_PEER in $SERVER_PEER                                         # v3.03
                            do
                                # Erase 'client' Peer device entry if it exists....
                                [ -n "$(grep "$DEVICE_NAME" ${CONFIG_DIR}${SERVER_PEER}.conf)" ] && sed -i "/# $DEVICE_NAME/,/# $DEVICE_NAME End/d" ${CONFIG_DIR}${SERVER_PEER}.conf    # v1.08
                            done
                        cat >> ${CONFIG_DIR}${SERVER_PEER}.conf << EOF
# $DEVICE_NAME $PEER_TOPOLOGY
[Peer]
PublicKey = $PUB_KEY
AllowedIPs = $VPN_POOL_IP
PresharedKey = $PRE_SHARED_KEY
# $DEVICE_NAME End
EOF
                        for SERVER_PEER in $SERVER_PEER                                         # v3.03
                            do
                                 echo -e $cBCYA"\tAdded $PEER_TOPOLOGY Peer '${cBMAG}${DEVICE_NAME}${cBCYA}' ${cBWHT}${VPN_POOL_IP}${cBCYA} to $HARDWARE_MODEL 'server' (${cBMAG}$SERVER_PEER${cBCYA}) and WireGuard® config\n"
                            done

                        Display_QRCode "${CONFIG_DIR}${DEVICE_NAME}.conf"
                    fi
                fi

                if [ "$SITE2SITE" == "Y" ];then             # v4.15

                    cat > /tmp/${DEVICE_NAME}${SITE_PEER}.conf << EOF  # v4.14
# $DEVICE_NAME $PEER_TOPOLOGY
[Peer]
PublicKey = $PUB_KEY
AllowedIPs = $ALLOWED_IPS     ${SPLIT_TXT}
#PresharedKey = $PRE_SHARED_KEY
PersistentKeepalive = 25
# $DEVICE_NAME End
EOF

                    echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED ADD $PEER_TOPOLOGY Peer '${cBMAG}${DEVICE_NAME}${cBRED}' ${cRESET}to remote 'server' Peer (${cBMAG}${SITE_PEER}${cRESET}) or press$cBGRE [Enter] to SKIP."
                    read -r "ANS"
                    if [ "$ANS" == "y" ];then
                        sed -i -e :a -e '/^\n*$/{$d;N;};/\n$/ba' ${CONFIG_DIR}${SITE_PEER}.conf     # v4.15 Delete all trailing blank lines from file
                        echo -e >> ${CONFIG_DIR}${SITE_PEER}.conf
                        cat /tmp/${DEVICE_NAME}${SITE_PEER}.conf >> ${CONFIG_DIR}${SITE_PEER}.conf

                        local SITE_PEER_PUB_KEY=$(cat ${CONFIG_DIR}${SITE_PEER}_public.key)
                        local SITE_PEER_LISTENPORT=$(awk '/^ListenPort/ {print $3}' ${CONFIG_DIR}${SITE_PEER}.conf)
                        local SITE_PEER_ENDPOINT=$(awk "/^Endpoint.*$SITE_PEER_LISTENPORT/ {print}" ${CONFIG_DIR}${SERVER_PEER}.conf)
                        local SITE_PEER_TAG=$(sqlite3 $SQL_DATABASE "SELECT tag FROM devices WHERE name='$SITE_PEER';" | awk '{$1=""}1' | awk '{$1=$1}1')
                        cat >> ${CONFIG_DIR}${DEVICE_NAME}.conf << EOF  # v4.14

# $DEVICE_NAME $PEER_TOPOLOGY ($SITE_PEER_TAG)
[Peer]
PublicKey = $SITE_PEER_PUB_KEY
AllowedIPs = $ALLOWED_IPS     ${SPLIT_TXT}
$SITE_PEER_ENDPOINT
#PresharedKey = $PRE_SHARED_KEY
PersistentKeepalive = 25
# $DEVICE_NAME End
EOF

                    fi

                fi

                if [ "$SITE2SITE_PEER_LAN" != "remoteonly" ];then           # v4.15
                    # Need to Restart the Peer (if it is UP) or Start it so it can listen for new 'client' Peer device/site-2-site
                    [ -n "$(wg show interfaces | grep "$SERVER_PEER")" ] && CMD="restart" ||  CMD="start"   # v1.08
                    echo -e $cBWHT"\a\n\tWireGuard® 'server' Peer needs to be ${CMD}ed to listen for 'client' $PEER_TOPOLOGY Peer ${cBMAG}$DEVICE_NAME $TAG"
                    echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'server' Peer (${cBMAG}${SERVER_PEER}${cRESET}) or press$cBGRE [Enter] to SKIP."
                    read -r "ANS"
                    [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$SERVER_PEER"; Show_Peer_Status "show"; }  # v3.03
                fi

                if [ "$SITE2SITE" == "Y" ];then
                    echo -e $cRESET"\n\tNow Copy ${cBMAG}${SITE_PEER}/${DEVICE_NAME}${cRESET} files:\n"$cBCYA
                    ls -l ${CONFIG_DIR} | grep -E "${SITE_PEER}.conf|${DEVICE_NAME}"    # v4.15
                    echo -e ${cBCYA}${cRESET}"\n\tto remote location\n\tNOTE: If ${cBMAG}${SITE_PEER}${cRESET} has already been imported at the remote site, then simply rename $cBCYA'${SITE_PEER}.conf'$cRESET to its 'wg2x' equivalent, then restart it"
                fi

        else
            echo -e $cRED"\a\n\t***ERROR: Peer $PEER_TOPOLOGY '${cBMAG}${DEVICE_NAME}${cRED}' already EXISTS!"
        fi
    else
        echo -e $cBRED"\a\n\t***ERROR Missing name of 'client' Peer $PEER_TOPOLOGY! e.g. iPhone\n"$cRESET
    fi
}
#For verbose debugging, uncomment the following two lines, and uncomment the last line of this script
#set -x
#(
#==========================================================================================================================================
Main() { true; }            # Syntax that is Atom Shellchecker compatible!

PATH=/opt/sbin:/opt/bin:/opt/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -z "$(grep -E "^NOCOLOR|^NOCOLOUR" ${INSTALL_DIR}WireguardVPN.conf)" ];then     # v4.15
    ANSIColours
fi

FIRMWARE=$(echo $(nvram get buildno) | awk 'BEGIN { FS = "." } {printf("%03d%02d",$1,$2)}')
HARDWARE_MODEL=$(Get_Router_Model)
# v384.13+ NVRAM variable 'lan_hostname' supersedes 'computer_name'
[ -n "$(nvram get computer_name)" ] && MYROUTER=$(nvram get computer_name) || MYROUTER=$(nvram get lan_hostname)
#BUILDNO=$(nvram get innerver)              # v4.12
BUILDNO=$(nvram get buildno)                # v4.14
BUILDNO=${BUILDNO}_$(nvram get extendno)    # v4.14
SCRIPT_NAME="${0##*/}"
ENTWARE_INFO="/opt/etc/entware_release"
SHELL=$(readlink /proc/$$/exe)              # 4.14

EASYMENU="Y"

IPV6_SERVICE=$(nvram get ipv6_service)                  # v4.14
if [ "$IPV6_SERVICE" != "disabled" ];then               # v4.14
    case $IPV6_SERVICE in
        native|ipv6pt|dhcp6|6to4|6in4|6rd)
            USE_IPV6="Y"; IPV6_TXT="(IPv6) "
            LAN_SUBNET_IPV6=$(nvram get ipv6_prefix)    # v4.14.6
            LAN_ADDR_IPV6=$(nvram get ipv6_rtr_addr)    # v4.14.6
        ;;
        other)
            :
        ;;
        spoof|simulate)
            USE_IPV6="Y"; IPV6_TXT="(IPv6) Simulate "   # v4.14
        ;;
    esac
fi

TS=$(date +"%Y%m%d-%H%M%S")    # current date and time 'yyyymmdd-hhmmss'

ACTION=$1
PEER=$2
NOPOLICY=$3

#[ -f /usr/sbin/helper.sh ] && source /usr/sbin/helper.sh                                  # v 4.12 v2.07 Required for external 'am_settings_set()/am_settings_get()'
#Say $SHELL

# Need assistance ?
if [ "$1" == "-h" ] || [ "$1" == "help" ];then
    clear                                                   # v1.21
    echo -e $cBWHT
    ShowHelp
    echo -e $cRESET
    exit 0
fi

# Enable debugging ?
if [ "$1" == "debug" ] || [ "$1" == "debugall" ];then
    if [ "$1" == "debug" ];then
        DEBUGMODE="$(echo -e ${cRESET}$cWRED"Debug mode enabled"$cRESET)"
        shift
    fi
   [ "$1" == "debug" ] && set +x
fi

[ ! -L "/opt/bin/wg_manager" ] && Manage_alias "create"

NOCHK="Martineau Disabled hack"
[ -n "$(echo "$@" | grep -w "nochk")" ] & NOCHK="Y"

# Remove WireGuard Manager ?
if [ "$1" == "uninstall" ];then         # v4.15
    NOCHK="Y"                           # v4.15
    Uninstall_WireGuard                 # v4.15
    echo -e $cRESET                     # v4.15
    exit 0                              # v4.15
fi

# Retain commandline compatibility
if [ "$1" != "install" ];then   # v2.01

    # v3.00 uses '/opt/etc/wireguard.d' rather than '/opt/etc/wireguard'
    # Check if v2.00 was installed, then offer to rename it
    VERSION_NUMDOT=$VERSION                                             # v3.03
    VERSION_NUM=$(echo "$VERSION" | sed 's/[^0-9]*//g')
    if [ "${VERSION_NUM:0:1}" -eq 3 ] && [ ! -d ${CONFIG_DIR} ];then    # v3.03

        if [ -d /opt/etc/wireguard ] && [ "$(ls -1 /opt/etc/wireguard | wc -l)" -gt "5" ];then

            echo -e $cBRED"\a\n\tWireGuard® Session Manager v3.0 requires '${CONFIG_DIR}'\n\n\t${cBWHT}Do you want to rename '/opt/etc/wireguard' to '${CONFIG_DIR}' ?"
            echo -e "\tPress$cBRED y$cRESET to$cBRED auto-migrate to WireGuard Session Manager v3.0${cRESET} or press$cBGRE [Enter] to SKIP."
                read -r "ANS"
                if [ "$ANS" == "y" ];then

                    mv /opt/etc/wireguard ${CONFIG_DIR}

                    # Legacy tidy-up! to adopt the new name for the configuration file
                    if [ -f /jffs/configs/WireguardVPN_map ];then
                        mv /jffs/configs/WireguardVPN_map /jffs/configs/WireguardVPN_map.bak
                        cp /jffs/configs/WireguardVPN_map.bak ${INSTALL_DIR}WireguardVPN.conf      # v2.01
                    fi

                else
                    echo -e $cBYEL"\n\tManually migrate by \n\n\t1. Reinstalling from Github\n\t2. Copy '/jffs/configs/WireguardVPN_map' to '${INSTALL_DIR}WireguardVPN.conf\n\t3. Copy /opt/etc/wireguard/'*.conf'/'*_key' to '${CONFIG_DIR}'\n"$cRESET
                    exit 99
                fi
        fi
    fi

    if [ "$1" == "import" ];then
        if [ "$2" == "dir" ];then
            DIR_OPT="dir"
            shift
            DIR=$2
            shift
        else
            shift
        fi
        Import_Peer import $@
        echo -e $cRESET
        exit_message
    fi

    # Purge old traffic/session database records        # trimdb {days [ 'traffic' | 'session' ] [auto]}
    if [ "$1" == "trimdb" ];then            # v4.15
        Purge_Database "$@" "auto"          # v4.15
        echo -e $cRESET                     # v4.15
        exit 0                              # v4.15
    fi

    # Show INFO
    if [ "$1" == "?" ];then                 # v4.15
        Show_Info_HDR                       # v4.15
        Show_Info                           # v4.15
        echo -e $cRESET                     # v4.15
        exit 0                              # v4.15
    fi

    if [ "$NOCHK" == "Y" ] || [ "$(WireGuard_Installed)" == "Y" ];then # v4.12 v2.01

        # Ensure Kernel module is loaded
        [ -z "$(lsmod | grep wireguard)" ] && Load_UserspaceTool    # v4.12

        case "$1" in

            start|init)

                if [ "$1" == "init" ];then

                    if [ "$(nvram get ntp_ready)" = "0" ];then              # v4.01 Ensure event 'restart_diskmon' triggers the actual start of WireGuard Session Manager
                        FN="/jffs/scripts/service-event-end"
                        [ ! -f $FN ] && { echo "#!/bin/sh" > $FN; chmod +x $FN; }
                        [ -z "$(grep -i "WireGuard" $FN)" ] && echo -e "if [ "\$2" = "diskmon" ]; then { /bin/sh /jffs/addons/wireguard/wg_manager.sh init & } ; fi # WireGuard_Manager" >> $FN   #  v4.16 v4.01
                        SayT "WireGuard Session Manager delayed for NTP synch event trigger 'restart_diskmon'"  # v4.11 v4.01
                        exit 99
                    fi

                    Load_UserspaceTool                      # v4.16

                    #if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^ENABLE_UDPMON" ${INSTALL_DIR}WireguardVPN.conf)" ];then                         # v4.16
                        #[ $(sqlite3 $SQL_DATABASE "SELECT COUNT(auto) FROM servers WHERE auto='Y';") -gt 0 ] && UDP_MONITOR=$(Manage_UDP_Monitor "INIT" "enable")  # v4.16 v4.11
                    #fi

                    Manage_Stats "INIT" "enable"

                    # Trim DB schedule
                    DAYS=90                             # Default in ${INSTALL_DIR}WireguardVPN.conf is 99 for debugging!
                    if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^TrimDB" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                        DAYS=$(awk '/^TrimDB/ {print $2}' ${INSTALL_DIR}WireguardVPN.conf)
                    fi
                    if [ $DAYS -gt 0 ];then
                        cru d WireGuard_DB 2>/dev/null                                                          # v4.16
                        cru a WireGuard_DB "0 7 * * 6 /jffs/addons/wireguard/wireguard_manager.sh trimdb $DAYS" # v4.16
                        SayT "Cron job scheduled 07:00 every Sunday to purge SQL Session/traffic statistics metrics records older than $DAYS days"  # v4.16
                    fi
                fi

                # http://www.snbforums.com/threads/beta-wireguard-session-manager.70787/post-688282
                if { [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^DISABLE_FLOW_CACHE" ${INSTALL_DIR}WireguardVPN.conf)" ] ;} || \
                     [ -n "$(echo "RT-AX86U RT-AX56U" | grep -ow "$HARDWARE_MODEL")" ];then     # v4.16 v4.15
                        RC="$(Manage_FC "disable")"                                             # v4.14
                fi

                Manage_Wireguard_Sessions "start" "$PEER" "$NOPOLICY"
                echo -e $cRESET
                exit_message
            ;;
            stop)
                Manage_Wireguard_Sessions "stop" "$PEER" "$NOPOLICY"
                echo -e $cRESET
                exit_message
            ;;
            restart)
                #/jffs/addons/wireguard/wg_firewall "KILLSWITCH"                     # v4.11 @Torson v2.03
                Manage_Wireguard_Sessions "stop" "$PEER" "$NOPOLICY"    # v2.03
                Manage_Wireguard_Sessions "start" "$PEER" "$NOPOLICY"   # v2.03
                echo -e $cRESET
                exit_message
            ;;
            show|list)
                # Force verbose detail if active Peers
                [ -n "$(wg show interfaces)" ] && Show_Peer_Status "full" || { echo -e; Say "WireGuard® ACTIVE Peer Status: Clients 0, Servers 0" ;}     # v4.16                       # Force verbose detail
                echo -e $cRESET
                exit_message
            ;;
            diag)
                Diag_Dump $2                        # Force verbose detail
                echo -e $cRESET
                exit_message
            ;;
            generatestats)

                Peer_Status_Summary "Syslog"
                CRON_PERIOD="Y"                     # v4.16
                Show_Peer_Status "generatestats"    # cron     # v4.16 v3.05
                echo -e $cRESET
                exit_message
            ;;
            stats*)                                         # stats [ enable | disable ]    # v4.01
                Manage_Stats $@
                echo -e $cRESET
                exit_message
            ;;
            udpmon*)                                        # udpmon [ enable | disable ]   # v4.01
                if [ $(Manage_UDP_Monitor $@) == "Y" ];then
                    echo -e $cBGRE"\n\t[✔]${cBWHT} UDP ${cBGRE}monitor is ENABLED"$cRESET
                else
                    [ "$(wg show interfaces | grep -c "wg2" )" -ge 1 ] && ALERT="${aREVERSE}" || ALERT=
                    echo -e $cRED"\n\t[✖]${cBWHT} UDP ${cBGRE}monitor is ${cBRED}${ALERT}DISABLED"$cRESET
                fi
                exit_message
            ;;
            menu*)                                          # menu [ hide | show ]          # v4.15

                ACTION=$2

                case "$ACTION" in
                    hide|off)
                        if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^#NOMENU" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                            sed -i 's/^#NOMENU/NOMENU/' ${INSTALL_DIR}WireguardVPN.conf                                 # v4.15
                        fi
                            echo -e $cRED"\n\t[✖]${cBWHT} Menu display ${cBGRE}is ${cBRED}${ALERT}DISABLED"$cRESET
                    ;;
                    show|on)
                        if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^NOMENU" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                            sed -i 's/^NOMENU/#NOMENU/' ${INSTALL_DIR}WireguardVPN.conf                                 # v4.15
                        fi
                            echo -e $cBGRE"\n\t[✔]${cBWHT} Menu display ${cBGRE}is ENABLED"$cRESET
                    ;;
                    *)
                        echo -en $cRED"\a\n\t***ERROR: Invalid arg $cBWHT'"$ACTION"'$cBRED for Menu dislay - valid 'off' or 'on' only!\n"$cRESET
                    ;;
                esac

                echo -e $cRESET
                exit_message
            ;;
            colour*|color*)                                          # colo[u]r [ off | on ]          # v4.15

                ACTION=$2

                case "$ACTION" in
                    hide|off)
                        if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^#NOCOLOUR|#NOCOLOR" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                            sed -i 's/^#NOCOLOR/NOCOLOR/' ${INSTALL_DIR}WireguardVPN.conf                                 # v4.15
                            ANSIColours "disable"
                        fi
                        echo -e $cRED"\n\t[✖]${cBWHT} Display colour attributes ${cBGRE}is ${cBRED}${ALERT}DISABLED"$cRESET
                    ;;
                    show|on)
                        if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^NOCOLOUR|NOCOLOR" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                            sed -i 's/^NOCOLOR/#NOCOLOR/' ${INSTALL_DIR}WireguardVPN.conf                                 # v4.15
                            ANSIColours
                        fi
                        echo -e $cBGRE"\n\t[✔]${cBWHT} Display colour attributes ${cBGRE}is ENABLED"$cRESET
                    ;;
                    *)
                        echo -en $cRED"\a\n\t***ERROR: Invalid arg $cBWHT'"$ACTION"'$cBRED for Display colour attributes - valid 'off' or 'on' only!\n"$cRESET
                    ;;
                esac

                echo -e $cRESET
                exit_message
            ;;
        esac
    else
        if [ "$1" != "init" ];then              # v4.11
            SayT "***ERROR WireGuard Manager/WireGuard Tool module 'wg' NOT installed"
            echo -e $cBRED"\a\n\t***ERROR WireGuard® Tool module 'wg' NOT installed\n"$cRESET
            exit_message
        fi
    fi
fi

# Override use of Pg-Up key for command retrieval?
if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^NOPG_UP" ${INSTALL_DIR}WireguardVPN.conf)" ];then    # v4.14
    READLINE=                                                                                                       # v4.14
fi

if [ -f ${INSTALL_DIR}WireguardVPN.conf ] && [ -n "$(grep -E "^NOMENU" ${INSTALL_DIR}WireguardVPN.conf)" ];then     # v4.15
    SUPPRESSMENU="NOMENU - specified"                                                                               # v4.15
fi

clear
#####################################DEBUG===============================================
if [ -n "$(ip rule | grep -E "^220:")" ] || [ -n "$(ip -6 rule | grep -E "^220:")" ];then
    echo -e "\a"
    Say "DEBUG= *********************************WTF!? Rogue RPDB rule 220 FOUND?????!!!!!*******************************"

    if [ -n "$(ip rule | grep -E "^220:")" ];then
        TABLE=$(ip rule | awk '/^220:/ {print $5}' )
        echo -e "\n\tIPv4 RPDB\n"$cBRED
        ip rule
        echo -e $cRESET"\n\tIPv4 Route Table $TABLE\n"$cBRED
        ip route show table $TABLE

    fi

    if [ -n "$(ip -6 rule | grep -E "^220:")" ];then
        TABLE=$(ip -6 rule | awk '/^220:/ {print $5}' )
        echo -e $cRESET"\n\tIPv6 RPDB\n"$cBRED
        ip -6 rule
        echo -e $cRESET"\n\tIPv6 Route Table $TABLE\n"$cBRED
        ip -6 route show table $TABLE
    fi

    echo -e $cRESET"\n\tPress$cBRED y$cRESET to$cBRED Delete rogue RPDB PRIO 220 rules${cRESET} or press$cBGRE [Enter] to SKIP."
    read -r "ANS"
    if [ "$ANS" == "y" ];then
        ip rule del prio 220
        ip -6 rule del prio 220
        clear
    else
        exit 99
    fi

fi
#########################################################################################

Check_Lock "wg"

Show_Main_Menu "$@"

echo -e $cRESET

rm -rf /tmp/wg.lock

exit 0


#) 2>&1 | logger -t $(basename $0)"[$$_***DEBUG]"
