#!/bin/sh
VERSION="v4.11b4"
#============================================================================================ © 2021 Martineau v4.11b4
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
# Last Updated Date: 13-May-2021
#
# Description:
#
# Acknowledgement:
#
# Contributors: odkrys,Torson,ZebMcKayhan,jobhax,elorimer,Sh0cker54,here1310

GIT_REPO="wireguard"
GITHUB_MARTINEAU="https://raw.githubusercontent.com/MartineauUK/$GIT_REPO/main"
GITHUB_MARTINEAU_DEV="https://raw.githubusercontent.com/MartineauUK/$GIT_REPO/dev"
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

Say() {
   echo -e $$ $@ | logger -st "($(basename $0))"
}
SayT() {
   echo -e $$ $@ | logger -t "($(basename $0))"
}
# shellcheck disable=SC2034
ANSIColours () {
    cRESET="\e[0m";cBLA="\e[30m";cRED="\e[31m";cGRE="\e[32m";cYEL="\e[33m";cBLU="\e[34m";cMAG="\e[35m";cCYA="\e[36m";cGRA="\e[37m";cFGRESET="\e[39m"
    cBGRA="\e[90m";cBRED="\e[91m";cBGRE="\e[92m";cBYEL="\e[93m";cBBLU="\e[94m";cBMAG="\e[95m";cBCYA="\e[96m";cBWHT="\e[97m"
    aBOLD="\e[1m";aDIM="\e[2m";aUNDER="\e[4m";aBLINK="\e[5m";aREVERSE="\e[7m"
    aBOLDr="\e[21m";aDIMr="\e[22m";aUNDERr="\e[24m";aBLINKr="\e[25m";aREVERSEr="\e[27m"
    cWRED="\e[41m";cWGRE="\e[42m";cWYEL="\e[43m";cWBLU="\e[44m";cWMAG="\e[45m";cWCYA="\e[46m";cWGRA="\e[47m"
    cYBLU="\e[93;48;5;21m"
    cRED_="\e[41m";cGRE_="\e[42m"
    xHOME="\e[H";xERASE="\e[2J";xERASEDOWN="\e[J";xERASEUP="\e[1J";xCSRPOS="\e[s";xPOSCSR="\e[u";xERASEEOL="\e[K";xQUERYCSRPOS="\e[6n"
    xGoto="\e[Line;Columnf"
}
# Print between line beginning with'#==' to first blank line inclusive
ShowHelp() {
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
    #[ -n "$(uname -m | grep "aarch64")" ] && echo Y || echo N
    [ -n "$(uname -m | grep "aarch64")" ] && { echo Y; return 0; } || { echo N; return 1; }
}
Is_AX() {
    # Kernel is '4.1.52+' (i.e. isn't '2.6.36*') and it isn't HND
    # Use the following at the command line otherwise 'return X' makes the SSH session terminate!
    # [ -n "$(uname -r | grep "^4")" ] && [ -z "$(uname -m | grep "aarch64")" ] && echo Y || echo N
    [ -n "$(uname -r | grep "^4")" ] && [ -z "$(uname -m | grep "aarch64")" ] && { echo Y; return 0; } || { echo N; return 1; }
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
Get_WAN_IF_Name () {

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
Is_IPv6() {
    # Note this matches compression anywhere in the address, though it won't match the loopback address ::1
    grep -oE '([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}'       # IPv6 format -very crude
}
Is_IPv4_CIDR() {
        grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'         # IPv4 CIDR range notation
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
    #date -d @1542142560 "+%F %T"
    #   2018-11-13 20:56:00

    if [ -z "$1" ];then
        RESULT=$(date +%s)                          # Convert current timestamp into Epoch seconds
    else
        if [ -z "$2" ];then
            RESULT=$(date -d @"$1" +%s)     # Convert specified YYYY-MM-DD HH:MM:SS into Epoch seconds
        else
            RESULT=$(date -d @"$1" "+%F %T")        # Convert specified Epoch seconds into YYYY-MM-DD HH:MM:SS
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
        esac

        [ "$GITHUB_BRANCH" == "dev" ] && local DEVTXT=${cRESET}$cWRED"Github 'dev/development' branch"$cRESET || local DEVTXT=

        STATUS="$(curl --retry 3 -L${SILENT} -w '%{http_code}' "$GITHUB_DIR/$FILE" -o "$DIR/$FILE")"
        if [ "$STATUS" -eq "200" ]; then
            [ -n "$(echo "$@" | grep -F "dos2unix")" ] && dos2unix $DIR/$FILE
            printf '\t%b%s%b downloaded successfully %b\n' "$cBGRE" "$FILE" "$cRESET" "$DEVTXT"
            [ -n "$CHMOD" ] && chmod $CHMOD "$DIR/$FILE"
        else
            printf '\n%b%s%b download FAILED with curl error %s\n\n' "\n\t\a$cBMAG" "'$FILE'" "$cBRED" "$STATUS"
            echo -e $cRESET"\a\n"

            exit 1
        fi
}
_Get_File() {

    local WEBFILE=$1

    [ -z "$2" ] && echo -e $cBCYA"\n\tDownloading WireGuard Kernel module ${cBWHT}'$WEBFILE'$cBCYA for $ROUTER (v$BUILDNO)..."$cRESET
    echo -e $cBGRA

    curl -# -fL --retry 3 https://github.com/odkrys/entware-makefile-for-merlin/raw/main/${WEBFILE} -o ${INSTALL_DIR}${WEBFILE}

    return $?
}
Download_Modules() {


    local ROUTER=$1

    #[ ! -d "${INSTALL_DIR}" ] && mkdir -p "${INSTALL_DIR}"

    local WEBFILE_NAMES=$(curl -${SILENT}fL https://www.snbforums.com/threads/experimental-wireguard-for-hnd-platform-4-1-x-kernels.46164/ | grep "<a href=.*odkrys.*wireguard" | grep -oE "wireguard.*" | sed 's/\"//g' | tr '\n' ' ')

    # The file list MAY NOT ALWAYS be in the correct Router Model order for the following 'case' statement?
    case "$ROUTER" in

        RT-AC86U|GT-AC2900)     # RT-AC86U, GT-AC2900 - 4.1.27
            _Get_File "$(echo "$WEBFILE_NAMES" | awk '{print $1}')"
            ;;
        RT-AX88U|GT-AX11000)    # RT-AX88U, GT-AX11000 - 4.1.51
            _Get_File "$(echo "$WEBFILE_NAMES" | awk '{print $2}')"
            ;;
        RT-AX68U|RT-AX86U)      # RT-AX68U, RT-AX86U - 4.1.52
            _Get_File "$(echo "$WEBFILE_NAMES" | awk '{print $3}')"
            ;;
        *)
            echo -e $cBRED"\a\n\t***ERROR: Unable to find WireGuard Kernel module for $ROUTER (v$BUILDNO)\n"$cRESET
            # Deliberately Download an incompatible file simply so that an error message is produced by 'opkg install*.ipk'
            #
            #       Unknown package 'wireguard-kernel'.
            #       Collected errors:
            #        * pkg_hash_fetch_best_installation_candidate: Packages for wireguard-kernel found, but incompatible with the architectures configured
            #        * opkg_install_cmd: Cannot install package wireguard-kernel.
            #
            #
            _Get_File "$(echo "$WEBFILE_NAMES" | awk '{print $1}')"

            ROUTER_COMPATIBLE="N"
            ;;
    esac

    # User Space Tools
    WEBFILE=$(echo "$WEBFILE_NAMES" | awk '{print $4}')
    echo -e $cBCYA"\n\tDownloading WireGuard User space Tool$cBWHT '$WEBFILE'$cBCYA for $ROUTER (v$BUILDNO)"$cRESET
    _Get_File  "$WEBFILE" "NOMSG"

}
Load_UserspaceTool() {

    if [ ! -d "${INSTALL_DIR}" ];then
        echo -e $cRED"\a\n\tNo modules found - '/${INSTALL_DIR} doesn't exist'\n"
        echo -e "\tPress$cBRED y$cRESET to$cBRED DOWNLOAD WireGuard Kernel and Userspace Tool modules ${cRESET} or press$cBGRE [Enter] to SKIP."
            read -r "ANS"
            if [ "$ANS" == "y" ];then
                Download_Modules $HARDWARE_MODEL

            fi
    fi

    STATUS=0
    echo -e $cBCYA"\n\tLoading WireGuard Kernel module and Userspace Tool for $HARDWARE_MODEL (v$BUILDNO)"$cRESET
    for MODULE in $(ls /jffs/addons/wireguard/*.ipk)
        do
            opkg install $MODULE
            if [ $? -eq 0 ];then
                MODULE_NAME=$(echo "$(basename $MODULE)" | sed 's/_.*$//')
                md5sum $MODULE > ${INSTALL_DIR}$MODULE_NAME".md5"
                sed -i 's~/jffs/addons/wireguard/~~' ${INSTALL_DIR}$MODULE_NAME".md5"
            else
                STATUS=0
            fi
        done

    if [ "$STATUS" -eq 0 ];then
        insmod /opt/lib/modules/wireguard 2>/dev/null

        echo -e $cBGRA"\t"$(dmesg | grep -a "WireGuard")
        echo -e $cBGRA"\t"$(dmesg | grep -a "wireguard: Copyright")"\n"$cRESET
        return 0
    else
        echo -e $cBRED"\a\n\t***ERROR: Unable to DOWNLOAD WireGuard Kernel and Userspace Tool modules\n"
        return 1
    fi

}
Show_MD5() {

    local TYPE=$1

    if [ "$TYPE" == "script" ];then
        echo -e $cBCYA"\tMD5="$(awk '{print $0}' ${INSTALL_DIR}wg_manager.md5)
    else
        echo -e $cBCYA"\tMD5="$(awk '{print $0}' ${INSTALL_DIR}wireguard-kernel.md5)
        echo -e $cBCYA"\tMD5="$(awk '{print $0}' ${INSTALL_DIR}wireguard-tools.md5)
    fi
}
Check_Module_Versions() {

    local ACTION=$1

    local UPDATES="N"

    echo -e $cBGRA"\t"$(dmesg | grep -a "WireGuard")
    echo -e $cBGRA"\t"$(dmesg | grep -a "wireguard: Copyright")"\n"$cRESET

    [ -n "$(lsmod | grep -i wireguard)" ] && echo -e $cBGRE"\t[✔] WireGuard Module is LOADED\n"$cRESET || echo -e $cBRED"\t[✖] WireGuard Module is NOT LOADED\n"$cRESET

    # Without a BOOT, there may be a mismatch
    local BOOTLOADED=$(dmesg | grep -a WireGuard | awk '{print $3}')
    local WGKERNEL=$(opkg list-installed | grep "wireguard-kernel" | awk '{print $3}' | sed 's/\-.*$//')
    local WGTOOLS=$(opkg list-installed | grep "wireguard-tools" | awk '{print $3}' | sed 's/\-.*$//')

    if [ -n "$WGKERNEL" ];then                  # v1.04
        [ "$WGKERNEL" != "$BOOTLOADED" ] && echo -e $cRED"\a\n\tWarning: Reboot required for (dmesg) WireGuard $WGKERNEL $BOOTLOADED\n"
    fi

    Show_MD5

    if [ "$ACTION" != "report" ];then

        # Check if Kernel and User Tools Update available
        echo -e $cBWHT"\tChecking for WireGuard Kernel and Userspace Tool updates..."
        local FILES=$(curl -${SILENT}fL https://www.snbforums.com/threads/experimental-wireguard-for-hnd-platform-4-1-x-kernels.46164/ | grep "<a href=.*odkrys.*wireguard" | sed 's/"//g; s/\n/ /g' | grep -oE "wireguard.*")

        [ -z "$(echo "$FILES" | grep -F "$WGKERNEL")" ] && { echo -e $cBYEL"\t\tKernel UPDATE available" $FILE; local UPDATES="Y"; }
        [ -z "$(echo "$FILES" | grep -F "$WGTOOLS")" ] && { echo -e $cBYEL"\t\tUserspace Tool UPDATE available" $FILE; local UPDATES="Y"; }

        if [ "$UPDATES" == "Y" ];then
            echo -e $cRESET"\n\tPress$cBRED y$cRESET to$cBRED Update WireGuard Kernel and Userspace Tool${cRESET} or press$cBGRE [Enter] to SKIP."
            read -r "ANS"
            if [ "$ANS" == "y" ];then
                Download_Modules $HARDWARE_MODEL
                Load_UserspaceTool
            else
                echo -e $cBWHT"\n\tUpdate skipped\n"$cRESET
            fi
        else
            echo -e $cBGRE"\n\tWireGuard Kernel and Userspace Tool up to date.\n"$cRESET
        fi
    fi
}
Create_Peer() {

    local ACTION=$1;shift
    local USE_IPV6="N"

    while [ $# -gt 0 ]; do          # v3.02
        case "$1" in
        auto*)
            local AUTO="$(echo "$@" | sed -n "s/^.*auto=//p" | awk '{print $1}')"
            ;;
        port*)
            local LISTEN_PORT="$(echo "$@" | sed -n "s/^.*port=//p" | awk '{print $1}')"
            local LISTEN_PORT_USER="Y"
            ;;
        ipv6*)
            local USE_IPV6="Y"
            local IPV6_TXT="(IPv6) "
            local SERVER_PEER=

            local VPN_POOL="$(echo "$@" | sed -n "s/^.*ipv6=//p" | awk '{print $1}')"
            if [ "${1:0:5}" == "ipv6=" ] && [ -n "$VPN_POOL" ];then
                local VPN_POOL_USER="Y"
            fi
            ;;
        ip=*)
            local VPN_POOL="$(echo "$@" | sed -n "s/^.*ip=//p" | awk '{print $1}')"
            local VPN_POOL_USER="Y"
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
        [ -n "$SERVER_PEER" ] && local AUTO_VPN_POOL=$(sqlite3 $SQL_DATABASE "SELECT subnet FROM servers WHERE peer='$SERVER_PEER';") || local AUTO_VPN_POOL="10.50.0.1/24"
        local SERVER_PEER=$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers;" | sort | tail -n 1)

        # User specified VPN Tunnel subnet?
        if [ -z "$VPN_POOL_USER" ];then
            [ -z "$AUTO_VPN_POOL" ] && AUTO_VPN_POOL="10.50.1.1/24"
            local ONE_OCTET=$(echo "$AUTO_VPN_POOL" | cut -d'.' -f1)
            local TWO_OCTET=$(echo "$AUTO_VPN_POOL" | cut -d'.' -f2)
            local THIRD_OCTET=$(echo "$AUTO_VPN_POOL" | cut -d'.' -f3)
            local REST=$(echo "$AUTO_VPN_POOL" | cut -d'.' -f4-)
            local NEW_THIRD_OCTET=$((THIRD_OCTET+1))
            local SERVER_CNT=$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM servers;")
            [ $SERVER_CNT -ge $NEW_THIRD_OCTET ] && local NEW_THIRD_OCTET=$((SERVER_CNT+1))
            local VPN_POOL=$(echo -e "$ONE_OCTET.$TWO_OCTET.$NEW_THIRD_OCTET.$REST")

            if [ "$USE_IPV6" == "Y" ];then
                [ -z "$TWO_OCTET" ] && local TWO_OCTET="50"
                [ -z "$NEW_THIRD_OCTET" ] && local NEW_THIRD_OCTET="1"
                local VPN_POOL="fc00:${TWO_OCTET}:${NEW_THIRD_OCTET}::1/64"
            fi
        fi

        # Add the new 'server' Peer at the end of the list in the config
        #POS=$(awk -v pattern="$SERVER_PEER" 'match($0,"^"pattern) {print NR":"$0}' ${INSTALL_DIR}WireguardVPN.conf | tail -n 1 | cut -d':' -f1)
        #INDEX=$(echo "$SERVER_PEER" | sed 's/^wg2//')
        local INDEX=$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM servers;")
        local INDEX=$((INDEX+1))
        local SERVER_PEER="wg2"$INDEX

        # User specified Listen Port?
        [ -z "$LISTEN_PORT_USER" ] && LISTEN_PORT=$((LISTEN_PORT+INDEX))
    else
        [ "${SERVER_PEER:0:3}" == "wg2" ] && INDEX=${SERVER_PEER:3:1} || { echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard 'server' Peer prefix (wg2*) '$SERVER_PEER'\n"$cRESET; return 1; }
    fi

    if [ "$USE_IPV6" == "N" ];then
        [ -z "$(echo "$VPN_POOL" | Is_IPv4_CIDR)" ] && { echo -e $cBRED"\a\n\t***ERROR: '$VPN_POOL' must be IPv4 CIDR"$cRESET; return 1; }
    else
        [ -z "$(echo "$VPN_POOL" | sed 's~/.*$~~' | Is_Private_IPv6)" ] && { echo -e $cBRED"\a\n\t***ERROR: ipv6='$VPN_POOL6' must be Private IPv6 address"$cRESET; return 1; }
    fi

    if [ -f ${CONFIG_DIR}${SERVER_PEER}.conf ] || [ -n "$(grep -E "^$SERVER_PEER" ${INSTALL_DIR}WireguardVPN.conf)" ];then
        echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard 'server' Peer '$SERVER_PEER' already exists\n"$cRESET
        return 1
    fi

    local WANIPADDR=$(nvram get wan0_ipaddr)
    [ -n "$(echo "$WANIPADDR" | Is_Private_IPv4)" ] && echo -e ${cRESET}${cBRED}${aBOLD}"\a\n\t*** Ensure Upstream router Port Foward entry for port:${cBMAG}${LISTEN_PORT}${cRESET}${cBRED}${aBOLD} ***"$cRESET
    echo -e $cBWHT"\n\tPress$cBRED y$cRESET to$cBRED Create ${IPV6_TXT}'server' Peer (${cBMAG}${SERVER_PEER}) ${cBWHT}${VPN_POOL}${cRESET}:${LISTEN_PORT}${cBWHT} or press$cBGRE [Enter] to SKIP."
    read -r "ANS"
    [ "$ANS" == "y" ] || return 1

    # Create Server template
    cat > ${CONFIG_DIR}${SERVER_PEER}.conf << EOF
# $HARDWARE_MODEL 'server' Peer #1 ($SERVER_PEER)
[Interface]
PrivateKey = Ha1rgO/plL4wCB+pRdc6Qh8bIAWNeNgPZ7L+HFBhoE4=
ListenPort = $LISTEN_PORT

# e.g. Accept a WireGuard connection from say YOUR mobile device to the router
# see '${CONFIG_DIR}mobilephone_private.key'

# Peer Example
#[Peer]
#PublicKey = This_should_be_replaced_with_the_Public_Key_of_YOUR_mobile_device
#AllowedIPs = PEER.ip.xxx.xxx/32
# Peer Example End
EOF

    echo -e $cBCYA"\tCreating WireGuard Private/Public key-pair for ${IPV6_TXT}'server' Peer ${cBMAG}${SERVER_PEER}${cBCYA} on $HARDWARE_MODEL (v$BUILDNO)"$cRESET
    if [ -n "$(which wg)" ];then
        wg genkey | tee ${CONFIG_DIR}${SERVER_PEER}_private.key | wg pubkey > ${CONFIG_DIR}${SERVER_PEER}_public.key
        local PRI_KEY=$(cat ${CONFIG_DIR}${SERVER_PEER}_private.key)
        local PRI_KEY=$(Convert_Key "$PRI_KEY")
        local PUB_KEY=$(cat ${CONFIG_DIR}${SERVER_PEER}_public.key)
        local PUB_KEY=$(Convert_Key "$PRI_KEY")
        sed -i "/^PrivateKey/ s~[^ ]*[^ ]~$PRI_KEY~3" ${CONFIG_DIR}${SERVER_PEER}.conf

        local ANNOTATE="# $HARDWARE_MODEL ${IPV6_TXT}Server $INDEX"
        sqlite3 $SQL_DATABASE "INSERT INTO servers values('$SERVER_PEER','$AUTO','${VPN_POOL}','$LISTEN_PORT','$PUB_KEY','$PRI_KEY','$ANNOTATE');"
    fi

    echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED Start ${IPV6_TXT}'server' Peer ($SERVER_PEER) or press$cBGRE [Enter] to SKIP."
    read -r "ANS"
    [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "start" "$SERVER_PEER"; Show_Peer_Status "show"; } # v3.03

    # Firewall rule to listen on multiple ports?
    #   e.g. iptables -t nat -I PREROUTING -i $WAN_IF -d <yourIP/32> -p udp -m multiport --dports 53,80,4444  -j REDIRECT --to-ports $LISTEN_PORT

}
Delete_Peer() {

    local FORCE=$2

    for WG_INTERFACE in $@
        do

            if [ -n "$FORCE" ] || [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then     # v3.05

                if [ "$WG_INTERFACE" != "force" ];then
                    [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ] && local Mode=$(Server_or_Client "$WG_INTERFACE") || local Mode="?"
                    local SQL_COL="peer"
                    [ "$Mode" == "server" ] && local TABLE="servers" || TABLE="clients"
                    #[  "${WG_INTERFACE:0:2}" != "wg" ] && { TABLE="devices"; local SQL_COL="name"; Mode="device"; }

                    echo -e $cBWHT"\n\tDeleting '$Mode' Peer (${cBMAG}${WG_INTERFACE}${cBWHT})\n"$cBRED

                    if [ "$Mode" == "server" ];then
                            # Check how many 'client' Peers exist
                            local CNT=$(grep -cE "^AllowedIPs" ${CONFIG_DIR}${WG_INTERFACE}.conf )
                            if [ $CNT -gt 0 ];then
                                echo -e $cBRED"\n\tWarning: 'server' Peer ${cBMAG}${WG_INTERFACE}${cBRED} has ${cBWHT}${CNT}${cBRED} 'client' Peer\n"$cBYEL
                                grep -E -B 3 -A 1 "^AllowedIPs" ${CONFIG_DIR}${WG_INTERFACE}.conf
                                echo -e $cBWHT"\n\tYou can manually reassign them to a different 'server' Peer by recreating the 'client' Peer then rescan the QR code on the device"
                            fi
                    fi

                    echo -e $cBWHT"\tPress$cBRED y$cRESET to ${aBOLD}CONFIRM${cRESET}${cBRED} or press$cBGRE [Enter] to SKIP."
                    read -r "ANS"

                    if [ "$ANS" == "y" ];then

                        [ -n "$(wg show $WG_INTERFACE 2>/dev/null)" ] && Manage_Wireguard_Sessions "stop" "$WG_INTERFACE"
                        sqlite3 $SQL_DATABASE "DELETE FROM $TABLE WHERE $SQL_COL='$WG_INTERFACE';"
                        [ -n "$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE name='$WG_INTERFACE';")" ] && sqlite3 $SQL_DATABASE "DELETE FROM devices WHERE name='$WG_INTERFACE';"

                        # ... and delete associated RPDB Selective Routing rule
                        sqlite3 $SQL_DATABASE "DELETE FROM policy WHERE peer='$WG_INTERFACE';"
                        # IPsets
                        sqlite3 $SQL_DATABASE "DELETE FROM ipset WHERE peer='$WG_INTERFACE';"

                        #   DDNS martineau.homeip.net
                        #   Endpoint = martineau.homeip.net:51820
                        if [ -n "$FORCE" ] || [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                            if [ -n "$FORCE" ] || [ "$(awk -F '[ :]' '/^Endpoint/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf)" == "$(nvram get ddns_hostname_x)" ];then      # v4.02

                                # Remove the 'client' from any 'server' Peers
                                #   # SGS8
                                #   ..........
                                #   # SGS8 End

                                # Scan for 'server' Peer that accepts this 'client' connection
                                SERVER_PEER=$(grep -HE "^#.*$WG_INTERFACE$" /opt/etc/wireguard.d/wg2*.conf | awk -F '[\/:\._]' '{print $6}')    # v4.11

                                for SERVER_PEER in $SERVER_PEER
                                    do
                                        echo -e $cBGRE"\t'device' Peer ${cBMAG}${WG_INTERFACE}${cBGRE} removed from 'server' Peer (${cBMAG}${SERVER_PEER}${cBGRE})"     # 4.02
                                        sed -i "/^# $WG_INTERFACE$/,/^# $WG_INTERFACE End$/d" ${CONFIG_DIR}${SERVER_PEER}.conf
                                        local RESTART_SERVERS=$RESTART_SERVERS" "$SERVER_PEER
                                    done
                            fi
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
                                    echo -e $cBWHT"\a\n\tWireGuard 'server' Peer needs to be ${CMD}ed to remove 'client' Peer ${cBMAG}$DEVICE_NAME $TAG"
                                    echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'server' Peer ($SERVER_PEER) or press$cBGRE [Enter] to SKIP."
                                    read -r "ANS"
                                    [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$SERVER_PEER"; Show_Peer_Status "show"; }  # v3.03
                                fi
                            done
                    fi
                fi
            else
                [ -n "$Mode" ] && TXT="'$Mode' " || TXT=            # v3.03
                SayT "***ERROR: WireGuard VPN ${TXT}Peer ('$WG_INTERFACE') config NOT found?....skipping $ACTION request"
                echo -e $cBRED"\a\n\t***ERROR: WireGuard ${TXT}Peer (${cBWHT}$WG_INTERFACE${cBRED}) config NOT found?....skipping delete Peer '${cBMAG}${WG_INTERFACE}${cBRED}' request\n"$cRESET   2>&1  # v1.09
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
    fi

    while [ $# -gt 0 ]; do
            if [ -n "$(echo "$1" | grep -F "name=")" ];then
                local RENAME="Y"
                local NEW_NAME=$(echo "$1" | sed -n "s/^.*name=//p" | awk '{print $0}')
                if [ -z "$NEW_NAME" ] || [ "$NEW_NAME" == "?" ];then
                    # Pick the next 'client' Peer name
                    for I in 11 12 13 14 15 16 17 18 19 111 112 113 114 115
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
            if [ "$1" == "tag=" ] || [ "$1" == "comment" ];then
                local ANNOTATE="$(echo "$1" | sed -n "s/^.*tag=//p" | awk '{print $0}')"
                [ -z "$ANNOTATE" ] && local ANNOTATE="$(echo "$@" | sed -n "s/^.*comment//p" | awk '{print $0}')"
                break
            fi
            if [ -n "$(echo "$1" | grep -F "type=")" ];then
                local FORCE_TYPE="$(echo "$1" | sed -n "s/^.*type=//p" | awk '{print $0}')"     # v4.03
            fi

            shift
    done

    for WG_INTERFACE in $WG_INTERFACE $@
        do
            [ "$WG_INTERFACE" = "comment" ] && break
            WG_INTERFACE=$(echo "$WG_INTERFACE" | sed 's~.conf$~~')     # v4.11
            if [ -f ${IMPORT_DIR}${WG_INTERFACE}.conf ];then
                local MODE=$(Server_or_Client "$WG_INTERFACE")
                [ -n "$FORCE_TYPE" ] && { MODE=$FORCE_TYPE; local FORCE_TYPE_TXT="(${cBRED}FORCED as 'client'${cRESET}) ${cBGRE}"; }                # v4.03
                if [ "$MODE" != "server" ];then
                    [ "$MODE" == "client" ] && { local TABLE="clients"; local AUTO="N"; local KEY="peer"; } || { TABLE="devices"; local AUTO="X"; local KEY="name"; }   # v4.09
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
                                AllowedIPs)
                                    local ALLOWIP=$(echo "$LINE" | awk '{print $3}')
                                ;;
                                Endpoint) local SOCKET=${LINE##* };;
                                "#"MTU) local MTU=${LINE##* };;                 # v4.09
                                "#"DNS) local COMMENT_DNS=${LINE##* } ;;
                                "#"Address) local COMMENT_SUBNET=${LINE##* } ;;
                                MTU) local MTU=${LINE##* }                      # v4.09
                                    # This must be commented out!
                                    [ "$MODE" == "client" ] && COMMENT_OUT="Y"
                                ;;
                                DNS) local DNS=${LINE##* }
                                    # This must be commented out!
                                    [ "$MODE" == "client" ] && COMMENT_OUT="Y"
                                ;;
                                Address) local SUBNET=${LINE##* }
                                    # This must be commented out!
                                    [ "$MODE" == "client" ] && COMMENT_OUT="Y"
                                ;;
                            esac
                        done < ${IMPORT_DIR}${WG_INTERFACE}.conf

                        [ -f ${IMPORT_DIR}${WG_INTERFACE}_public.key ] && local PUB_KEY=$(awk 'NR=1{print $0}' ${IMPORT_DIR}${WG_INTERFACE}_public.key)

                        [ -z "$DNS" ] && local DNS=$COMMENT_DNS             # v4.03
                        [ -z "$SUBNET" ] && local SUBNET=$COMMENT_SUBNET       # v4.03

                        # Strip IPV6
                        if [ "$(nvram get ipv6_service)" == "disabled" ];then
                            local SUBNET=$(echo "$SUBNET" | tr ',' ' ' | awk '{print $1}')
                            [ -z "$(echo "$SUBNET" | Is_IPv4_CIDR)" ] && local SUBNET=$SUBNET"/32"
                        fi
                        if [ "$MODE" = "client" ];then
                            if [ "$RENAME" != "Y" ];then
                                sqlite3 $SQL_DATABASE "INSERT INTO $TABLE values('$WG_INTERFACE','$AUTO','$SUBNET','$SOCKET','$DNS','$MTU','$PUB_KEY','$PRI_KEY','$ANNOTATE');"     # v4.09
                            else
                                sqlite3 $SQL_DATABASE "INSERT INTO $TABLE values('$NEW_NAME','$AUTO','$SUBNET','$SOCKET','$DNS','$MTU','$PUB_KEY','$PRI_KEY','$ANNOTATE');"         # v4.09
                            fi
                            #sqlite3 $SQL_DATABASE "INSERT INTO policy values('$WG_INTERFACE','<>');"
                        else
                            sqlite3 $SQL_DATABASE "INSERT INTO $TABLE values('$WG_INTERFACE','$AUTO','$SUBNET','$DNS','$ALLOWIP','$PUB_KEY','$PRI_KEY','$ANNOTATE','');"
                        fi

                        cp ${IMPORT_DIR}${WG_INTERFACE}.conf ${CONFIG_DIR}${WG_INTERFACE}.conf_imported

                        if [ "$COMMENT_OUT" == "Y" ];then
                            sed -i 's/^DNS/#DNS/' ${IMPORT_DIR}${WG_INTERFACE}.conf
                            sed -i 's/^Address/#Address/' ${IMPORT_DIR}${WG_INTERFACE}.conf
                            sed -i 's/^MTU/#MTU/' ${IMPORT_DIR}${WG_INTERFACE}.conf # v4.09
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

                        [ "$IMPORT_DIR" != "$CONFIG_DIR" ] && cp ${IMPORT_DIR}${WG_INTERFACE}.conf ${CONFIG_DIR}${WG_INTERFACE}.conf

                        [ "$RENAME" == "Y" ] && { mv ${CONFIG_DIR}${WG_INTERFACE}.conf ${CONFIG_DIR}${NEW_NAME}.conf; local AS_TXT="as ${cBMAG}$NEW_NAME "$cRESET; }

                        echo -e $cBGRE"\n\t[✔] Config ${cBMAG}${WG_INTERFACE}${cBGRE} import ${AS_TXT}${FORCE_TYPE_TXT}success"$cRESET 2>&1

                        local COMMENTOUT=; local RENAME=; local AS_TXT=
                    else
                        SayT "***ERROR: WireGuard VPN 'client' Peer ('$WG_INTERFACE') ALREADY exists in database?....skipping import request"
                        echo -e $cBRED"\a\n\t***ERROR: WireGuard 'client' Peer (${cBWHT}$WG_INTERFACE${cBRED}) ALREADY exists in database?....skipping import Peer '${cBMAG}${WG_INTERFACE}${cBRED}' request\n"$cRESET   2>&1
                    fi
                else
                    SayT "***ERROR: WireGuard VPN Peer ('$WG_INTERFACE') must be 'client'....skipping import request"
                    echo -e $cBRED"\a\n\t***ERROR: WireGuard Peer (${cBWHT}$WG_INTERFACE${cBRED}) must be 'client'....skipping import Peer '${cBMAG}${WG_INTERFACE}${cBRED}' request\n"$cRESET   2>&1
                fi
            else
                SayT "***ERROR: WireGuard VPN 'client' Peer ('${IMPORT_DIR}$WG_INTERFACE') config NOT found?....skipping import request"
                echo -e $cBRED"\a\n\t***ERROR: WireGuard 'client' Peer (${cBWHT}${IMPORT_DIR}$WG_INTERFACE${cBRED}) config NOT found?....skipping import Peer '${cBMAG}${WG_INTERFACE}${cBRED}' request\n"$cRESET   2>&1
            fi
        done

}
Manage_Peer() {

    local ACTION=$1;shift

    WG_INTERFACE=$1;shift
    local CMD=$1

    if [ "$WG_INTERFACE" == "new" ] || [ "$WG_INTERFACE" == "newC" ] || [ "$WG_INTERFACE" == "new6" ] ;then
        CMD="$WG_INTERFACE";
        WG_INTERFACE=
    fi

    [ "$WG_INTERFACE" == "help" ] && { CMD="help"; WG_INTERFACE=; }

    [ -z "$CMD" ] && CMD="list"

    [ -n "$(echo $@ | grep -iw "ipset")" ] && { local SUBCMD=$CMD;local CMD="ipset"; }

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

                    echo -e "\tpeer new [peer_name [options]]\t\t\t\t\t\t- Create new server Peer e.g. peer new wg27 ip=10.50.99.1/24 port=12345"

                    echo -e "\tpeer peer_name [del|add] ipset {ipset_name[...]}\t\t\t- Selectively Route IPSets e.g. peer wg13 add ipset NetFlix Hulu"

                    echo -e "\tpeer peer_name {rule [del {id_num} |add [wan] rule_def]}\t\t- Manage Policy rules e.g. peer wg13 rule add 172.16.1.0/24 comment All LAN"
                    echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t   peer wg13 rule add wan 52.97.133.162 comment smtp.office365.com"
                    echo -e "\t\t\t\t\t\t\t\t\t\t\t\t\t   peer wg13 rule add wan 172.16.1.100 9.9.9.9 comment Quad9 DNS"
                    return
                fi

                local FN=${INSTALL_DIR}WireguardVPN.confXXX

                if [ "$WG_INTERFACE" == "new" ] || [ "$WG_INTERFACE" == "newC" ] || [ "$WG_INTERFACE" == "add" ] || [ "$WG_INTERFACE" == "new6" ] ;then
                    CMD=$WG_INTERFACE
                    shift
                    WG_INTERFACE=$1
                fi

                if [ "$WG_INTERFACE" != "category" ];then                   # v3.04

                    if [ "$CMD" == "import" ] || [ "$CMD" == "delX" ] || [ "$CMD" == "new" ] || [ "$CMD" == "add" ] || [ "$CMD" == "new6" ] || [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
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

                                if [ "$(echo "$AUTO" | grep "^[yYnNpPZ]$" )" ];then
                                    FLAG=$(echo "$AUTO" | tr 'a-z' 'A-Z')
                                    if [ -z "$(echo "$CMD" | grep "autoX")" ];then
                                        # If Auto='P' then enforce existence of RPDB Selective Routing rules for the 'client' Peer
                                        if [ "$FLAG" == "P" ];then
                                            [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$WG_INTERFACE';") -eq 0 ] && { echo -e $cBRED"\a\n\t***ERROR No Policy rules exist for ${cBMAG}$WG_INTERFACE ${cBRED}(${cBWHT}use 'peer $WG_INTERFACE rule add' command${cBRED} first)\n"$cRESET; return 1; }
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
                                #echo -e $cBCYA"\n\tPeer Comment (Before): $(grep -E "^$WG_INTERFACE[[:space:]]" $FN)"$cRESET
                                shift 1
                                COMMENT="$@"
                                [ "${COMMENT:0:1}" != "#" ] && COMMENT="# "$COMMENT
                                COMMENT=$(echo "$COMMENT" | sed "s/'/''/g")
                                [ ${WG_INTERFACE:0:3} == "wg2" ] && local TABLE="servers" || TABLE="clients"
                                sqlite3 $SQL_DATABASE "UPDATE $TABLE SET tag='$COMMENT' WHERE peer='$WG_INTERFACE';"
                                #sed -i "/^$WG_INTERFACE/ s~\#.*$~$COMMENT~" ${INSTALL_DIR}WireguardVPN.conf
                                #echo -e $cBGRE"\tPeer Comment (After) : $(grep -E "^$WG_INTERFACE[[:space:]]" $FN)\n"$cRESET

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

                                    if [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$WG_INTERFACE';") -gt 0 ];then
                                        local COLOR=$cBCYA;local TXT=
                                        if [ "$Mode" == "client" ] && [ "$AUTO" != "P" ];then
                                            COLOR=$cRED;local TXT="DISABLED"
                                        fi
                                        echo -e $COLOR"\n\tSelective Routing RPDB rules $TXT\n"
                                        sqlite3 $SQL_DATABASE "SELECT rowid,peer,iface,srcip,dstip,tag FROM policy WHERE $ID='$WG_INTERFACE' ORDER BY iface DESC;" |column -t  -s '|' --table-columns ID,Peer,Interface,Source,Destination,Description # v4.08
                                    else
                                        if [ "$Mode" == "client" ];then
                                            [ "$AUTO" != "P" ] && local COLOR=$cGRA || local COLOR=$cRED                    # v4.11
                                            echo -e $COLOR"\n\tNo RPDB Selective Routing rules for $WG_INTERFACE\n"$cRESET  # v4.11
                                        fi
                                    fi
                                fi

                                [ "$Mode" == "device" ] && { local HDR="Device"; local ID="name"; }  || { local HDR="Peer"; local ID="peer"; } # v4.02 Hotfix

                                echo -e $cBMAG
                                sqlite3 $SQL_DATABASE "SELECT $ID,tag FROM $TABLE WHERE $ID='$WG_INTERFACE';" | column -t  -s '|' --table-columns $HDR,'Annotation' # v4.02 Hotfix

                                echo -e $cBCYA"\nConnected Session duration: $cBGRE"$(Session_Duration "$WG_INTERFACE")$cRESET

                            ;;
                            import*)
                                Import_Peer "$WG_INTERFACE"
                            ;;
                            rule*)
                                Manage_RPDB_rules $menu1
                                [ $? -eq 1 ] && Show_Peer_Config_Entry "$WG_INTERFACE"
                            ;;
                            allowedips=*)
                                shift
                                local Mode=$(Server_or_Client "$WG_INTERFACE")
                                local ALLOWEDIPSCMD="$(echo "$CMD" | sed -n "s/^.*allowedips=//p" | awk '{print $1}' | tr ',' ' ')" # v4.11
                                local ALLOWEDIPS=
                                for IP in $ALLOWEDIPSCMD
                                    do
                                        if [ -n "$(echo "$IP" | Is_IPv4_CIDR)" ] || [ -n "$(echo "$IP" | Is_IPv4)" ] || [ -n "$(echo "$IP" | Is_IPv6)" ];then       # v4.11
                                            [ -n "$ALLOWEDIPS" ] && local ALLOWEDIPS=$ALLOWEDIPS","
                                            ALLOWEDIPS=$ALLOWEDIPS""$IP
                                        else
                                            echo -e $cBRED"\n\a\t***ERROR: Invalid IP '${cBWHT}${IP}${cBRED}'"$RESET
                                            return
                                        fi
                                    done

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
                                        echo -e $cBWHT"\a\n\tWireGuard 'client' Peer ${cBMAG}${WG_INTERFACE} ${TAG}$cBWHT needs to be ${CMD}ed"
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
                                                                echo -e $cBWHT"\a\n\tWireGuard 'server' Peer needs to be ${CMD}ed to update 'client' Peer ${cBMAG}${DEVICE_NAME} $TAG"
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
                                    sed -i "/^DNS/ s~[^ ]*[^ ]~$DNS~3" ${CONFIG_DIR}${WG_INTERFACE}.conf

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
                                    if [ "$MTU" -ge "1280" ] && [ "$MTU" -le "1420" ];then
                                        sqlite3 $SQL_DATABASE "UPDATE $TABLE SET mtu='$MTU' WHERE $ID='$WG_INTERFACE';"
                                        sed -i "/^MTU/ s~[^ ]*[^ ]~$MTU~3" ${CONFIG_DIR}${WG_INTERFACE}.conf

                                        echo -e $cBGRE"\n\t[✔] Updated MTU\n"$cRESET
                                    else
                                        echo -e $cBRED"\a\n\t***ERROR 'client' Peer'$WG_INTERFACE' MTU '$MTU' invalid; range 1280-1420 Only\n"$cRESET
                                    fi
                                else
                                     echo -e $cBRED"\a\n\t***ERROR 'server' Peer '$WG_INTERFACE' cannot set MTU\n"$cRESET
                                fi
                            ;;
                            add*|ipset*)                            # peer wg13 [add|del|edit] ipset Netflix[.....]

                                local ARGS=$@
                                if [ "$SUBCMD" == "add" ] || [ "$SUBCMD" == "del" ] || [ "$SUBCMD" == "upd" ];then
                                    shift 2
                                    Manage_IPSET "$SUBCMD" "$WG_INTERFACE" "$@"
                                else
                                    echo -e $cBRED"\a\n\t***ERROR Invalid command '$SUBCMD' e.g. [add | del | upd]\n"$cRESET
                                fi
                            ;;
                            *)
                                #echo -e $cBCYA"\n\tPeer Entry: $(grep -E "^$WG_INTERFACE[[:space:]]" $FN)\n"$cRESET
                                local Mode=$(Server_or_Client "$WG_INTERFACE")
                                case $Mode in
                                    server) local TABLE="servers";;
                                    client) local TABLE="clients";;
                                esac

                                [ "${WG_INTERFACE:0:2}" != "wg" ] && local TABLE="devices"

                                echo -e $cBYEL"\tTable:$TABLE"$cBCYA 2>&1
                                sqlite3 $SQL_DATABASE "SELECT * FROM $TABLE;"
                            ;;
                        esac
                    else
                        echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard Peer '$WG_INTERFACE'\n"$cRESET
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

    # ALL Peers?
    if [ -z "$WG_INTERFACE" ];then
            local WG_INTERFACE=

            # If no specific Peer specified, for Stop/Restart retrieve ACTIVE Peers otherwise for Start use Peer configuration
            if [ "$ACTION" == "start" ];then                  # v2.02 v1.09
                WG_INTERFACE=$(sqlite3 $SQL_DATABASE "SELECT peer FROM clients WHERE auto='Y' OR auto='P';" | tr '\n' ' ')
                WG_INTERFACE=$WG_INTERFACE" "$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers WHERE auto='Y' OR auto='P';" | tr '\n' ' ')
                if [ -z "$WG_INTERFACE" ];then
                    echo -e $cRED"\a\n\t***ERROR: No WireGuard Peers WHERE (${cBWHT}Auto='Y'${cBRED}) defined\n"$cRESET 2>&1
                    return 1
                fi
            else
                # Wot if there are Peers we don't control?
                WG_INTERFACE=$(wg show interfaces)                # v1.09
            fi
            SayT "$VERSION Requesting WireGuard VPN Peer $ACTION ($WG_INTERFACE)"
    else
        echo -en $cBCYA
        # Allow category
        case "$WG_INTERFACE" in
            clients)
                WG_INTERFACE=$(sqlite3 $SQL_DATABASE "SELECT peer FROM clients WHERE auto='Y' OR auto='P';" | tr '\n' ' ')
                local CATEGORY=" for Category 'Clients'"
                SayT "$VERSION Requesting WireGuard VPN Peer ${ACTION}$CATEGORY ($WG_INTERFACE)"
                local TABLE="clients"
                if [ -z "$WG_INTERFACE" ];then
                    echo -e $cRED"\a\n\t***ERROR: No Peers$CATEGORY WHERE (${cBWHT}Auto='Y' or 'P'${cBRED}) defined\n"$cRESET 2>&1
                    return 1
                fi
            ;;
            servers)
                WG_INTERFACE=$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers WHERE auto='Y' OR auto='P';" | tr '\n' ' ')
                local CATEGORY=" for Category 'Servers'"
                SayT "$VERSION Requesting WireGuard VPN Peer ${ACTION}$CATEGORY ($WG_INTERFACE)"
                local TABLE="servers"
                if [ -z "$WG_INTERFACE" ];then
                    echo -e $cRED"\a\n\t***ERROR: No Peers$CATEGORY WHERE (${cBWHT}Auto='Y'${cBRED}) defined\n"$cRESET 2>&1
                    return 1
                fi
            ;;
            *)

                local PEERS=$WG_INTERFACE" "$@              # v3.04

                for PEER in $PEERS
                    do
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

    WG_INTERFACE=$(printf "%s" "$WG_INTERFACE" | sed 's/^[ \t]*//;s/[ \t]*$//')

    [ -n "$WG_INTERFACE" ] && echo -e $cBWHT"\n\tRequesting WireGuard VPN Peer ${ACTION}$CATEGORY (${cBMAG}$WG_INTERFACE"$cRESET")"

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

                    [ "$WG_INTERFACE" == "nopolicy" ] && continue                           # v2.02

                    LOOKAHEAD=$(echo "$LOOKAHEAD" | awk '{$1=""}1')
                    if [ "$(echo "$LOOKAHEAD" | awk '{print $1}')" == "nopolicy" ];then     # v2.02
                        Route="default"
                        POLICY_MODE="Policy override ENFORCED"
                    fi

                    if [ -z "$Route" ];then
                        if [ "$Mode" == "client" ];then
                            if [ "$(sqlite3 $SQL_DATABASE "SELECT auto FROM $TABLE WHERE peer='$WG_INTERFACE';")" == "P" ];then

                                if [ "$(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$WG_INTERFACE';")" -gt 0 ];then
                                    Route="policy"
                                else
                                    SayT "Warning: WireGuard '$Mode' Peer ('$WG_INTERFACE') defined as Policy mode but no RPDB Selective Routing rules found?"
                                    echo -e $cRED"\tWarning: WireGuard '$Mode' Peer (${cBWHT}$WG_INTERFACE${cBRED}) defined as Policy mode but no RPDB Selective Routing rules found?\n"$cRESET 2>&1
                                fi
                            else
                                Route="default"
                            fi
                        fi
                    fi

                    if [ "$ACTION" == "restart" ];then                                      # v1.09
                        # If it is UP then terminate the Peer
                        if [ -n "$(ifconfig $WG_INTERFACE 2>/dev/null | grep inet)" ];then  # v1.09
                            echo -e $cBWHT"\tRestarting Wireguard '$Mode' Peer (${cBMAG}${WG_INTERFACE}${cBWHT})"$cRESET 2>&1
                            SayT "$VERSION Restarting Wireguard '$Mode' Peer ($WG_INTERFACE)"
                            [ "$Mode" == "server" ] && /jffs/addons/wireguard/wg_server $WG_INTERFACE "disable" || ${INSTALL_DIR}wg_client $WG_INTERFACE "disable"                 # v1.09
                        fi
                    fi

                    echo -en $cBCYA
                    SayT "$VERSION Initialising Wireguard VPN '$Mode' Peer ($WG_INTERFACE) ${POLICY_MODE}"
                    if [ -n "$(ifconfig | grep -E "^$WG_INTERFACE")" ];then
                        SayT "Warning: WireGuard '$Mode' Peer ('$WG_INTERFACE') ALREADY ACTIVE"
                        echo -e $cRED"\tWarning: WireGuard '$Mode' Peer (${cBWHT}$WG_INTERFACE${cBRED}) ALREADY ACTIVE\n"$cRESET 2>&1
                    else                                                                    # v3.04 Hotfix
                        if [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                            if [ "$Mode" == "server" ] ; then

                                local TS=$(date +%s)
                                sh ${INSTALL_DIR}wg_server $WG_INTERFACE
#[ "$(wg show interfaces | grep "wg2[1-9]" | wc -w)" -eq 1 ] && local UDP_MONITOR=$(Manage_UDP_Monitor "server" "enable")

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
                                    sh ${INSTALL_DIR}wg_client $WG_INTERFACE
                                else
                                    sh ${INSTALL_DIR}wg_client $WG_INTERFACE "policy"
                            fi
                        else
                            [ -n "$Mode" ] && TXT="'$Mode' " || TXT=            # v1.09
                            SayT "***ERROR: WireGuard VPN ${TXT}Peer ('$WG_INTERFACE') config NOT found?....skipping $ACTION request"
                            echo -e $cBRED"\a\n\t***ERROR: WireGuard ${TXT}Peer (${cBWHT}$WG_INTERFACE${cBRED}) config NOT found?....skipping $ACTION request\n"$cRESET   2>&1  # v1.09
                        fi
                    fi
                    # Reset the Policy flag
                    Route=                                  # v2.02
                done
            WG_show
            ;;
        stop)

            # Default is to terminate ALL ACTIVE Peers,unless a list of Peers belonging to a category has been provided
            if [ -z "$WG_INTERFACE" ];then
                WG_INTERFACE=$(wg show interfaces)      # ACTIVE Peers
                if [ -n "$WG_INTERFACE" ];then
                    WG_INTERFACE=
                    SayT "$VERSION Requesting termination of ACTIVE WireGuard VPN Peers ($WG_INTERFACE)"
                    echo -e $cBWHT"\tRequesting termination of ACTIVE WireGuard VPN Peers ($WG_INTERFACE)\n"$cRESET 2>&1
                else
                    echo -e $cRED"\n\tNo WireGuard VPN Peers ACTIVE for Termination request\n" 2>&1
                    SayT "No WireGuard VPN Peers ACTIVE for Termination request"
                    echo -e 2>&1
                    return 0
                fi
            fi

            echo -e

            for WG_INTERFACE in $WG_INTERFACE
                do
                   [ -z "$(grep -iE "^Endpoint" ${CONFIG_DIR}${WG_INTERFACE}.conf)" ] && { Mode="server"; TABLE="servers"; } || { Mode="client"; TABLE="clients"; }
                   if [ -n "$(wg show $WG_INTERFACE)" ] || [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                        if [ -n "$(wg show $WG_INTERFACE)" ] && [ ! -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                            local FORCE="force"
                        fi
                        local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM $TABLE WHERE peer='$WG_INTERFACE';")
                        echo -en $cBCYA
                        SayT "$VERSION Requesting termination of WireGuard VPN '$Mode' Peer ('$WG_INTERFACE')"

                        if [ -z "$(ifconfig | grep -E "^$WG_INTERFACE")" ];then
                            echo -e $cRED"\a\t";Say "WireGuard VPN '$Mode' Peer ('$WG_INTERFACE') NOT ACTIVE";echo -e
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

                                sh ${INSTALL_DIR}wg_server $WG_INTERFACE "disable"

                                # If there are no 'server' Peers ACTIVE then terminate UDP monitoring
                                # Will require REBOOT to reinstate! or 'wgm init'
                                [ "$(wg show interfaces | grep "wg2[1-9]" | wc -w)" -eq 0 ] && local UDP_MONITOR=$(Manage_UDP_Monitor "server" "disable")

                            else
                                # Dump the stats
                                Show_Peer_Status "generatestats" "$WG_INTERFACE"                # v4.04
                                if [ "$Mode" == "client" ] && [ "$Route" != "policy" ] ; then
                                    /opt/bin/wg show $WG_INTERFACE >/dev/null 2>&1 && sh ${INSTALL_DIR}wg_client $WG_INTERFACE "disable" "$FORCE" || Say "WireGuard $Mode service ('$WG_INTERFACE') NOT running."
                                else
                                    /opt/bin/wg show $WG_INTERFACE >/dev/null 2>&1 && sh ${INSTALL_DIR}wg_client $WG_INTERFACE "disable" "policy" "$FORCE" || Say "WireGuard $Mode (Policy) service ('$WG_INTERFACE') NOT running."
                                fi
                            fi

                        fi
                    else
                        SayT "***ERROR: WireGuard VPN ${TXT}Peer ('$WG_INTERFACE') config NOT found?....skipping $ACTION request"
                        echo -e $cBRED"\a\n\t***ERROR: WireGuard ${TXT}Peer (${cBWHT}$WG_INTERFACE${cBRED}) config NOT found?....skipping $ACTION request\n"$cRESET   2>&1  # v1.09
                    fi
                done

            WG_show
            ;;
    esac
}
Manage_alias() {

    local ALIASES="start stop restart show diag"

    case "$1" in
        del)
            echo -e $cBCYA"\tDeleted aliases for '$SCRIPT_NAME'"$cRESET
            sed -i "/$SCRIPT_NAME/d" /jffs/configs/profile.add
            rm -rf "/opt/bin/unbound_manager" 2>/dev/null                                   # v2.01
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

    if [ -z "$(echo "$SRC" | Is_IPv4_CIDR)" ] && [ -z "$(echo "$SRC" | Is_Private_IPv4)" ];then
        local DST=$SRC
        local SRC=
    fi

    [ -z "$IFACE" ] && IFACE="VPN"
    [ -z "$SRC" ] && SRC="Any"
    [ -z "$DST" ] && DST="Any"

    local IFACE=$(echo "$IFACE" | tr 'a-z' 'A-Z')

    case "$CMD" in
        add)
            sqlite3 $SQL_DATABASE "INSERT INTO policy values('$WG_INTERFACE','$IFACE','$SRC','$DST','$ANNOTATE');"
            echo -e $cBGRE"\n\t[✔] Updated RPDB Selective Routing rule for $WG_INTERFACE \n"$cRESET  2>&1
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
                echo -e $cRED"\n\tNo RPDB Selective Routing rules for $WG_INTERFACE\n"$cRESET
            fi

            REDISPLAY=0
        ;;
    esac

    return $REDISPLAY
}
Initialise_SQL() {

    local ACTION=$2
    local FORCE=$2

    #[ -n "$(which sqlite3)" ] && opkg install sqlite3-cli

    local TS=$(date +"%Y%m%d-%H%M%S")    # current date and time 'yyyymmdd-hhmmss'

    local FCNT=$(ls -lah ${CONFIG_DIR}*.conf 2>/dev/null | wc -l)
    [ -f ${INSTALL_DIR}WireguardVPN.conf ] && local CCNT=$(grep -E "^wg[1-2]" ${INSTALL_DIR}WireguardVPN.conf | wc -l) || local CCNT=0

    if [ $CCNT -eq 0 ];then
        echo -e $cBRED"\a\n\tNo Peer entries to auto-migrate ${cBCYA}from '${cBWHT}${INSTALL_DIR}WireguardVPN.conf${cBCYA}', but you will need to manually import the 'device' Peer '*.conf' files:\n\n"$cRESET

        ls -1 ${CONFIG_DIR}*.conf 2>/dev/null | awk -F '/' '{print $5}' | grep -v "wg[1-2]" | sed 's/\.conf$//' | sort
        [ "$ACTION" == "migrate" ] && return 0
    fi

    if [ -f $SQL_DATABASE ] && [ "$ACTION" != "keep" ];then
        mv $SQL_DATABASE ${SQL_DATABASE}.$TS 2>/dev/null
    fi

    # v4.09 Modify policy
    cat > /tmp/sql_cmds.txt << EOF
CREATE TABLE IF NOT EXISTS servers (peer varchar(5) PRIMARY KEY, auto varchar(1) NOT NULL, subnet varchar(19) NOT NULL, port integer(5), pubkey varchar(55), prikey varchar(55) NOT NULL, tag varchar(40));
CREATE TABLE IF NOT EXISTS clients (peer varchar(5) PRIMARY KEY, auto varchar(1) NOT NULL, subnet varchar(19) NOT NULL, socket varchar(25), dns varchar(19), mtu integer(4),pubkey varchar(55), prikey varchar(55), tag varchar(40));
CREATE TABLE IF NOT EXISTS devices (name varchar(15) PRIMARY KEY, auto varchar(1) NOT NULL, ip varchar(19)  NOT NULL, dns varchar(15)  NOT NULL, allowedip varchar(100), pubkey varchar(55)  NOT NULL, prikey varchar(55), tag varchar(40), conntrack UNSIGNED BIG INT );
CREATE TABLE IF NOT EXISTS policy  (peer varchar(5), iface varchar(4), srcip varchar(19), dstip varchar(19), tag varchar(30), PRIMARY KEY(peer,iface,srcip,dstip));
CREATE TABLE IF NOT EXISTS fwmark  (fwmark varchar(10), peer varchar(15) NOT NULL, PRIMARY KEY(fwmark,peer));
CREATE TABLE IF NOT EXISTS ipset   (ipset PRIMARY KEY, use varchar(1), peer varchar(5),fwmark varchar(10) NOT NULL, dstsrc varchar (11) NOT NULL);
CREATE TABLE IF NOT EXISTS traffic (peer NOT NULL,timestamp UNSIGNED BIG INT NOT NULL,rx UNSIGNED BIG INT NOT NULL,tx UNSIGNED BIG INT NOT NULL);
CREATE TABLE IF NOT EXISTS session (peer NOT NULL,state varchar(1), timestamp UNSIGNED BIG INT NOT NULL);
EOF
    echo -en $cBRED
    sqlite3 $SQL_DATABASE < /tmp/sql_cmds.txt
    [ $? -eq 0 ] &&  echo -e $cBGRE"\n\t[✔] WireGuard Peer SQL Database initialised OK\n"$cRESET
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
        echo -e $cBYEL"\a\n\tWarning: WireGuard configuration file '${INSTALL_DIR}WireguardVPN.conf' already exists!...renamed to 'WireguardVPN.conf$TS'"
        mv ${INSTALL_DIR}WireguardVPN.conf ${INSTALL_DIR}WireguardVPN.conf.$TS
    fi
    echo -e $cBCYA"\a\n\tCreating WireGuard configuration file '${INSTALL_DIR}WireguardVPN.conf'"

    cat > ${INSTALL_DIR}WireguardVPN.conf << EOF
# WireGuard Session Manager v4.01

# Categories
None=

# WAN KILL-Switch
KILLSWITCH

# Statistics Gathering
STATS


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
            echo -e $cBWHT"\tPress$cBRED y$cRESET to Display QR Code for Scanning into WireGuard App on device $cBMAG'$DEVICE_NAME' ${cRESET}or press$cBGRE [Enter] to SKIP."
            read -r "ANS"
        fi
        [ "$ANS" == "y" ] && { clear; qrencode -t ANSIUTF8 < $FN; }             # v1.05
    fi
}
Edit_nat_start() {

    if [ "$1" != "del" ];then

        [ ! -f /jffs/scripts/nat-start ] && { echo -e "#!/bin/sh\n\n"    > /jffs/scripts/nat-start; chmod +x /jffs/scripts/nat-start; }
        if [ -z "$(grep "WireGuard" /jffs/scripts/nat-start)" ];then
            echo -e "/jffs/addons/wireguard/wg_firewall            # WireGuard" >> /jffs/scripts/nat-start
            cat > /jffs/addons/wireguard/wg_firewall << EOF                     # v2.04
#!/bin/sh
VERSION="$TS"
# Reinstate WireGuard firewall rules by restarting WireGuard as nat-start has executed
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

logger -st "(\$(basename "\$0"))" \$\$ "Checking if WireGuard VPN Peer KILL-Switch is required....."
if [ -n "\$(grep -E "^KILLSWITCH" /jffs/addons/wireguard/WireguardVPN.conf)" ];then
    iptables -D FORWARD -i br0 -o \$(nvram get wan0_ifname) -j REJECT -m comment --comment "WireGuard KILL-Switch" 2>/dev/null
    iptables -I FORWARD -i br0 -o \$(nvram get wan0_ifname) -j REJECT -m comment --comment "WireGuard KILL-Switch" 2>/dev/null
    logger -st "(\$(basename "\$0"))" \$\$ "WireGuard VPN Peer KILL-Switch ENABLED"
fi

if [ -n "\$(wg show interfaces)" ];then
    logger -st "(\$(basename "\$0"))" \$\$ "Restarting WireGuard to reinstate RPDB/firewall rules"
    /jffs/addons/wireguard/wg_manager.sh stop
    /jffs/addons/wireguard/wg_manager.sh start

fi
EOF

            chmod +x /jffs/addons/wireguard/wg_firewall
        fi
        echo -e $cBCYA"\n\tnat-start updated to protect WireGuard firewall rules"$cRESET
        SayT "nat-start updated to protect WireGuard firewall rules"
    else
        sed -i '/WireGuard/d' /jffs/scripts/nat-start
        echo -e $cBCYA"\n\tnat-start updated - no longer protecting WireGuard firewall rules"$cRESET
        SayT "nat-start updated - no longer protecting WireGuard firewall rules"
    fi

}
Server_or_Client() {

    local WG_INTERFACE=$1
    local PEER_TYPE="**ERROR**"                                                         # v4.05

        # Always identify if it's a 'client','server' or 'device' Peer from its config file
        if [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then                                # v1.03
            if [ -n "$(grep -iE "^Endpoint" ${CONFIG_DIR}${WG_INTERFACE}.conf)" ];then  # v1.03
                local PEER_TYPE="client"
                if [ -n "$(nvram get ddns_hostname_x)" ];then                           # v4.05
                    [ -n "$(grep -iF "$(nvram get ddns_hostname_x)" ${CONFIG_DIR}${WG_INTERFACE}.conf)" ] && PEER_TYPE="device"
                fi
            else
                local PEER_TYPE="server"
            fi
        fi

    echo "$PEER_TYPE"
}
WG_show() {

    local SHOW=$1

    if [ "$SHOW" == "Y" ];then
        echo -e $cBCYA"\tStatus:\n"$cRESET
        /opt/bin/wg show all
    fi
}
DNSmasq_Listening_WireGuard_Status() {
    # Check if DNSmasq is listening on ALL wg* interfaces               # v1.07
    if [ -z "$(grep -F "wg*" /etc/dnsmasq.conf)" ];then
        echo -e $cBRED"\t[✖]${cBWHT} DNSmasq ${cRED}is not listening on any WireGuard interfaces 'wg*'\n"$cRESET 2>&1
    else
        echo -e $cBGRE"\t[✔]${cBWHT} DNSmasq ${cBGRE}is listening on ALL WireGuard interfaces 'wg*'\n"$cRESET 2>&1
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

    if [ -n "$ACTION" ];then
        if [ "$ACTION" != "off" ];then
                iptables -D FORWARD -i br0 -o $(nvram get wan0_ifname) -j REJECT -m comment --comment "WireGuard KILL-Switch" 2>/dev/null
                iptables -I FORWARD -i br0 -o $(nvram get wan0_ifname) -j REJECT -m comment --comment "WireGuard KILL-Switch" 2>/dev/null
                [ "$SILENT" == "N" ] && echo -e $cBGRE"\n\t[✔] WireGuard WAN KILL Switch ${cBRED}${aREVERSE}ENABLED"$cRESET 2>&1
        else
                iptables -D FORWARD -i br0 -o $(nvram get wan0_ifname) -j REJECT -m comment --comment "WireGuard KILL-Switch" 2>/dev/null
                [ "$SILENT" == "N" ] && echo -e $cBRED"\n\t[✖] ${cBGRE}WireGuard WAN KILL Switch ${cBRED}${aREVERSE}DISABLED"$cRESET 2>&1
        fi
    fi

    [ -n "$(iptables -L FORWARD | grep "WireGuard KILL-Switch")" ] && STATUS="Y" || STATUS="N"

    echo "$STATUS"      # Y/N
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
        local TXT="${cBGRE}\t[✔] Statistics gathering is ENABLED"$cRESET
        STATUS=1
    else
        local TXT="${cBRED}\t[✖] ${cBGRE}Statistics gathering is ${cRED}DISABLED"$cRESET
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

    chmod +x ${INSTALL_DIR}wg_manager.sh
    chmod +x ${INSTALL_DIR}wg_client
    chmod +x ${INSTALL_DIR}wg_server
    chmod +x ${INSTALL_DIR}UDP_Updater.sh                                               # v4.01

    md5sum ${INSTALL_DIR}wg_manager.sh      > ${INSTALL_DIR}"wg_manager.md5"
    md5sum ${INSTALL_DIR}wg_client          > ${INSTALL_DIR}"wg_client.md5"
    md5sum ${INSTALL_DIR}wg_server          > ${INSTALL_DIR}"wg_server.md5"
    md5sum ${INSTALL_DIR}UDP_Updater.sh     > ${INSTALL_DIR}"UDP_Updater.md5"          # v4.01
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
    if [ -f "${INSTALL_DIR}WireguardVPN.conf" ] && [ -n "$(which wg)" ];then   # v2.00
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
    local PEER_STATUS=

    [ -n "$(which wg)" ] && ACTIVE_PEERS="$(wg show interfaces)"

    for PEER in $ACTIVE_PEERS
        do
            TYPE=$(Server_or_Client "$PEER")
            case $TYPE in
                client)
                    CLIENT_PEERS=$((CLIENT_PEERS+1))
                ;;
                server)
                    SERVER_PEERS=$((SERVER_PEERS+1))
                ;;
            esac
        done

    PEER_STATUS="Clients ${cBWHT}$CLIENT_PEERS${cBMAG}, Servers ${cBWHT}$SERVER_PEERS"
    echo -e "$PEER_STATUS" 2>&1

    [ -n "$1" ] && SayT "$PEER_STATUS"
}
Show_credits() {
    printf '\n+======================================================================+\n'
    printf '|  Welcome to the %bWireGuard Manager/Installer script (Asuswrt-Merlin)%b  |\n' "$cBGRE" "$cRESET"
    printf '|                                                                      |\n'
    local local CNT=23;VERSION_LENGTH=${#VERSION}
    [ $VERSION_LENGTH -gt 4 ] && CNT=$((CNT-(VERSION_LENGTH-4)))
    local BLANKS=$(Repeat $CNT " ")
    printf '|                      Version %b%s%b by Martineau%b' "$cBMAG" "$VERSION" "${cRESET}" "${BLANKS}|\n"    # v3.22
    printf '|                                                                      |\n'
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

    echo -e $cBWHT"\n\tInstalling WireGuard Manager - Router$cBMAG $HARDWARE_MODEL (v$BUILDNO) $(grep -E "^arch" $ENTWARE_INFO)\n"$cRESET

    if [ "$(Is_AX)" == "N" ] && [ "$(Is_HND)" == "N" ];then
        echo -e $cBRED"\a\n\tERROR: Router$cRESET $HARDWARE_MODEL (v$BUILDNO)$cBRED is not currently compatible with WireGuard!\n"
        exit 96
    else
        if [ "$(grep  "^arch" $ENTWARE_INFO | awk -F'=' '{print $2}' )" != "aarch64" ];then     # v4.11 Hotfix
            echo -e $cBRED"\a\n\tERROR: Entware version not compatible with WireGuard!\n"       # v4.11
            exit 97
        fi
    fi

    echo -en $cBRED

    # Amtm
    # mkdir -p /jffs/addons/wireguard
    if [ -d /opt/etc/ ];then
        # Legacy pre v2.03 install?
        if [ -d /opt/etc/wireguard ];then
            echo -e $cRED"\a\n\tWarning: obsolete WireGuard Session Manager v1.xx config directory Found!!! (${cBWHT}'/opt/etc/wireguard'{$cBRED})\n"$cRESET
            SayT "Warning obsolete WireGuard Session Manager config directory Found!!! ('/opt/etc/wireguard')"
        fi
        [ ! -d ${CONFIG_DIR} ] && mkdir -p ${CONFIG_DIR}
    else
        echo -e $cBRED"\a\n\t***ERROR: Entware directory '${cRESET}/opt/etc/${cBRED}' not found? - Please install Entware (amtm Diversion)\n"$cRESET
        exit 95
    fi

    # Scripts
    if [ -d "${INSTALL_DIR}" ];then
        Get_scripts "$2"
        echo -e
    fi

    modprobe xt_comment
    opkg install column                     # v2.02
    opkg install coreutils-mkfifo

    # Kernel module
    echo -e $cBCYA"\tDownloading Wireguard Kernel module for $HARDWARE_MODEL (v$BUILDNO)"$cRESET

    ROUTER_COMPATIBLE="Y"

    Download_Modules $HARDWARE_MODEL

    Load_UserspaceTool

    # Create the Sample/template parameter file '${INSTALL_DIR}WireguardVPN.conf'
    Create_Sample_Config

    Initialise_SQL                                      # v3.04

    # Create 'Server' Peer
    echo -e $cBCYA"\tCreating WireGuard 'Server' Peer ${cBMAG}(wg21)${cBCYA}'"$cRESET

    # Create Server template
    local PEER_LIST="1"
    for I in $PEER_LIST                                            # v3.02
        do
            cat > ${CONFIG_DIR}wg2${I}.conf << EOF
# $HARDWARE_MODEL 'server' Peer #1 (wg2$I)
[Interface]
PrivateKey = Ha1rgO/plL4wCB+pRdc6Qh8bIAWNeNgPZ7L+HFBhoE4=
ListenPort = 51820

# e.g. Accept a WireGuard connection from say YOUR mobile device to the router

# DeviceExample
#[Peer]
#PublicKey = This_should_be_replaced_with_the_Public_Key_of_YOUR_mobile_device
#AllowedIPs = 0.0.0.0/0 # All Access or [192.168.1.0/24,10.8.0.21/32] i.e. List of IP/Subnet/networks YOUR mobile device may access.
# DeviceExample End
EOF

        done

    echo -e $cBCYA"\tCreating WireGuard Private/Public key-pairs for ${cBMAG}$HARDWARE_MODEL (v$BUILDNO)"$cRESET
    if [ -n "$(which wg)" ];then

            # do
                # wg genkey | tee ${CONFIG_DIR}wg1${I}_private.key | wg pubkey > ${CONFIG_DIR}wg1${I}_public.key
            # done
        for I in $PEER_LIST
            do
                wg genkey | tee ${CONFIG_DIR}wg2${I}_private.key | wg pubkey > ${CONFIG_DIR}wg2${I}_public.key

                # Update the Sample Peer templates with the router's real keys
                # PRIV_KEY=$(cat ${CONFIG_DIR}wg11_private.key)
                # PRIV_KEY=$(Convert_Key "$PRIV_KEY")
                # sed -i "/^PrivateKey/ s~[^ ]*[^ ]~$PRIV_KEY~3" ${CONFIG_DIR}wg11.conf

                PRIV_KEY=$(cat ${CONFIG_DIR}wg2${I}_private.key)
                PRIV_KEY=$(Convert_Key "$PRIV_KEY")
                sed -i "/^PrivateKey/ s~[^ ]*[^ ]~$PRIV_KEY~3" ${CONFIG_DIR}wg2${I}.conf

                local WG_INTERFACE="wg2"${I}
                local AUTO="Y"
                local SUBNET="10.50.1.1/24"
                local PORT=51820
                local ANNOTATE="# $HARDWARE_MODEL Server #1"
                local PUB_KEY=$(cat ${CONFIG_DIR}${WG_INTERFACE}_public.key)
                local PRI_KEY=$(cat ${CONFIG_DIR}${WG_INTERFACE}_private.key)

                sqlite3 $SQL_DATABASE "INSERT INTO servers values('$WG_INTERFACE','$AUTO','$SUBNET','$PORT','$PUB_KEY','$PRI_KEY','$ANNOTATE');"
            done
    fi

    if  [ -n "$(which wg)" ] && [ "$ROUTER_COMPATIBLE" == "Y" ];then

        # Test 'wg' and this script - (well actually the one used @BOOT) against the 'server' Peers e.g. wg21
        #echo -e $cBCYA"\t${cRESET}${cYBLU}Test ${cRESET}${cBCYA}Initialising the Sample WireGuard 'client' and 'server' Peers, ${cYBLU}but ONLY the Sample 'server' (wg21) is VALID :-)${cYBLU}"$cRESET

        echo -e $cBCYA"\tInitialising WireGuard VPN 'server' Peer"$cRESET
        Manage_Wireguard_Sessions "start" "wg21"

        Manage_Stats "init" "enable"
    else
        echo -e $cBRED"\a\n\t***ERROR: WireGuard install FAILED!\n"$cRESETd
    fi

    Edit_nat_start                                      # v1.07

    Edit_DNSMasq                                        # v1.12

    Manage_alias

    Manage_Event_Scripts                                # v4.01 @ZebMcKayhan

    # Auto start ALL defined WireGuard Peers @BOOT
    # Use post-mount
    echo -e $cBCYA"\tAdding Peer Auto-start @BOOT"$cRESET
    if [ -z "$(grep -i "WireGuard" /jffs/scripts/post-mount)" ];then
        echo -e "/jffs/addons/wireguard/wg_manager.sh init \"$@\" & # WireGuard Manager" >> /jffs/scripts/post-mount
    fi

    echo -e $cBCYA"\tInstalling QR rendering module"$cBGRA
    opkg install qrencode

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
        echo -e $cBCYA"\tWireGuard Peer Status"
        Show_Peer_Status
    fi

    echo -e $cBGRE"\n\t${aREVERSE}$VERSION WireGuard Session Manager install COMPLETED.\n"$cRESET

}
Uninstall_WireGuard() {
    echo -e $cBCYA"\n\tUninstalling WireGuard Session Manager"$cRESET
    Manage_Wireguard_Sessions "stop"
    echo -en $cBRED
    [ -f ${INSTALL_DIR}WireguardVPN.conf ] && rm ${INSTALL_DIR}WireguardVPN.conf
        # legacy tidy-up!
        [ -f ${CONFIG_DIR}WireguardVPN_map ] && rm ${CONFIG_DIR}WireguardVPN_map

    # Only remove WireGuard Entware packages if user DELETES '/opt/etc/wireguard'
    echo -e "\n\tPress$cBRED Y$cRESET to$cBRED delete ALL WireGuard DATA files (Peer *.config etc.) $cRESET('${CONFIG_DIR}') or press$cBGRE [Enter] to keep custom WireGuard DATA files."
    read -r "ANS"
    if [ "$ANS" == "Y" ];then
       echo -e $cBCYA"\n\tDeleting $cRESET'${CONFIG_DIR}'"
       [ -d "${CONFIG_DIR}" ] && rm -rf ${CONFIG_DIR}

       echo -e $cBCYA"\tUninstalling Wireguard Kernel module and Userspace Tool for $HARDWARE_MODEL (v$BUILDNO)"$cBGRA
       opkg remove wireguard-kernel wireguard-tools
       rm -rf /opt/etc/wireguard/
    else
        Manage_Event_Scripts "backup"                           # v4.01
        [ -f ${INSTALL_DIR}WireguardVPN.conf ] && mv ${INSTALL_DIR}WireguardVPN.conf ${CONFIG_DIR}
    fi

    rm -rf ${INSTALL_DIR}

    echo -e $cBCYA"\tDeleted Peer Auto-start @BOOT\n"$cRESET
    [ -n "$(grep -i "WireGuard" /jffs/scripts/post-mount)" ] && sed -i '/WireGuard/d' /jffs/scripts/post-mount  # v2.01

    cru d "WireGuard"

    Manage_Stats "DISABLE" "disable"

    Edit_nat_start "del"

    Manage_alias "del"                  # v1.11

    Edit_DNSMasq "del"                  # v1.12

    echo -e $cBGRE"\n\tWireGuard Uninstall complete for $HARDWARE_MODEL (v$BUILDNO)\n"$cRESET

    exit 0
}
Session_Duration() {

    local WG_INTERFACE=$1

    local LAST_START=$(sqlite3 $SQL_DATABASE "SELECT timestamp FROM session WHERE (peer='$WG_INTERFACE' AND state='Start') order by timestamp desc limit 1;")
    local LAST_END=$(sqlite3 $SQL_DATABASE "SELECT timestamp FROM session WHERE (peer='$WG_INTERFACE' AND state='End') order by timestamp desc limit 1;")

    local MODE=$(Server_or_Client "$WG_INTERFACE")

    if [ "$MODE" == "device" ];then
        LAST_START=$(sqlite3 $SQL_DATABASE "SELECT conntrack FROM devices WHERE name='$WG_INTERFACE';")
        BEGINTAG=$(EpochTime "$LAST_START" "Human")
        LAST_END=$(date +%s)
    else

        if [ -n "$LAST_START" ];then
            if [ -n "$LAST_END" ];then
                if [ $LAST_START -lt $LAST_END ];then
                    BEGINTAG=$(EpochTime "$LAST_START" "Human")
                else
                    BEGINTAG=$(EpochTime "$LAST_START" "Human")
                    LAST_END=
                fi
            fi
        fi

        if [ -z "$LAST_END" ];then
            [ -n "$(wg show "$WG_INTERFACE" 2>/dev/null)" ] && local LAST_END=$(date +%s) || local LAST_START=$LAST_END
            local ENDTAG=" >>>>>>"
        else
            local ENDTAG=" to "$(EpochTime "$LAST_END" "Human")
        fi
    fi

    if [ -z "${LAST_START##[0-9]*}" ] && [ -z "${LAST_END##[0-9]*}" ];then
        local DURATION=$((LAST_END-LAST_START))
        echo -e $(Convert_SECS_to_HHMMSS "$DURATION" "Days")" from "${BEGINTAG}${ENDTAG}
    else
        echo -e "<$(EpochTime "$LAST_START" "Human")> to <$(EpochTime "$LAST_START" "Human")>"
    fi

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
        *)
            WG_INTERFACE=$WG_INTERFACE" "$1
            ;;
        esac
        shift
    done

    [ -z "$WG_INTERFACE" ] && WG_INTERFACE=$(wg show interfaces)

    for WG_INTERFACE in $WG_INTERFACE           # v3.02
        do
            [ -f "/tmp/WireGuard.txt" ] && rm /tmp/WireGuard.txt

            /opt/bin/wg show $WG_INTERFACE >> /tmp/WireGuard.txt

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
                            local LISTEN_PORT=$(awk '/^ListenPort/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf)
                            local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM $TABLE WHERE peer='$WG_INTERFACE';")
                            local DESC=$(printf "%s" "$DESC" | sed 's/^[ \t]*//;s/[ \t]*$//')
                            local VPN_IP_TXT="Port:${LISTEN_PORT}\t${VPN_ADDR} ${cBYEL}\t\tVPN Tunnel Network"
                        else
                            if [ "$MODE" == "client" ];then
                                local TYPE="client"
                                local TABLE="clients"
                            else
                                local TABLE="devices"
                            fi

                            # Tag it on screen if this is the default route
                            local DEFAULT_ROUTE=$(ip route | grep -Em 1 "^0.0.|128.0" | awk '{print $3}')       # v4.07
                            [ "$DEFAULT_ROUTE" == "$WG_INTERFACE" ] && DEF="$aUNDER" || DEF=
                            local LOCALIP=$(sqlite3 $SQL_DATABASE "SELECT subnet FROM $TABLE WHERE peer='$WG_INTERFACE';")
                            [ "$(nvram get ipv6_service)" == "disabled"  ] && local LOCALIP=$(echo "$LOCALIP" | awk -F ',' '{print $1}')
                            #local SOCKET=$(sqlite3 $SQL_DATABASE "SELECT socket FROM $TABLE WHERE peer='$WG_INTERFACE';")
                            local SOCKET=$(awk '/^^Endpoint/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf)

                            local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM $TABLE WHERE peer='$WG_INTERFACE';")
                            local DESC=$(printf "%s" "$DESC" | sed 's/^[ \t]*//;s/[ \t]*$//')
                            local VPN_IP_TXT=${SOCKET}"\t\t\t${cBYEL}${LOCALIP}\t"

                        fi

                        local LINE=${DEF}${COLOR}${LINE}${cRESET}" ${cBMAG}\t${cBWHT}$VPN_IP_TXT\t${cBMAG}${DESC}"$cRESET  # v3.05 v3.01
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

                                # Need to get the last logged RX/TX values for the Peer, and only add to SQL if total > 0
                                Parse "$(sqlite3 $SQL_DATABASE "select rx,tx from traffic WHERE peer='$WG_INTERFACE' order by timestamp desc limit 1;")" "|" RX_OLD TX_OLD
                                if [ -n "$RX_OLD" ] && [ -n "$TX_OLD" ];then
                                    local RX_DELTA=$((RX-RX_OLD))
                                    local TX_DELTA=$((TX-TX_OLD))
                                else
                                    local RX_DELTA=$RX
                                    local TX_DELTA=$TX
                                fi

                                if [ $((RX_DELTA+TX_DELTA)) -gt 0 ];then
                                    local TIMESTAMP=$(date +%s)

                                    sqlite3 $SQL_DATABASE "INSERT into traffic values('$WG_INTERFACE','$TIMESTAMP','$RX_DELTA','$TX_DELTA');"       # v3.05
                                fi
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
                            [ -z "$DESC" ] && DESC="# Unidentified"
                            WG_INTERFACE=$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE pubkey='$PUB_KEY';")

                            [ -z "$WG_INTERFACE" ] && WG_INTERFACE=$(grep -F "$PUB_KEY" /opt/etc/wireguard.d/*_public.key | awk -F '[\/:\._]' '{print $6}')

                            [ -n "$WG_INTERFACE" ] && local VPN_ADDR=$(awk '/^Address/ {print $3}' ${CONFIG_DIR}${WG_INTERFACE}.conf ) || local DESC=${cBRED}$DESC" owner of this Public key:"

                            local LINE=${COLOR}$LINE" \t${cBWHT}${VPN_ADDR}\t\t${cBMAG}${DESC}\t"
                        fi
                    fi

                    if [ -z "$DETAIL" ];then
                        if [ "$STATS" == "Y" ];then
                            if [ -n "$(echo "$LINE" | grep -E "transfer:")" ];then
                                SayT ${WG_INTERFACE}":"${LINE}$cRESET
                                SayT ${WG_INTERFACE}": period : $(Size_Human $RX_DELTA) received, $(Size_Human $TX_DELTA) sent (Rx=$RX_DELTA;Tx=$TX_DELTA)"
                            fi
                        else
                            [ -n "$(echo "$LINE" | grep -E "interface:|peer:|transfer:|latest handshake:")" ] && echo -e ${TAB}${COLOR}$LINE
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

    echo -e $cBWHT"\n\tPeers (Auto=P - Policy, Auto=X - External i.e. Cell/Mobile)"$cBCYA

    case ${WG_INTERFACE:0:3} in

        "")
            COLUMN_TXT="Server,Auto,Subnet,Port,Annotate"
            sqlite3 $SQL_DATABASE "SELECT peer,auto,subnet,port,tag from servers;" | column -t  -s '|' --table-columns "$COLUMN_TXT"
            echo -e
            COLUMN_TXT="Client,Auto,IP,Endpoint,DNS,MTU,Annotate"           # v4.09
            sqlite3 $SQL_DATABASE "SELECT peer,auto,subnet,socket,dns,mtu,tag from clients;" | column -t  -s '|' --table-columns "$COLUMN_TXT"
            echo -e
            COLUMN_TXT="Device,Auto,IP,DNS,Allowed IPs,Annotate"                    # v4.09
            sqlite3 $SQL_DATABASE "SELECT name,auto,ip,dns,allowedip,tag from devices;" | column -t  -s '|' --table-columns "$COLUMN_TXT"
        ;;
        *)
            local Mode=$(Server_or_Client "$WG_INTERFACE")
            case "$Mode" in
                server)
                    local TABLE="servers"; local ID="peer"
                    local COLUMN_TXT="Server,Auto,Subnet,Port,Public,Private,Annotate"
                    ;;
                client)
                    local TABLE="clients"; local ID="peer"
                    local COLUMN_TXT="Client,Auto,IP,Endpoint,DNS,MTU,Public,Private,Annotate"    # v4.09 v4.04
                    ;;
                *)
                    local TABLE="devices"; local ID="name"
                    local COLUMN_TXT="Device,Auto,IP,DNS,Allowed IPs,Public,Private,Annotate,Conntrack" # v4.09
                    ;;
            esac

            local AUTO="$(sqlite3 $SQL_DATABASE "SELECT auto FROM $TABLE WHERE $ID='$WG_INTERFACE';")"  # v4.11

            echo -e
            sqlite3 $SQL_DATABASE "SELECT * from $TABLE WHERE $ID='$WG_INTERFACE';" | column -t  -s '|' --table-columns "$COLUMN_TXT"

            if [ "$ID" == "peer" ];then                                                        # v4.09
                if [ $(sqlite3 $SQL_DATABASE "SELECT COUNT(peer) FROM policy WHERE peer='$WG_INTERFACE';") -gt 0 ];then
                    echo -e $cBCYA"\n\tSelective Routing RPDB rules"
                    sqlite3 $SQL_DATABASE "SELECT rowid,peer,iface,srcip,dstip,tag FROM policy WHERE peer='$WG_INTERFACE' ORDER BY iface DESC;" |column -t  -s '|' --table-columns ID,Peer,Interface,Source,Destination,Description # v4.08
                else
                    if [ "$Mode" == "client" ];then
                        [ "$AUTO" != "P" ] && local COLOR=$cGRA || local COLOR=$cRED                    # v4.11
                        echo -e $COLOR"\n\tNo RPDB Selective Routing rules for $WG_INTERFACE\n"$cRESET  # v4.11
                    fi
                fi

                echo -e
                if [ "$(sqlite3 $SQL_DATABASE "SELECT * FROM ipset WHERE peer='$WG_INTERFACE';")" ] ;then
                    sqlite3 $SQL_DATABASE "SELECT * FROM ipset WHERE peer='$WG_INTERFACE';" | column -t  -s '|' --table-columns IPSet,Enable,Peer,FWMark,DST/SRC
                fi
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

    local TYPE=$1
    [ "$TYPE" == "diag" ] && TYPE=
    local TABLE=$2;shift 2
    local REST=$@

    if [ -z "$TYPE" ] || [ "$TYPE" == "route" ] || [ "$TYPE" == "rpdb" ];then

        echo -e $cBYEL"\n\tDEBUG: Routing info MTU etc.\n"$cBCYA 2>&1          # v1.07
        for WG_INTERFACE in $(wg show interfaces)
            do
                ip a l $WG_INTERFACE                                # v1.07
                [ "$(nvram get ipv6_service)" != "disabled" ] && ip -6 a l $WG_INTERFACE
            done

        echo -e
        netstat -rn | grep -E "wg.|Kernel|irtt"

        [ "$(nvram get ipv6_service)" != "disabled" ] && { echo -e $cBYEL"\n\tDEBUG: RPDB IPv6 rules\n"$cBCYA 2>&1 ; ip -6 rule show; }

        echo -e $cBYEL"\n\tDEBUG: RPDB rules\n"$cBCYA 2>&1
        ip rule

        for WG_INTERFACE in $(wg show interfaces)
            do
                local I=${WG_INTERFACE:3:1}
                if [ "${WG_INTERFACE:0:3}" != "wg2" ];then
                    local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM clients WHERE peer='$WG_INTERFACE';")
                    local DESC=$(printf "%s" "$DESC" | sed 's/^[ \t]*//;s/[ \t]*$//')
                    echo -e $cBYEL"\n\tDEBUG: Routing Table 12$I (wg1$I) ${cBMAG}$DESC\n"$cBCYA 2>&1
                    ip route show table 12$I
                    [ "$(nvram get ipv6_service)" != "disabled" ] && ip -6 route show table 12$I
                fi
            done

        echo -e $cBYEL"\n\tDEBUG: Routing Table main\n"$cBCYA 2>&1
        ip route | grep "wg."

    fi

    if [ -z "$TYPE" ] || [ "$TYPE" == "udp" ] || [ "$TYPE" == "sockets" ];then
        echo -e $cBYEL"\n\tDEBUG: UDP sockets.\n"$cBCYA 2>&1
        netstat -l -n -p | grep -e "^udp\s.*\s-$"
    fi

    if [ -z "$TYPE" ] || [ "$TYPE" == "firewall" ];then

        echo -e $cBYEL"\n\tDEBUG: Firewall rules \n"$cBCYA 2>&1
        echo -e $cBYEL"\n\tDEBUG: -t filter \n"$cBCYA 2>&1
        iptables --line -nvL FORWARD | grep -iE "WireGuard|Chain|pkts"
        echo -e
        iptables --line -nvL INPUT | grep -iE "WireGuard|Chain|pkts"
        echo -e
        iptables --line -nvL OUTPUT | grep -iE "WireGuard|Chain|pkts"

        if [ "$(nvram get ipv6_service)" != "disabled" ];then
            echo -e $cBYEL"\n\tDEBUG: Firewall IPv6 rules\n"$cBCYA 2>&1
            echo -e $cBYEL"\n\tDEBUG: -t filter \n"$cCYA 2>&1
            ip6tables --line -nvL FORWARD | grep -iE "WireGuard|Chain|pkts"
            echo -e
            ip6tables --line -nvL INPUT | grep -iE "WireGuard|Chain|pkts"
            echo -e
            ip6tables --line -nvL OUTPUT | grep -iE "WireGuard|Chain|pkts"
        fi

        echo -e $cBYEL"\n\tDEBUG: -t nat \n"$cBCYA 2>&1
        iptables --line -t nat -nvL PREROUTING | grep -iE "WireGuard|Chain|pkts"
        echo -e
        iptables --line -t nat -nvL POSTROUTING | grep -iE "WireGuard|Chain|pkts"

        for WG_INTERFACE in $(wg show interfaces)
            do
                case $WG_INTERFACE in
                    wg1*)

                        local I=$(echo "$WG_INTERFACE" | grep -oE "[1-9]*$")
                        [ ${#I} -gt 2 ] && local I=${I#"${I%??}"} || local I=${I#"${I%?}"}
                        if [ "$(Chain_exists "WGDNS${I}" "nat")" == "Y" ];then
                            echo -e
                            iptables --line -t nat -nvL WGDNS${I} | grep -iE "WireGuard|Chain|pkts"
                        fi
                    ;;
                    *)
                    ;;
                esac

            done

        echo -e $cBYEL"\n\tDEBUG: -t mangle \n"$cBCYA 2>&1
        iptables --line -t mangle -nvL FORWARD | grep -iE "WireGuard|Chain|pkts"
        echo -e
        iptables --line -t mangle -nvL PREROUTING | grep -iE "WireGuard|Chain|pkts"

        [ "$(nvram get ipv6_service)" != "disabled" ] && ip -6 rule show
    fi

    if [ "$TYPE" != "sql" ];then
        echo -e $cBWHT"\n\nUse command 'diag sql [ table_name ]' to see the SQL data (might be many lines!)\n"
        echo -en $cBWHT"       Valid SQL Database tables: "$cBCYA 2>&1
        echo -e ".tables" > /tmp/sql_cmds.txt
        sqlite3 $SQL_DATABASE < /tmp/sql_cmds.txt
        echo -e $cRESET
        echo -e "             e.g. ${cBGRE}diag sql traffic${cBWHT} will show the traffic stats SQL table"$cRESET
    fi

    if [ "$TYPE" == "sql" ] || [ "$TYPE" == "cmd" ];then

        if [ "$TABLE" != "cmd" ];then
            # Probably not a good idea for * - last couple of days maybe?
            if [ -z "$TABLE" ];then
                echo -e $cBYEL"\n\tDEBUG: SQL '$SQL_DATABASE'\n"$cBCYA 2>&1
                sqlite3 $SQL_DATABASE "SELECT * FROM servers;" |
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
                        sqlite3 $SQL_DATABASE "SELECT peer, datetime(timestamp, 'unixepoch', 'localtime') AS time, rx, tx FROM $TABLE;" | column -t  -s '|' --table-columns Peer,Timestamp,RX,TX
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
                        sqlite3 $SQL_DATABASE "SELECT * FROM $TABLE;" | column -t  -s '|' --table-columns Device,Auto,IPADDR,DNS,'Allowed',Public,Private,tag,Conntrack
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
        echo -e $cBGRE"\n\t$VERSION - No WireGuard Manager updates available - you have the latest version\n"              # v1.03
        return 0
    fi

}
Display_SplashBox() {
    printf '| Requirements: USB drive with Entware installed                       |\n'
    printf '|                                                                      |\n'
    if [ "$EASYMENU" == "N" ];then
        printf '|   i = Install WireGuard Advanced Mode                     |\n'
    else
        printf '|   1 = Install WireGuard                                              |\n'
    fi
    local YES_NO="   "                              # v2.07
    [ "$EASYMENU" == "Y" ] && local YES_NO="${cBGRE}   ";   printf '|       o1. Enable nat-start protection for Firewall rules     %b    %b |\n' "$YES_NO" "$cRESET"
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
                {INSTALL_DIR}UDP_Monitor.sh &
            fi


            if [ -z "$(pidof UDP_Updater.sh)" ];then
                ${INSTALL_DIR}UDP_Updater.sh &
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
                        local DSTSRC="dst"

                        if [ "$ACTION" == "add" ];then
                            ipset list $IPSET >/dev/null 2>&1;if [ $? -eq 0 ]; then
                                if [ -z "$(sqlite3 $SQL_DATABASE "SELECT * FROM ipset WHERE peer='$WG_INTERFACE' AND ipset='$IPSET';")" ];then
                                    sqlite3 $SQL_DATABASE "INSERT into ipset values('$IPSET','$USE','$WG_INTERFACE','$FWMARK','$DSTSRC');"
                                    echo -e $cBGRE"\n\t[✔] Ipset '$IPSET' Selective Routing ${ACTION}ed ${cBMAG}$WG_INTERFACE"$cRESET
                                else
                                    echo -e $cRED"\tWarning: IPSet '$IPSET' already exists for Peer ${cBMAG}$WG_INTERFACE"$cRESET
                                fi
                            else
                                echo -e $cRED"\a\t***ERROR: IPSet '$IPSET' does not EXIST! for routing via ${cBMAG}$WG_INTERFACE"$cRESET
                            fi
                        else
                            if [ -n "$(sqlite3 $SQL_DATABASE "SELECT * FROM ipset WHERE peer='$WG_INTERFACE' AND ipset='$IPSET';")" ];then
                                sqlite3 $SQL_DATABASE "DELETE FROM ipset WHERE ipset='$IPSET' AND peer='$WG_INTERFACE';"
                                echo -e $cBGRE"\n\t[✔] Ipset '$IPSET' Selective Routing ${ACTION}ed ${cBMAG}$WG_INTERFACE"$cRESET
                            else
                                echo -e $cRED"\tWarning: IPSet '$IPSET' not used by Peer ${cBMAG}$WG_INTERFACE"$cRESET
                            fi
                        fi
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
        Manage_Peer "list" "$WG_INTERFACE"
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
                dst","dst);;
                *)
                    VALID="N"
                ;;
            esac
            if [ "$VALID" == "Y" ];then
                [ "$IPSET" != "all" ] && local SQL_WHERE="ipset='$IPSET' AND" || SQL_WHERE=
                sqlite3 $SQL_DATABASE "UPDATE ipset SET dstsrc='$DSTSRC' WHERE $SQL_WHERE AND peer='$WG_INTERFACE';"
                echo -e $cBGRE"\n\t[✔] Updated IPSet DST/SRC for ${cBMAG}$WG_INTERFACE \n"$cRESET
            fi
        ;;
        enable)
            local USE=$1
            [ "$IPSET" != "all" ] && local SQL_WHERE="ipset='$IPSET'" || SQL_WHERE=
            if [ -n $(echo "$USE" | grep -iE "Y|N") ];then
                local USE=$(echo "$USE" | tr 'a-z' 'A-Z')
                sqlite3 $SQL_DATABASE "UPDATE ipset SET use='$USE' WHERE $SQL_WHERE peer='$WG_INTERFACE';"
                echo -e $cBGRE"\n\t[✔] Updated IPSet Enable for ${cBMAG}$WG_INTERFACE \n"$cRESET
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
Build_Menu() {
    if [ -z "$SUPPRESSMENU" ];then

        # Generate dynamically context aware menu
        if [ "$(WireGuard_Installed)" == "Y" ];then
            MENU_I="$(printf '%b1 %b = %bUpdate%b Wireguard modules' "${cBYEL}" "${cRESET}" "${cBGRE}" "${cRESET}")"
            MENU_Z="$(printf '%b2 %b = %bRemove%b WireGuard/wg_manager\n' "${cBYEL}" "${cRESET}" "${cBRED}" "${cRESET}")"
        else
            MENU_I="$(printf '%b1 %b = %bBegin%b WireGuard Installation Process' "${cBYEL}" "${cRESET}" "${cBGRE}" "${cRESET}")"
        fi

        if [ "$(WireGuard_Installed)" == "Y" ];then

            MENU_VX="$(printf '%bv %b = View %b%s\n' "${cBYEL}" "${cRESET}" "$cBGRE" "('${INSTALL_DIR}WireguardVPN.conf')")"
            MENU_RS="$(printf '%brs%b = %bRestart%b (or %bStart%b) WireGuard Sessions(%b)\n' "${cBYEL}" "${cRESET}" "$cBGRE" "${cRESET}" "$cBGRE" "${cRESET}" )"
            MENU_S="$(printf '%b4 %b = %bStart%b   [ [Peer [nopolicy]...] | category ] e.g. start clients \n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"        # v2.02
            if [ -n "$(wg show interfaces)" ];then
                MENU_L="$(printf '%b3 %b = %bList%b ACTIVE Peers Summary [Peer...] [full]\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
                MENU_T="$(printf '%b5 %b = %bStop%b    [ [Peer... ] | category ] e.g. stop clients\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
            else
                MENU_L="$(printf '%b3 %b = %bList%b ACTIVE Peers Summary [Peer...] [full]\n' "${cBYEL}" "${cRESET}" "${cGRA}" "${cBGRA}")"   # v2.03
                MENU_T="$(printf '%b5 %b = %bStop%b    [ [Peer... ] | category ] e.g. stop clients\n' "${cBYEL}" "${cRESET}" "${cGRA}" "${cBGRA}")"
            fi
            MENU_R="$(printf '%b6 %b = %bRestart%b [ [Peer... ] | category ]%b e.g. restart servers\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
            MENU_Q="$(printf '%b7 %b = %bDisplay QR code for a Peer {device} e.g. iPhone%b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
            MENU_P="$(printf '%b8 %b = %bPeer management [ "list" | "category" | "new" ] | [ {Peer | category} [ 'del' | 'show' | 'add' [{"auto="[y|n|p]}] ]%b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
            MENU_C="$(printf '%b9 %b = %bCreate Key-pair for Peer {Device} e.g. Nokia6310i (creates Nokia6310i.conf etc.)%b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
            MENU_IPS="$(printf '%b10 %b= %bIPSet management [ "list" ] | [ "upd" { ipset [ "fwmark" {fwmark} ] | [ "enable" {"y"|"n"}] | [ "dstsrc"] ] } ] %b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"

        fi

        MENU__="$(printf '%b? %b = About Configuration\n' "${cBYEL}" "${cRESET}")"
        echo -e ${cWGRE}"\n"$cRESET      # Separator line

        echo -e
        printf "%s\t\t\t\t\t\t%s\n"                 "$MENU_I" "$MENU_Q"

        if [ "$(WireGuard_Installed)" == "Y" ];then
            printf "%s\t\t\t\t\t%s\n"                   "$MENU_Z" "$MENU_P"
            printf "\t\t\t\t\t\t\t\t\t%s\n"                       "$MENU_C"
            printf "%s\t\t\t\t%s\n"                     "$MENU_L" "$MENU_IPS"
            printf "%s\t\t\t\t\t\t\t\t\t%s\n"           "$MENU_S"
            printf "%s\t\t\t\t\t\t\t\t\t%s\n"           "$MENU_T"
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
            1|i)
                [ -z "$(ls ${INSTALL_DIR}*.ipk 2>/dev/null)" ]  && menu1="install" || menu1="getmodules";;
            2|z) menu1="uninstall";;
            3*|list*|show*) menu1=$(echo "$menu1" | awk '{$1="list"}1');;
            4*|start*) menu1=$(echo "$menu1" | awk '{$1="start"}1') ;;
            5*|stop*) menu1=$(echo "$menu1" | awk '{$1="stop"}1') ;;
            6*|restart*) menu1=$(echo "$menu1" | awk '{$1="restart"}1') ;;
            7*|qrcode*) menu1=$(echo "$menu1" | awk '{$1="qrcode"}1') ;;
            8*|peer*) menu1=$(echo "$menu1" | awk '{$1="peer"}1') ;;
            9*) menu1=$(echo "$menu1" | awk '{$1="create"}1') ;;
            10*|ipset*) menu1=$(echo "$menu1" | awk '{$1="ipset"}1') ;;
            u|uf|uf" "*) ;;                           # v3.14
            "?") ;;
            v|vx) ;;
            createsplit*|create*) ;;
            ip) ;;                         # v3.03
            getmod*) ;;
            loadmod*) ;;
            dns*) ;;                       # v2.01
            natstart*) ;;
            alias*) ;;
            diag*) ;;
            debug) ;;
            initdb*|migrate*);;            # v4.01
            stats*);;
            wg|wg" "*) ;;
            scripts*) ;;                    # v4.01
            import*) ;;
            udpmon*) ;;                     # v4.01
            jump*|geo*|livin*) ;;           # v4.08 v4.07
            generatestats) ;;
            killsw*) ;;             # v2.03
            killinter*) ip link del dev $(echo "$menu1" | awk '{print $2}'); menu1=;;
            rpfilter*|rp_filter*);;         # v4.11
            "") ;;
            e*) ;;
            *) printf '\n\a\t%bInvalid Option%b "%s"%b Please enter a valid option\n' "$cBRED" "$cRESET" "$menu1" "$cBRED"
               menu1=
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
                        [ -z "$ARG" ] && { echo -e $cBYEL"\n\t\t WireGuard VPN Peer Status"$cRESET; wg show all; }
                        Diag_Dump ${menu1#* }
                    else
                        Show_Peer_Status                    # v3.04 Hotfix
                    fi
                else
                    echo -en $cRED"\a\n\t";Say "Wireguard VPN module 'wg' NOT installed\n"$cRESET
                    echo -e
                fi
                ;;
            install)

                Install_WireGuard_Manager

                ;;

            alias*)                                                  # ['del']

                local ARG=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                fi
                Manage_alias "$ARG"                                     # v1.05

                ;;
            getmod*)

                Download_Modules $HARDWARE_MODEL
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

                Uninstall_WireGuard
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

                Create_RoadWarrior_Device $menu1

                ;;
            "?"|u|u" "*|uf|uf" "*)

                local ACTION="$(echo "$menu1"| awk '{print $1}')"

                local CHANGELOG="$cRESET(${cBCYA}Change Log: ${cBYEL}https://github.com/MartineauUK/wireguard/commits/main/wg_manager.sh$cRESET)"   #v2.01
                [ -n "$(echo $VERSION | grep "b")" ] && local CHANGELOG="$cRESET(${cBCYA}Change Log: ${cBYEL}https://github.com/MartineauUK/wireguard/commits/dev/wg_manager.sh$cRESET)" #v2.01
                echo -e $cBMAG"\n\t${VERSION}$cBWHT WireGuard Session Manager" ${CHANGELOG}$cRESET  # v2.01
                Show_MD5 "script"

                case "$ACTION" in
                    "?")

                        echo -e $cBGRE"\n\t[✔]$cBWHT $(grep -E "^arch" $ENTWARE_INFO)\n"$cRESET     # v4.01 @Torson
                        Check_Module_Versions "report"

                        echo -e $cRESET
                        DNSmasq_Listening_WireGuard_Status

                        if [ -z "$(grep -i "wireguard" /jffs/scripts/nat-start)" ];then     # v1.11
                            echo -e $cBRED"\t[✖]${cBWHT} nat-start$${cBRED} is NOT monitoring WireGuard Firewall rules - ${cBWHT}use 'wgm natstart' to ENABLE\n"$cRESET
                        else
                            echo -e $cBGRE"\t[✔]${cBWHT} nat-start ${cBGRE}is monitoring WireGuard Firewall rules\n"$cRESET
                        fi

                        if [ "$(Manage_KILL_Switch)" == "Y" ];then
                            echo -e $cBGRE"\t[✔]$cBWHT WAN ${cBGRE}KILL-Switch is ENABLED$cRESET"
                        else
                            echo -e $cRED"\t[✖]$cBWHT WAN ${cBGRE}KILL-Switch is ${cBRED}${aREVERSE}DISABLED$cRESET"
                        fi

                        if [ "$(Manage_UDP_Monitor)" == "Y" ];then                          # v4.01
                            echo -e $cBGRE"\t[✔]${cBWHT} UDP ${cBGRE}monitor is ENABLED$cRESET"
                        else
                            echo -e $cRED"\t[✖]${cBWHT} UDP ${cBGRE}monitor is ${cBRED}DISABLED$cRESET"
                        fi

                        local WAN_IF=$(Get_WAN_IF_Name)                                             # v4.11
                        local VAL=$(cat /proc/sys/net/ipv4/conf/$WAN_IF/rp_filter)                  # v4.11
                        [ "$VAL" == "1" ] && STATE="ENABLED" || STATE="${cBRED}DISABLED${cBGRE}"    # v4.11
                        echo -e $cBGRE"\n\t[ℹ ] Reverse Path Filtering $STATE\n"$cRESET         # v4.11

                        Manage_Stats

                        ;;
                    *)
                        [ "$2" == "dev" ] && DEV="dev" || DEV="main"
                        DOWNLOAD="N"

                        echo -e
                        Check_Module_Versions

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
                            [ -f ${INSTALL_DIR}$SCRIPT_NAME ] && { rm $0.u; sleep 3; exec "$0" "$@"; } || mv $0.u $0
                            # Never get here!!!
                            echo -e $cRESET
                        fi
                        ;;
                esac
                ;;
            natstart*)

                local ARG=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                fi

                Edit_nat_start "$ARG"

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
                        echo -e $cBRED"\a\n\t***ERROR WireGuard Peer Configuration '$FN' NOT found\n"$cRESET
                    fi

            ;;
            peer*)                                           # peer [ 'list' | interface { [auto y|n|p ] 'del' | 'add' | 'comment' {'#'comment}'} ]  # v1.10

                Manage_Peer $menu1

                ;;
            restart*|stop*|start*)                              # start [ Peer [policy] | [client|server]] ]

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
                echo -e $cBWHT"\n\tWireGuard Userspace Tool:\n"
                $menu1
            ;;
            killsw*)

                local ARG=
                if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                    local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                fi

                RC=$(Manage_KILL_Switch "$ARG")
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
            scripts*)

                Manage_Event_Scripts $menu1                                     # v4.01
            ;;
            ipset*)

                Manage_IPSET $menu1

            ;;
            generatestats*)
                Show_Peer_Status "generatestats"
            ;;
            jump*|geo*|livin*)                                                         # livin { @home | * | {[France | wg14]} {LAN device}     # v4.07
                shift
                local LOCATION=$1
                shift
                local IP=$1

                [ -z "$IP" ] && { echo -en $cRED"\a\n\t***ERROR: LAN Host name or LAN IP address required'\n"$cRESET ; return 1; }

                [ -z "$(echo "$IP" | Is_Private_IPv4)" ] && local IP=$(grep -i "$IP" /etc/hosts.dnsmasq  | awk '{print $1}')
                [ -z "$IP" ] && { echo -en $cRED"\a\n\t***ERROR: Invalid host IP address!'\n"$cRESET ; return 1; }

                if [ "$LOCATION" != "@home" ] && [ "$LOCATION" != "*" ];then
                    local WG_INTERFACE=$LOCATION
                    # If a Peer wasn't specified, scan the Policy Peers for a description match?
                    [ ! -f ${CONFIG_DIR}${WG_INTERFACE}.conf ] && local WG_INTERFACE=$(sqlite3 $SQL_DATABASE "SELECT peer FROM clients WHERE tag LIKE '%$WG_INTERFACE%';")   # v4.02

                    if [ -n "$WG_INTERFACE" ];then
                        if [ "$(sqlite3 $SQL_DATABASE "SELECT auto FROM clients WHERE peer='$WG_INTERFACE';")" == "P" ];then
                            local I=$(echo "$WG_INTERFACE" | grep -oE "[1-9]*$")
                            [ ${#I} -gt 2 ] && local I=${I#"${I%??}"} || local I=${I#"${I%?}"}
                            local DNS=$(sqlite3 $SQL_DATABASE "SELECT dns FROM clients WHERE peer='$WG_INTERFACE';")
                            local DESC=$(sqlite3 $SQL_DATABASE "SELECT tag FROM clients WHERE peer='$WG_INTERFACE';")
                            local PRIO=$(ip rule | awk -v pattern="$IP" 'match($0, pattern) {print $1}')
                            ip rule del from $IP prio $PRIO 2>/dev/null
                            # Live in......
                            ip rule add from $IP table 12${I}
                            iptables -t nat -A WGDNS${I} -s $IP -j DNAT --to-destination $DNS -m comment --comment "WireGuard 'client${I} DNS'"
                            echo -e $cBGRE"\n\t[✔] Welcome Expat to '$DESC'\n"$cRESET
                        else
                            echo -en $cRED"\a\n\t***ERROR: ${cBMAG}${WG_INTERFACE} not is Policy mode\n"$cRESET
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
                            local TXT="value is "$VAL
                            echo -e $cBGRE"\n\t [ℹ ] Reverse Path Filtering $TXT\n"$cRESET
                        fi
                    ;;
                    *)
                        echo -en $cRED"\a\n\t***ERROR: Invalid Reverse Path Filter request $cBWHT'"$ARG"'$cBRED - use 'disable|enable'\n"$cRESET
                    ;;
                esac
            ;;
            *)
                printf '\n\a\t%bInvalid Option%b "%s"%b Please enter a valid option\n' "$cBRED" "$cRESET" "$menu1" "$cBRED"    # v4.03 v3.04 v1.09
            ;;
        esac
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

            local STATUS_LINE="WireGuard ACTIVE Peer Status: "$(Peer_Status_Summary)                  # v3.04 v2.01
            [ "$(Manage_KILL_Switch)" == "Y" ] && local KILL_STATUS="${cBGRE}${aREVERSE}ENABLED$cRESET" || local KILL_STATUS="        "
            echo -e $cRESET"\n"${KILL_STATUS}"\t"${cRESET}${cBMAG}${STATUS_LINE}$cRESET

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

    local TAG="$(echo "$@" | sed -n "s/^.*tag=//p" | awk '{print $0}')"
    local ADD_ALLOWED_IPS="$(echo "$@" | sed -n "s/^.*ip=//p" | awk '{print $0}')"
    local DNS_RESOLVER="$(echo "$@" | sed -n "s/^.*dns=//p" | awk '{print $0}')"        # v3.04 Hotfix

    # List of 'server' Peers for device to be added to?
    local SERVER_PEER=

    while [ $# -gt 0 ]; do          # v3.03
        case "$1" in
            create*)
                ACTION=$1
            ;;
            wg*)
                SERVER_PEER=$1
            ;;
            *)

            ;;
        esac
        shift
    done

    # If user did not specify 'server' Peers, use the oldest 'server' Peer found ACTIVE or the first defined in the config
    [ -z "$SERVER_PEER" ] && SERVER_PEER=$(wg show interfaces | grep -vE "wg1")
    [ -z "$SERVER_PEER" ] && SERVER_PEER=$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers order by peer;" | head -n 1)
    [ -z "$SERVER_PEER" ] && { echo -e $cBRED"\a\n\t***ERROR: no 'server' Peers specified or found (wg2*)"$cRESET; return 1; }
    for SERVER_PEER in $SERVER_PEER
        do
            # Is it ACTUALLY a 'server' Peer?                           # v1.08
            if [ -f ${CONFIG_DIR}${SERVER_PEER}.conf ] && [ -z "$(grep -iE "^Endpoint" ${CONFIG_DIR}${SERVER_PEER}.conf)" ];then
                continue
            else
                echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard 'server' Peer '$SERVER_PEER'\n"$cRESET
                return 1
            fi
        done

    [ "$ACTION" == "createsplit" ] && SPLIT_TUNNEL="Y" || SPLIT_TUNNEL="Q. Split Tunnel"                       # v1.11 v1.06

    if [ -n "$DEVICE_NAME" ];then

        if [ ! -f ${CONFIG_DIR}${DEVICE_NAME} ] && [ -z "$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE name='$DEVICE_NAME';")" ];then
                echo -e $cBCYA"\n\tCreating Wireguard Private/Public key pair for device '${cBMAG}${DEVICE_NAME}${cBCYA}'"$cBYEL
                wg genkey | tee ${CONFIG_DIR}${DEVICE_NAME}_private.key | wg pubkey > ${CONFIG_DIR}${DEVICE_NAME}_public.key
                echo -e $cBYEL"\tDevice '"$DEVICE_NAME"' Public key="$(cat ${CONFIG_DIR}${DEVICE_NAME}_public.key)"\n"$cRESET

                # Generate the Peer config to be imported into the device
                local PUB_KEY=$(cat ${CONFIG_DIR}${DEVICE_NAME}_public.key)

                local PUB_SERVER_KEY=
                # Use the Public key of the designated 'server' Peer
                # For instant testing the 'server' Peer needs to be restarted? # v1.06
                if [ -n "$SERVER_PEER" ];then

                    local PUB_SERVER_KEY=$(cat ${CONFIG_DIR}${SERVER_PEER}_public.key)                  # v1.06
                    echo -e $cBCYA"\tUsing Public key for 'server' Peer '"${cBMAG}${SERVER_PEER}${cBCYA}"'\n"

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
                    echo -e $cRED"\a\tWarning: Peer device '${cBMAG}${DEVICE_NAME}${cRED}' WireGuard config already EXISTS!"
                    echo -e $cRESET"\tPress$cBRED y$cRESET to$cBRED ${aBOLD}CONFIRM${cRESET}${cBRED} Overwriting Peer device '${cBMAG}$DEVICE_NAME.config${cRESET}' or press$cBGRE [Enter] to SKIP."
                    read -r "ANS"
                    [ "$ANS" != "y" ] && CREATE_DEVICE_CONFIG="N"
                fi

                [ -z "$VPN_POOL_IP" ] && local VPN_POOL=$(sqlite3 $SQL_DATABASE "SELECT subnet FROM servers WHERE peer='$SERVER_PEER';")
                if [ -z "$(echo "$VPN_POOL" | grep -F "::")" ];then
                    local VPN_POOL_PREFIX=$(echo "$VPN_POOL_POOL" | sed 's/\:\:.*$//')
                    if [ -z "$VPN_POOL_IP" ];then
                        if [ -n "$VPN_POOL" ];then
                            local VPN_POOL_SUBNET=${VPN_POOL%.*}
                            #local VPN_POOL_IP=$(grep -F "$VPN_POOL_SUBNET." ${INSTALL_DIR}WireguardVPN.conf | grep -Ev "^#" | grep -v "$SERVER_PEER" | awk '{print $2}' | sed 's~/32.*$~~g' | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | tail -n 1)
                            local IP=$(sqlite3 $SQL_DATABASE "SELECT COUNT(ip) FROM devices WHERE ip LIKE '${VPN_POOL_SUBNET}.%';") # v4.01 Hotfix
                            #local IP=${VPN_POOL_IP##*.}        # 4th octet
                            local IP=$((IP+2))
                            #[ $IP -eq 1 ] && local IP=2                # .1 is the the 'server' Peer!                  # v4.02

                            while true
                                do
                                    local DUPLICATE=$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE ip LIKE '$VPN_POOL_PREFIX.%';") # v4.02
                                    [ -z "$DUPLICATE" ] && break || local IP=$((IP+1))

                                    if [ $IP -ge 255 ];then
                                        echo -e $cBRED"\a\t***ERROR: 'server' Peer ($SERVER_PEER) subnet MAX 254 reached '${INSTALL_DIR}WireguardVPN.conf'"
                                        exit 92
                                    fi
                                done

                                local VPN_POOL_IP=$VPN_POOL_SUBNET"."$IP"/32"
                        else
                            echo -e $cBRED"\a\t***ERROR: 'server' Peer ($SERVER_PEER) subnet NOT defined 'device' Peers?"
                            return 1
                        fi
                    fi
                else
                    local USE_IPV6="Y"
                    local IPV6_TXT="IPv6 "
                    local VPN_POOL_PREFIX=${VPN_POOL%/*}
                    local VPN_POOL_PREFIX=$(echo "$VPN_POOL_PREFIX" | awk -F '[:/]' '{print $1":"$2":"$3"::"}')
                    local IP=$(sqlite3 $SQL_DATABASE "SELECT COUNT(ip) FROM devices WHERE ip LIKE '${VPN_POOL_SUBNET}.%';")
                    local IP=$((IP+2))

                    while true
                        do
                            local DUPLICATE=$(sqlite3 $SQL_DATABASE "SELECT name FROM devices WHERE ip LIKE '$VPN_POOL_PREFIX.%';") # v4.02
                            [ -z "$DUPLICATE" ] && break || local IP=$((IP+1))

                            if [ $IP -ge 255 ];then
                                echo -e $cBRED"\a\t***ERROR: 'server' Peer ($SERVER_PEER) subnet MAX 254 reached '${INSTALL_DIR}WireguardVPN.conf'"
                                exit 92
                            fi
                        done

                    local VPN_POOL_IP=${VPN_POOL_PREFIX}$IP"/128"
                fi

                # Should the Peer ONLY have access to LAN ? e.g. 192.168.0.0/24         # v1.06
                # NOTE: These are routes, so a savvy user could simply tweak the allowed IPs to 0.0.0.0/0 on his Peer device!!!
                #
                if [ "$SPLIT_TUNNEL" == "Y" ];then

                    local LAN_ADDR=$(nvram get lan_ipaddr)
                    local LAN_SUBNET=${LAN_ADDR%.*}

                    # Any other custom routes say to a specific server on the LAN?
                    [ -z "$ADD_ALLOWED_IPS" ] && local IP=$LAN_SUBNET".0/24" || local IP=$LAN_SUBNET".0/24,"$ADD_ALLOWED_IPS

                    local SPLIT_TXT="# Split Traffic LAN Only"
                else
                    # Default route ALL traffic via the remote 'server' Peer
                    local IP="0.0.0.0/0"
                    [ "$USE_IPV6" == "Y" ] && IPV6=", ::/0"
                    local SPLIT_TXT="# ALL Traffic"
                fi

                local ALLOWED_IPS=${IP}${IPV6}

                # User specifed DNS ?
                if [ -z "$DNS_RESOLVER" ];then                               # v3.04 Hotfix
                    local DNS_RESOLVER=$(nvram get wan0_dns | awk '{print $1}')             # v3.04 Hotfix @Sh0cker54 #v3.04 Hotfix
                    [ "$USE_IPV6" == "Y" ] && DNS_RESOLVER=$DNS_RESOLVER","$(nvram get ipv6_dns1)   # v3.04 Hotfix
                fi

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
PersistentKeepalive = 25
# $DEVICE_NAME End
EOF

                echo -e $cBGRE"\n\tWireGuard config for Peer device '${cBMAG}${DEVICE_NAME}${cBGRE}' created ${cBWHT}(Allowed IP's ${ALLOWED_IPS} ${SPLIT_TXT})\n"$cRESET
                fi

                Display_QRCode "${CONFIG_DIR}${DEVICE_NAME}.conf"

                echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED ADD device '${cBMAG}${DEVICE_NAME}${cBRED}' ${cRESET}to 'server' Peer (${cBMAG}${SERVER_PEER}${cRESET}) or press$cBGRE [Enter] to SKIP."
                read -r "ANS"
                if [ "$ANS" == "y" ];then

                    for SERVER_PEER in $SERVER_PEER                                         # v3.03
                        do
                            echo -e $cBCYA"\n\tAdding device Peer '${cBMAG}${DEVICE_NAME}${cBCYA}' ${cBWHT}${VPN_POOL_IP}${cBCYA} to $HARDWARE_MODEL 'server' (${cBMAG}$SERVER_PEER${cBCYA}) and WireGuard config\n"

                            # Erase 'client' Peer device entry if it exists....
                            [ -n "$(grep "$DEVICE_NAME" ${CONFIG_DIR}${SERVER_PEER}.conf)" ] && sed -i "/# $DEVICE_NAME/,/# $DEVICE_NAME End/d" ${CONFIG_DIR}${SERVER_PEER}.conf    # v1.08
                        done

                    local PUB_KEY=$(Convert_Key "$PUB_KEY")

                    echo -e >> ${CONFIG_DIR}${SERVER_PEER}.conf
                    cat >> ${CONFIG_DIR}${SERVER_PEER}.conf << EOF
# $DEVICE_NAME
[Peer]
PublicKey = $PUB_KEY
AllowedIPs = $VPN_POOL_IP
# $DEVICE_NAME End
EOF

                    # Add device IP address and identifier to config
                    [ -z "$TAG" ] && TAG=$(echo -e "\"Device\"")                                   # v1.03
                    LINE=$(echo "$DEVICE_NAME\tX\t\t$VPN_POOL_IP\t\t$PUB_KEY\t\t# $DEVICE_NAME $TAG")
                    #POS=$(awk '/^# Custom.*Peers/ {print NR}' ${INSTALL_DIR}WireguardVPN.conf)
                    #[ -n "$POS" ] && sed -i "$POS a $LINE" ${INSTALL_DIR}WireguardVPN.conf
                    TAG=$(echo "$TAG" | sed "s/'/''/g")
                    sqlite3 $SQL_DATABASE "INSERT into devices values('$DEVICE_NAME','X','$VPN_POOL_IP','$DNS_RESOLVER','$ALLOWED_IPS','$PUB_KEY','$PRI_KEY','# $DEVICE_NAME $TAG','0');"

                    #tail -n 1 ${INSTALL_DIR}WireguardVPN.conf

                    # Need to Restart the Peer (if it is UP) or Start it so it can listen for new 'client' Peer device
                    [ -n "$(wg show interfaces | grep "$SERVER_PEER")" ] && CMD="restart" ||  CMD="start"   # v1.08
                    echo -e $cBWHT"\a\n\tWireGuard 'server' Peer needs to be ${CMD}ed to listen for 'client' Peer ${cBMAG}$DEVICE_NAME $TAG"
                    echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'server' Peer ($SERVER_PEER) or press$cBGRE [Enter] to SKIP."
                    read -r "ANS"
                    [ "$ANS" == "y" ] && { Manage_Wireguard_Sessions "$CMD" "$SERVER_PEER"; Show_Peer_Status "show"; }  # v3.03

                fi
        else
            echo -e $cRED"\a\n\t***ERROR: Peer device '${cBMAG}${DEVICE_NAME}${cRED}' already EXISTS!"
        fi
    else
        echo -e $cBRED"\a\n\t***ERROR Missing name of 'client' Peer device! e.g. iPhone\n"$cRESET
    fi
}
#For verbose debugging, uncomment the following two lines, and uncomment the last line of this script
#set -x
#(
#==========================================================================================================================================
Main() { true; }            # Syntax that is Atom Shellchecker compatible!

PATH=/opt/sbin:/opt/bin:/opt/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ANSIColours

FIRMWARE=$(echo $(nvram get buildno) | awk 'BEGIN { FS = "." } {printf("%03d%02d",$1,$2)}')
HARDWARE_MODEL=$(Get_Router_Model)
# v384.13+ NVRAM variable 'lan_hostname' supersedes 'computer_name'
[ -n "$(nvram get computer_name)" ] && MYROUTER=$(nvram get computer_name) || MYROUTER=$(nvram get lan_hostname)
BUILDNO=$(nvram get buildno)
SCRIPT_NAME="${0##*/}"
ENTWARE_INFO="/opt/etc/entware_release"

EASYMENU="Y"

#[ "$(nvram get ipv6_service)" != "disabled" ] && USE_IPV6="Y"               # v1.07

TS=$(date +"%Y%m%d-%H%M%S")    # current date and time 'yyyymmdd-hhmmss'

ACTION=$1
PEER=$2
NOPOLICY=$3

source /usr/sbin/helper.sh                                  # v2.07 Required for external 'am_settings_set()/am_settings_get()'

# Need assistance ?
if [ "$1" == "-h" ] || [ "$1" == "help" ];then
    clear                                                   # v1.21
    echo -e $cBWHT
    ShowHelp
    echo -e $cRESET
    exit 0
fi

if [ "$1" == "debug" ] || [ "$1" == "debugall" ];then
    if [ "$1" == "debug" ];then
        DEBUGMODE="$(echo -e ${cRESET}$cWRED"Debug mode enabled"$cRESET)"
        shift
    fi
   [ "$1" == "debug" ] && set +x
fi

[ ! -L "/opt/bin/wg_manager" ] && Manage_alias "create"

NOCHK=
NOCHK="Martineau Disabled hack"
[ -n "$(echo "$@" | grep -w "nochk")" ] & NOCHK="Y"

# http://www.snbforums.com/threads/beta-wireguard-session-manager.70787/post-688282
if [ "$HARDWARE_MODEL" == "RT-AX86U" ];then
    [ -n "$(fc status | grep "Flow Learning Enabled")" ] && { fc disable; Say "Broadcom Packet Flow Cache learning via BLOG (Flow Cache) DISABLED"; }   # v4.11 @Torson
fi

# Retain commandline compatibility
if [ "$1" != "install" ];then   # v2.01

    # v3.00 uses '/opt/etc/wireguard.d' rather than '/opt/etc/wireguard'
    # Check if v2.00 was installed, then offer to rename it
    VERSION_NUMDOT=$VERSION                                             # v3.03
    VERSION_NUM=$(echo "$VERSION" | sed 's/[^0-9]*//g')
    if [ "${VERSION_NUM:0:1}" -eq 3 ] && [ ! -d ${CONFIG_DIR} ];then    # v3.03

        if [ -d /opt/etc/wireguard ] && [ "$(ls -1 /opt/etc/wireguard | wc -l)" -gt "5" ];then

            echo -e $cBRED"\a\n\tWireGuard Session Manager v3.0 requires '${CONFIG_DIR}'\n\n\t${cBWHT}Do you want to rename '/opt/etc/wireguard' to '${CONFIG_DIR}' ?"
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

    if [ "$(WireGuard_Installed)" == "Y" ];then # v2.01

        case "$1" in

            start|init)

                if [ "$1" == "init" ];then

                    if [ "$(nvram get ntp_ready)" = "0" ];then              # v4.01 Ensure event 'restart_diskmon' triggers the actual start of WireGuard Session Manager
                        FN="/jffs/scripts/service-event-end"
                        [ ! -f $FN ] && { echo "#!/bin/sh" > $FN; chmod +x $FN; }
                        [ -z "$(grep -i "WireGuard" $FN)" ] && echo -e "if [ "\$2" = "diskmon" ]; then { sh /jffs/addons/wireguard/wg_manager.sh init & } ; fi # WireGuard_Manager" >> $FN   # v4.01
                        SayT "WireGuard Session Manager delayed for NTP synch event trigger 'restart_diskmon'"  # v4.11 v4.01
                        exit 99
                    fi

                    #[ $(sqlite3 $SQL_DATABASE "SELECT COUNT(auto) FROM servers WHERE auto='Y';") -gt 0 ] && UDP_MONITOR=$(Manage_UDP_Monitor "INIT" "enable")  # v4.11

                    Manage_Stats "INIT" "enable"

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
                /jffs/addons/wireguard/wg_firewall "KILLSWITCH"                     # v2.03
                Manage_Wireguard_Sessions "stop" "$PEER" "$NOPOLICY"    # v2.03
                Manage_Wireguard_Sessions "start" "$PEER" "$NOPOLICY"   # v2.03
                echo -e $cRESET
                exit_message
            ;;
            show)
                Show_Peer_Status "full"                        # Force verbose detail
                echo -e $cRESET
                exit_message
            ;;
            diag)
                Diag_Dump                        # Force verbose detail
                echo -e $cRESET
                exit_message
            ;;
            generatestats)

                Peer_Status_Summary "Syslog"
                Show_Peer_Status "generatestats" # cron     # v3.05
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
        esac

    else
        if [ "$1" != "init" ];then              # v4.11
            SayT "***ERROR WireGuard Manager/WireGuard Tool module 'wg' NOT installed"
            echo -e $cBRED"\a\n\t***ERROR WireGuard Tool module 'wg' NOT installed\n"$cRESET
            exit_message
        fi
    fi
fi

clear

Check_Lock "wg"

Show_Main_Menu "$@"

echo -e $cRESET

rm -rf /tmp/wg.lock

exit 0


#) 2>&1 | logger -t $(basename $0)"[$$_***DEBUG]"
