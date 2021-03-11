#!/bin/sh
VERSION="v3.01b2"
#============================================================================================ © 2021 Martineau v3.01b2
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
# Last Updated Date: 11-Mar-2021
#
# Description:
#
# Acknowledgement:
#
# Contributors: odkrys,Torson,ZebMcKayhan,jobhax,elorimer

GIT_REPO="wireguard"
GITHUB_MARTINEAU="https://raw.githubusercontent.com/MartineauUK/$GIT_REPO/main"
GITHUB_MARTINEAU_DEV="https://raw.githubusercontent.com/MartineauUK/$GIT_REPO/dev"
GITHUB_DIR=$GITHUB_MARTINEAU                       # default for script
CONFIG_DIR="/opt/etc/wireguard.d/"                 # Conform to "standards"         # v2.03 @elorimer
INSTALL_DIR="/jffs/addons/wireguard/"
CHECK_GITHUB="Y"                                   # Check versions on Github
SILENT="s"                                         # Default is no progress messages for file downloads
DEBUGMODE=
READLINE="ReadLine"                                # Emulate 'readline' for 'read'  # v2.03
CMDLINE=                                           # Command line INPUT             # v2.03
CMD1=;CMD2=;CMD3=;CMD4=;CMD5=                      # Command recall push stack      # v2.03

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
Repeat() {
    # Print 25 '=' use HDRLINE=$(Repeat 25 "=")
    printf "%${1}s\n" | tr " " "$2"
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
Load_Module_UserspaceTool() {                                           # v1.03

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

    [ -n "$(lsmod | grep -i wireguard)" ] &&  echo -e $cBGRE"\t[✔] WireGuard Module is LOADED\n"$cRESET || echo -e $cBRED"\t[✖] WireGuard Module is NOT LOADED\n"$cRESET

    # Without a BOOT, there may be a mismatch
    local BOOTLOADED=$(dmesg | grep -a WireGuard | awk '{print $3}')
    local WGKERNEL=$(opkg list-installed | grep "wireguard-kernel" | awk '{print $3}' | sed 's/\-.*$//')
    local WGTOOLS=$(opkg list-installed | grep "wireguard-tools" | awk '{print $3}' | sed 's/\-.*$//')

    if [ -n "$WGKERNEL" ];then                  # v1.04
        [ "$WGKERNEL" != "$BOOTLOADED" ] && echo -e $cRED"\a\n\tWarning Reboot required for (dmesg) WireGuard $WGKERNEL $BOOTLOADED\n"
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
                Load_Module_UserspaceTool
            else
                echo -e $cBWHT"\n\tUpdate skipped\n"$cRESET
            fi
        else
            echo -e $cBGRE"\n\tWireGuard Kernel and Userspace Tool up to date.\n"$cRESET
        fi
    fi
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
                WG_INTERFACE=$(awk '$2 == "Y" || $2 =="P" {print $1}' ${INSTALL_DIR}WireguardVPN.conf | tr '\n#' ' ')
            else
                # Whot if there are Peers we don't control?
                WG_INTERFACE=$(wg show interfaces)                # v1.09
            fi
            SayT "$VERSION Requesting WireGuard VPN Peer $ACTION ($WG_INTERFACE)"
            #echo -e $cBWHT"n\tRequesting WireGuard VPN Peer ALL-${ACTION}$CATEGORY ($WG_INTERFACE)"$cRESET
    else
        echo -en $cBCYA
        # Allow category
        case "$WG_INTERFACE" in
            clients)
                WG_INTERFACE=$(grep -E "^wg1" ${INSTALL_DIR}WireguardVPN.conf | awk '$2 == "Y" || $2 =="P" {print $1}' | tr '\n' ' ' | sed 's/ $//')     # v2.02
                local CATEGORY=" for Category 'Clients'"
                SayT "$VERSION Requesting WireGuard VPN Peer ${ACTION}$CATEGORY ($WG_INTERFACE)"
                #echo -e $cBWHT"Requesting WireGuard VPN Peer ${ACTION}$CATEGORY ($WG_INTERFACE)"$cRESET
            ;;
            servers)
                WG_INTERFACE=$(grep -E "^wg2" ${INSTALL_DIR}WireguardVPN.conf | awk '$2 == "Y" || $2 =="P" {print $1}' | tr '\n' ' ' | sed 's/ $//')     # v2.02
                local CATEGORY=" for Category 'Servers'"
                SayT "$VERSION Requesting WireGuard VPN Peer ${ACTION}$CATEGORY ($WG_INTERFACE)"
                #echo -e $cBWHT"Requesting WireGuard VPN Peer ${ACTION}$CATEGORY ($WG_INTERFACE)"$cRESET
            ;;
            *)
                WG_INTERFACE=$WG_INTERFACE" "$@
            ;;
        esac
    fi

    WG_INTERFACE=$(echo "$WG_INTERFACE" | sed 's/ $//')
    echo -e $cBWHT"\n\tRequesting WireGuard VPN Peer ${ACTION}$CATEGORY (${cBMAG}$WG_INTERFACE"$cRESET")"

    case "$ACTION" in
        start|restart)                                  # v1.09

            # Commandline request overrides entry in config file                            # v1.10 Hotfix
            #[ -n "$(echo "$@" | grep -w "policy")" ] && { Route="policy"; POLICY_MODE="Policy Mode"; } || Route="default"      # v2.01 @jobhax v1.09
            [ -n "$(echo "$@" | grep -w "nopolicy")" ] && Route="default"                   # v1.11 Hotfix

            echo -e

            LOOKAHEAD=$WG_INTERFACE

            for WG_INTERFACE in $WG_INTERFACE
                do

                    [ "$WG_INTERFACE" == "nopolicy" ] && continue                           # v2.02

                    LOOKAHEAD=$(echo "$LOOKAHEAD" | awk '{$1=""}1')
                    if [ "$(echo "$LOOKAHEAD" | awk '{print $1}')" == "nopolicy" ];then     # v2.02
                        Route="default"
                        POLICY_MODE="Policy override ENFORCED"
                    fi

                    if [ -z "$Route" ];then
                        [ "$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $2}' ${INSTALL_DIR}WireguardVPN.conf)" == "P" ] && Route="policy" || Route="default"
                    fi

                    if [ "$ACTION" == "restart" ];then                                      # v1.09
                        # If it is UP then terminate the Peer
                        if [ -n "$(ifconfig $WG_INTERFACE 2>/dev/null | grep inet)" ];then  # v1.09
                            echo -e $cBWHT;Say "$VERSION Restarting Wireguard VPN '$Mode' Peer ($WG_INTERFACE)" 2>&1
                            [ "$Mode" == "server" ] && /jffs/addons/wireguard/wg_server $WG_INTERFACE "disable" || ${INSTALL_DIR}wg_client $WG_INTERFACE "disable"                 # v1.09
                        fi
                    fi

                    echo -en $cBCYA
                    SayT "$VERSION Initialising Wireguard VPN '$Mode' Peer ($WG_INTERFACE) ${POLICY_MODE}"
                    if [ -n "$(ifconfig | grep -E "^$WG_INTERFACE")" ];then
                        SayT "***ERROR: WireGuard '$Mode' Peer ('$WG_INTERFACE') ALREADY ACTIVE"
                        echo -e $cRED"\a\t***ERROR: WireGuard '$Mode' Peer (${cBWHT}$WG_INTERFACE${cBRED}) ALREADY ACTIVE\n"$cRESET 2>&1
                    else
                        if [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                            # Rather than rely on naming convention; verify the content
                            [ -z "$(grep -iE "^Endpoint" ${CONFIG_DIR}${WG_INTERFACE}.conf)" ] && Mode="server" || Mode="client"

                            if [ "$Mode" == "server" ] ; then
                                sh ${INSTALL_DIR}wg_server $WG_INTERFACE

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
                    if [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then
                        [ -z "$(grep -iE "^Endpoint" ${CONFIG_DIR}${WG_INTERFACE}.conf)" ] && Mode="server" || Mode="client"

                        DESC=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $0}' ${INSTALL_DIR}WireguardVPN.conf | grep -oE "#.*$" | sed 's/^[ \t]*//;s/[ \t]*$//')
                        echo -en $cBCYA
                        SayT "$VERSION Requesting termination of WireGuard VPN '$Mode' Peer ('$WG_INTERFACE')"

                        if [ -z "$(ifconfig | grep -E "^$WG_INTERFACE")" ];then
                            echo -e $cRED"\a\t";Say "WireGuard VPN '$Mode' Peer ('$WG_INTERFACE') NOT ACTIVE";echo -e
                        else
                            if [ "$Mode" == "server" ]; then

                                    sh ${INSTALL_DIR}wg_server $WG_INTERFACE "disable"

                                    elif [ "$Mode" == "client" ] && [ "$Route" != "policy" ] ; then

                                        #wg show $WG_INTERFACE >/dev/null 2>&1 && ${CONFIG_DIR}wg-down $WG_INTERFACE || Say "WireGuard $Mode service ('$WG_INTERFACE') NOT running."
                                        /opt/bin/wg show $WG_INTERFACE >/dev/null 2>&1 && sh ${INSTALL_DIR}wg_client $WG_INTERFACE "disable" || Say "WireGuard $Mode service ('$WG_INTERFACE') NOT running."
                                    else
                                        /opt/bin/wg show $WG_INTERFACE >/dev/null 2>&1 && sh ${INSTALL_DIR}wg_client $WG_INTERFACE "disable" "policy" || Say "WireGuard $Mode (Policy) service ('$WG_INTERFACE') NOT running."
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
                echo -e $cBCYA"\tCreating 'wg_manager' alias for '$SCRIPT_NAME'" 2>&1
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
Create_Sample_Config() {
    if [ -f ${INSTALL_DIR}WireguardVPN.conf ];then
        echo -e $cBYEL"\a\n\tWarning: WireGuard configuration file '${INSTALL_DIR}WireguardVPN.conf' already exists!...renamed to 'WireguardVPN.conf$TS'"
        mv ${INSTALL_DIR}WireguardVPN.conf ${INSTALL_DIR}WireguardVPN.conf.$TS
    fi
    echo -e $cBCYA"\a\n\tCreating WireGuard configuration file '${INSTALL_DIR}WireguardVPN.conf'"

    cat > ${INSTALL_DIR}WireguardVPN.conf << EOF
# NOTE: Auto=Y  Command 'wg_manager.sh start' will auto-start this Peer
#       Auto=P  Command 'wg_manager.sh start' will auto-start this Peer using it's Selective Routing RPDB Policy rules if defined e.g 'rp11'
#
#
# VPN   Auto   Local Peer IP         Remote Peer Socket     DNS               Annotation Comment
wg11    N      12.34.56.78/32        86.106.143.93:51820    193.138.218.74    # ****THIS IS NOT A REAL PEER** Edit 'wg11.conf' with real DATA!
wg12    N      xxx.xxx.xxx.xxx/32    209.58.188.180:51820   193.138.218.74    # Mullvad China, Hong Kong
wg13    N      xxx.xxx.xxx.xxx/32    103.231.88.18:51820    193.138.218.74    # Mullvad Oz, Melbourne
wg14    N      xxx.xxx.xxx.xxx/32    193.32.126.66:51820    193.138.218.74    # Mullvad France, Paris
wg15    N                                                                     #

# For each 'server' Peer you need to allocate a unique VPN subnet
#              VPN Subnet
wg21    Y      10.50.1.1/24                                                   # $HARDWARE_MODEL Local Host Peer 1
wg22    N      10.50.2.1/24                                                   # $HARDWARE_MODEL Local Host Peer 2

# The following default 'wg0' interface retained for backward compatibility!
wg0     N      xxx.xxx.xxx.xxx/32     86.106.143.93:51820    193.138.218.74   # Mullvad USA, New York

#       RPDB Selection Routing rules same format as 'nvram get vpn_clientX_clientlist'
#       < Desciption > Source IP/CIDR > [Target IP/CIDR] > WAN_or_VPN[...]
rp11    <>
rp12
rp13    <Dummy VPN 3>172.16.1.3>>VPN<Plex>172.16.1.123>1.1.1.1>VPN<Router>172.16.1.1>>WAN<All LAN>172.16.1.0/24>>VPN
rp14
rp15    <Router>192.168.1.0/24>>VPN<LAN>192.168.1.1>>WAN

# Custom 'client' Peer interfaces - simply to annotate
SGS8    N      1.2.3.4            xxx.xxx.xxx.xxx        dns.xxx.xxx.xxx      # A comment here
wg0-client5 N  4.3.2.1                                                        # Mullvad UK, London

# WAN KILL-Switch
#KILLSWITCH

# Optionally define the 'server' Peer 'clients' so they can be identified by name in the enhanced WireGuard Peer status report
# (These entries are automatically added below when the 'create' command is used)
# Public Key                                      DHCP IP             Annotation Comment
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=      10.50.1.11/32       # A Cell phone for 'server' 1


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
    local PEER_TYPE=

    # Is this a standard 'client' Peer interface 'wg11-wg15' or 'server' 'wg21-wg22'    # v1.09
    #if [ -z "$(echo "$WG_INTERFACE" | grep -oE "^wg[2][1-2]|^wg[1][1-5]*$")" ];then     # v1.09
        # Always identfy if it's a 'client' or 'server' Peer from its config file
        if [ -f ${CONFIG_DIR}${WG_INTERFACE}.conf ];then                                # v1.03
            if [ -n "$(grep -iE "^Endpoint" ${CONFIG_DIR}${WG_INTERFACE}.conf)" ];then  # v1.03
                local PEER_TYPE="client"
            else
                local PEER_TYPE="server"
            fi
        fi
    #fi
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
            echo -e $cBGRE"\tAdded 'wg*' interfaces to DNSMasq"$cRESET 2>&1
            echo -e "interface=wg*     # WireGuard" >> /jffs/configs/dnsmasq.conf.add
            service restart_dnsmasq 2>/dev/null
        fi
    else
        if [ -f /jffs/configs/dnsmasq.conf.add ];then
            if [ -n "$(grep "WireGuard" /jffs/configs/dnsmasq.conf.add)" ];then
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
                [ "$SILENT" == "N" ] && echo -e $cBGRE"\n\tWireGuard WAN KILL Switch ${cBRED}${aREVERSE}ENABLED"$cRESET 2>&1
        else
                iptables -D FORWARD -i br0 -o $(nvram get wan0_ifname) -j REJECT -m comment --comment "WireGuard KILL-Switch" 2>/dev/null
                [ "$SILENT" == "N" ] && echo -e $cBGRE"\n\tWireGuard WAN KILL Switch ${cBRED}${aREVERSE}DISABLED"$cRESET 2>&1
        fi
    fi

    [ -n "$(iptables -L FORWARD | grep "WireGuard KILL-Switch")" ] && STATUS="Y" || STATUS="N"

    echo "$STATUS"      # Y/N
}
Get_scripts() {
    local BRANCH="$1"
    local BRANCH="dev" ############## DO NOT USE IN PRODUCTION #################
    echo -e $cBCYA"\tDownloading scripts"$cRESET 2>&1

    # Allow use of custom script for debugging
    [ "$(WireGuard_Installed)" == "Y" ] && download_file ${INSTALL_DIR} wg_manager.sh martineau $BRANCH dos2unix 777
    download_file ${INSTALL_DIR} wg_client martineau $BRANCH dos2unix 777
    download_file ${INSTALL_DIR} wg_server martineau $BRANCH dos2unix 777
    chmod +x ${INSTALL_DIR}wg_manager.sh
    chmod +x ${INSTALL_DIR}wg_client
    chmod +x ${INSTALL_DIR}wg_server

    md5sum ${INSTALL_DIR}wg_manager.sh > ${INSTALL_DIR}"wg_manager.md5"
    md5sum ${INSTALL_DIR}wg_client     > ${INSTALL_DIR}"wg_client.md5"
    md5sum ${INSTALL_DIR}wg_server     > ${INSTALL_DIR}"wg_server.md5"
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
Peer_Status() {

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
        SayT "$PEER_STATUS"
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

    echo -e $cBWHT"\n\tInstalling WireGuard Manager - Router$cBMAG $HARDWARE_MODEL (v$BUILDNO)\n"$cRESET

    if [ "$(Is_AX)" == "N" ] && [ "$(Is_HND)" == "N" ];then
        echo -e $cBRED"\a\n\tERROR: Router$cRESET $HARDWARE_MODEL (v$BUILDNO)$cBRED is not currently compatible with WireGuard!\n"
        exit 96
    fi

    echo -en $cBRED

    # Amtm
    # mkdir -p /jffs/addons/wireguard
    if [ -d /opt/etc/ ];then
        # Legacy pre v2.03 install?
        if [ -d /opt/etc/wireguard ];then
            echo -e $cRED"\a\n\tWarning obsolete WireGuard Session Manager v1.xx config directory Found!!! (${cBWHT}'/opt/etc/wireguard'{$cBRED})\n"$cRESET
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

    # Kernel module
    echo -e $cBCYA"\tDownloading Wireguard Kernel module for $HARDWARE_MODEL (v$BUILDNO)"$cRESET

    ROUTER_COMPATIBLE="Y"

    Download_Modules $HARDWARE_MODEL

    Load_Module_UserspaceTool

    # Create the Sample/template parameter file '${INSTALL_DIR}WireguardVPN.conf'
    Create_Sample_Config

    # Create dummy 'Client' and 'Server' templates
    echo -e $cBCYA"\tCreating WireGuard 'Client' and 'Server' Peer templates '${cBMAG}wg11.conf$cBCYA' and ${cBMAG}wg21.conf${cBCYA}'"$cRESET

    cat > ${CONFIG_DIR}wg11.conf << EOF
[Interface]
#Address = 10.10.10.2/24
#DNS = 10.10.10.1
PrivateKey = Ba1dgO/plL4wCB+p111h8bIAWNeNgPZ7L+HFBhoE4=

[Peer]
Endpoint = 10.11.12.13:51820
PublicKey = Ba1dgO/plL4wCB+pRdabQh8bIAWNeNgPZ7L+HFBhoE4=
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # Create Server templates
    for I in 1 2                                            # v3.02
        do
            cat > ${CONFIG_DIR}wg2${I}.conf << EOF
# $HARDWARE_MODEL 'server' Peer #1 (wg2$I)
[Interface]
PrivateKey = Ha1rgO/plL4wCB+pRdc6Qh8bIAWNeNgPZ7L+HFBhoE4=
ListenPort = 51820

# e.g. Accept a WireGuard connection from say YOUR mobile device to the router
# see '${CONFIG_DIR}mobilephone_private.key'

# Peer Example
#[Peer]
#PublicKey = This_should_be_replaced_with_the_Public_Key_of_YOUR_mobile_device
#AllowedIPs = PEER.ip.xxx.xxx/32
# Peer Example End
EOF

        done
    # Create 'server' Peer wg21
    echo -e $cBCYA"\tCreating WireGuard Private/Public key-pairs for $HARDWARE_MODEL (v$BUILDNO)"$cRESET
    if [ -n "$(which wg)" ];then
        for I in 1
            do
                wg genkey | tee ${CONFIG_DIR}wg1${I}_private.key | wg pubkey > ${CONFIG_DIR}wg1${I}_public.key
            done
        for I in 1 2
            do
                wg genkey | tee ${CONFIG_DIR}wg2${I}_private.key | wg pubkey > ${CONFIG_DIR}wg2${I}_public.key
            done

        # Update the Sample Peer templates with the router's real keys
        PRIV_KEY=$(cat ${CONFIG_DIR}wg11_private.key)
        PRIV_KEY=$(Convert_Key "$PRIV_KEY")
        sed -i "/^PrivateKey/ s~[^ ]*[^ ]~$PRIV_KEY~3" ${CONFIG_DIR}wg11.conf

        PRIV_KEY=$(cat ${CONFIG_DIR}wg21_private.key)
        PRIV_KEY=$(Convert_Key "$PRIV_KEY")
        sed -i "/^PrivateKey/ s~[^ ]*[^ ]~$PRIV_KEY~3" ${CONFIG_DIR}wg21.conf

    fi

    if  [ -n "$(which wg)" ] && [ "$ROUTER_COMPATIBLE" == "Y" ];then

        # Test 'wg' and this script - (well actually the one used @BOOT) against the two Sample Peers (wg11 and Wg21)
        echo -e $cBCYA"\t${cRESET}${cYBLU}Test ${cRESET}${cBCYA}Initialising the Sample WireGuard 'client' and 'server' Peers, ${cYBLU}but ONLY the Sample 'server' (wg21) is VALID :-)${cYBLU}"$cRESET
        ${INSTALL_DIR}$SCRIPT_NAME start
        # Test the Status report
        echo -e $cBCYA"\tWireGuard Peer Status"
        ${INSTALL_DIR}$SCRIPT_NAME show               # v1.11

        echo -e $cBCYA"\tTerminating ACTIVE WireGuard Peers ...\n"$cRESET
        ${INSTALL_DIR}$SCRIPT_NAME stop
    else
        echo -e $cBRED"\a\n\t***ERROR: WireGuard install FAILED!\n"$cRESETd
    fi

    Edit_nat_start                                      # v1.07

    Edit_DNSMasq                                        # v1.12

    Manage_alias

    # Auto start ALL defined WireGuard Peers @BOOT
    # Use post-mount
    echo -e $cBCYA"\tAdding Peer Auto-start @BOOT"$cRESET
    if [ -z "$(grep -i "WireGuard" /jffs/scripts/post-mount)" ];then
        echo -e "/jffs/addons/wireguard/wg_manager.sh init \"$@\" & # WireGuard Manager" >> /jffs/scripts/post-mount
    fi

    echo -e $cBCYA"\tInstalling QR rendering module"$cBGRA
    opkg install qrencode

    Display_QRCode ${CONFIG_DIR}wg11.conf
    echo -e $cBGRE"\tWireGuard install COMPLETED.\n"$cRESET

}
Show_Peer_Status() {

    local ACTION=$1

    [ -f "/tmp/WireGuard.txt" ] && rm /tmp/WireGuard.txt

    if [ -n "$(wg show interfaces)" ];then
        echo "#$ACTION"  > /tmp/WireGuard.txt
        /opt/bin/wg show all >> /tmp/WireGuard.txt
    fi
    #echo -e
    if [ -f /tmp/WireGuard.txt ] && [ $(wc -l < /tmp/WireGuard.txt) -ne 0 ];then

        while IFS='' read -r LINE || [ -n "$LINE" ]; do

            if [ "${LINE:0:1}" == "#" ];then
                menu1="$(echo "$LINE" | sed 's/#//')"
                continue
            fi

            COLOR=$cBCYA

            # interface: wg1? or wg2?
            if [ -n "$(echo "$LINE" | grep -E "interface:")" ];then
                TAB="\t"
                COLOR=$cBMAG
                WG_INTERFACE=$(echo $LINE | awk '{print $2}')

                [ -z "$(grep -iE "^Endpoint" ${CONFIG_DIR}${WG_INTERFACE}.conf)" ] && TYPE="server" || TYPE="client"

                # Read the Remote peer config to set the LOCAL peer Endpoint
                if [ -f ${INSTALL_DIR}WireguardVPN.conf ];then
                    LOCALIP=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $2}' ${INSTALL_DIR}WireguardVPN.conf)
                    SOCKET=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $4}' ${INSTALL_DIR}WireguardVPN.conf)
                    DESC=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $0}' ${INSTALL_DIR}WireguardVPN.conf | grep -oE "#.*$" | sed 's/^[ \t]*//;s/[ \t]*$//')
                fi
                LINE=${COLOR}$LINE" ${cBMAG}\t('$TYPE' $DESC)"
            else
                TAB="\t\t"
                [ -n "$(echo "$LINE" | grep -E "transfer:")" ] && COLOR=$cBWHT
            fi

            if [ -n "$(echo "$LINE" | grep -iE "peer:" )" ] && [ "$TYPE" == "server" ];then
                PUB_KEY=$(echo "$LINE" | awk '{print $2}')
                DESC=$(grep -F "$PUB_KEY" ${INSTALL_DIR}WireguardVPN.conf | grep -oE "#.*$" | sed 's/^[ \t]*//;s/[ \t]*$//')
                [ -z "$DESC" ] && DESC="# Unidentified"
                LINE=${COLOR}$LINE" ${cBMAG}\t('$TYPE client'  $DESC)"
            fi

            if [ "${ACTION:4:1}" != "+" ];then
                [ -n "$(echo "$LINE" | grep -E "interface:|peer:|transfer:")" ] && echo -e ${TAB}${COLOR}$LINE
            else
                echo -e ${TAB}${COLOR}$LINE
            fi

        done < /tmp/WireGuard.txt

        rm /tmp/WireGuard.txt
    else
        SayT "No WireGuard Peers active"
        echo -e "\tNo WireGuard Peers active\n" 2>&1
    fi
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

                HDR="N"
            fi

            local STATUS_LINE="WireGuard ACTIVE Peer Status: "$(Peer_Status)                  # v2.01
            [ "$(Manage_KILL_Switch)" == "Y" ] && local KILL_STATUS="${cBGRE}${aREVERSE}ENABLED$cRESET" || local KILL_STATUS="        "
            echo -e $cRESET"\n"${KILL_STATUS}"\t"${cRESET}${cBMAG}${STATUS_LINE}$cRESET

            [ "$CHECK_GITHUB" != "N" ] && Check_Version_Update      # v2.01
            CHECK_GITHUB="N"

            if [ "$1" = "uninstall" ]; then
                menu1="z"
            else

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
                            MENU_L="$(printf '%b3 %b = %bList%b ACTIVE Peers [%b3x%b - lists ALL details]\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}" "${cBYEL}" "${cRESET}" )"
                            MENU_T="$(printf '%b5 %b = %bStop%b    [ [Peer... ] | category ] e.g. stop clients\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
                        else
                            MENU_L="$(printf '%b3 %b = %bList%b ACTIVE Peers [%b3x%b - lists ALL details]\n' "${cBYEL}" "${cRESET}" "${cGRA}" "${cBGRA}" "${cBYEL}" "${cBGRA}" )"   # v2.03
                            MENU_T="$(printf '%b5 %b = %bStop%b    [ [Peer... ] | category ] e.g. stop clients\n' "${cBYEL}" "${cRESET}" "${cGRA}" "${cBGRA}")"
                        fi
                        MENU_R="$(printf '%b6 %b = %bRestart%b [ [Peer... ] | category ]%b e.g. restart servers\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
                        MENU_Q="$(printf '%b7 %b = %bDisplay QR code for a Peer {device} e.g. iPhone%b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
                        MENU_P="$(printf '%b8 %b = %bPeer management ['list'] | [ {Peer} [ add | del | {auto [y|n|p]}] ] ]%b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"
                        MENU_C="$(printf '%b9 %b = %bCreate Key-pair for Peer {Device} e.g. Nokia6310i (creates Nokia6310i.conf etc.)%b\n' "${cBYEL}" "${cRESET}" "${cGRE}" "${cRESET}")"

                    fi

                    MENU__="$(printf '%b? %b = About Configuration\n' "${cBYEL}" "${cRESET}")"
                    echo -e ${cWGRE}"\n"$cRESET      # Separator line

                    echo -e
                    printf "%s\t\t\t\t\t\t%s\n"                 "$MENU_I" "$MENU_Q"

                    if [ "$(WireGuard_Installed)" == "Y" ];then
                        printf "%s\t\t\t\t\t%s\n"                   "$MENU_Z" "$MENU_P"
                        printf "\t\t\t\t\t\t\t\t\t%s\n"                       "$MENU_C"
                        printf "%s\t\t\t\t\t\t\t\t\t%s\n"           "$MENU_L"
                        printf "%s\t\t\t\t\t\t\t\t\t%s\n"           "$MENU_S"
                        printf "%s\t\t\t\t\t\t\t\t\t%s\n"           "$MENU_T"
                        printf "%s\t\t\t\t\t\t\t\t\t%s\n"           "$MENU_R"
                        printf "\n%s\t\t\t\t\t\n"                   "$MENU__"
                        printf "%s\t\t\n"                           "$MENU_VX"
                    fi

                    printf '\n%be %b = Exit Script [?]\n' "${cBYEL}" "${cRESET}"
                fi
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

            # Translate v3.00 (restricted) Easy menu but Advanced mode commands remain for consistency backward compatibility.
            if [ "$EASYMENU" == "Y" ];then
                case "$menu1" in
                    0) ;;
                    1|i)
                        [ -z "$(ls ${INSTALL_DIR}*.ipk 2>/dev/null)" ]  && menu1="install" || menu1="getmodules";;
                    2|z) menu1="uninstall";;
                    3*|list*|show*) menu1=$(echo "$menu1" | awk '{$1="show"}1');;
                    4*|start*) menu1=$(echo "$menu1" | awk '{$1="start"}1') ;;
                    5*|stop*) menu1=$(echo "$menu1" | awk '{$1="stop"}1') ;;
                    6*|restart*) menu1=$(echo "$menu1" | awk '{$1="restart"}1') ;;
                    7*|qrcode*) menu1=$(echo "$menu1" | awk '{$1="qrcode"}1') ;;
                    8*|peer*) menu1=$(echo "$menu1" | awk '{$1="peer"}1') ;;
                    9*|createsplit*|create*) menu1=$(echo "$menu1" | awk '{$1="create"}1') ;;
                    u|uf|uf" "*) ;;                           # v3.14
                    "?") ;;
                    v|vx) ;;
                    loadmodules) ;;
                    dns*) ;;                            # v2.01
                    natstart*) ;;
                    alias*) ;;
                    diag) ;;
                    debug) ;;                   # v3.04
                    wg*) ;;
                    killswitch*) ;;             # v2.03
                    killinterface*) ip link del dev $(echo "$menu1" | awk '{print $2}'); continue ;;
                    "") ;;
                    e*) ;;
                    *) printf '\n\a\t%bInvalid Option%b "%s"%b Please enter a valid option\n' "$cBRED" "$cRESET" "$menu1" "$cBRED"
                       continue
                       ;;
                esac
            fi

            [ -n "$DEBUGMODE" ] && set -x

            menu1=$(printf "%s" "$menu1" | sed 's/^[ \t]*//;s/[ \t]*$//')       # Old-skool strip leading/trailing spaces

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
                diag*|list|show*)

                    local ACTION="$(echo "$menu1"| awk '{print $1}')"

                    local ARG=
                    if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                        local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                    fi

                    if [ -n "$(which wg)" ];then

                        echo -e $cBYEL"\n\t\t WireGuard VPN Peer Status\n"$cRESET
                        Show_Peer_Status

                        if [ "$ACTION" == "diag" ];then
                            #echo -e $cBWHT"\n\tDEBUG: Routing Table main\n";ip route | grep "wg.";for WG_INTERFACE in $(wg show interfaces);do I=${WG_INTERFACE:3:1};echo -e "\n\tDEBUG: Routing Table 12$I";ip route show table 12$I;done
                            echo -e $cBYEL"\n\tDEBUG: Routing Table main\n"$cBCYA
                            ip route | grep "wg."
                            for WG_INTERFACE in $(wg show interfaces)
                                do
                                    I=${WG_INTERFACE:3:1}
                                    if [ "${WG_INTERFACE:0:3}" != "wg2" ];then
                                        DESC=$(awk -v pattern="$WG_INTERFACE" 'match($0,"^"pattern) {print $0}' ${INSTALL_DIR}WireguardVPN.conf | grep -oE "#.*$" | sed 's/^[ \t]*//;s/[ \t]*$//')
                                        echo -e $cBYEL"\n\tDEBUG: Routing Table 12$I (wg1$I) ${cBMAG}$DESC\n"$cBCYA
                                        ip route show table 12$I
                                    fi
                                done

                            echo -e $cBYEL"\n\tDEBUG: RPDB rules\n"$cBCYA
                            #ip rule | grep -E "lookup 12[1-5]"
                            ip rule

                            echo -e $cBYEL"\n\tDEBUG: Routing info MTU etc.\n"$cBCYA          # v1.07
                            for WG_INTERFACE in $(wg show interfaces)
                                do
                                    ip a l $WG_INTERFACE                                # v1.07
                                done

                            echo -e $cBYEL"\n\tDEBUG: UDP sockets.\n"$cBCYA
                            netstat -l -n -p | grep -e "^udp\s.*\s-$"

                            echo -e $cBYEL"\n\tDEBUG: Firewall rules \n"$cBCYA
                            iptables --line -nvL FORWARD | grep -iE "WireGuard|Chain|pkts"
                            echo -e
                            iptables --line -t nat -nvL POSTROUTING | grep -iE "WireGuard|Chain|pkts"
                            echo -e
                            iptables --line -t mangle -nvL POSTROUTING | grep -iE "WireGuard|Chain|pkts"
                            echo -e
                            iptables --line -nvL INPUT | grep -iE "WireGuard|Chain|pkts"
                            echo -e
                            iptables --line -nvL OUTPUT | grep -iE "WireGuard|Chain|pkts"


                            [ "$(nvram get ipv6_service)" != "disabled" ] && ip -6 rule show

                            echo -e $cRESET
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
                getmodules)

                    Download_Modules $HARDWARE_MODEL
                    ;;
                loadmodules)

                    Load_Module_UserspaceTool
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

                    echo -e $cBCYA"\n\tUninstalling WireGuard Session Manager"$cRESET
                    echo -en $cBRED
                    [ -f ${INSTALL_DIR}WireguardVPN.conf ] && rm ${INSTALL_DIR}WireguardVPN.conf
                        # legacy tidy-up!
                        [ -f ${CONFIG_DIR}WireguardVPN_map ] && rm ${CONFIG_DIR}WireguardVPN_map

                    rm -rf /jffs/addons/wireguard

                    # Only remove WireGuard Entware packages if user DELETES '/opt/etc/wireguard'
                    echo -e "\n\tPress$cBRED Y$cRESET to$cBRED delete ALL WireGuard DATA files (Peer *.config etc.) $cRESET('${CONFIG_DIR}') or press$cBGRE [Enter] to keep custom WireGuard DATA files."
                    read -r "ANS"
                    if [ "$ANS" == "Y" ];then
                       echo -e $cBCYA"\n\tDeleting $cRESET'${CONFIG_DIR}'"
                       [ -d "${CONFIG_DIR}" ] && rm -rf ${CONFIG_DIR}

                       echo -e $cBCYA"\tUninstalling Wireguard Kernel module and Userspace Tool for $HARDWARE_MODEL (v$BUILDNO)"$cBGRA
                       opkg remove wireguard-kernel wireguard-tools
                    fi

                    echo -e $cBCYA"\tDeleted Peer Auto-start @BOOT\n"$cRESET
                    [ -n "$(grep -i "WireGuard" /jffs/scripts/post-mount)" ] && sed -i '/WireGuard/d' /jffs/scripts/post-mount  # v2.01

                    Edit_nat_start "del"

                    Manage_alias "del"                  # v1.11

                    Edit_DNSMasq "del"                  # v1.12

                    echo -e $cBGRE"\n\tWireGuard Uninstall complete for $HARDWARE_MODEL (v$BUILDNO)\n"$cRESET

                    exit 0
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


                    [ "$ACTION" == "createsplit" ] && SPLIT_TUNNEL="Y" || SPLIT_TUNNEL="Q. Split Tunnel"                       # v1.11 v1.06

                    DEVICE_NAME=$ARG
                    if [ -n "$DEVICE_NAME" ];then
                        echo -e $cBCYA"\n\tCreating Wireguard Private/Public key pair for device '$DEVICE_NAME'"$cBYEL
                        wg genkey | tee ${CONFIG_DIR}${DEVICE_NAME}_private.key | wg pubkey > ${CONFIG_DIR}${DEVICE_NAME}_public.key
                        echo -e $cBYEL"\n\tDevice '"$DEVICE_NAME"' Public key="$(cat ${CONFIG_DIR}${DEVICE_NAME}_public.key)"\n"$cRESET

                        # Generate the Peer config to be imported into the device
                        PUB_KEY=$(cat ${CONFIG_DIR}${DEVICE_NAME}_public.key)
                        # Use the first 'server' Peer if one is found ACTIVE
                        for SERVER_PEER in $(wg show interfaces | grep -vE "^wg1")
                            do
                                # Is it ACTUALLY a 'server' Peer?                           # v1.08
                                [ -n "$(grep -iE "^Endpoint" ${CONFIG_DIR}${SERVER_PEER}.conf)" ] && continue || break
                            done

                        PUB_SERVER_KEY=
                        # Use the Public key of the ACTIVE 'server' Peer for instant testing! although the 'server' Peer needs to be restarted? # v1.06
                        if [ -n "$SERVER_PEER" ];then
                            PUB_SERVER_KEY=$(wg show "$SERVER_PEER" | awk '/public key:/ {print $3}')        # v1.06
                            echo -e $cBCYA"\tUsing 'server' Peer '"$SERVER_PEER"'\n"
                        else
                            # Extract the Public keys from the first 'server' Peer Public key file  # v1.06
                            for I in 1 2
                                do
                                    if [ -f ${CONFIG_DIR}wg2${I}_public.key ];then
                                        PUB_SERVER_KEY=$(awk '{print $1}' ${CONFIG_DIR}wg2${I}_public.key)  #v1.06
                                        echo -e $cBCYA"\tUsing 'server' Peer 'wg2"${I}"'s Public\n"
                                        SERVER_PEER="wg2"${I}                                   # v1.06
                                        break
                                    fi
                                done
                        fi

                        PRI_KEY=$(cat ${CONFIG_DIR}${DEVICE_NAME}_private.key)
                        ROUTER_DDNS=$(nvram get ddns_hostname_x)
                        [ -z "$ROUTER_DDNS" ] && ROUTER_DDNS="IP_of_YOUR_DDNS_$HARDWARE_MODEL"
                        CREATE_DEVICE_CONFIG="Y"
                        if [ -f ${CONFIG_DIR}${DEVICE_NAME}.conf ];then
                            echo -e $cRED"\a\tWarning: Peer device ${cBMAG}'$DEVICE_NAME'${cRESET}${cRED} WireGuard config already EXISTS!"
                            echo -e $cRESET"\tPress$cBRED y$cRESET to$cBRED ${aBOLD}CONFIRM${cRESET}${cBRED} Overwriting Peer device ${cBMAG}'$DEVICE_NAME.config'${cRESET} or press$cBGRE [Enter] to SKIP."
                            read -r "ANS"
                            [ "$ANS" != "y" ] && CREATE_DEVICE_CONFIG="N"
                        fi

                        # Should the Peer ONLY have access to LAN ? e.g. 192.168.0.0/24         # v1.06
                        LAN_ADDR=$(nvram get lan_ipaddr)
                        LAN_SUBNET=${LAN_ADDR%.*}
                        if [ "$SPLIT_TUNNEL" == "Y" ];then

                            # Reuse the IP if device already exists in '${INSTALL_DIR}WireguardVPN.conf'
                            if [ -z "$(grep -F "# $DEVICE_NAME $TAG" ${INSTALL_DIR}WireguardVPN.conf)" ];then
                                DHCP_POOL=$(awk -v pattern="$SERVER_PEER" 'match($0,"^"pattern) {print $3}' ${INSTALL_DIR}WireguardVPN.conf | tr '/' ' ' | awk '{print $1}') # v1.06
                            else
                                IP=$(grep -w "$DEVICE_NAME" ${INSTALL_DIR}WireguardVPN.conf | awk '{print $2}')  # v1.06
                                sed -i "/# $DEVICE_NAME $TAG/d" ${INSTALL_DIR}WireguardVPN.conf  # v1.06
                            fi
                            if [ -n "$DHCP_POOL" ] || [ -n "$IP" ];then                                     # v1.06 Hack

                                if [ -z "$IP" ];then
                                    DHCP_POOL_SUBNET=${DHCP_POOL%.*}
                                    IP=$(grep -F "$DHCP_POOL_SUBNET." ${INSTALL_DIR}WireguardVPN.conf | grep -Ev "^#" | grep -v "$SERVER_PEER" | awk '{print $2}' | sed 's~/32.*$~~g' | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | tail -n 1)
                                    IP=${IP##*.}        # 4th octet
                                    IP=$((IP+1))
                                else
                                    IP=$(echo "$IP" | cut -d'.' -f3)
                                fi

                                if [ $IP -le 254 ];then
                                    [ "$USE_IPV6" == "Y" ] && IPV6=", fc00:23:5::${IP}/128, 2001:db8:23:5::/64"     # v1.07
                                    IP=$DHCP_POOL_SUBNET"."$IP"/32"
                                else
                                    echo -e $cBRED"\a\t***ERROR: 'server' Peer ($SERVER_PEER) subnet MAX 254 reached '${INSTALL_DIR}WireguardVPN.conf'"
                                    exit 92
                                fi

                            else
                                echo -e $cBRED"\a\t***ERROR: 'server' Peer ($SERVER_PEER) subnet NOT defined in '${INSTALL_DIR}WireguardVPN.conf'"
                                exit 91
                            fi

                            SPLIT_TXT="# Split Traffic LAN Only"
                        else
                            # Default route ALL traffic via the remote 'server' Peer
                            IP="0.0.0.0/0"
                            [ "$USE_IPV6" == "Y" ] && IPV6=", ::/0"
                            SPLIT_TXT="# ALL Traffic"
                        fi

                        ALLOWED_IPS=${IP}${IPV6}

                        if [ "$CREATE_DEVICE_CONFIG" == "Y" ];then
                            cat > ${CONFIG_DIR}${DEVICE_NAME}.conf << EOF
# $DEVICE_NAME
[Interface]
PrivateKey = $PRI_KEY
Address = 10.81.196.55/24
DNS = 1.1.1.1

# $HARDWARE_MODEL 'server' ($SERVER_PEER)
[Peer]
PublicKey = $PUB_SERVER_KEY
AllowedIPs = $ALLOWED_IPS     ${SPLIT_TXT}
Endpoint = $ROUTER_DDNS:51820
PersistentKeepalive = 25
# $DEVICE_NAME End
EOF

                        echo -e $cBGRE"\n\tWireGuard config for Peer device '${DEVICE_NAME}' created (Allowed IP's ${ALLOWED_IPS} ${SPLIT_TXT})\n"$cRESET
                        fi

                        Display_QRCode "${CONFIG_DIR}${DEVICE_NAME}.conf"

                        echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED ADD device '$DEVICE_NAME' ${cRESET}to 'server' Peer ($SERVER_PEER) or press$cBGRE [Enter] to SKIP."
                        read -r "ANS"
                        if [ "$ANS" == "y" ];then
                            echo -e $cBCYA"\n\tAdding device Peer '$DEVICE_NAME' to $HARDWARE_MODEL 'server' ($SERVER_PEER) and WireGuard config\n"

                            # Erase 'client' Peer device entry if it exists....
                            [ -n "$(grep "$DEVICE_NAME" ${CONFIG_DIR}${SERVER_PEER}.conf)" ] && sed -i "/# $DEVICE_NAME/,/# $DEVICE_NAME End/d" ${CONFIG_DIR}${SERVER_PEER}.conf    # v1.08

                            PUB_KEY=$(Convert_Key "$PUB_KEY")

                            echo -e >> ${CONFIG_DIR}${SERVER_PEER}.conf
                            cat >> ${CONFIG_DIR}${SERVER_PEER}.conf << EOF
# $DEVICE_NAME
[Peer]
PublicKey = $PUB_KEY
AllowedIPs = $ALLOWED_IPS
# $DEVICE_NAME End
EOF
                            tail -n 4 ${CONFIG_DIR}${SERVER_PEER}.conf

                            # Add device IP address and identifier to config
                            TAG=$(echo "$@" | sed -n "s/^.*tag=//p" | awk '{print $0}')
                            [ -z "$TAG" ] && TAG="Device"                                   # v1.03

                            [ -z "$(grep "$PUB_KEY" ${INSTALL_DIR}WireguardVPN.conf)" ] && echo -e "$PUB_KEY      $IP     # $DEVICE_NAME $TAG" >> ${INSTALL_DIR}WireguardVPN.conf     # v.03
                            tail -n 1 ${INSTALL_DIR}WireguardVPN.conf

                            # Need to Restart the Peer (if it is UP) or Start it so it can listen for new 'client' Peer device
                            INSTANCE=${SERVER_PEER:3:1}

                            [ -n "$(wg show interfaces | grep "$SERVER_PEER")" ] && CMD="restart" ||  CMD="start"   # v1.08
                            echo -e $cBWHT"\a\n\tWireGuard 'server' Peer needs to be ${CMD}ed to listen for 'client' Peer $DEVICE_NAME $TAG"
                            echo -e $cBWHT"\tPress$cBRED y$cRESET to$cBRED $CMD 'server' Peer ($SERVER_PEER) or press$cBGRE [Enter] to SKIP."
                            read -r "ANS"
                            [ "$ANS" == "y" ] && { ${INSTALL_DIR}/wg_manager.sh restart server "$INSTANCE"; ${INSTALL_DIR}wg_manager.sh "show"; }

                        fi
                    else
                        echo -e $cBRED"\a\n\t***ERROR Missing name of client Peer device\n"$cRESET
                    fi
                    ;;
                "?"|u|u" "*|uf|uf" "*)

                    local ACTION="$(echo "$menu1"| awk '{print $1}')"

                    case "$ACTION" in
                        "?")

                            local CHANGELOG="$cRESET(${cBCYA}Change Log: ${cBYEL}https://github.com/MartineauUK/wireguard/commits/main/wg_manager.sh$cRESET)"   #v2.01
                            [ -n "$(echo $VERSION | grep "b")" ] && local CHANGELOG="$cRESET(${cBCYA}Change Log: ${cBYEL}https://github.com/MartineauUK/wireguard/commits/dev/wg_manager.sh$cRESET)" #v2.01
                            echo -e $cBMAG"\n\t${VERSION}$cBWHT WireGuard Session Manager" ${CHANGELOG}$cRESET  # v2.01
                            Show_MD5 "script"
                            echo -e
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

                            ;;
                        *)
                            [ "$2" == "dev" ] && DEV="dev" || DEV="main"
                            DOWNLOAD="N"

                            if [ "$ACTION" == "uf" ];then
                                echo -e ${cRESET}$cWRED"\n\tForced Update"$cRESET"\n"
                                DOWNLOAD="Y"
                            else
                                Check_Version_Update
                                [ $? -eq 1 ] && DOWNLOAD="Y"        # '2' means 'Push to GitHub' pending! ;-;
                            fi

                            if [ "$DOWNLOAD" == "Y" ];then
                                Get_scripts "$DEV"
                            fi

                            Check_Module_Versions

                            echo -e $cRESET
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

                    FN="${INSTALL_DIR}WireguardVPN.conf"

                    local ACTION="$(echo "$menu1"| awk '{print $1}')"

                    local ARG=
                    if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                        local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                    fi
                    local ARG2=
                    if [ "$(echo "$menu1" | wc -w)" -ge 3 ];then
                        local ARG2="$(printf "%s" "$menu1" | cut -d' ' -f3)"
                    fi
                    local ARG3=
                    if [ "$(echo "$menu1" | wc -w)" -ge 3 ];then
                        local ARG3="$(printf "%s" "$menu1" | cut -d' ' -f4)"
                    fi

                    [ -z "$ARG" ] && ARG="list"                 # default

                    case $ARG in
                        list|"")
                            echo -e $cBWHT"\n\tList of WireGuard Peers\n"$cBCYA
                            if [ -n "$(which column)" ];then
                                awk '($2=="Y" || $2=="N" || $2=="P") {print $0}' $FN | column -t        # v2.02
                            else
                                awk '($2=="Y" || $2=="N" || $2=="P") {print $0}' $FN
                            fi
                            echo -e "\n"$cRESET
                        ;;
                        *)
                            WG_INTERFACE=$ARG

                            if [ "$ARG2" == "add" ] || [ -n "$(grep "^$WG_INTERFACE" $FN )" ];then
                                case $ARG2 in
                                    auto)
                                        if [ "$(echo "$ARG3" | grep "^[yYnNpP]$" )" ];then
                                            FLAG=$(echo "$ARG3" | tr 'a-z' 'A-Z')
                                            sed -i "/^$WG_INTERFACE/ s~[^ ]*[^ ]~$FLAG~2" $FN
                                            echo -e $cBGRE"\n\tUpdated AUTO=$FLAG: $(grep -E "^$WG_INTERFACE[[:space:]]" $FN)\n"$cRESET
                                        else
                                            echo -e $cBRED"\a\n\t***ERROR Invalid Peer Auto='$ARG3''$WG_INTERFACE'\n"$cRESET
                                        fi
                                    ;;
                                    del)
                                        sed -i "/^$WG_INTERFACE/d" $FN
                                        echo -e $cBGRE"\n\tWireGuard Peer '$WG_INTERFACE' ${cBRED}${aREVERSE}DELETED\n"$cRESET
                                    ;;
                                    add)
                                        if [ -z "$(grep "^$WG_INTERFACE" $FN )" ];then
                                            shift 3
                                            LINE=$WG_INTERFACE"   $@"
                                            [ $(echo "$LINE" | wc -w) -eq 1 ] && LINE=$LINE"     N     #"
                                            [ -z "$(echo "$LINE" grep -F "#")" ] && LINE=$LINE" # "
                                            LINE=$(_quote "$LINE")
                                            POS=$(awk '($2=="Y"|| $2=="N"||$2=="P") {print NR":"$0}' $FN | tail -n 1 | cut -d':' -f1)
                                            AUTO="$(echo "$LINE" | awk '{print $2}')"
                                            if [ -n "$(echo "$AUTO" | grep "^[yYnNpP]$" )" ];then
                                                [ -n "$POS" ] && sed -i "$POS a $LINE" $FN
                                                echo -e $cBGRE"\n\tWireGuard Peer '$WG_INTERFACE' added\n"$cRESET
                                            else
                                                echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard Peer Auto='$AUTO' flag for '$WG_INTERFACE'\n"$cRESET
                                            fi
                                        else
                                            echo -e $cBRED"\a\n\t***ERROR WireGuard Peer '$WG_INTERFACE' already exists\n"$cRESET
                                        fi
                                    ;;
                                    comment)
                                        echo -e $cBCYA"\n\tPeer Comment (Before): $(grep -E "^$WG_INTERFACE[[:space:]]" $FN)"$cRESET
                                        shift 3
                                        COMMENT="$@"
                                        [ "${COMMENT:0:1}" != "#" ] && COMMENT="# "$COMMENT
                                        sed -i "/^$WG_INTERFACE/ s~\#.*$~$COMMENT~" $FN
                                        echo -e $cBGRE"\tPeer Comment (After) : $(grep -E "^$WG_INTERFACE[[:space:]]" $FN)\n"$cRESET

                                    ;;
                                    *)
                                        echo -e $cBCYA"\n\tPeer Entry: $(grep -E "^$WG_INTERFACE[[:space:]]" $FN)\n"$cRESET
                                    ;;
                                esac
                            else
                                echo -e $cBRED"\a\n\t***ERROR Invalid WireGuard Peer '$WG_INTERFACE'\n"$cRESET
                            fi
                        ;;
                    esac

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
                wg*)
                    # Expose the WireGuard Userspace Tool
                    echo -e $cBWHT"WireGuard Userspace Tool:\n"
                    $menu1
                ;;
                killswitch*)
                    local ACTION="$(echo "$menu1"| awk '{print $1}')"

                    local ARG=
                    if [ "$(echo "$menu1" | wc -w)" -ge 2 ];then
                        local ARG="$(printf "%s" "$menu1" | cut -d' ' -f2)"
                    fi

                    RC=$(Manage_KILL_Switch "$ARG")
                ;;
                *)

                    ShowHelp
                    echo -e $cBWHT"$VERSION wg_manager.sh WireGuard Session Manager\n\n\t${cBRED}***ERROR Invalid/missing arg '$ACTION'\n"$cRESET    # v1.09
                    ;;
            esac

            #echo -en ${cWGRE}"\n"$cRESET      # Separator line
set +x
        done
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

EASYMENU="Y"

[ "$(nvram get ipv6_service)" != "disabled" ] && USE_IPV6="Y"               # v1.07

TS=$(date +"%Y%m%d-%H%M%S")    # current date and time 'yyyymmdd-hhmmss'

ACTION=$1
PEER=$2
NOPOLICY=$3

# Legacy tidy-up! to adopt a new name for the configuration file
[ -f /jffs/configs/WireguardVPN_map ] && mv /jffs/configs/WireguardVPN_map ${INSTALL_DIR}WireguardVPN.conf      # v2.01

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

# Retain commandline comaptibility
if [ "$1" != "install" ];then   # v2.01
    if [ "$(WireGuard_Installed)" == "Y" ];then             # v2.01
        case "$1" in

            start|init)
                Manage_Wireguard_Sessions "start" "$PEER" "$NOPOLICY"             # Post mount should start ALL defined sessions @BOOT
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
                Show_Peer_Status "show+"                        # Force verbose detail
                echo -e $cRESET
                exit_message
            ;;
        esac
    else
        SayT "***ERROR WireGuard Manager/WireGuard Tool module 'wg' NOT installed"
        echo -e $cBRED"\a\n\t***ERROR WireGuard Tool module 'wg' NOT installed\n"$cRESET
        exit_message
    fi
fi

clear

Check_Lock "wg"

Show_Main_Menu "$@"

echo -e $cRESET

rm -rf /tmp/wg.lock

exit 0



#) 2>&1 | logger -t $(basename $0)"[$$_***DEBUG]"
