#!/bin/sh
VERSION="v1.01"
#============================================================================================ © 2021 Martineau v1.01

SQL_DATABASE="/opt/etc/wireguard.d/WireGuard.db"   # SQL

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
Is_IPv4_Port () {
    grep -oE '^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])(-([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?'$

}

ANSIColours

LOCKFILE="/tmp/${0##*/}.pid"

echo $$ > $LOCKFILE

# wg is 23rd and 7th letters in alphabet
FD=237
eval exec "$FD>$LOCKFILE"
flock -n $FD || { Say "WireGuard UDP tracker/updater...ABORTing"; exit; }

Say "WireGuard UDP tracker/updater.........."

FN=$1
[ -z "$FN" ] && FN="/tmp/WireGuard_UDP.log"

[ ! -f ] && true > $FN

tail -F "$FN" | \
    while read UDP_PACKET
        do
            case "$UDP_PACKET" in
                *51820*|*1150*)                 # Server Listen ports, could extract from live config if 'server' Peer running
                    COLOR=$cYEL
                    if [ -n "$(echo "$UDP_PACKET" | grep -io "ASSURED")" ];then
                        COLOR=$cBGRE
                        TS=$(echo "$UDP_PACKET" | tr -d '[]' | awk -F'.' '{print $1}')
                        PORT=$(echo "$UDP_PACKET" | grep -o "sport=[0-9]*" | tail -n 1)
                        PORT=${PORT##*=}
                        echo -e ${aREVERSE}$(date -d @$TS)">>>>>>>>>>>>"${PORT}${cRESET}${cBGRE}

                        case "$PORT" in
                            51820)
                                SERVER=$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers where port='51820';")
                                PEER="SGS8"
                                sqlite3 $SQL_DATABASE "INSERT into session values('$WG_INTERFACE','End','$((TS-1))');"
                                sqlite3 $SQL_DATABASE "INSERT into session values('$WG_INTERFACE','Start','$TS');"
                                sqlite3 $SQL_DATABASE "UPDATE devices SET conntrack='$TS' WHERE name='$PEER';"
                            ;;
                            11502)
                                SERVER=$(sqlite3 $SQL_DATABASE "SELECT peer FROM servers where port='11502';")
                                PEER="iPhone"
                                sqlite3 $SQL_DATABASE "UPDATE devices SET conntrack='$TS' WHERE name='$PEER';"
                            ;;
                        esac

                        echo -e $cBGRE"\n\t[✔] Peer (${cBMAG}${PEER}${cBGRE})\n"$cRESET
                        Say "WireGuard 'device' Peer Connected (${PEER}) to 'server' Peer ($SERVER) on Port:$PORT"

                    fi
                ;;
                *)
                    COLOR=$cBGRA
                ;;
            esac

            echo -e ${COLOR}${date}${UDP_PACKET}${cRESET}

            PORT=;TS=

            # Check for external kill switch; NOTE: Termination can be delayed on a quiet system!
            if [ ! -f "$LOCKFILE" ];then                                # Tacky! should really check for a separate 'KILL' file?
                echo -en $cBYEL
                Say "WireGuard UDP Monitor external termination trigger.....terminating"
                echo -e $cRESET
                flock -u $FD
                exit
            fi

        done

