# wireguard
Manage/Install WireGuard on applicable ASUS routers

see https://www.snbforums.com/threads/experimental-wireguard-for-rt-ac86u-gt-ac2900-rt-ax88u-rt-ax86u.46164/

## Installation ##

Enable SSH on router, then use your preferred SSH Client e.g. Xshell6,MobaXterm, PuTTY etc.

(TIP: Triple-click the install command below) to copy'n'paste into your router's SSH session:

    curl --retry 3 "https://raw.githubusercontent.com/MartineauUK/wireguard/main/S50wireguard" -o "/jffs/scripts/S50wireguard" && chmod 755 "/jffs/scripts/S50wireguard"
