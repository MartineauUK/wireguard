# wireguard
Manage/Install WireGuard on applicable ASUS routers

see https://www.snbforums.com/threads/experimental-wireguard-for-rt-ac86u-gt-ac2900-rt-ax88u-rt-ax86u.46164/

## Installation ##

###NOTE: Entware is assumed to be installed###

Enable SSH on router, then use your preferred SSH Client e.g. Xshell6,MobaXterm, PuTTY etc.

(TIP: Triple-click the install command below) to copy'n'paste into your router's SSH session:
    
    curl --retry 3 "https://raw.githubusercontent.com/MartineauUK/wireguard/main/S50wireguard" -o "/jffs/scripts/S50wireguard" && chmod 755 "/jffs/scripts/S50wireguard" && /jffs/scripts/S50wireguard install
    
Example successful install.....

	Retrieving scripts 'wg_manager.sh/wg_server'

    <snip> 100.0%
    <snip> 100.0%

	Retrieving Wireguard Kernel module for RT-AC86U (v386.2)
    
    % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
    100   190  100   190    0     0    822      0 --:--:-- --:--:-- --:--:--   833
    100 57251  100 57251    0     0   166k      0 --:--:-- --:--:-- --:--:--  166k

	Retrieving WireGuard User space Tools for RT-AC86U (v386.2)
    
    % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed                            
    100   187  100   187    0     0    820      0 --:--:-- --:--:-- --:--:--   834
    100 46503  100 46503    0     0  98315      0 --:--:-- --:--:-- --:--:-- 98315

	Loading WireGuard Kernel module and Userspace Tools for RT-AC86U (v386.2)

    Installing wireguard-kernel (1.0.20210219-k27) to root...
    Configuring wireguard-kernel.

    Installing wireguard-tools (1.0.20210223-1) to root...
    Configuring wireguard-tools.

    wireguard: WireGuard 1.0.20210219 loaded. See www.wireguard.com for information.

	Creating WireGuard configuration file '/jffs/configs/WireguardVPN_map'

	Creating WireGuard 'Client' Peer and 'Server' templates 'wg11.conf' and wg21.conf'

	WireGuard install COMPLETED.

In lieu of the NVRAM variables that can retain OpenVPN Client/Server configurations across reboots, this script uses 

'/jffs/configs/WireguardVPN_map' for the WireGuard directives.

As this is a beta, the layout of the file includes placeholders, but currently, the first column is significant and is used as a primary lookup key and only the 'Auto' and 'Annotation Comment' fileds are extracted/used to determine the actions taken by the script.

e.g.

    wg13    P      xxx.xxx.xxx.xxx/32    103.231.88.18:51820    193.138.218.74    # Mullvad Oz, Melbourne

is used to auto-start Wireguard VPN 'client' Peer 3 ('wg13')' in Policy mode, where the associated Policy rules are defined as

    rp13    <Dummy VPN 3>172.16.1.3>>VPN<Plex>172.16.1.123>1.1.1.1>VPN<Router>172.16.1.1>>WAN<All LAN>172.16.1.0/24>>VPN

which happens to be in the same format as the Policy rules created by the GUI for OpenVPN clients i.e.

Use the GUI to generate the rules using a spare VPN Client and simply copy'n'paste the resulting NVRAM variable

    vpn_client?_clientlist etc.
    
The contents of the configuration file will be used when 'w13.conf' is activated - assuming that you have used say the appropriate WireGuard Web configurator such as Mullvads' to create the Local IP address and Public/Private key-pair for the remote Peer.
 e.g
 
    /jffs/scripts/S50wireguard start client 3
    
 The script supports several commands:
    
    S50wireguard   {start|stop|restart|check|install} [ [client [policy] |server]} [wg_instance] ]
    S50wireguard   start 0
                   Initialises remote peer 'client' 'wg0' solely to remain backwards compatibilty with original
    S50wireguard   start client 0
                   Initialises remote peer 'client' 'wg0'
    S50wireguard   start 1
                   Initialises local peer 'server' 'wg1' solely to remain backwards compatibilty with original
    S50wireguard   start server 1
                   Initialises local peer 'server' 'wg21' uses interface naming convention as per OpenVPN e.g. tun21
    S50wireguard   start client 1
                   Initialises remote peer 'client' 'wg11' uses interface naming convention as per OpenVPN e.g. tun11
    S50wireguard   start client 1 policy
                   Initialises remote peer 'client' 'wg11' in 'policy' Selective Routing mode
    S50wireguard   stop client 3
                   Terminates remote peer 'client' 'wg13'
    S50wireguard   stop 1
                   Terminates local peer 'server' 'wg21'
    S50wireguard   stop
                   Terminates ALL ACTIVE peers (wg1* and wg2*)
    S50wireguard   start
                   Initialises ALL peers (wg1* and wg2*) defined in the configuration file where Auto=Y or Auto=P
                 
and if the install is successful, there should now be simple aliases

e.g.

    wgstart
    wgstop
    wgr
    wgd
    
where the top two aliases allow quickly Starting/Stopping all of the Defined/Active WireGuard Peers, and the bottom two generate a report of active Peers (either with or without DEBUG iptables/RPDB rules)
 
NOTE: Currently, if you start say three WireGuard remote Peers concurrently and none of which are designated as Policy Peers, ALL traffic will be forced via the most recent connection, so if you then terminate that Peer, then the least oldest of the previous Peers will then have ALL traffic directed through it.
Very crude fall-over configuration but may be useful. 



    




    
    
     
