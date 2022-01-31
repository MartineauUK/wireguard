# WireGuard Manager
© Copyright 2021-2022 MartineaUK All Rights Reserved.

Manage/Install WireGuard®  on applicable ASUS routers

Based on https://www.snbforums.com/threads/experimental-wireguard-for-rt-ac86u-gt-ac2900-rt-ax88u-rt-ax86u.46164/

"WireGuard" and the "WireGuard" logo https://www.wireguard.com/ are registered trademarks of Jason A. Donenfeld. © Copyright 2015-2022 Jason A. Donenfeld. All Rights Reserved. 

## Installation ##

###NOTE: Entware is assumed to be installed###

Enable SSH on router, then use your preferred SSH Client e.g. Xshell6,MobaXterm, PuTTY etc.

(TIP: Triple-click the install command below) to copy'n'paste into your router's SSH session:
    
    curl --retry 3 "https://raw.githubusercontent.com/MartineauUK/wireguard/dev/wg_manager.sh" --create-dirs -o "/jffs/addons/wireguard/wg_manager.sh" && chmod 755 "/jffs/addons/wireguard/wg_manager.sh" && /jffs/addons/wireguard/wg_manager.sh install
    
Example successful install.....

    +======================================================================+
    |  Welcome to the WireGuard Manager/Installer script (Asuswrt-Merlin)  |
    |                                                                      |
    |                      Version v4.14 by Martineau                      |
    |                                                                      |
    | Requirements: HND or AX router with Kernel 4.1.xx or later           |
    |                         e.g. RT-AC86U or RT-AX86U etc.               |
    |                                                                      |
    |               USB drive with Entware installed                       |
    |                                                                      |
    |   1 = Install WireGuard                                              |
    |       o1. Enable firewall-start protection for Firewall rules        |
    |       o2. Enable DNS                                                 |
    |                                                                      |
    |                                                                      |
    +======================================================================+

	    WireGuard ACTIVE Peer Status: Clients 0, Servers 0

    1  = Begin WireGuard Installation Process						

    e  = Exit Script [?]

	Downloading scripts
	wg_client downloaded successfully 
	wg_server downloaded successfully 
	UDP_Updater.sh downloaded successfully 

    Package column (2.36.1-2) installed in root is up to date.
    Package coreutils-mkfifo (8.32-6) installed in root is up to date.
	Downloading Wireguard Kernel module for RT-AC86U (v386.2)

	Downloading WireGuard Kernel module 'wireguard-kernel_1.0.20210219-k27_aarch64-3.10.ipk' for RT-AC86U (v386.2)...

      ##################################################################################################################################################################################### 100.0%##################################################################################################################################################################################### 100.0%

	Downloading WireGuard User space Tool 'wireguard-tools_1.0.20210223-1_aarch64-3.10.ipk' for RT-AC86U (v386.2)

    ##################################################################################################################################################################################### 100.0%##################################################################################################################################################################################### 100.0%

	Loading WireGuard Kernel module and Userspace Tool for RT-AC86U (v386.2)
    Package wireguard-kernel (1.0.20210219-k27) installed in root is up to date.
    Package wireguard-tools (1.0.20210223-1) installed in root is up to date.
	wireguard: WireGuard 1.0.20210219 loaded. See www.wireguard.com for information.
	wireguard: Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.


	Creating WireGuard configuration file '/jffs/addons/wireguard/WireguardVPN.conf'

	No Peer entries to auto-migrate from '/jffs/addons/wireguard/WireguardVPN.conf', but you will need to manually import the 'device' Peer '*.conf' files:



	[✔] WireGuard Peer SQL Database initialised OK

	Creating WireGuard 'Server' Peer (wg21)'
	Creating WireGuard Private/Public key-pairs for RT-AC86U (v386.2)
	Initialising WireGuard VPN 'server' Peer

	Requesting WireGuard VPN Peer start (wg21)

	wireguard-server1: Initialising Wireguard VPN 'Server' Peer (wg21) on 10.88.8.1:51820 (# RT-AC86U Server #1)
	wireguard-server1: Initialisation complete.

	[✔] Statistics gathering is ENABLED

	nat-start updated to protect WireGuard firewall rules
	Restarting DNSmasq to add 'wg*' interfaces

    Done.

	Creating 'wg_manager' alias for 'wg_manager.sh'

	Event scripts

	Adding Peer Auto-start @BOOT
	Installing QR rendering module
    Package qrencode (4.1.1-1) installed in root is up to date.
	Do you want to create a 'device' Peer for 'server' Peer (wg21) ?
	Press y to create 'device' Peer or press [Enter] to skip
    y
    Enter the device name e.g. iPhone
    iPhone

	Creating Wireguard Private/Public key pair for device 'iPhone'
	Device 'iPhone' Public key=zHI1BIxOsF9nKwfsPGoGPFa9ffMt83jRWz+ipPexWjM=

	Using Public key for 'server' Peer 'wg21'


	WireGuard config for Peer device 'iPhone' created (Allowed IP's 0.0.0.0/0 # ALL Traffic)

	Press y to Display QR Code for Scanning into WireGuard App on device 'iPhone' or press [Enter] to SKIP.
    y
	Press y to ADD device 'iPhone' to 'server' Peer (wg21) or press [Enter] to SKIP.
    y

	Adding device Peer 'iPhone' 10.50.1.2/32 to RT-AC86U 'server' (wg21) and WireGuard config


	WireGuard 'server' Peer needs to be restarted to listen for 'client' Peer iPhone "Device"
	Press y to restart 'server' Peer (wg21) or press [Enter] to SKIP.
    y

	Requesting WireGuard VPN Peer restart (wg21)

	Restarting Wireguard 'server' Peer (wg21)
	wireguard-server1: Wireguard VPN '' Peer (wg21) on 10.88.8.1:51820 (# RT-AC86U Server #1) Terminated

	wireguard-server1: Initialising Wireguard VPN 'Server' Peer (wg21) on 10.88.8.1:51820 (# RT-AC86U Server #1)
	wireguard-server1: Initialisation complete.


	interface: wg21 	Port:51820	10.50.1.1/24 		VPN Tunnel Network	# RT-AC86U Server #1
		peer: zHI1BIxOsF9nKwfsPGoGPFa9ffMt83jRWz+ipPexWjM= 	10.50.1.2/32		# iPhone "Device"	

	v4.08 WireGuard Session Manager install COMPLETED.


 	WireGuard ACTIVE Peer Status: Clients 0, Servers 1


In lieu of the NVRAM variables that can retain OpenVPN Client/Server configurations across reboots, this script mainly uses SQL tables for the Peer configuration, but the .conf files are modified to reflect the SQL table contents. (NOTE: Peer configs provided by the WireGuard ISP may be imported into the SQL database.)

Peers defined as Policy mode 'client' peers, have their associated Policy rules defined using the 'peer' command

see peer help command for examples

    e  = Exit Script [?]

E:Option ==> peer help

    peer help                                                           - This text
    peer                                                                - Show ALL Peers in database
    peer peer_name                                                      - Show Peer in database or for details e.g peer wg21 config
    peer peer_name {cmd {options} }                                     - Action the command against the Peer
    peer peer_name del                                                  - Delete the Peer from the database and all of its files *.conf, *.key
    peer peer_name ip=xxx.xxx.xxx.xxx                                   - Change the Peer VPN Pool IP
    peer category                                                       - Show Peer categories in database
    peer peer_name category [category_name {del | add peer_name[...]} ] - Create a new category with 3 Peers e.g. peer category GroupA add wg17 wg99 wg11
    peer new [peer_name [options]]                                      - Create new server Peer e.g. peer new wg27 ip=10.50.99.1/24 port=12345
    peer peer_name [del|add] ipset {ipset_name[...]}                    - Selectively Route IPSets e.g. peer wg13 add ipset NetFlix Hulu
    peer peer_name {rule [del {id_num} |add [wan] rule_def]}            - Manage Policy rules e.g. peer wg13 rule add 172.16.1.0/24 comment All LAN
                                                                                                   peer wg13 rule add wan 52.97.133.162 comment smtp.office365.com
                                                                                                   peer wg13 rule add wan 172.16.1.100 9.9.9.9 comment Quad9 DNS


The contents of the WireGuard configuration file will be used when 'wg13.conf' is activated - assuming that you have used say the appropriate WireGuard Web configurator such as Mullvads' to create the Local IP address and Public/Private key-pair for the remote Peer.
 e.g
 
    wgm start client 3
    
 The script supports several commands:
    
    wgm   {start|stop|restart|check|install} [ [client [policy] |server]} [wg_instance] ]
    wgm   start 0
                   Initialises remote peer 'client' 'wg0' solely to remain backwards compatibilty with original
    wgm   start client 0
                   Initialises remote peer 'client' 'wg0'
    wgm  start 1
                   Initialises local peer 'server' 'wg1' solely to remain backwards compatibilty with original
    wgm  start server 1
                   Initialises local peer 'server' 'wg21' uses interface naming convention as per OpenVPN e.g. tun21
    wgm  start client 1
                   Initialises remote peer 'client' 'wg11' uses interface naming convention as per OpenVPN e.g. tun11
    wgm  start client 1 policy
                   Initialises remote peer 'client' 'wg11' in 'policy' Selective Routing mode
    wgm  stop client 3
                   Terminates remote peer 'client' 'wg13'
    wgm   stop 1
                   Terminates local peer 'server' 'wg21'
    wgm   stop
                   Terminates ALL ACTIVE peers (wg1* and wg2*)
    wgm   start
                   Initialises ALL peers (wg1* and wg2*) defined in the configuration file where Auto=Y or Auto=P
                 
and if the install is successful, there should now be a simple alias

e.g.

    wgm

An example of the enhanced WireGuard Peer Status report showing the names of the Peers rather than just their cryptic Public Keys

    wgm status

    (wg_manager.sh): 15024 v1.01b4 WireGuard VPN Peer Status check.....

	interface: wg21 	(# Martineau Host Peer 1)
		 public key: j+aNKC0yA7+hFyH7cA9gISJ9+Ms05G3q4kYG/JkBwAU=
		 private key: (hidden)
		 listening port: 1151
		
		peer: wML+L6hN7D4wx+E1SA0K4/5x1cMjlpYzeTOPYww2WSM= 	(# Samsung Galaxy S8)
		 allowed ips: 10.50.1.88/32
		
		peer: LK5/fu1iX1puR7+I/njj6W88Cr6/tDZhuaKp3XKM/R4= 	(# Device iPhone12)
		 allowed ips: 10.50.1.90/32
 
NOTE: Currently, if you start say three WireGuard remote Peers concurrently and none of which are designated as Policy Peers, ALL traffic will be forced via the most recent connection, so if you then terminate that Peer, then the least oldest of the previous Peers will then have ALL traffic directed through it.
Very crude fall-over configuration but may be useful. 

For hosting a 'server' Peer (wg21) you can use the following command to generate a Private/Public key-pair and auto add it to the 'wg21.conf' and to the WireGuard config '/jffs/configs/WireGuardVPN_map'

    wg_manager.sh genkeys GoldstrikeriPhone3GSSupreme24K

	Creating Wirewg_manager.shguard Private/Public key pair for device 'GoldstrikeriPhone3GSSupreme24K'

	Device 'GoldstrikeriPhone3GSSupreme24K' Public key=uAMVeM6DNsj9rEsz9rjDJ7WZEiJjEp98CDfDhSFL0W0=

	Press y to ADD device 'GoldstrikeriPhone3GSSupreme24K' to 'server' Peer (wg21) or press [Enter] to SKIP.
    y
	Adding device Peer 'GoldstrikeriPhone3GSSupreme24K' to RT-AC86U 'server' (wg21) and WireGuard config
and the resulting entry in the WireGuard 'server' Peer config 'wg21.conf' - where 10.50.1.125 is derived from the DHCP pool for the 'server' Peer

and the next avaiable IP with DHCP pool prefix '10.60.1' .125 is chosen if .124 is aleady assigned when the Peer is appended to 'wg21.conf'

    #GoldstrikeriPhone3GSSupreme24K
    [Peer]
    PublicKey = uAMVeM6DNsj9rEsz9rjDJ7WZEiJjEp98CDfDhSFL0W0=
    AllowedIPs = 10.50.1.125/32
  
and the cosmetic Annotation identification for the device '# Device GoldstrikeriPhone3GSSupreme24K' is added to the SQL database
    




    
    
     
