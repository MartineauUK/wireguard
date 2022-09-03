# WireGuard Manager
© Copyright 2021-2022 MartineaUK All Rights Reserved.

Manage/Install WireGuard®  on applicable ASUS routers

Based on https://www.snbforums.com/threads/experimental-wireguard-for-rt-ac86u-gt-ac2900-rt-ax88u-rt-ax86u.46164/

"WireGuard" and the "WireGuard" logo https://www.wireguard.com/ are registered trademarks of Jason A. Donenfeld. © Copyright 2015-2022 Jason A. Donenfeld. All Rights Reserved. 

## Installation ##

###NOTE: Entware is assumed to be installed###

Enable SSH on router, then use your preferred SSH Client e.g. Xshell6,MobaXterm, PuTTY etc.

(TIP: Triple-click the install command below) to copy'n'paste into your router's SSH session:
    
    curl --retry 3 "https://raw.githubusercontent.com/MartineauUK/wireguard/main/wg_manager.sh" --create-dirs -o "/jffs/addons/wireguard/wg_manager.sh" && chmod 755 "/jffs/addons/wireguard/wg_manager.sh" && /jffs/addons/wireguard/wg_manager.sh install
    
Example successful install.....

    +======================================================================+
    |  Welcome to the WireGuard Manager/Installer script (Asuswrt-Merlin)  |
    |                                                                      |
    |                      Version v4.17 by Martineau                      |
    |                                                                      |
    | Requirements: HND or AX router with Kernel 4.1.xx or later           |
    |                         e.g. RT-AC86U or RT-AX86U etc.               |
    |                                                                      |
    |               USB drive with Entware installed                       |
    |                                                                      |  
    | ******************************************************************** |
    ! ******************************************************************** !
    ! *   NOTE:  WireGuard® is incompatible with Hardware Acceleration   * !
    ! *          which is REQUIRED if your WAN ISP speed is > 350 Mbps   * !
    ! *                                                                  * !
    ! *          You can disable Hardware Acceleration using command     * !
    ! *                                                                  * !
    ! *                   E:Option ==> fc disable                        * !
    ! *                                                                  * !
    ! *          but you will LIMIT ALL WAN throughput (not just         * !
    ! *               WireGuard® clients) to about 350 Mbps              * !
    ! ******************************************************************** !

    | ******************************************************************** |
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

To prove the exception, RT-AX58U using @RMerlin Beta firmware (which includes the ASUS WireGuard Kernel/Userspace tools modules) although it's designated 'AX' it uses CPU ARMv7 ('arm') rather than 'aarch64'.....

    E:Option ==> 1

	Installing WireGuard Manager - Router RT-AX58U (v3.0.0.4.386.3_beta3) arch=arm

	Downloading scripts
	wg_client downloaded successfully 
	wg_server downloaded successfully 
	UDP_Updater.sh downloaded successfully 

    Installing column (2.37-1) to root...
    Downloading https://bin.entware.net/armv7sf-k3.2/column_2.37-1_armv7-3.2.ipk
    Configuring column.
    Installing coreutils-mkfifo (8.32-6) to root...
    Downloading https://bin.entware.net/armv7sf-k3.2/coreutils-mkfifo_8.32-6_armv7-3.2.ipk
    Configuring coreutils-mkfifo.

	Creating WireGuard configuration file '/jffs/addons/wireguard/WireguardVPN.conf'

	No Peer entries to auto-migrate from '/jffs/addons/wireguard/WireguardVPN.conf', but you will need to manually import the 'device' Peer '*.conf' files:



	[✔] WireGuard Peer SQL Database initialised OK

	Creating WireGuard 'Server' Peer (wg21)'
	Creating WireGuard Private/Public key-pairs for RT-AX58U (v3.0.0.4.386.3_beta3)
	Initialising WireGuard VPN 'server' Peer

	Requesting WireGuard VPN Peer start (wg21)

	wireguard-server1: Initialising Wireguard VPN 'Server' Peer (wg21) on 10.88.8.1:51820 (# RT-AX58U Server #1)
	wireguard-server1: Initialisation complete.

	[✔] Statistics gathering is ENABLED

	firewall-start updated to protect WireGuard firewall rules
	Restarting DNSmasq to add 'wg*' interfaces

    Done.

	Creating 'wg_manager' alias for 'wg_manager.sh'

	Event scripts

	Adding Peer Auto-start @BOOT
	Installing QR rendering module
    Installing qrencode (4.1.1-1) to root...
    Downloading https://bin.entware.net/armv7sf-k3.2/qrencode_4.1.1-1_armv7-3.2.ipk
    Configuring qrencode.
	Installing xargs module
    Package findutils (4.8.0-1) installed in root is up to date.
	Do you want to create a 'device' Peer for 'server' Peer (wg21) ?
	Press y to create 'device' Peer or press [Enter] to skip
    y
    Enter the device name e.g. iPhone
    iPhone

	Creating Wireguard Private/Public key pair for device 'iPhone'
	Device 'iPhone' Public key=K2RjDsyCvT1sJWhk5zHOGNer4Q+pt7Fcbf4mPiiyOm8=

	Device 'iPhone' Pre-shared key=K2RjDsyCvT1sJWhk5zHOGNer4Q+pt7Fcbf4mPiiyOm8=

	Using Public key for 'server' Peer 'wg21'

	Warning: No DDNS is configured!
	Press y to use the current WAN IP or enter DDNS name or press [Enter] to SKIP.


	WireGuard config for Peer device 'iPhone' (10.50.1.2/32) created (Allowed IP's 0.0.0.0/0 # ALL Traffic)

	Press y to Display QR Code for Scanning into WireGuard App on device 'iPhone' or press [Enter] to SKIP.

	Press y to ADD device 'iPhone' to 'server' Peer (wg21) or press [Enter] to SKIP.
    y

	Adding device Peer 'iPhone' 10.50.1.2/32 to RT-AX58U 'server' (wg21) and WireGuard config


	WireGuard 'server' Peer needs to be restarted to listen for 'client' Peer iPhone "Device"
	Press y to restart 'server' Peer (wg21) or press [Enter] to SKIP.
    y

	Requesting WireGuard VPN Peer restart (wg21)

	Restarting Wireguard 'server' Peer (wg21)
	wireguard-server1: Wireguard VPN '' Peer (wg21) on 10.88.8.1:51820 (# RT-AX58U Server #1) Terminated

	wireguard-server1: Initialising Wireguard VPN 'Server' Peer (wg21) on 10.88.8.1:51820 (# RT-AX58U Server #1)
	wireguard-server1: Initialisation complete.


	interface: wg21 	Port:51820	10.50.1.1/24 		VPN Tunnel Network	# RT-AX58U Server #1
		peer: K2RjDsyCvT1sJWhk5zHOGNer4Q+pt7Fcbf4mPiiyOm8= 	10.50.1.2/32		# iPhone "Device"	

	v4.12 WireGuard Session Manager install COMPLETED.


 	WireGuard ACTIVE Peer Status: Clients 0, Servers 1 

Display interactive WireGuard Manager menu

    wgm

    +======================================================================+
    |  Welcome to the WireGuard Manager/Installer script (Asuswrt-Merlin)  |
    |                                                                      |
    |                      Version v4.12 by Martineau                      |
    |                                                                      |
    +======================================================================+
    
	       WireGuard ACTIVE Peer Status: Clients 3, Servers 2

    =============================================================================================================================================================


    1  = Update WireGuard modules						7  = QRcode for a Peer {device} e.g. iPhone
    2  = Remove WireGuard/(wg_manager)					8  = Peer management [ "list" | "category" | "new" ] | [ {Peer | category} [ del | show | add [{"auto="[y|n|p]}] ]
									        9  = Create[split] Key-pair for Peer {Device} e.g. Nokia6310i (creates Nokia6310i.conf etc.)
    3  = List ACTIVE Peers Summary [Peer...] [full]				10 = IPSet management [ "list" ] | [ "upd" { ipset [ "fwmark" {fwmark} ] | [ "enable" {"y"|"n"}] | [ "dstsrc"] ] } ] 
    4  = Start   [ [Peer [nopolicy]...] | category ] e.g. start clients 	11 = Import WireGuard configuration { [ "?" | [ "dir" directory ] | [/path/]config_file [ "name="rename_as ] ]} 
    5  = Stop    [ [Peer... ] | category ] e.g. stop clients									
    6  = Restart [ [Peer... ] | category ] e.g. restart servers									

    ?  = About Configuration					
    v  = View ('/jffs/addons/wireguard/WireguardVPN.conf')		

    e  = Exit Script [?]

    E:Option ==> 
    
e.g.

    E:Option ==> 3

		 WireGuard VPN Peer Status

	interface: wg11 	('client' # Mullvad USA, New York)
		peer: ru9aQRxYBkK5pWvNkdFlCR8VMPSqcEENBPGkIGEN0XU=
		 transfer: 228.31 KiB received, 32.93 KiB sent
	interface: wg12 	('client' # Mullvad China, Hong Kong)
		peer: oS4vR1RHoFtpevzl2KLUjqDH9AiLwnh9GHBMiB5FVgM=
		 transfer: 204.65 KiB received, 24.38 KiB sent
	interface: wg13 	('client' # Mullvad Oz, Melbourne)
		peer: D2ltFd7TbpYNq9PejAeGwlaJ2bEFLqOSYywdY9N5xCY=
		 transfer: 189.15 KiB received, 15.96 KiB sent
	interface: wg21 	('server' # Martineau RT-AC86U Host Peer 1)
		peer: jCLceBJGCk1nKFHsMEAXbnxm5DvGkbM+EspGM84B/Ck= 	('server client' # Unidentified)
	interface: wg22 	('server' # Martineau RT-AC86U Host Peer 2)
		peer: EOv5VAl6eD8JaBQbL7vEu5kyKtQODrxuSK9GYNROThc= 	('server client' # Unidentified)

    e  = Exit Script [?]

    E:Option ==> ?

	Router RT-AX58U Firmware (v3.0.0.4.386.3_beta3)

	[✔] Entware Architecture arch=arm


	v4.12 WireGuard Session Manager (Change Log: https://github.com/MartineauUK/wireguard/commits/main/wg_manager.sh)
	MD5=e78a51b9ef616c1d062038e5adada441 /jffs/addons/wireguard/wg_manager.sh

	[✔] WireGuard Kernel module/User Space Tools included in Firmware (1.0.20210124)


	[✔] DNSmasq is listening on ALL WireGuard interfaces 'wg*'

	[✔] firewall-start is monitoring WireGuard Firewall rules

	[✖] WAN KILL-Switch is DISABLED (use 'vx' command for info)
	[✖] UDP monitor is DISABLED

	[ℹ ] Reverse Path Filtering ENABLED

	[✔] Statistics gathering is ENABLED

	[ℹ ] Speedtest quick link https://fast.com/en/gb/ 

	[ℹ ] @ZebMcKayhan's Hint's and Tips Guide https://github.com/ZebMcKayhan/WireguardManager/blob/main/README.md#table-of-content 


	WireGuard ACTIVE Peer Status: Clients 3, Servers 2




In lieu of the NVRAM variables that can retain OpenVPN Client/Server configurations across reboots, this script uses SQL database

'/opt/etc/wireguard.d/Wireguard.db' for the WireGuard configuration directives.


The contents of the WireGuard configuration database will be used when say 'wg13.conf' is activated - assuming that you have used say the appropriate WireGuard Web configurator such as Mullvad's to create the Local IP address and Public/Private key-pair for the remote Peer.
 e.g
 
    start wg13
    
 The script supports several commands:
    
    wgm   {start|stop|restart|check|install} [ [client [policy] |server]} [wg_instance] ]
    wgm   start 0
                   Initialises remote peer 'client' 'wg0' solely to remain backwards compatibilty with original
    wgm   start client 0
                   Initialises remote peer 'client' 'wg0'
    wgm   start 1
                   Initialises local peer 'server' 'wg1' solely to remain backwards compatibilty with original
    wgm   start server 1
                   Initialises local peer 'server' 'wg21' uses interface naming convention as per OpenVPN e.g. tun21
    wgm   start client 1
                   Initialises remote peer 'client' 'wg11' uses interface naming convention as per OpenVPN e.g. tun11
    wgm   start client 1 policy
                   Initialises remote peer 'client' 'wg11' in 'policy' Selective Routing mode
    wgm   stop client 3
                   Terminates remote peer 'client' 'wg13'
    wgm   stop 1
                   Terminates local peer 'server' 'wg21'
    wgm   stop
                   Terminates ALL ACTIVE peers (wg1* and wg2* etc.)
    wgm   start
                   Initialises ALL peers (wg1* and wg2* etc.) defined in the configuration file where Auto=Y or Auto=P
                 
and if the install is successful, there should now be a couple of simple aliases

e.g.

    wg_manager and wgm 
to start the script   (NOTE 'wg_manager' is available immediately, but 'wgm' will require you to logoff/login to refesh your terminal profile.) 

 
    The following (WireGuard Manager) is the alias to invoke the script 
  
e.g.

    wgm peer list   Lists the defined Peers in the config The sub-commands for peer allow manipulation of the Auto= value etc

An example of the enhanced WireGuard Peer Status report showing the names of the Peers rather than just their cryptic Public Keys

    wgm show

	interface: wg21 	(# Martineau Host Peer 1)
		 public key: j+aNKC0yA7+hFyH7cA9gIJ9+Ms05G3q4kYG/JkBwAU=
		 private key: (hidden)
		 listening port: 1151
		
		peer: wML+L6hN7D4wx+E1SA0K4/5x1cMjlpYzeTOPYww2WSM= 	(# Samsung Galaxy S8)
		 allowed ips: 10.50.1.88/32
		
		peer: LK5/fu1iX1puR7+I/njj6W88Cr6/tDZhuaKp3XKM/R4= 	(# Device iPhone12)
		 allowed ips: 10.50.1.90/32
 
NOTE: Currently, if you start say three WireGuard remote Peers concurrently and none of which are designated as Policy Peers, ALL traffic will be forced via the most recent connection, so if you then terminate that Peer, then the least oldest of the previous Peers will then have ALL traffic directed through it.
Very crude fall-over configuration but may be useful. 

For hosting a 'server' Peer (wg21) you can use the following command to generate a Road-Warrior Private/Public key-pair and auto add it to the 'wg21.conf' 

    wgm create Nokia6310i

	Creating Wireguard Private/Public key pair for device 'Nokia6310i'

	Device 'Nokia6310i' Public key=uAMVeM6DNsj9rEsz9rjDJ7WZEiJjEp98CDfDhSFL0W0=

	Press y to ADD device 'Nokia6310i' to 'server' Peer (wg21) or press [Enter] to SKIP.
    y
	Adding device Peer 'Nokia6310i' to RT-AC86U 'server' (wg21) and WireGuard config

and the resulting entry in the WireGuard 'server' Peer config 'wg21.conf' - where 10.50.1.125 is derived from the DHCP pool for the 'server' Peer

e.g. 

    	Peers (Auto=P - Policy, Auto=X - External i.e. Cell/Mobile)
    Server  Auto  Subnet        Port   Annotate
    wg21    Y     10.50.1.1/24  11501  # RT-AC86U Server 1


and the next avaiable IP with DHCP pool prefix '10.50.1' e.g. .125 is chosen as .124 is already assigned when the Peer is appended to 'wg21.conf'

    # Nokia6310i
    [Peer]
    PublicKey = uAMVeM6DNsj9rEsz9rjDJ7WZEiJjEp98CDfDhSFL0W0=
    AllowedIPs = 10.50.1.125/32
    # Nokia6310i End
  
and the cosmetic Annotation identification for the device '# Device Nokia6310i' is appended to the WireGuard Peer configuration  


To import the device Nokia6310i into the WireGuard App on the mobile device or tablet, rather than manually enter the details, or import the text file using a secure means of transfer, it is easier to simply display the QR Code containing the configuration and point the phone's/tablet's camera at the QR Code! ;-)

     wgm qrcode Nokia6310i

