# wireguard
Manage/Install WireGuard on applicable ASUS routers

see https://www.snbforums.com/threads/experimental-wireguard-for-rt-ac86u-gt-ac2900-rt-ax88u-rt-ax86u.46164/

## Installation ##

###NOTE: Entware is assumed to be installed###

Enable SSH on router, then use your preferred SSH Client e.g. Xshell6,MobaXterm, PuTTY etc.

(TIP: Triple-click the install command below) to copy'n'paste into your router's SSH session:
    
    mkdir -p /jffs/addons 2>/dev/null;mkdir -p /jffs/addons/wireguard 2>/dev/null;curl --retry 3 "https://raw.githubusercontent.com/MartineauUK/wireguard/main/wg_manager.sh" -o "/jffs/addons/wireguard/wg_manager.sh" && chmod 755 "/jffs/addons/wireguard/wg_manager.sh" && /jffs/addons/wireguard/wg_manager.sh install
    
Example successful install.....

    +======================================================================+
    |  Welcome to the WireGuard Manager/Installer script (Asuswrt-Merlin)  |
    |                                                                      |
    |                      Version v2.01b8 by Martineau                    |
    |                                                                      |
    | Requirements: USB drive with Entware installed                       |
    |                                                                      |
    |   1 = Install WireGuard                                              |
    |       o1. Enable nat-start protection for Firewall rules             |
    |       o2. Enable DNS                                                 |
    |                                                                      |
    |                                                                      |
    +======================================================================+

	    WireGuard ACTIVE Peer Status: Clients 0, Servers 0

	    v2.01b8 - No WireGuard Manager updates available - you have the latest version

    1  = Begin WireGuard Installation Process						

    e  = Exit Script [?]

    E:Option ==> 1

	Installing WireGuard Manager - Router RT-AC86U (v386.1)
	Downloading scripts
	wg_client downloaded successfully 
	wg_server downloaded successfully 

	Downloading Wireguard Kernel module for RT-AC86U (v386.1)

	Downloading WireGuard Kernel module 'wireguard-kernel_1.0.20210219-k27_aarch64-3.10.ipk' for RT-AC86U (v386.1)...

    ##################################################################################################################################################################################### 100.0%##################################################################################################################################################################################### 100.0%

	Downloading WireGuard User space Tool 'wireguard-tools_1.0.20210223-1_aarch64-3.10.ipk' for RT-AC86U (v386.1)

     ##################################################################################################################################################################################### 100.0%##################################################################################################################################################################################### 100.0%

	Loading WireGuard Kernel module and Userspace Tool for RT-AC86U (v386.1)
    Installing wireguard-kernel (1.0.20210219-k27) to root...
    Configuring wireguard-kernel.

    Installing wireguard-tools (1.0.20210223-1) to root...
    Configuring wireguard-tools.
	wireguard: WireGuard 1.0.20210219 loaded. See www.wireguard.com for information.
	wireguard: Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.


	Creating WireGuard configuration file '/jffs/addons/wireguard/WireguardVPN.conf'
	Creating WireGuard 'Client' and 'Server' Peer templates 'wg11.conf' and wg21.conf'
	Creating WireGuard Private/Public key-pairs for RT-AC86U (v386.1)
	Test Initialising the Sample WireGuard 'client' and 'server' Peers, BUT ONLY the Sample 'server' (wg21) will Initialise WITHOUT errors!!!! :-)

    (wg_manager.sh): 26628 v2.01b8 Requesting WireGuard VPN Peer auto-start (wg11 wg21 )


	wireguard-client1: Initialising Wireguard VPN 'client' Peer (wg11) to 86.106.143.93:51820 (# ****THIS IS NOT A REAL PEER** Edit 'wg11.conf' with real DATA!)
	wireguard-client1: Initialisation complete.

	wireguard-server1: Initialising Wireguard VPN 'Server' Peer (wg21) on 0.0.0.0:51820 (# RT-AC86U Local Host Peer 1)
	wireguard-server1: Initialisation complete.



	WireGuard Peer Status
	interface: wg11 	('client' # ****THIS IS NOT A REAL PEER** Edit 'wg11.conf' with real DATA!)
		 listening port: 34465
		
	interface: wg21 	('server' # RT-AC86U Local Host Peer 1)
		 public key: RPLF0ksVHyLvffhzNG7agfvaAbN3L3QIl08qkZ3pH0U=
		 private key: (hidden)
		 listening port: 51820


	Terminating ACTIVE WireGuard Peers ...
	Requesting termination of Active WireGuard VPN Peers (wg11 wg21)


    (wg_manager.sh): 27073 v2.01b8 Requesting termination of WireGuard VPN 'client' Peer ('wg11')
	wireguard-client1: Wireguard VPN 'client' Peer (wg11) to 86.106.143.93:51820 (# ****THIS IS NOT A REAL PEER** Edit 'wg11.conf' with real DATA!) DELETED

    (wg_manager.sh): 27073 v2.01b8 Requesting termination of WireGuard VPN 'server' Peer ('wg21')
	wireguard-server1: Wireguard VPN '' Peer (wg21) on 0.0.0.0:51820 (# RT-AC86U Local Host Peer 1) DELETED



	nat-start updated to protect WireGuard firewall rules
	Added 'wg*' interfaces to DNSMasq

    Done.
	Creating 'wg_manager' alias for 'wg_manager.sh'
	Adding Peer Auto-start @BOOT
	Installing QR rendering module
    Package qrencode (4.1.1-1) installed in root is up to date.
	Press y to Display QR Code for Scanning into WireGuard App on device '' or press [Enter] to SKIP.
    y

***QR code image goes here***

	WireGuard install COMPLETED.


	WireGuard ACTIVE Peer Status: Clients 0, Servers 0



WireGuard Manager v2.0 now uses a menu (amtm compatible)

    wgm

    +======================================================================+
    |  Welcome to the WireGuard Manager/Installer script (Asuswrt-Merlin)  |
    |                                                                      |
    |                      Version v2.01b9 by Martineau                    |
    |                                                                      |
    +======================================================================+
	       WireGuard ACTIVE Peer Status: Clients 3, Servers 2

    =============================================================================================================================================================

    1  = Update Wireguard modules						7  = Display QR code for a Peer {device} e.g. iPhone
    2  = Remove WireGuard/wg_manager					8  = Peer management [ {Peer} [ add | del | {auto [y|n|p]}] ] ]
  	    								        9  = Create Key-pair for Peer {Device} e.g. Nokia6310i (creates Nokia6310i.conf etc.)
    3  = List ACTIVE WireGuard Peers [3x - lists ALL details]									
    4  = Start   WireGuard Peer [Peer]									
    5  = Stop    WireGuard Peer [Peer]									
    6  = Restart WireGuard Peer [Peer]									

    ?  = About Configuration					
    v  = View ('/jffs/addons/wireguard/WireguardVPN.conf')		

    e  = Exit Script [?]


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

	No updates available - you have the latest version
	Checking for WireGuard Kernel and Userspace Tool updates...
	wireguard: WireGuard 1.0.20210219 loaded. See www.wireguard.com for information.
	wireguard: Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

	[✔] WireGuard Module is LOADED

	MD5=07a24a0efa926b3ad2c564d18b12312f wireguard-kernel_1.0.20210219-k27_aarch64-3.10.ipk
	MD5=d7fdc2f1a770856a66c2c677ecb64d1b wireguard-tools_1.0.20210223-1_aarch64-3.10.ipk

	WireGuard Kernel and Userspace Tool up to date.



	WireGuard ACTIVE Peer Status: Clients 3, Servers 2




In lieu of the NVRAM variables that can retain OpenVPN Client/Server configurations across reboots, this script uses 

'/jffs/addons/wireguard/WireguardVPN.conf' for the WireGuard directives.

As this is a beta, the layout of the file includes placeholders, but currently, the first andsecond column are significant and are used as a primary lookup key e.g the 'Auto' and 'Annotation Comment' fields are extracted/used to determine the actions taken by the script.

e.g.

    wg13    P      xxx.xxx.xxx.xxx/32    103.231.88.18:51820    193.138.218.74    # Mullvad Oz, Melbourne

is used to auto-start WireGuard VPN 'client' Peer 3 ('wg13')' in Policy mode, where the associated Policy rules are defined as

    rp13    <Dummy VPN 3>172.16.1.3>>VPN<Plex>172.16.1.123>1.1.1.1>VPN<Router>172.16.1.1>>WAN<All LAN>172.16.1.0/24>>VPN

which happens to be in the same format as the Policy rules created by the GUI for OpenVPN clients i.e.

Use the GUI to generate the rules using a spare VPN Client and simply copy'n'paste the resulting NVRAM variable

    vpn_client?_clientlist etc.
    
The contents of the WireGuard configuration file will be used when 'wg13.conf' is activated - assuming that you have used say the appropriate WireGuard Web configurator such as Mullvads' to create the Local IP address and Public/Private key-pair for the remote Peer.
 e.g
 
    S50wireguard start client 3
    
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
                   Terminates ALL ACTIVE peers (wg1* and wg2* etc.)
    S50wireguard   start
                   Initialises ALL peers (wg1* and wg2* etc.) defined in the configuration file where Auto=Y or Auto=P
                 
and if the install is successful, there should now be a couple of simple aliases

e.g.

    wg_manager and wgm 
to start the script   (NOTE 'wg_manager' is available immediately, but 'wgm' will require you to logoff/login to refesh your terminal profile.) 

 
    The following (WireGuard Manager) is the alias to invoke the script 
  
e.g.

    wgm peer list   Lists the defined Peers in the config The sub-commands for peer allow manipulation of the Auto= value etc

An example of the enhanced WireGuard Peer Status report showing the names of the Peers rather than just their cryptic Public Keys

    wgshow

    (S50wireguard): 15024 v1.01b4 WireGuard VPN Peer Status check.....

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

For hosting a 'server' Peer (wg21) you can use the following command to generate a Private/Public key-pair and auto add it to the 'wg21.conf' and to the WireGuard config '/jffs/addons/wireguard/WireGuardVPN,conf'

    wgm create Nokia6310i

	Creating Wireguard Private/Public key pair for device 'Nokia6310i'

	Device 'Nokia6310i' Public key=uAMVeM6DNsj9rEsz9rjDJ7WZEiJjEp98CDfDhSFL0W0=

	Press y to ADD device 'Nokia6310i' to 'server' Peer (wg21) or press [Enter] to SKIP.
    y
	Adding device Peer 'Nokia6310i' to RT-AC86U 'server' (wg21) and WireGuard config

and the resulting entry in the WireGuard 'server' Peer config 'wg21.conf' - where 10.50.1.125 is derived from the DHCP pool for the 'server' Peer

e.g. WireGuard configuration 'WireguardVPN_map' contains

    wg21    Y      10.50.1.1/24                                                 # Martineau Host Peer 1

and the next avaiable IP with DHCP pool prefix '10.50.1' e.g. .125 is chosen as .124 is already assigned when the Peer is appended to 'wg21.conf'

    # Nokia6310i
    [Peer]
    PublicKey = uAMVeM6DNsj9rEsz9rjDJ7WZEiJjEp98CDfDhSFL0W0=
    AllowedIPs = 10.50.1.125/32
    # Nokia6310i End
  
and the cosmetic Annotation identification for the device '# Device Nokia6310i' is appended to the WireGuard configuration 'WireguardVPN_map'  

    # Optionally define the 'server' Peer 'clients' so they can be identified by name in the enhanced WireGuard Peer status report
    # Public Key                                      DHCP IP             Annotation Comment
    <snip>
    xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=      10.50.1.124         # A Cell phone
    snip>
    
    uAMVeM6DNsj9rEsz9rjDJ7WZEiJjEp98CDfDhSFL0W0=      10.50.1.125         # Device Nokia6310i

To import the device Nokia6310i into the WireGuard App on the mobile device or tablet, rather than manually enter the details, or import the text file using a secure means of transfer, it is easier to simply display the QR Code containing the configuration and point the phone's/tablet's camera at the QR Code! ;-)

     wgr qrcode Nokia6310i



    
    
     
