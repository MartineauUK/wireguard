
<body style="background-color:lightgrey;">
<h1>WireGuard&#174; Manager&#169;</h1>

<hr>
<hr>
<h2>***WireGuard&#174; is currently incompatible with the H/W Acceleration/Flow Cache on ASUS Routers, therefore WAN speeds above 500Mbs cannot be exploited***</h2>
<hr>
<hr>
<h2>History</h2>

<p>Jason Donenfeld's WireGuard&#174; Kernel module and Userspace Tools see <a href="https://www.wireguard.com/">Wireguard Home</a> was compiled by SNB Forums member <strong>@odkrys</strong> back in 2018 to run on two ASUS HND routers (<strong>RT-AC86U/RT-AX88U</strong>) running Kernel <strong>v4.1.xx</strong> , and generously shared the modules with the ASUS router community; see <a href="https://www.snbforums.com/threads/experimental-wireguard-for-hnd-platform-4-1-x-kernels.46164/">Original thread</a></p>
<p>WireGuard&#174; Manager&#169; <strong>v1.01b4</strong> was conceived/written by SNB Forums member <strong>@Martineau</strong> in Early Feb. 2021 (see <a href="https://www.snbforums.com/threads/experimental-wireguard-for-hnd-platform-4-1-x-kernels.46164/post-668252">Release post</a>) to automate the install of <strong>@odkrys'</strong> manual instructions, and later redesigned and enhanced the concept by no longer requiring to run WireGuard&#174; as an Entware-style service (S60Wireguardwith manual editing by the user.
<br>
<p>In Nov. 2021, ASUS released two Public Betas <strong>(ASUSWRT 386 RC3-2/3)</strong> firmwares see <a href="https://www.snbforums.com/threads/asuswrt-386-rc3-3-public-beta-for-ipv6-ddns-and-ipv6-vpn-server.75829/">ASUS Public Beta RC3-2/3</a> that contain the WireGuard&#174; Kernel module, and provided (via their consolidated re-vamped VPN WebUI) the ability to run a single WireGuard 'server' Peer (<strong>wgs</strong>) and up to 5 'client' Peers (<strong>wgc1</strong> thru' <strong>wgc5</strong>) concurrently with OpenVPN etc. see <a href="https://www.snbforums.com/threads/session-manager-discussion-2nd-thread.75129/post-722830">@Martineau's brief review</a>
whilst WireGuard&#174; Manager&#169; allows for 5 'server' Peers (<strong>wg21</strong> thru' <strong>wg25</strong>) and up to 9 'client' Peers (<strong>wg11</strong> thru' <strong>wg19</strong>)
<p>MIPS routers such as the venerable <strong>RT-AC68U</strong> are based on Kernel <strong>v2.6.xx</strong> therefore unfortunately lack Kernel support for the WireGuard&#174; modules, however @RMerlin firmware <strong>v386.4+</strong> (Jan 2022) now includes the necessary Kernel/Userspace Tools (<strong>v1.0.20210124</strong>) in a larger number of ASUS supported routers such as <strong>RT-AX58U/GT-AXE11000</strong> etc.</p>
<p>SNB Forums member <strong>@ZebMcKayhan</strong> has now taken on the task to compile new WireGuard&#174; Kernel modules/Userspace Tools for certain HND router models to keep in line with <a href="https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/log/">WireGuard&#174; GitHub Patches/Release</a> from Jason, and these updated modules may optionally be used by WireGuard&#174; Manager&#169; to override <strong>@RMerlin's</strong> included firmware modules. see <a href="https://github.com/ZebMcKayhan/Wireguard">@ZebMcKayhan's Kernel Modules</a></p>
<p><strong>NOTE: As of July 2022 the Nov 2021 ASUSWRT 386 RC3-3 Public Beta has not been updated by ASUS.</strong></p>

<h2>User commands</h2>

<h3>Main menu options</h2>
<hr>

<pre><code>
    1  = Update WireGuard&#174 modules                                          7  = QRcode display for a Peer {device} e.g. iPhone
    2  = Remove WireGuard&#174/(wg_manager)                                     8  = Peer management [ "help" | "list" | "new" ] | [ {Peer | category} [ del | show | add [{"auto="[y|n|p]}] ]
                                                                            9  = Create[split] Road-Warrior device Peer for server Peer {device [server]} e.g. create myPhone wg21
    3  = List ACTIVE Peers Summary [Peer...] [full]                         10 = IPSet management [ "upd" { ipset [ "fwmark" {fwmark} ] | [ "enable" {"y"|"n"}] | [ "dstsrc"] {src} ] }]
    4  = Start   [ [Peer [nopolicy]...] | category ] e.g. start clients     11 = Import WireGuard® configuration { [ "?" | [ "dir" directory ] | [/path/]config_file [ "name="rename_as ] ]}
    5  = Stop    [ [Peer... ] | category ] e.g. stop clients                12 = vpndirector Clone VPN Director rules [ "clone" [ "wan" | "ovpn"n [ changeto_wg1n ]] | "delete" | "list" ]
    6  = Restart [ [Peer... ] | category ] e.g. restart servers

    ?  = About Configuration
    v  = View [ Peer[.conf] (default WireguardVPN.conf) (vx - Edit)

    e  = Exit Script [?]

    E:Option ==>
</pre></code>

<h3>Recommended Reading</h3><a href="https://github.com/ZebMcKayhan/WireguardManager/blob/main/README.md#table-of-content">@ZebMcKayhan's Hint's and Tips Guide</a>

<blockquote>
<p>There's already a wealth of information on @ZebMcKayhan's blog, so it isn't necessary to rewrite or include in full here.</p>
<p>WireGuard&#174; Manager&#169; was designed as a command line menu driven utility, and to create WebUI buttons/option for every command line invocation isn't feasible, but all features except the QRCode display of Road-Warrior 'device' Peers is cuurently available via the WebUI CMD dialog box</p>
</blockquote>
<blockquote>
<p>Useful features such as being able to import a desired profile from a vendor such as Mullvad via the WebUI (ASUS rc-3 Beta requires you to manually clone/input the vendor provided WireGuard&#174 .conf directives) plus the ability to manage the state of the WireGuard&#174 interfaces by the default categories (ALL. clients or servers) is available, together with useful diagnostic/Info Buttons etc.</p>
<p>Peers are configured via the 'peer' command </p>
<h4>Peer help</h4>

<pre><code>
e  = Exit Script [?]

E:Option ==> peer help

    peer help                                                               - This text
    peer                                                                    - Show ALL Peers in database
    peer peer_name                                                          - Show Peer in database or for details e.g peer wg21 config
    peer peer_name {cmd {options} }                                         - Action the command against the Peer
    peer peer_name del                                                      - Delete the Peer from the database and all of its files *.conf, *.key
    peer peer_name ip=xxx.xxx.xxx.xxx                                       - Change the Peer VPN Pool IP
    peer category                                                           - Show Peer categories in database
    peer peer_name category [category_name {del | add peer_name[...]} ]     - Create a new category with 3 Peers e.g. peer category GroupA add wg17 wg99 wg11
    peer new [peer_name [options]]                                          - Create new server Peer             e.g. peer new wg27 ip=10.50.99.1/24 port=12345
    peer new [peer_name] {ipv6}                                             - Create new Dual-stack server Peer with 'aa' prefix e.g. peer new ipv6
    peer new [peer_name] {ipv6}                                             - Create new Dual-stack server Peer with 'fd' prefix e.g. peer new ipv6 ula
    peer new [peer_name] {ipv6 noipv4 [ula[4]]}                             - Create new IPv6 Only server Peer   e.g. peer new ipv6 noipv4
    peer new [peer_name] {ipv6 noipv4}                                      - Create new IPv6 Only server Peer   e.g. peer new ipv6 noipv4 ipv6=aaff:a37f:fa75:100:100::1/120
    peer import peer_conf [options]                                         - Import '.conf' into SQL database e.g. import Mullvad_Dallas
                                                                                                                    import SiteA type=server
    peer peer_name [del|add|upd] ipset {ipset_name[...]}                    - Selectively Route IPSets e.g. peer wg13 add ipset NetFlix Hulu
                                                                                                            peer wg12 upd ipset MACs dstsrc src
                                                                                                            peer wg12 upd ipset all enable n
    peer peer_name [add] subnet {IPSubnet[...]}                             - Configure downstream subnets e.g. peer wg13 add subnet 192.168.5.0/24
    peer peer_name {rule [del [all|id_num]|add [wan] rule_def]}             - Manage Policy rules e.g. peer wg13 rule add 172.16.1.0/24 comment All LAN
                                                                                                       peer wg13 rule add wan 52.97.133.162 comment smtp.office365.com
                                                                                                       peer wg13 rule add wan 172.16.1.100 9.9.9.9 comment Quad9 DNS
                                                                                                       peer wg17 rule del 10
                                                                                                       peer wg17 rule del all
    peer serv_peer_name {passthru client_peer {[add|del] [device|IP/CIDR]}} - Manage Passthu rules; 'server' peer devices/IPs/CIDR outbound via 'client' peer
                                                                                     peer wg21 passthru add wg11 SGS8
                                                                                     peer wg21 passthru add wg15 all
                                                                                     peer wg21 passthru add wg12 10.100.100.0/27
                                                                                     peer wg21 passthru del wg15 all
                                                                                     peer wg21 passthru del SGS8
                                                                                     peer wg21 passthru del all
    peer serv_peer_name {bind device_peer}                                  - Bind a Road Warrior 'device' Peer to a 'server' Peer e.g. peer wg21 bind SGS20

    Visit @ZebMcKayhan's Hint's and Tips Guide https://github.com/ZebMcKayhan/WireguardManager/blob/main/README.md#table-of-content

</pre></code>
</blockquote>

<hr>
<h2>Acknowledgements</h2>
<p>Many thanks to SNB Forum members for supporting this project with bug reports etc. Apologies to any valued contributors I have inadvertantly missed!<br><br><em>Torson,<strong>ZebMcKayhan</strong>,jobhax,elorimer,Sh0cker54,here1310,defung,The Chief,abir1909,JGrana,heysoundude,archiel,Cam,endiz,Meshkoff,johndoe85,Juched</em> and of course <strong>@odkrys</strong> for his <em>'experimental'</em> initial post.</p>

</body>
