# netfoot - network footprinting tools

* [`netfoot`](netfoot.py) : quick active network footprinting, output to directory tree
* [`netfoot_remote`](netfoot_remote.sh) : run netfoot and netcred on remote hosts
* [`netcred`](netcred.sh) : look for credentials on the network or offline

`netfoot` executes a list of commands (including `ip`,`route`,`masscan`,`traceroute`,`snmpwalk`,`nmap`) depending on the selected command groups (see `netfoot -c help` or [Netfoot executed commands list and groups](#Netfoot-executed-commands-list-and-groups) section) and stores the results in a directory structure (see `netfoot -o help` or [Netfoot command-line usage](#Netfoot-command-line-usage) section).

Readme sections:
* [Netfoot example: LAN discovery](#Netfoot-example-LAN-discovery)
* [Netfoot example: Target discovery](#Netfoot-example-Target-discovery)
  * [Initial scan](#Initial-scan)
  * [Created directory tree](#Created-directory-tree)
  * [Running another scan from a different perspective](#Running-another-scan-from-a-different-perspective)
  * [Different scan commands](#Different-scan-commands)
* [Netfoot command-line usage](#Netfoot-command-line-usage)
* [Netfoot scans from remote machines](#Netfoot-scans-from-remote-machines)
* [Netfoot Directory structure details](#Netfoot-Directory-structure-details)
* [Netfoot executed commands list and groups](#Netfoot-executed-commands-list-and-groups)

## Netfoot example: LAN discovery

By only providing a network interface to netfoot, it performs LAN discovery. 

The network configuration for the example bellow is:
* wired connection
* local ip 192.168.0.3
* public ip 23.23.23.128

``` bash
$ sudo netfoot enp0s31f6
```

The following commands will get executed automatically:

``` bash
# get IP addresses : ip addr show
# get IP routes : ip route show
# get DNS servers : grep -q systemd /etc/resolv.conf && systemd-resolve --status || cat /etc/resolv.conf
# get Wifi settings : iwconfig
# Traceroute google : traceroute -n 8.8.8.8
# UPNP connections : upnpc -m enp0s31f6 -s ||true
# UPNP redirects : upnpc -m enp0s31f6 -l ||true
# LAN portscan : masscan --interactive --rate=100 -e enp0s31f6 --adapter-port 61389 --banners --capture html -p21,22,23,25,53,80,88,110,111,143,443,445,554,1098,3306,3389,5900,6000,6881,8080,8081,8443,10000,27017 --ports U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060 --ping -oX masscan--interactive--rate100-e_enp0s31f6--adapter-port_61389--banners--capture_html-p21,22,23...0000,27017--ports_U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060--ping-oX_xml_192.168.0.3+24.xml 192.168.0.3/24
# speedtest
```

A directory tree will be created, see the next example for more informations about what it looks like.

## Netfoot example: Target discovery

### Initial scan

The network configuration for the example bellow is:
* wired connection
* local ip 10.0.0.3
* public ip 23.23.23.128

Target of scan: 192.168.0.0/24

``` bash
$ sudo netfoot enp0s31f6 192.168.0.0/24
```

Bellow is an extract of the netfoot output (also logged in the per-scan logs directory):

``` bash
getting LAN IP : ip -o a s dev enp0s31f6 |awk '{print $4}' |cut -d"/" -f1 |head -n1
getting Public IP : dig -b 10.0.0.3 +short myip.opendns.com @resolver1.opendns.com
pub23.23.23.128_lan10.0.0.3

================================================================================
[*] 20201012_161713 START

Command-line          : /usr/local/bin/netfoot enp0s31f6 192.168.0.0/24
Directory tree output : /tmp/netfoot1
Directory scan logs   : /tmp/netfoot1/netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3
Full log file         : /tmp/netfoot1/netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3/netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3.log

loading targets done, 1 targets
192.168.0.0/24

Commands to be executed:
* IP addresses: ip addr show 
* IP routes: ip route show 
* DNS servers: grep -q systemd /etc/resolv.conf && systemd-resolve --status || cat /etc/resolv.conf 
* Wifi settings: iwconfig  
* Portscan: masscan --interactive --rate=%r -e %i --adapter-port 61389 --banners --capture html -p21,22,23,25,53,80,88,110,111,143,443,445,554,1098,3306,3389,5900,6000,6881,8080,8081,8443,10000,27017 --ports U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060 --ping -oX %o.xml -iL %t (t=all_targets_file)
* Traceroute: traceroute -n %T (t=single_target)
* SNMP walk: snmpwalk -v 2c -c public %T system ||true (t=single_target)

[...]

================================================================================
# 20201012_161713 Portscan : masscan --interactive --rate=100 -e enp0s31f6 --adapter-port 61389 --banners --capture html -p21,22,23,25,53,80,88,110,111,143,443,445,554,1098,3306,3389,5900,6000,6881,8080,8081,8443,10000,27017 --ports U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060 --ping -oX masscan--interactive--rate100-e_enp0s31f6--adapter-port_61389--banners--capture_html-p21,22,23...0000,27017--ports_U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060--ping-oX_xml-iL_config_targets.txt.xml -iL config_targets.txt

running pre-command iptables -A INPUT -p tcp -i enp0s31f6 --dport 61389 -j DROP

Starting masscan 1.0.6 (http://bit.ly/14GZzcT) at 2020-10-12 14:17:13 GMT

[...]

# [0] (97.32s)
running post-command iptables -D INPUT -p tcp -i enp0s31f6 --dport 61389 -j DROP
created 30 files, updated 0 files in output directory tree

================================================================================
# 20201012_161850 Traceroute : traceroute -n 192.168.0.1

traceroute to 192.168.0.1 (192.168.0.1), 30 hops max, 60 byte packets

[...]

created 0 files, updated 1 files in output directory tree

================================================================================
# 20201012_161850 SNMP walk : snmpwalk -v 2c -c public 192.168.0.1 system ||true

[...]

================================================================================
[*] 20201012_161856 DONE

Command-line          : /usr/local/bin/netfoot enp0s31f6 192.168.0.0/24
Directory tree output : /tmp/netfoot1 (created 30 files,updated 1 files)
Directory scan logs   : /tmp/netfoot1/netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3
Full log file         : /tmp/netfoot1/netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3/netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3.log
```

Netfoot will create the following directory structure in the current directory (use -o to output to another directory), by parsing the different logs created by executed commands:

### Created directory tree

See the comments inline for explanations.

``` bash
$ tree
.
├── from_cha
# "cha" is the autodetected perspective name taken from the hostname of the scanning machine
# from where the scan is done (can be manually set using -f)
│   ├── host_192.168.0.1
# bellow we have the results per detected hosts from the "cha" perspective
│   │   ├── comment -> ../host_192.168.0.1_20201012_161713/comment
│   │   ├── host -> ../../host_192.168.0.1
│   │   ├── tcp
│   │   │   ├── 22
│   │   │   │   ├── answer_time -> ../../../host_192.168.0.1_20201012_161713/tcp/22/answer_time
│   │   │   │   ├── banner_answer_time -> ../../../host_192.168.0.1_20201012_161713/tcp/22/banner_answer_time
# [...] more symlinks to host_192.168.0.1_20201012_161713
│   ├── host_192.168.0.1_20201012_161713
│   │   ├── comment
│   │   ├── host -> ../../host_192.168.0.1
│   │   ├── netfoot -> ../../netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3
│   │   ├── tcp
│   │   │   ├── 22
│   │   │   │   ├── answer_time
│   │   │   │   ├── banner_answer_time
│   │   │   │   ├── banner_ssh
│   │   │   │   ├── reason
│   │   │   │   ├── reason_ttl
│   │   │   │   └── state
│   │   │   └── 53
│   │   │       ├── answer_time
│   │   │       ├── banner_answer_time
│   │   │       ├── banner_unknown
│   │   │       ├── reason
│   │   │       ├── reason_ttl
│   │   │       └── state
│   │   └── udp
│   │       └── 53
│   │           ├── answer_time
│   │           ├── banner_answer_time
│   │           ├── banner_dns-ver
│   │           ├── banner_unknown
│   │           ├── reason
│   │           ├── reason_ttl
│   │           └── state
│   ├── host_192.168.0.1_lastseen -> host_192.168.0.1_20201012_161713
│   ├── host_192.168.0.2
│   │   ├── comment -> ../host_192.168.0.2_20201012_161713/comment
│   │   ├── host -> ../../host_192.168.0.2
│   │   └── tcp
│   │       └── 22
│   │           ├── answer_time -> ../../../host_192.168.0.2_20201012_161713/tcp/22/answer_time
│   │           ├── banner_answer_time -> ../../../host_192.168.0.2_20201012_161713/tcp/22/banner_answer_time
# [...] more symlinkis to host_192.168.0.2_20201012_161713
│   ├── host_192.168.0.2_20201012_161713
│   │   ├── comment
│   │   ├── host -> ../../host_192.168.0.2
│   │   ├── netfoot -> ../../netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3
│   │   └── tcp
│   │       └── 22
│   │           ├── answer_time
│   │           ├── banner_answer_time
│   │           ├── banner_ssh
│   │           ├── reason
│   │           ├── reason_ttl
│   │           └── state
│   ├── host_192.168.0.2_lastseen -> host_192.168.0.2_20201012_161713
│   └── perspective
├── host_192.168.0.1
│   ├── from_cha -> ../from_cha/host_192.168.0.1
│   ├── from_cha_20201012_161713 -> ../from_cha/host_192.168.0.1_20201012_161713
│   ├── from_cha_lastseen -> ../from_cha/host_192.168.0.1_lastseen
│   └── ip
├── host_192.168.0.2
│   ├── from_cha -> ../from_cha/host_192.168.0.2
│   ├── from_cha_20201012_161713 -> ../from_cha/host_192.168.0.2_20201012_161713
│   ├── from_cha_lastseen -> ../from_cha/host_192.168.0.2_lastseen
│   └── ip
├── netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3
# bellow we have scan logs from this specific scans
# it is the raw output of the different commands
│   ├── cmd_OK_grep-q_systemd_+etc+resolv.conf_&&_systemd-resolve--status_||_cat_+etc+resolv.conf.log
│   ├── cmd_OK_ip_addr_show.log
│   ├── cmd_OK_ip_route_show.log
│   ├── cmd_OK_iwconfig.log
│   ├── cmd_OK_masscan--interactive--rate100-e_enp0s31f6--adapter-port_61389--banners--capture_html-p21,22,23...0000,27017--ports_U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060--ping-oX_xml-iL_config_targets.txt.log
│   ├── cmd_OK_snmpwalk-v_2c-c_public_192.168.0.1_system_||true.log
│   ├── cmd_OK_traceroute-n_192.168.0.1.log
│   ├── config_date_start.txt
│   ├── config_perspective.txt
│   ├── config_targets.txt
│   ├── from_cha -> ../from_cha
│   ├── host_192.168.0.1 -> ../from_cha/host_192.168.0.1_20201012_161713
│   ├── host_192.168.0.2 -> ../from_cha/host_192.168.0.2_20201012_161713
│   ├── lan_ip.txt
│   ├── masscan--interactive--rate100-e_enp0s31f6--adapter-port_61389--banners--capture_html-p21,22,23...0000,27017--ports_U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060--ping-oX_xml-iL_config_targets.txt.xml
# netfoot_*.log is the log of what you see in the terminal when running netfoot
│   ├── netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3.log
│   └── pub_ip.txt
└── netfoot_lastscan -> netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3

40 directories, 71 files
```

For explanations about each file, see `netfoot -o help` or [Netfoot Directory structure details](#Netfoot-Directory-structure-details) section.

### Running another scan from a different perspective

Now we connect our scanning machine to another leg of the network, via wifi, and we rescan the same target 192.168.0.0/24.

The network configuration for the example bellow is:
* wifi connection
* local ip 192.168.1.154
* public ip 23.23.23.128

Target of scan: 192.168.0.0/24


``` bash
$ sudo netfoot -f cha_wifi wlp3s0 192.168.0.0/24
```

Here we did set manualy the perspective name using `-f cha_wifi`

An extract of the output log from our new scan:

``` bash
getting LAN IP : ip -o a s dev wlp3s0 |awk '{print $4}' |cut -d"/" -f1 |head -n1
getting Public IP : dig -b 192.168.1.154 +short myip.opendns.com @resolver1.opendns.com
pub23.23.23.128_lan192.168.1.154

================================================================================
[*] 20201012_163902 START

Command-line          : /usr/local/bin/netfoot -f cha_wifi wlp3s0 192.168.0.0/24
Directory tree output : /tmp/netfoot1
Directory scan logs   : /tmp/netfoot1/netfoot_20201012_163902_cha_wifi_wlp3s0_pub23.23.23.128_lan192.168.1.154
Full log file         : /tmp/netfoot1/netfoot_20201012_163902_cha_wifi_wlp3s0_pub23.23.23.128_lan192.168.1.154/netfoot_20201012_163902_cha_wifi_wlp3s0_pub23.23.23.128_lan192.168.1.154.log

loading targets done, 1 targets
192.168.0.0/24

Commands to be executed:
* IP addresses: ip addr show 
* IP routes: ip route show 
* DNS servers: grep -q systemd /etc/resolv.conf && systemd-resolve --status || cat /etc/resolv.conf 
* Wifi settings: iwconfig  
* Portscan: masscan --interactive --rate=%r -e %i --adapter-port 61389 --banners --capture html -p21,22,23,25,53,80,88,110,111,143,443,445,554,1098,3306,3389,5900,6000,6881,8080,8081,8443,10000,27017 --ports U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060 --ping -oX %o.xml -iL %t (t=all_targets_file)
* Traceroute: traceroute -n %T (t=single_target)
* SNMP walk: snmpwalk -v 2c -c public %T system ||true (t=single_target)

[...]

================================================================================
[*] 20201012_164115 DONE

Command-line          : /usr/local/bin/netfoot -f cha_wifi wlp3s0 192.168.0.0/24
Directory tree output : /tmp/netfoot1 (created 15 files,updated 2 files)
Directory scan logs   : /tmp/netfoot1/netfoot_20201012_163902_cha_wifi_wlp3s0_pub23.23.23.128_lan192.168.1.154
Full log file         : /tmp/netfoot1/netfoot_20201012_163902_cha_wifi_wlp3s0_pub23.23.23.128_lan192.168.1.154/netfoot_20201012_163902_cha_wifi_wlp3s0_pub23.23.23.128_lan192.168.1.154.log
```

### Updated directory tree

``` bash
$ tree
.
├── from_cha
# [...] this is the perspective "cha" from the first scan
├── from_cha_wifi
# this is the perspective "cha_wifi" from our new scan
│   ├── host_192.168.0.1
│   │   ├── comment -> ../host_192.168.0.1_20201012_163902/comment
│   │   ├── host -> ../../host_192.168.0.1
│   │   ├── tcp
│   │   │   └── 53
│   │   │       ├── answer_time -> ../../../host_192.168.0.1_20201012_163902/tcp/53/answer_time
│   │   │       ├── banner_answer_time -> ../../../host_192.168.0.1_20201012_163902/tcp/53/banner_answer_time
# [...] more symlinks to host_192.168.0.1_20201012_163902
│   ├── host_192.168.0.1_20201012_163902
# we have detected the same host 192.168.0.1 but this time with only the DNS service is exposed
│   │   ├── comment
│   │   ├── host -> ../../host_192.168.0.1
│   │   ├── netfoot -> ../../netfoot_20201012_163902_cha_wifi_wlp3s0_pub23.23.23.128_lan192.168.1.154
│   │   ├── tcp
│   │   │   └── 53
│   │   │       ├── answer_time
│   │   │       ├── banner_answer_time
│   │   │       ├── banner_unknown
│   │   │       ├── reason
│   │   │       ├── reason_ttl
│   │   │       └── state
│   │   └── udp
│   │       └── 53
│   │           ├── answer_time
│   │           ├── banner_answer_time
│   │           ├── banner_dns-ver
│   │           ├── banner_unknown
│   │           ├── reason
│   │           ├── reason_ttl
│   │           └── state
│   ├── host_192.168.0.1_lastseen -> host_192.168.0.1_20201012_163902
│   └── perspective
├── host_192.168.0.1
# we now see that 192.168.0.1 is reachable both from perspective "cha" and "cha_wifi"
│   ├── from_cha -> ../from_cha/host_192.168.0.1
│   ├── from_cha_20201012_161713 -> ../from_cha/host_192.168.0.1_20201012_161713
│   ├── from_cha_lastseen -> ../from_cha/host_192.168.0.1_lastseen
│   ├── from_cha_wifi -> ../from_cha_wifi/host_192.168.0.1
│   ├── from_cha_wifi_20201012_163902 -> ../from_cha_wifi/host_192.168.0.1_20201012_163902
│   ├── from_cha_wifi_lastseen -> ../from_cha_wifi/host_192.168.0.1_lastseen
│   └── ip
├── host_192.168.0.2 is only reachable from "cha" perspective
# 192.168.0.2 is reachable both from perspective "cha" and "cha_wifi"
│   ├── from_cha -> ../from_cha/host_192.168.0.2
│   ├── from_cha_20201012_161713 -> ../from_cha/host_192.168.0.2_20201012_161713
│   ├── from_cha_lastseen -> ../from_cha/host_192.168.0.2_lastseen
│   └── ip
├── netfoot_20201012_161713_cha_enp0s31f6_pub23.23.23.128_lan10.0.0.3
# [...] logs from our first scan
├── netfoot_20201012_163902_cha_wifi_wlp3s0_pub23.23.23.128_lan192.168.1.154
# [...] logs from our new scan
│   ├── cmd_OK_grep-q_systemd_+etc+resolv.conf_&&_systemd-resolve--status_||_cat_+etc+resolv.conf.log
│   ├── cmd_OK_ip_addr_show.log
│   ├── cmd_OK_ip_route_show.log
│   ├── cmd_OK_iwconfig.log
│   ├── cmd_OK_masscan--interactive--rate100-e_wlp3s0--adapter-port_61389--banners--capture_html-p21,22,23...0000,27017--ports_U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060--ping-oX_xml-iL_config_targets.txt.log
│   ├── cmd_OK_snmpwalk-v_2c-c_public_192.168.0.1_system_||true.log
│   ├── cmd_OK_traceroute-n_192.168.0.1.log
│   ├── config_date_start.txt
│   ├── config_perspective.txt
│   ├── config_targets.txt
│   ├── from_cha_wifi -> ../from_cha_wifi
│   ├── host_192.168.0.1 -> ../from_cha_wifi/host_192.168.0.1_20201012_163902
│   ├── lan_ip.txt
│   ├── masscan--interactive--rate100-e_wlp3s0--adapter-port_61389--banners--capture_html-p21,22,23...0000,27017--ports_U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060--ping-oX_xml-iL_config_targets.txt.xml
│   ├── netfoot_20201012_163902_cha_wifi_wlp3s0_pub23.23.23.128_lan192.168.1.154.log
│   └── pub_ip.txt
└── netfoot_lastscan -> netfoot_20201012_163902_cha_wifi_wlp3s0_pub23.23.23.128_lan192.168.1.154

61 directories, 114 files
```

### Different scan commands

Netfoot can run different groups of commands.

We will now use scan mode `portscan_nmap_aggressive` with packet rate `1000`.

It uses nmap command with many NSE scripts enabled, allowing for in-depth discovery.

Each NSE script output is stored in it's own file in the directory tree output.

The network configuration for the example bellow is:
* wired connection
* local ip 192.168.1.3
* public ip 23.23.23.128

Target of scan: 192.168.0.0/24

``` bash
$ sudo netfoot -c portscan_nmap_aggressive -r 1000 enp0s31f6 192.168.0.0/24
```

Bellow is the produced directory tree:
``` bash
$ tree
.
├── from_cha
│   ├── host_192.168.0.1
│   │   ├── comment -> ../host_192.168.0.1_20201013_223922/comment
│   │   ├── host -> ../../host_192.168.0.1
│   │   ├── state_up_reason -> ../host_192.168.0.1_20201013_223922/state_up_reason
│   │   ├── tcp
│   │   │   ├── 22
│   │   │   │   ├── banner -> ../../../host_192.168.0.1_20201013_223922/tcp/22/banner
│   │   │   │   ├── product_ssh -> ../../../host_192.168.0.1_20201013_223922/tcp/22/product_ssh
│   │   │   │   ├── reason -> ../../../host_192.168.0.1_20201013_223922/tcp/22/reason
# [...] more symlinks to host_192.168.0.1_20201013_223922
│   ├── host_192.168.0.1_20201013_223922
│   │   ├── comment
│   │   ├── host -> ../../host_192.168.0.1
│   │   ├── netfoot -> ../../netfoot_20201013_223922_cha_enp0s31f6_pub23.23.23.128_lan192.168.1.3
│   │   ├── state_up_reason
│   │   ├── tcp
│   │   │   ├── 22
│   │   │   │   ├── banner
│   │   │   │   ├── product_ssh
│   │   │   │   ├── reason
│   │   │   │   ├── reason_ttl
│   │   │   │   ├── ssh2-enum-algos
│   │   │   │   ├── ssh-brute
│   │   │   │   ├── ssh-hostkey
│   │   │   │   ├── state
│   │   │   │   └── vulners
│   │   │   └── 53
│   │   │       ├── product_domain
│   │   │       ├── reason
│   │   │       ├── reason_ttl
│   │   │       └── state
│   │   └── traceroute_tcp199
│   ├── host_192.168.0.1_lastseen -> host_192.168.0.1_20201013_223922
│   ├── host_192.168.0.2
│   │   ├── comment -> ../host_192.168.0.2_20201013_223922/comment
│   │   ├── host -> ../../host_192.168.0.2
│   │   ├── state_up_reason -> ../host_192.168.0.2_20201013_223922/state_up_reason
│   │   ├── tcp
│   │   │   ├── 18793
│   │   │   │   ├── reason -> ../../../host_192.168.0.2_20201013_223922/tcp/18793/reason
│   │   │   │   ├── reason_ttl -> ../../../host_192.168.0.2_20201013_223922/tcp/18793/reason_ttl
│   │   │   │   └── state -> ../../../host_192.168.0.2_20201013_223922/tcp/18793/state
│   │   │   ├── 2121
│   │   │   │   ├── banner -> ../../../host_192.168.0.2_20201013_223922/tcp/2121/banner
│   │   │   │   ├── ftp-brute -> ../../../host_192.168.0.2_20201013_223922/tcp/2121/ftp-brute
# [...] more symlinks to host_192.168.0.2_20201013_223922
│   ├── host_192.168.0.2_20201013_223922
│   │   ├── comment
│   │   ├── host -> ../../host_192.168.0.2
│   │   ├── netfoot -> ../../netfoot_20201013_223922_cha_enp0s31f6_pub23.23.23.128_lan192.168.1.3
│   │   ├── state_up_reason
│   │   ├── tcp
│   │   │   ├── 18793
│   │   │   │   ├── reason
│   │   │   │   ├── reason_ttl
│   │   │   │   └── state
│   │   │   ├── 2121
│   │   │   │   ├── banner
│   │   │   │   ├── ftp-brute
│   │   │   │   ├── ftp-syst
│   │   │   │   ├── product_ftp
│   │   │   │   ├── reason
│   │   │   │   ├── reason_ttl
│   │   │   │   ├── state
│   │   │   │   └── unusual-port
│   │   │   ├── 2122
│   │   │   │   ├── banner
│   │   │   │   ├── ftp-brute
│   │   │   │   ├── ftp-syst
│   │   │   │   ├── product_ftp
│   │   │   │   ├── reason
│   │   │   │   ├── reason_ttl
│   │   │   │   ├── state
│   │   │   │   └── unusual-port
│   │   │   ├── 2123
│   │   │   │   ├── banner
│   │   │   │   ├── ftp-anon
│   │   │   │   ├── ftp-brute
│   │   │   │   ├── ftp-syst
│   │   │   │   ├── product_ftp
│   │   │   │   ├── reason
│   │   │   │   ├── reason_ttl
│   │   │   │   ├── state
│   │   │   │   └── unusual-port
│   │   │   └── 22
│   │   │       ├── banner
│   │   │       ├── product_ssh
│   │   │       ├── reason
│   │   │       ├── reason_ttl
│   │   │       ├── ssh2-enum-algos
│   │   │       ├── ssh-brute
│   │   │       ├── ssh-hostkey
│   │   │       └── state
│   │   └── traceroute_tcp199
│   ├── host_192.168.0.2_lastseen -> host_192.168.0.2_20201013_223922
│   └── perspective
├── host_192.168.0.1
│   ├── from_cha -> ../from_cha/host_192.168.0.1
│   ├── from_cha_20201013_223922 -> ../from_cha/host_192.168.0.1_20201013_223922
│   ├── from_cha_lastseen -> ../from_cha/host_192.168.0.1_lastseen
│   └── ip
├── host_192.168.0.2
│   ├── from_cha -> ../from_cha/host_192.168.0.2
│   ├── from_cha_20201013_223922 -> ../from_cha/host_192.168.0.2_20201013_223922
│   ├── from_cha_lastseen -> ../from_cha/host_192.168.0.2_lastseen
│   └── ip
├── netfoot_20201013_223922_cha_enp0s31f6_pub23.23.23.128_lan192.168.1.3
# scan logs
│   ├── cmd_OK_grep-q_systemd_+etc+resolv.conf_&&_systemd-resolve--status_||_cat_+etc+resolv.conf.log
│   ├── cmd_OK_ip_addr_show.log
│   ├── cmd_OK_ip_route_show.log
│   ├── cmd_OK_iwconfig.log
│   ├── cmd_OK_nmap-sV-sS-O--traceroute-e_enp0s31f6-T_4-v100--script_safe_or_brute_-p_0-65535-PE-PS22,443-PA80-PP-oA_-iL_config_targets.txt.log
│   ├── config_date_start.txt
│   ├── config_perspective.txt
│   ├── config_targets.txt
│   ├── from_cha -> ../from_cha
│   ├── host_192.168.0.1 -> ../from_cha/host_192.168.0.1_20201013_223922
│   ├── host_192.168.0.2 -> ../from_cha/host_192.168.0.2_20201013_223922
│   ├── lan_ip.txt
│   ├── netfoot_20201013_223922_cha_enp0s31f6_pub23.23.23.128_lan192.168.1.3.log
│   ├── nmap-sV-sS-O--traceroute-e_enp0s31f6-T_4-v100--script_safe_or_brute_-p_0-65535-PE-PS22,443-PA80-PP-oA_-iL_config_targets.txt.gnmap
│   ├── nmap-sV-sS-O--traceroute-e_enp0s31f6-T_4-v100--script_safe_or_brute_-p_0-65535-PE-PS22,443-PA80-PP-oA_-iL_config_targets.txt.nmap
│   ├── nmap-sV-sS-O--traceroute-e_enp0s31f6-T_4-v100--script_safe_or_brute_-p_0-65535-PE-PS22,443-PA80-PP-oA_-iL_config_targets.txt.xml
│   └── pub_ip.txt
└── netfoot_lastscan -> netfoot_20201013_223922_cha_enp0s31f6_pub23.23.23.128_lan192.168.1.3

44 directories, 127 files
```

## Netfoot command-line usage

``` bash
$ netfoot -h
usage: netfoot [-h] [-c COMMANDS] [-f FFROM] [-i IMPORT_DIR] [-o OUTPUT_DIR]
               [-t TARGETS_FILE] [-r RATE] [-D] [-N]
               [iface] [target [target ...]]

quick active network footprinting

positional arguments:
  iface            network interface to use
  target           target IPs and IP ranges, leave empty for LAN discovery

optional arguments:
  -h, --help       show this help message and exit
  -c COMMANDS      use specific commands group(s), or 'help' to list commands
  -f FFROM         name of the scan perspective, defaults to hostname
  -i IMPORT_DIR    import scan directory and create output directory tree. usefull to import previous scans done with -D
  -o OUTPUT_DIR    output directory tree, or 'help' to preview output layout. defaults current directory
  -t TARGETS_FILE  use targets from file or - for stdin, one ip/range per line
  -r RATE          packet rate for scans, defaults to 100
  -D               disable directory tree output
  -N               disable internet tests

Use '-c help' to list commands executed by netfoot
Use '-i help' for extensive help on importing scans
Use '-o help' to preview the directory structure created by netfoot.
```

## Netfoot scans from remote machines

Multiple perspective scans can be run from multiple machines, using netfoot_remote.

It is a wrapper around ssh and netfoot that provides simple controls:

``` bash
$ netfoot_remote 
usage: netfoot_remote <host> (deploy|run|check|tail|fetch-results|fetch-tools|kill|shred) ...
actions:
    <host> deploy                    : copy netfoot tools to remote host
    <host> run netfoot|netcred <options> : run program on remote host (stdin will not work).
                                           for netfoot, -D option is added automatically
    <host> check                     : check status of execution on remote host
    <host> tail netfoot              : tail log of tool, to get real-time results
    <host> fetch-results             : fetch results from remote host to netfoot_remote_<host>/
    <host> fetch-tools               : fetch netfoot tools from remote host
    <host> kill                      : stop execution of tools on remote host
    <host> shred                     : delete tools and results from remote host
    help-examples                    : provide additional example usages
environment variables:
    REMOTE_DIR: base directory for tools and results on remote host
```

``` bash
$ netfoot_remote help-examples
example scans with netfoot and netcred from remote host 192.168.1.1:
    netfoot_remote 192.168.1.1 deploy

    netfoot_remote 192.168.1.1 run netfoot -f as1300 -t /tmp/targets_lab.txt eth0
    netfoot_remote 192.168.1.1 check
    netfoot_remote 192.168.1.1 tail netfoot
    netfoot_remote 192.168.1.1 fetch-results

    netfoot_remote 192.168.1.1 run netcred -v brute ssh <remote_scandir>
    netfoot_remote 192.168.1.1 check
    netfoot_remote 192.168.1.1 fetch-results

    netfoot_remote 192.168.1.1 shred
```

Remote netfoot scans we be executed with -D, that disables output directory creation on the remote host.

You can then import netfoot logs in your local directory tree using netfoot -i, see `netfoot -i help` as seen bellow:

```bash
$ netfoot -i help
Import previously created scans logs directory and create output directory tree (see netfoot -o help).
Scan logs must be inside a directory previously created by netfoot or manual scans following with a specific naming.
Scan logs directory name created by netfoot (or netfoot -D):
* netfoot_<date>_<time>_<perspective>_<interface>_pub<public_ip>_lan<lan_ip>/
Required file naming in import directory:
* 'config_date_start.txt' must exist and contain a date in the format %Y%m%d_%H%M%S
* 'config_perspective.txt' must exist and contain the name of the scan perspective, like netfoot -f argument
* 'config_targets.txt' must exist and contain one targets per line, like nmap -iL format
* optional: nmap scan output (nmap -oX) must be named like 'nmap-*.xml'
* optional: masscan scan output (masscan -oX) must be named like 'masscan-*.xml'
```

## Netfoot Directory structure details

``` bash
$ netfoot -o help
Directory structure created by netfoot:

Created per-scan:
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/netfoot_<date>_<from>[_pub<pubip>][_lan<lanip].log # main log containing a copy of terminal output
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/cmd_(OK|FAILED)_<cmd>.txt   # output of command
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/config_date_start.txt       # scan start date
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/config_perspective.txt      # scan perspective name
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/config_targets.txt          # list of targets passed as arguments for the scan
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/lan_ip.txt                  # LAN IP
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/pub_ip.txt                  # Public IP
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/host_<ip>/                  # -> symlink to discovered from_<from>/host_<ip>_<date>/
netfoot_<date>_<from>_<iface>[_pub<pubip>][_lan<lanip>]/from_<from>/                # -> symlink to from_<from>/

Shared accross multiple scans:
netfoot_lastscan/                                                                   # -> symlink to last netfoot_*/
host_<ip>/
host_<ip>/ip                                            # ip address
host_<ip>/from_<from>_<date>/                           # -> symlink to from_<from>/host_<ip>_<date>/
host_<ip>/from_<from>_lastseen/                         # -> symlink to from_<from>/host_<ip>_lastseen/
from_<from>/
from_<from>/perspective                                 # perspective name
from_<from>/host_<ip>_<date>/host                       # -> symlink to host_<ip>/
from_<from>/host_<ip>_<date>/comment                    # host user comment
from_<from>/host_<ip>_<date>/traceroute_<proto><port>   # traceroute <proto+port> "<hopn> <delay1> <ip1>\n..."
from_<from>/host_<ip>_<date>/<proto>/
from_<from>/host_<ip>_<date>/<proto>/<port>/
from_<from>/host_<ip>_<date>/<proto>/<port>/state       # open
from_<from>/host_<ip>_<date>/<proto>/<port>/reason      # answer type from target
from_<from>/host_<ip>_<date>/<proto>/<port>/reason_ttl  # TTL in answer from target
from_<from>/host_<ip>_<date>/<proto>/<port>/banner      # banner returned from this port, if any
from_<from>/host_<ip>_<date>/<proto>/<port>/answer_time # time of answer
from_<from>/host_<ip>_<date>/netfoot                    # -> symlink to logs of this scan
from_<from>/host_<ip>_lastseen/                         # -> symlink to last from_<from>/host_<ip>_<date>/
from_<from>/host_<ip>/
from_<from>/host_<ip>/host                              # -> symlink to host_<ip>/
from_<from>/host_<ip>/comment                           # -> symlink to last created from_<from>/host_<ip>_<date>/comment
from_<from>/host_<ip>/<proto>/<port>/*                  # -> symlinks to last created from_<from>/host_<ip>_<date>/<proto>/<port>/*

```

## Netfoot executed commands list and groups

``` bash
$ netfoot -c help
Commands always executed : localinfos
Default commands if only interface is specified : landiscovery
Default commands if targets are specified : portscan,scan_hostinfos
Commands list:
++ localinfos
| IP addresses: ip addr show 
| IP routes: ip route show 
| DNS servers: grep -q systemd /etc/resolv.conf && systemd-resolve --status || cat /etc/resolv.conf 
| Wifi settings: iwconfig  
++ landiscovery
| Traceroute google: traceroute -n 8.8.8.8 
| UPNP connections: upnpc -m %i -s ||true 
| UPNP redirects: upnpc -m %i -l ||true 
| LAN portscan: masscan --interactive --rate=%r -e %i --adapter-port 61389 --banners --capture html -p21,22,23,25,53,80,88,110,111,143,443,445,554,1098,3306,3389,5900,6000,6881,8080,8081,8443,10000,27017 --ports U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060 --ping -oX %o.xml %l/24 (t=all_targets_file)
| Speedtest: speedtest  
++ portscan
| Portscan: masscan --interactive --rate=%r -e %i --adapter-port 61389 --banners --capture html -p21,22,23,25,53,80,88,110,111,143,443,445,554,1098,3306,3389,5900,6000,6881,8080,8081,8443,10000,27017 --ports U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060 --ping -oX %o.xml -iL %t (t=all_targets_file)
++ portscan_allports
| Portscan all ports: masscan --interactive --rate=%r -e %i --adapter-port 61389 --banners --capture html -p0-65535 --ports U:53,U:67,U:111,U:123,U:161,U:500,U:2123,U:5060 --ping -oX %o.xml -iL %t (t=all_targets_file)
++ portscan_nmap_aggressive
| Portscan nmap aggressive: nmap -sV -sS -O --traceroute -e %i -T %R -v100 --script="safe or brute" -p 0-65535 -PE -PS22,443 -PA80 -PP -oA %o -iL %t (t=all_targets_file)
++ scan_hostinfos
| Traceroute: traceroute -n %T (t=single_target)
| SNMP walk: snmpwalk -v 2c -c public %T system ||true (t=single_target)
```

## Adding commands to Netfoot

Netfoot can be extended easily by adding any commands to be executed, by editing source code.

A more convenient method may be introduced in the future.

In [netfoot.py](netfoot.py):
* The CMDS dict holds lists of commands for the different scan modes
* The Proc class can be extended to parse commands logs/output files to create directory tree output

