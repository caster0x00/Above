# Above

Network security sniffer for finding vulnerabilities in the network. Designed for pentesters and security engineers.

![](/banner/banner.png)

```
Above: Invisible network protocol sniffer
Designed for pentesters and security engineers

Author: Mahama Bazarov, <mahamabazarov@mailbox.org>
Pseudonym: Caster
Version: 2.8
Codename: Rubens Barrichello
```

# Disclaimer

**All information contained in this repository is provided for educational and research purposes only. The author is not responsible for any illegal use of this tool**.

**It is a specialized network security tool that helps both pentesters and security professionals**.

---

# Mechanics

Above is a invisible network sniffer for finding vulnerabilities in network equipment. It is based entirely on network traffic analysis, so it does not make any noise on the air. He's invisible. Completely based on the Scapy library.

> Above allows pentesters to automate the process of finding vulnerabilities in network hardware. Discovery protocols, dynamic routing, 802.1Q, Resolution protocols, ICS, FHRP, STP, LLMNR/NBT-NS, etc.

## Supported protocols

Detects up to 28 protocols:

```
MACSec (802.1X AE)
EAPOL (Checking 802.1X versions)
ARP (Host Discovery)
CDP (Cisco Discovery Protocol)
DTP (Dynamic Trunking Protocol)
LLDP (Link Layer Discovery Protocol) 
VLAN (802.1Q)
S7COMM (Siemens) (SCADA)
OMRON (SCADA)
TACACS+ (Terminal Access Controller Access Control System Plus)
ModbusTCP (SCADA)
STP (Spanning Tree Protocol)
OSPF (Open Shortest Path First)
EIGRP (Enhanced Interior Gateway Routing Protocol)
BGP (Border Gateway Protocol)
VRRP (Virtual Router Redundancy Protocol)
HSRP (Host Standby Redundancy Protocol)
GLBP (Gateway Load Balancing Protocol)
IGMP (Internet Group Management Protocol)
LLMNR (Link Local Multicast Name Resolution)
NBT-NS (NetBIOS Name Service)
MDNS (Multicast DNS)
DHCP (Dynamic Host Configuration Protocol)
DHCPv6 (Dynamic Host Configuration Protocol v6)
ICMPv6 (Internet Control Message Protocol v6)
SSDP (Simple Service Discovery Protocol)
MNDP (MikroTik Neighbor Discovery Protocol)
SNMP (Simple Network Management Protocol)
```
## Operating Mechanism

Above works in two modes:

- Hot mode: Sniffing on your interface specifying a timer
- Cold mode: Analyzing traffic dumps

The tool is very simple in its operation and is driven by arguments:

- Interface: Specifying the network interface on which sniffing will be performed
- Timer: Time during which traffic analysis will be performed
- Input: The tool takes an already prepared `.pcap` as input and looks for protocols in it
- Output: Above will record the listened traffic to `.pcap` file, its name you specify yourself
- Passive ARP: Detecting hosts in a segment using Passive ARP
- VLAN Search: Search for VLAN segments by extracting VLAN IDs in traffic

```
usage: above.py [-h] [--interface INTERFACE] [--timer TIMER] [--output OUTPUT] [--input INPUT] [--passive-arp] [--search-vlan]

options:
  -h, --help            show this help message and exit
  --interface INTERFACE
                        Interface for traffic listening
  --timer TIMER         Time in seconds to capture packets, default: not set
  --output OUTPUT       File name where the traffic will be recorded, default: not set
  --input INPUT         File name of the traffic dump
  --passive-arp         Passive ARP (Host Discovery)
  --search-vlan         VLAN Search
```

---

## Information about protocols

The information obtained will be useful not only to the pentester, but also to the security engineer, he will know what he needs to pay attention to.

When Above detects a protocol, it outputs the necessary information to indicate the attack vector or security issue:

- Impact: What kind of attack can be performed on this protocol;

- Tools: What tool can be used to launch an attack;

- Technical information: Required information for the pentester, sender MAC/IP addresses, FHRP group IDs, OSPF/EIGRP domains, etc.

- Mitigation: Recommendations for fixing the security problems

- Source/Destination Addresses: For protocols, Above displays information about the source and destination MAC addresses and IP addresses

---

# Installation

### Linux
You can install Above directly from the Kali Linux repositories
```bash
caster@kali:~$ sudo apt update && sudo apt install above
```

Or:

```bash
:~$ sudo apt-get install python3-scapy python3-colorama python3-setuptools
:~$ git clone https://github.com/caster0x00/above
:~$ cd above/
:~/above$ sudo python3 setup.py install
```

### macOS:
```bash
# Install python3 first
brew install python3
# Then install required dependencies
sudo pip3 install scapy colorama setuptools

# Clone the repo
git clone https://github.com/caster0x00/above
cd above/
sudo python3 setup.py install
```

Don't forget to **deactivate** your firewall on macOS!
#### Settings > Network > Firewall
--------------------------

# How to Use

## Hot mode

> Above requires root access for sniffing

Above can be run with or without a timer:

```bash
caster@kali:~$ sudo above --interface eth0 --timer 120
```
> To stop traffic sniffing, press CTRL + С
>

Example:

```bash
caster@kali:~$ sudo above --interface eth0 --timer 120
                                             
      ___  _                    
     / _ \| |                   
    / /_\ \ |__   _____   _____ 
    |  _  | '_ \ / _ \ \ / / _ \
    | | | | |_) | (_) \ V /  __/
    \_| |_/_.__/ \___/ \_/ \___|
    
    Invisible network protocol sniffer. Designed for security engineers

    Author: Mahama Bazarov, <mahamabazarov@mailbox.org>
    Alias: Caster
    Version: 2.8
    Codename: Rubens Barrichello

    [!] Above does NOT perform MITM or credential capture. Passive analysis only
    [!] Unauthorized use in third-party networks may violate local laws
    [!] The developer assumes NO liability for improper or illegal use

    [*] OUI Database Loaded. Entries: 36858
-----------------------------------------------------------------------------------------
[+] Start sniffing...

[*] After the protocol is detected - all necessary information about it will be displayed
==============================
[+] Detected STP Frame
[*] Attack Impact: Partial MITM
[*] Tools: Yersinia, Scapy
[*] STP Root Switch MAC: 78:9a:18:4d:55:63
[*] STP Root ID: 32768
[*] STP Root Path Cost: 0
[*] Mitigation: Enable BPDU Guard
[*] Vendor: Routerboard.com
==============================
[+] Detected MDNS Packet
[*] Attack Impact: MDNS Spoofing, Credentials Interception
[*] Tools: Responder
[*] MDNS Spoofing works specifically against Windows machines
[*] You cannot get NetNTLMv2-SSP from Apple devices
[*] MDNS Speaker IP: 10.10.100.252
[*] MDNS Speaker MAC: 02:10:de:64:f2:34
[*] Mitigation: Monitor mDNS traffic, this protocol can't just be turned off
[*] Vendor: Unknown Vendor
```

If you need to record the sniffed traffic, use the `--output` argument

```bash
caster@kali:~$ sudo above --interface eth0 --timer 120 --output above.pcap
```
> If you interrupt the tool with CTRL+C, the traffic is still written to the file

## Cold mode

If you already have some recorded traffic, you can use the `--input` argument to look for potential security issues

```bash
caster@kali:~$ above --input ospf-md5.cap
```

Example:

```bash
caster@kali:~$ sudo above --input dopamine.cap

[*] OUI Database Loaded. Entries: 36858
[+] Analyzing pcap file...

==============================
[+] Detected DHCP Discovery
[*] DHCP Discovery can lead to unauthorized network configuration
[*] DHCP Client IP: 0.0.0.0 (Broadcast)
[*] DHCP Speaker MAC: 00:11:5a:c6:1f:ea
[*] Mitigation: Use DHCP Snooping
[*] Vendor: Ivoclar Vivadent AG
==============================
[+] Detected HSRPv2 Packet
[*] Attack Impact: MITM
[*] Tools: Loki
[!] HSRPv2 has not yet been implemented in Scapy
[!] Check priority and state manually using Wireshark
[!] If the Active Router priority is less than 255 and you were able to break MD5 authentication, you can do a MITM
[*] HSRPv2 Speaker MAC: 00:00:0c:9f:f0:01
[*] HSRPv2 Speaker IP: 10.0.0.10
[*] Mitigation: Priority 255, Authentication, Extended ACL
[*] Vendor: Cisco Systems
```

# Passive ARP

This can be very useful if an attacker doesn't want to make noise on the air with ARP scans and quietly discover hosts. This function is run with `--passive-arp` and all hosts found will be written to the `above_passive_arp.txt` file.

```bash
caster@kali:~$ sudo above --interface eth0 --passive-arp

[+] Starting Host Discovery...
[*] IP and MAC addresses will be saved to 'above_passive_arp.txt'
```

> If you want, you can specify a timer for how long to listen to ARP frames to find hosts. By default, no timer is set.

Once started, the terminal will be completely cleared and a table consisting of a mapping of IP Address and MAC Address will be displayed:

```bash
+--------------------+------------------------------+--------------------+
| IP Address         | MAC Address                   | ARP Type           |
+--------------------+------------------------------+--------------------+
| 172.16.120.12      | f0:27:65:ba:1c:42             | ARP Response       |
| 172.16.120.45      | 6d:9f:84:2b:33:ea             | ARP Request        |
| 172.16.120.78      | 3a:7c:19:d8:4e:21             | ARP Response       |
| 172.16.120.103     | c4:12:76:ae:50:bb             | ARP Request        |
| 172.16.120.127     | 89:3b:df:92:6a:54             | ARP Response       |
| 172.16.120.156     | b7:5d:49:cb:72:99             | ARP Request        |
| 172.16.120.189     | 1e:47:ac:3d:15:f8             | ARP Response       |
| 172.16.120.222     | 43:9a:df:e0:84:3c             | ARP Request        |
+--------------------+------------------------------+--------------------+

```

The contents of the `above_passive_arp.txt` file will look like this:

```bash
caster@kali:~$ cat above_passive_arp.txt 
Above: Passive ARP Host Discovery
Time: 2024-08-16 17:30:16
--------------------------------------------------
172.16.120.12 - f0:27:65:ba:1c:42
172.16.120.45 - 6d:9f:84:2b:33:ea
172.16.120.78 - 3a:7c:19:d8:4e:21
172.16.120.103 - c4:12:76:ae:50:bb
172.16.120.127 - 89:3b:df:92:6a:54
172.16.120.156 - b7:5d:49:cb:72:99
172.16.120.189 - 1e:47:ac:3d:15:f8
172.16.120.222 - 43:9a:df:e0:84:3c
```

This is how Above with ARP frame learning can help discover hosts in a segment without noise in the air.

# VLAN Segments Search

Above can also find VLAN IDs in traffic. This is a useful option if the attacker is on a trunk port under some circumstances during the pentest. And the problem is that on a trunk port, all traffic is tagged with 802.1Q tags belonging to VLAN segments. Above can extract all VLAN IDs from the air or from a traffic dump:

```bash
caster@kali:~$ sudo above --interface eth0 --search-vlan 
```

When you run this function, the terminal will also be cleared and a table will be displayed and updated:

```bash
+------------------------------+---------------+----------------------------------------+
|VLAN ID                       |Frames Count   |How to Jump                             |
+------------------------------+---------------+----------------------------------------+
|120                           |8              |sudo vconfig add eth0 120               |
|80                            |8              |sudo vconfig add eth0 80                |
|251                           |7              |sudo vconfig add eth0 251               |
|190                           |6              |sudo vconfig add eth0 190               |
+------------------------------+---------------+----------------------------------------+
```

Also, the result of this function will be written to the `above_discovered_vlan.txt` file:

```bash
caster@kali:~$ cat above_discovered_vlan.txt
Above: Discovered VLAN ID
Time: 2024-08-16 17:41:19
--------------------------------------------------------------------------------
VLAN ID                       Frames Count   How to Jump                             
--------------------------------------------------------------------------------
1                             208            sudo vconfig add eth0 1                 
5                             972            sudo vconfig add eth0 5                 
6                             904            sudo vconfig add eth0 6                 
10                            20             sudo vconfig add eth0 10                
12                            20             sudo vconfig add eth0 12                
13                            20             sudo vconfig add eth0 13                
11                            20             sudo vconfig add eth0 11                
2000                          1              sudo vconfig add eth0 2000              
1000                          2              sudo vconfig add eth0 1000              
--------------------------------------------------------------------------------
```

This is how you can find information about VLAN segments based on traffic operations alone. But it is worth considering that this is a specific scenario, it is not often that an attacker will be on a trunk port. Either he will be lucky with DTP or he will stumble upon a switch port forgotten by the administrator.

# MAC Lookup

As of version 2.8 Above is now able to identify the vendor by MAC address, specifically by the first 24 bits. This is done by using a [downloaded database](https://standards-oui.ieee.org/), then converting it into the `above_oui_dict.py` module, which is a dictionary consisting of unique OUIs and vendor names.

# Copyright

Copyright (c) 2025 Mahama Bazarov. This project is licensed under the Apache 2.0 License

# Outro

When I create this instrument, I am inspired by the track KOAN Sound - View From Above (VIP)
This track was everything to me when I was working on this tool.

---

