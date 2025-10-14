#!/usr/bin/env python3

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import argparse
from scapy.all import sniff, rdpcap, wrpcap, Ether, Dot1Q, IP, VRRP, VRRPv3, STP, IPv6, AH, Dot3, ARP, TCP, UDP, CookedLinux
from scapy.contrib.macsec import MACsec, MACsecSCI
from scapy.contrib.eigrp import EIGRP, EIGRPAuthData
from scapy.contrib.ospf import OSPF_Hdr
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPlatform, CDPMsgPortID, CDPAddrRecordIPv4, CDPMsgSoftwareVersion
from scapy.contrib.dtp import DTP
from scapy.layers.hsrp import HSRP, HSRPmd5
from scapy.layers.llmnr import LLMNRQuery
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
from scapy.layers.eap import EAPOL
from scapy.contrib.tacacs import TacacsHeader
from scapy.contrib.bgp import BGPHeader, BGPOpen
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import *
from scapy.layers.inet6 import ICMPv6ND_RS
from scapy.contrib.lldp import LLDPDU, LLDPDUSystemName, LLDPDUSystemDescription, LLDPDUPortID, LLDPDUManagementAddress
from colorama import Fore, Style, init
import socket
import signal
import sys
import os
import sys
from collections import defaultdict
from datetime import datetime
from scapy.layers.snmp import SNMP
from above.above_oui_dict import above_oui

# For colors (colorama)
init(autoreset=True)

# banner
banner = r"""                                         
  ___  _                    
 / _ \| |                   
/ /_\ \ |__   _____   _____ 
|  _  | '_ \ / _ \ \ / / _ \
| | | | |_) | (_) \ V /  __/
\_| |_/_.__/ \___/ \_/ \___|
"""

indent = "    "

# right indented banner output
print(indent + banner.replace("\n", "\n" + indent))
print(indent + Fore.YELLOW + "Invisible network protocol sniffer. Designed for security engineers\n")
print(indent + Fore.YELLOW + "Author: " + Style.RESET_ALL + "Mahama Bazarov, <mahamabazarov@mailbox.org>")
print(indent + Fore.YELLOW + "Alias: " + Style.RESET_ALL + "Caster")
print(indent + Fore.YELLOW + "Version: " + Style.RESET_ALL + "2.8")
print(indent + Fore.YELLOW + "Codename: " + Style.RESET_ALL + "Rubens Barrichello\n")
print(indent + Fore.YELLOW + "[!] Above does NOT perform MITM or credential capture. Passive analysis only")
print(indent + Fore.YELLOW + "[!] Unauthorized use in third-party networks may violate local laws")
print(indent + Fore.YELLOW + "[!] The developer assumes NO liability for improper or illegal use\n" + Style.RESET_ALL)

def get_mac_vendor(mac_address):
    mac_clean = mac_address.replace(":", "").upper()[:6]
    return above_oui.get(mac_clean, "Unknown Vendor")

def get_mac_from_packet(packet, protocol=None):
    if protocol == "STP" and packet.haslayer(STP):
        return str(packet[STP].rootmac)

    if protocol == "DTP" and packet.haslayer(Dot3):
        return packet[Dot3].src

    if packet.haslayer(Ether):
        return packet[Ether].src
    elif packet.haslayer(CookedLinux):
        return 'Unknown (Cooked Capture)'

    return 'Unknown'

print(indent + Fore.GREEN + f"[*] OUI Database Loaded. Entries: {len(above_oui)}")


# Parsing pcaps
def analyze_pcap(pcap_path):
    packets = rdpcap(pcap_path)
    for packet in packets:
        packet_detection(packet)

# Packet Processing
def packet_detection(packet):
    if (packet.haslayer(OSPF_Hdr) or packet.haslayer(CDPv2_HDR) or packet.haslayer(MACsec) or packet.haslayer(EAPOL) 
        or packet.haslayer(EIGRP) or packet.haslayer(DTP) or packet.haslayer(STP) or packet.haslayer(LLDPDU) 
        or packet.haslayer(HSRP) or packet.haslayer(VRRP) or packet.haslayer(VRRPv3) or packet.haslayer(ModbusADURequest) 
        or packet.haslayer(ModbusADUResponse) or packet.haslayer(BGPOpen) or packet.haslayer(BGPHeader) 
        or packet.haslayer(Dot1Q) or packet.haslayer(Dot3) or packet.haslayer(BOOTP) or packet.haslayer(DHCP) 
        or packet.haslayer(IGMP) or packet.haslayer(ICMPv6ND_RS) or packet.haslayer(IPv6) 
        or (packet.haslayer(UDP) and packet[UDP].dport in [137, 161, 5353, 5355, 5678, 3222, 546, 547, 1900, 9600])
        or (packet.haslayer(TCP) and packet[TCP].dport == 102)
        or (packet.haslayer(IP) and packet.haslayer(UDP) and packet[IP].dst == "224.0.0.102" and packet[UDP].dport == 1985)):
        packets.append(packet)

    # MACSec
    if packet.haslayer(MACsec):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[*] Detected MACSec")
        print(Fore.YELLOW + Style.BRIGHT + "[*] Most likely the infrastructure used is 802.1X-2010, keep in mind")
        packets.append(packet)
        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] System Identifier: " + Fore.WHITE + Style.BRIGHT + packet[0][MACsec][MACsecSCI].system_identifier)
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] System Identifier: " + Fore.WHITE + Style.BRIGHT + "Not Found")

    # OSPF
    if packet.haslayer(OSPF_Hdr):
        def hex_to_string(hex):
            if hex[:2] == '0x':
                hex = hex[2:]
            string_value = bytes.fromhex(hex).decode('utf-8')
            return string_value
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected OSPF Packet")
        print(Fore.GREEN + Style.BRIGHT + "[+] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Subnets Discovery, Blackhole, Evil Twin, Routing Table Overflow")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, FRRouting")
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Area ID: " + Fore.WHITE + Style.BRIGHT + str(packet[OSPF_Hdr].area))
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Neighbor IP: " + Fore.WHITE + Style.BRIGHT + str(packet[OSPF_Hdr].src))
        packets.append(packet)

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)

        # Authentication Checking
        if packet[OSPF_Hdr].authtype == 0x0:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: No")
        elif packet[OSPF_Hdr].authtype == 0x1:
            raw = packet[OSPF_Hdr].authdata
            hex_value = hex(raw)
            string = hex_to_string(hex_value)
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: Plaintext Phrase: " + string)
        elif packet[OSPF_Hdr].authtype == 0x02:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: MD5 or SHA-256")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: Ettercap, John the Ripper")
            print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Key ID: " + Fore.WHITE + Style.BRIGHT + str(packet[OSPF_Hdr].keyid))

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Passive interfaces, Authentication, Extended ACL")
        # Vendor
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # BGP
    if packet.haslayer(BGPHeader):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected BGP Packet")
        print(Fore.GREEN + Style.BRIGHT + "[+] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Route Hijacking")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, FRRouting")
        packets.append(packet)

        bgp_header = packet.getlayer(BGPHeader)
        if bgp_header:
            print(Fore.GREEN + Style.BRIGHT + "[*] BGP Header Fields: " + Fore.WHITE + Style.BRIGHT + str(bgp_header.fields))

        if packet.haslayer(BGPOpen):
            bgp_open = packet.getlayer(BGPOpen)
            print(Fore.GREEN + Style.BRIGHT + "[*] Source AS Number: " + Fore.WHITE + Style.BRIGHT + str(bgp_open.my_as))
            print(Fore.GREEN + Style.BRIGHT + "[*] Peer IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
            print(Fore.GREEN + Style.BRIGHT + "[*] Hold Time: " + Fore.WHITE + Style.BRIGHT + str(bgp_open.hold_time))

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + Style.BRIGHT + "[*] Peer MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use authentication, filter routes")
        # Vendor
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # HSRP (v1)
    if packet.haslayer(HSRP) and packet[HSRP].state == 16:
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected HSRP Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Active Router Priority: " + Fore.WHITE + Style.BRIGHT + str(packet[HSRP].priority))
        print(Fore.GREEN + Style.BRIGHT + "[+] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, Yersinia")
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Group Number: " + Fore.WHITE + Style.BRIGHT + str(packet[HSRP].group))
        print(Fore.GREEN + Style.BRIGHT + "[+] HSRP Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + str(packet[HSRP].virtualIP))
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
        packets.append(packet)

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)

        # Authentication Checking
        if packet.haslayer(HSRPmd5):
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
        elif packet[HSRP].auth:
            hsrpv1_plaintext = packet[HSRP].auth
            simplehsrppass = hsrpv1_plaintext.decode("UTF-8")
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "Plaintext Phrase: " + simplehsrppass)

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Priority 255, Authentication, Extended ACL")
        # Vendor
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # HSRP (v2)
    if packet.haslayer(IP) and packet.haslayer(UDP):
        if packet[IP].dst == "224.0.0.102" and packet[UDP].dport == 1985:
            print(Fore.WHITE + Style.BRIGHT + '=' * 30)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected HSRPv2 Packet")
            print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki")
            # Caution
            print(Fore.YELLOW + Style.BRIGHT + "[!] HSRPv2 has not yet been implemented in Scapy")
            print(Fore.YELLOW + Style.BRIGHT + "[!] Check priority and state manually using Wireshark")
            print(Fore.YELLOW + Style.BRIGHT + "[!] If the Active Router priority is less than 255 and you were able to break MD5 authentication, you can do a MITM")
            packets.append(packet)

            if packet.haslayer(Ether):
                mac_src = packet[Ether].src
            elif packet.haslayer(CookedLinux):
                mac_src = 'Unknown (Cooked Capture)'
            else:
                mac_src = 'Unknown'

            mac_src = get_mac_from_packet(packet)
            vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

            print(Fore.GREEN + Style.BRIGHT + "[*] HSRPv2 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
            print(Fore.GREEN + Style.BRIGHT + "[*] HSRPv2 Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
            # Mitigation
            print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Priority 255, Authentication, Extended ACL")
            # Vendor
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # VRRPv2
    if packet.haslayer(VRRP):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected VRRPv2 Packet")
        packets.append(packet)
        
        if packet.haslayer(AH):
            print (Fore.YELLOW + Style.BRIGHT + "[!] Authentication: AH Header detected, VRRP packet is encrypted")
            return 0
        
        if packet.haslayer(VRRP):
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Master Router Priority: " + Fore.WHITE + Style.BRIGHT + str(packet[VRRP].priority))
            print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, Loki")
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Group Number: " + Fore.WHITE + Style.BRIGHT + str(packet[VRRP].vrid))
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + ', '.join(packet[VRRP].addrlist))

            if packet.haslayer(Ether):
                mac_src = packet[Ether].src
            elif packet.haslayer(CookedLinux):
                mac_src = 'Unknown (Cooked Capture)'
            else:
                mac_src = 'Unknown'

            mac_src = get_mac_from_packet(packet)
            vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

            print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)

            if packet[VRRP].authtype == 0:
                print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: No")
            elif packet[VRRP].authtype == 0x1:
                print(Fore.WHITE + Style.BRIGHT + "[*] Authentication: Plaintext")
                try:
                    auth1_bytes = packet[VRRP].auth1.to_bytes(4, byteorder='big')
                    auth2_bytes = packet[VRRP].auth2.to_bytes(4, byteorder='big')
                    plaintext_password = (auth1_bytes + auth2_bytes).decode(errors="ignore").strip("\x00")
                    print(Fore.YELLOW + Style.BRIGHT + "[!] Extracted VRRP Password: " + Fore.WHITE + Style.BRIGHT + plaintext_password)
                except Exception as e:
                    print(Fore.RED + Style.BRIGHT + "[!] Failed to extract password: " + str(e))
            elif packet[VRRP].authtype == 254:
                print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: MD5")

            # Mitigation
            print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Authentication, ACL")
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)


    # VRRPv3
    if packet.haslayer(VRRPv3):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected VRRPv3 Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 master router priority: " + Fore.WHITE + Style.BRIGHT + str(packet[VRRPv3].priority))
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, Loki")
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Group Number: " + Fore.WHITE + Style.BRIGHT + str(packet[VRRPv3].vrid))
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
        packets.append(packet)
        
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + ', '.join(packet[VRRPv3].addrlist))
        
        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Filter VRRP traffic using ACL")
        # Vendor
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # GLBP
    if packet.haslayer(IP) and packet.haslayer(UDP):
        if packet[IP].dst == "224.0.0.102" and packet[UDP].dport == 3222:
            print(Fore.WHITE + Style.BRIGHT + '=' * 30)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected GLBP Packet")
            print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki")
            # Caution
            print(Fore.YELLOW + Style.BRIGHT + "[!] GLBP has not yet been implemented by Scapy")
            print(Fore.YELLOW + Style.BRIGHT + "[!] Check AVG router priority values manually using Wireshark")
            print(Fore.YELLOW + Style.BRIGHT + "[!] If the AVG router's priority value is less than 255, you have a chance of launching a MITM attack.")
            packets.append(packet) 

            if packet.haslayer(Ether):
                mac_src = packet[Ether].src
            elif packet.haslayer(CookedLinux):
                mac_src = 'Unknown (Cooked Capture)'
            else:
                mac_src = 'Unknown'

            mac_src = get_mac_from_packet(packet)
            vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
    
            print(Fore.GREEN + Style.BRIGHT + "[*] GLBP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
            print(Fore.GREEN + Style.BRIGHT + "[*] GLBP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))

            # Mitigation
            print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use priority 255, use authentication")
            # Vendor
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)        

    # DTP
    if packet.haslayer(DTP):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected DTP Frame")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "VLAN Segmentation Bypass")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Yersinia, Scapy")
        packets.append(packet)

        if packet.haslayer(Dot3):
            mac_src = packet[Dot3].src
        elif packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + Style.BRIGHT + "[*] DTP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable DTP")
        # Vendor
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)


    # STP
    if packet.haslayer(STP):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected STP Frame")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Partial MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Yersinia, Scapy")
        packets.append(packet)

        if packet.haslayer(Ether):
            root_switch_mac = str(packet[STP].rootmac)
        elif packet.haslayer(Dot3):
            root_switch_mac = packet[Dot3].src
        elif packet.haslayer(CookedLinux):
            root_switch_mac = 'Unknown (Cooked Capture)'
        else:
            root_switch_mac = 'Unknown'

        # Vendor lookup
        vendor = get_mac_vendor(root_switch_mac) if root_switch_mac != 'Unknown' else 'N/A'

        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Switch MAC: " + Fore.WHITE + Style.BRIGHT + root_switch_mac)
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root ID: " + Fore.WHITE + Style.BRIGHT + str(packet[STP].rootid))
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Path Cost: " + Fore.WHITE + Style.BRIGHT + str(packet[STP].pathcost))

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable BPDU Guard")
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)
 
    # CDP
    if packet.haslayer(CDPv2_HDR):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected CDP Frame")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering, CDP Flood")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Wireshark, Yersinia")

        hostname = packet[CDPMsgDeviceID].val.decode() if packet.haslayer(CDPMsgDeviceID) else "Unknown"
        os_version = packet[CDPMsgSoftwareVersion].val.decode() if packet.haslayer(CDPMsgSoftwareVersion) else "Unknown"
        platform = packet[CDPMsgPlatform].val.decode() if packet.haslayer(CDPMsgPlatform) else "Unknown"
        port_id = packet[CDPMsgPortID].iface.decode() if packet.haslayer(CDPMsgPortID) else "Unknown"
        ip_address = packet[CDPAddrRecordIPv4].addr if packet.haslayer(CDPAddrRecordIPv4) else "Not Found"

        print(Fore.GREEN + Style.BRIGHT + "[*] Hostname: " + Fore.WHITE + Style.BRIGHT + hostname)
        print(Fore.GREEN + Style.BRIGHT + "[*] OS Version: " + Fore.WHITE + Style.BRIGHT + os_version)
        print(Fore.GREEN + Style.BRIGHT + "[*] Platform: " + Fore.WHITE + Style.BRIGHT + platform)
        print(Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.WHITE + Style.BRIGHT + port_id)
        print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + ip_address)

        packets.append(packet)

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(Dot3):
            mac_src = packet[Dot3].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + Style.BRIGHT + "[*] CDP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable CDP if not required, be careful with VoIP")


    # EIGRP
    if packet.haslayer(EIGRP):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected EIGRP Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Subnets Discovery, Blackhole, Evil Twin")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, FRRouting")
        print(Fore.GREEN + Style.BRIGHT + "[*] AS Number: " + Fore.WHITE + Style.BRIGHT + str(packet[EIGRP].asn))
        packets.append(packet)

        if packet.haslayer(IP):
            print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
        elif packet.haslayer(IPv6):
            print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IPv6].src))

        if packet.haslayer(Ether):
            neighbor_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            neighbor_mac = 'Unknown (Cooked Capture)' 
        else:
            neighbor_mac = 'Unknown'

        neighbor_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(neighbor_mac) if neighbor_mac != 'Unknown' else 'N/A'
           
        print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + neighbor_mac)

        # Authentication Checking
        if packet.haslayer(EIGRPAuthData):
            print(Fore.YELLOW + Style.BRIGHT + "[!] There is EIGRP Authentication")
            authtype = packet[EIGRPAuthData].authtype
            if authtype == 2:
                print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: MD5")
                print(Fore.GREEN + Style.BRIGHT + "[*] Tools for bruteforce: eigrp2john.py, John the Ripper")
            elif authtype == 3:
                print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: SHA-256")
        else:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: No")

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable passive interfaces, use authentication")
        # Vendor
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # LLMNR
    if packet.haslayer(UDP) and packet[UDP].dport == 5355:
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected LLMNR Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "LLMNR Spoofing, Credentials Interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        packets.append(packet)

        try:
            llmnr_query_name = packet[LLMNRQuery].qd.qname.decode()
        except:
            llmnr_query_name = "Not Found"
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Query Name: " + Fore.WHITE + Style.BRIGHT + llmnr_query_name)

        try:
            llmnr_trans_id = packet[LLMNRQuery].id
        except:
            llmnr_trans_id = "Not Found"
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + str(llmnr_trans_id))

        if packet.haslayer(IP):
            ip_src = packet[IP].src
        elif packet.haslayer(IPv6):
            ip_src = packet[IPv6].src
        else:
            print(Fore.RED + Style.BRIGHT + "[!] No IP layer found")
            return
        
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Speaker IP: " + Fore.WHITE + Style.BRIGHT + ip_src)
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable LLMNR")
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # NBT-NS
    if packet.haslayer(UDP) and packet[UDP].dport == 137:
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected NBT-NS Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "NBT-NS Spoofing, Credentials Interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        packets.append(packet)

        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Question Name: " + Fore.WHITE + Style.BRIGHT + str(packet[0]["NBNS registration request"].QUESTION_NAME.decode()))
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Question Name: " + Fore.WHITE + Style.BRIGHT + "Not Found")

        try:
            print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + str(packet[0]["NBNS Header"].NAME_TRN_ID))
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + "Not Found")

        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(packet[0][IP].src))

        if packet.haslayer(Ether):
            speaker_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            speaker_mac = 'Unknown (Cooked Capture)'
        else:
            speaker_mac = 'Unknown'

        speaker_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(speaker_mac) if speaker_mac != 'Unknown' else 'N/A'

        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Speaker MAC: " + Fore.WHITE + Style.BRIGHT + speaker_mac)

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable NBT-NS")
        # Vendor
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # MDNS
    if packet.haslayer(UDP) and packet[UDP].dport == 5353:
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected MDNS Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MDNS Spoofing, Credentials Interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        print(Fore.YELLOW + Style.BRIGHT + "[*] MDNS Spoofing works specifically against Windows machines")
        print(Fore.YELLOW + Style.BRIGHT + "[*] You cannot get NetNTLMv2-SSP from Apple devices")
        packets.append(packet)

        if packet.haslayer(IP):
            ip_src = packet[IP].src
        elif packet.haslayer(IPv6):
            ip_src = packet[IPv6].src

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'
        
        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(ip_src))
        print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT +  "Monitor mDNS traffic, this protocol can't just be turned off")
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # EAPOL
    if packet.haslayer(EAPOL):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected EAPOL")
        packets.append(packet)
        if packet[EAPOL].version == 3:
            print (Fore.YELLOW + Style.BRIGHT + "[*] 802.1X Version: 2010")     
        elif packet[EAPOL].version == 2:
            print (Fore.YELLOW + Style.BRIGHT + "[*] 802.1X Version: 2004")   
        elif packet[EAPOL].version == 1:
            print (Fore.YELLOW + Style.BRIGHT + "[*] 802.1X Version: 2001")  
        else:
            print (Fore.YELLOW + Style.BRIGHT + "[*] 802.1X Version: Unknown")
      
    # DHCP Discover
    if packet.haslayer(UDP) and packet[UDP].dport == 67 and packet.haslayer(DHCP):
        packets.append(packet)
        dhcp_options = packet[DHCP].options
        for option in dhcp_options:
            if option[0] == 'message-type' and option[1] == 1: 
                print(Fore.WHITE + Style.BRIGHT + '=' * 30)
                print(Fore.WHITE + Style.BRIGHT + "[+] Detected DHCP Discovery")
                print(Fore.YELLOW + Style.BRIGHT + "[*] DHCP Discovery can lead to unauthorized network configuration")
                print(Fore.GREEN + Style.BRIGHT + "[*] DHCP Client IP: " + Fore.WHITE + Style.BRIGHT + "0.0.0.0 (Broadcast)")

                if packet.haslayer(Ether):
                    mac_src = packet[Ether].src
                elif packet.haslayer(CookedLinux):
                    mac_src = 'Unknown (Cooked Capture)'
                else:
                    mac_src = 'Unknown'

                mac_src = get_mac_from_packet(packet)
                vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

                print(Fore.GREEN + Style.BRIGHT + "[*] DHCP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)

                # Mitigation
                print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use DHCP Snooping")
                # Vendor
                print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # IGMP
    if packet.haslayer(IGMP):
        igmp_type = packet[IGMP].type
        igmp_types = {
            0x11: "Membership Query", 0x12: "Version 1 - Membership Report",
            0x16: "Version 2 - Membership Report", 0x17: "Leave Group", 0x22: "Version 3 - Membership Report"
        }
        packets.append(packet)
        igmp_type_description = igmp_types.get(igmp_type, "Unknown IGMP Type")
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + f"[+] Detected IGMP Packet: {igmp_type_description}")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "IGMP Sniffing, IGMP Flood")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, Wireshark")
        print(Fore.YELLOW + Style.BRIGHT + "[*] IGMP is used to manage multicast groups")
        print(Fore.YELLOW + Style.BRIGHT + "[*] IGMP types include queries, reports, and leaves")
        print(Fore.GREEN + Style.BRIGHT + "[*] IGMP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] Multicast Address: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].dst))

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "If there is a lot of multicast traffic, use IGMP Snooping")  
    
    # ICMPv6 RS
    if packet.haslayer(ICMPv6ND_RS):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected ICMPv6 Router Solicitation (RS)")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Potential for DoS attacks and network reconnaissance")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy")
        print(Fore.YELLOW + Style.BRIGHT + "[*] ICMPv6 RS messages are used by devices to locate routers")
        print(Fore.GREEN + Style.BRIGHT + "[*] IPv6 Source Address: " + Fore.WHITE + Style.BRIGHT + str(packet[IPv6].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] Target of Solicitation: " + Fore.WHITE + Style.BRIGHT + "All Routers Multicast Address (typically ff02::2)")
        packets.append(packet)
    
    # LLDP
    if packet.haslayer(LLDPDU):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected LLDP Frame")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Wireshark")
        packets.append(packet)

        hostname = packet[LLDPDUSystemName].system_name.decode() if packet.haslayer(LLDPDUSystemName) and isinstance(packet[LLDPDUSystemName].system_name, bytes) else packet[LLDPDUSystemName].system_name if packet.haslayer(LLDPDUSystemName) else "Not Found"
        os_version = packet[LLDPDUSystemDescription].description.decode() if packet.haslayer(LLDPDUSystemDescription) and isinstance(packet[LLDPDUSystemDescription].description, bytes) else packet[LLDPDUSystemDescription].description if packet.haslayer(LLDPDUSystemDescription) else "Not Found"
        port_id = packet[LLDPDUPortID].id.decode() if packet.haslayer(LLDPDUPortID) and isinstance(packet[LLDPDUPortID].id, bytes) else packet[LLDPDUPortID].id if packet.haslayer(LLDPDUPortID) else "Not Found"
        print(Fore.GREEN + Style.BRIGHT + "[*] Hostname: " + Fore.WHITE + Style.BRIGHT + hostname)
        print(Fore.GREEN + Style.BRIGHT + "[*] OS Version: " + Fore.WHITE + Style.BRIGHT + os_version)
        print(Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.WHITE + Style.BRIGHT + port_id)

        try:
            lldp_mgmt_address_bytes = packet[LLDPDUManagementAddress].management_address
            decoded_mgmt_address = socket.inet_ntoa(lldp_mgmt_address_bytes)
            print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + decoded_mgmt_address)
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + "Not Found")

        if packet.haslayer(Ether):
            source_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            source_mac = 'Unknown (Cooked Capture)'
        else:
            source_mac = 'Unknown'

        source_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(source_mac) if source_mac != 'Unknown' else 'N/A'

        print(Fore.GREEN + Style.BRIGHT + "[*] LLDP Source MAC: " + Fore.WHITE + Style.BRIGHT + source_mac)

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable LLDP if not required, be careful with VoIP")
        # Vendor
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # MNDP
    if packet.haslayer(UDP) and packet[UDP].sport == 5678 and packet[UDP].dport == 5678:
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected MNDP Packet")
        print(Fore.WHITE + Style.BRIGHT + "[*] MikroTik device may have been detected")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Wireshark")
        packets.append(packet)

        if packet.haslayer(IP):
            speaker_ip = str(packet[IP].src)
        elif packet.haslayer(IPv6):
            speaker_ip = str(packet[IPv6].src)
        else:
            speaker_ip = "Unknown"
        print(Fore.GREEN + Style.BRIGHT + "[*] MNDP Speaker IP: " + Fore.WHITE + Style.BRIGHT + speaker_ip)

        if packet.haslayer(Ether):
            speaker_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            speaker_mac = 'Unknown (Cooked Capture)'
        else:
            speaker_mac = 'Unknown'

        speaker_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(speaker_mac) if speaker_mac != 'Unknown' else 'N/A'
        
        print(Fore.GREEN + Style.BRIGHT + "[*] MNDP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + speaker_mac)

        print(Fore.YELLOW + Style.BRIGHT + "[*] You can get more information from the packet in Wireshark")
        print(Fore.YELLOW + Style.BRIGHT + "[*] The MNDP protocol is not yet implemented in Scapy")

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable MNDP if not required")
        # Vendor
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # DHCPv6
    if packet.haslayer(UDP) and (packet[UDP].sport == 546 or packet[UDP].dport == 546 or packet[UDP].sport == 547 or packet[UDP].dport == 547):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected DHCPv6 Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Potential DNS IPv6 Spoofing")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "mitm6")
        packets.append(packet)
        
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            ip_src = packet[IPv6].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
            ip_src = packet[IPv6].src
        else:
            mac_src = 'Unknown'
            ip_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
        print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Speaker IP: " + Fore.WHITE + Style.BRIGHT + ip_src)

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable DHCPv6 Snooping")
        # Vendor
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # SSDP
    if packet.haslayer(UDP) and packet[UDP].dport == 1900:
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected SSDP Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Potential for UPnP Device Exploitation, MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "evil-ssdp")
        print(Fore.YELLOW + Style.BRIGHT + "[*] Not every SSDP packet tells you that an attack is possible")
        packets.append(packet)

        if packet.haslayer(IP):
            print(Fore.GREEN + Style.BRIGHT + "[*] SSDP Source IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
        elif packet.haslayer(IPv6):
            print(Fore.GREEN + Style.BRIGHT + "[*] SSDP Source IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IPv6].src))

        if packet.haslayer(Ether):
            source_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            source_mac = 'Unknown (Cooked Capture)'
        else:
            source_mac = 'Unknown'

        source_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(source_mac) if source_mac != 'Unknown' else 'N/A'   
        
        print(Fore.GREEN + Style.BRIGHT + "[*] SSDP Source MAC: " + Fore.WHITE + Style.BRIGHT + source_mac)

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: "+ Fore.WHITE + Style.BRIGHT +  "Ensure UPnP is disabled on all devices unless absolutely necessary, monitor UPnP and SSDP traffic")
        # Vendor
        print(Fore.MAGENTA + Style.BRIGHT + "[*] Vendor: " + Fore.WHITE + Style.BRIGHT + vendor)

    # Modbus TCP (Request & Response Detecton)
    if packet.haslayer(ModbusADURequest):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected Modbus ADU Request Packet")
        print(Fore.YELLOW + Style.BRIGHT + "[!] SCADA device may have been detected")
        print(Fore.GREEN + Style.BRIGHT + "[*] Transaction ID: " + Fore.WHITE + Style.BRIGHT + str(packet[ModbusADURequest].transId))
        print(Fore.GREEN + Style.BRIGHT + "[*] Protocol ID: " + Fore.WHITE + Style.BRIGHT + str(packet[ModbusADURequest].protoId))
        print(Fore.GREEN + Style.BRIGHT + "[*] Unit ID: " + Fore.WHITE + Style.BRIGHT + str(packet[ModbusADURequest].unitId))
        packets.append(packet)
    
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
            print(Fore.YELLOW + Style.BRIGHT + "[+] Source MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
            print(Fore.YELLOW + Style.BRIGHT + "[+] Destination MAC: " + Fore.WHITE + Style.BRIGHT + mac_dst)

            vendor_src = get_mac_vendor(mac_src)
            vendor_dst = get_mac_vendor(mac_dst)
            
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Source Vendor: " + Fore.WHITE + Style.BRIGHT + vendor_src)
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Destination Vendor: " + Fore.WHITE + Style.BRIGHT + vendor_dst)
        if packet.haslayer(IP):
            print(Fore.YELLOW + Style.BRIGHT + "[+] Source IP: " + Fore.WHITE + Style.BRIGHT + packet[IP].src)
            print(Fore.YELLOW + Style.BRIGHT + "[+] Destination IP: " + Fore.WHITE + Style.BRIGHT + packet[IP].dst)
        if packet.haslayer(TCP):
            print(Fore.WHITE + Style.BRIGHT + "[+] Source TCP Port: " + Fore.WHITE + Style.BRIGHT + str(packet[TCP].sport))
            print(Fore.WHITE + Style.BRIGHT + "[+] Destination TCP Port: " + Fore.WHITE + Style.BRIGHT + str(packet[TCP].dport))

    if packet.haslayer(ModbusADUResponse):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected Modbus ADU Response Packet")
        print(Fore.YELLOW + Style.BRIGHT + "[!] SCADA device may have been detected")
        print(Fore.GREEN + Style.BRIGHT + "[*] Transaction ID: " + Fore.WHITE + Style.BRIGHT + str(packet[ModbusADUResponse].transId))
        print(Fore.GREEN + Style.BRIGHT + "[*] Protocol ID: " + Fore.WHITE + Style.BRIGHT + str(packet[ModbusADUResponse].protoId))
        print(Fore.GREEN + Style.BRIGHT + "[*] Unit ID: " + Fore.WHITE + Style.BRIGHT + str(packet[ModbusADUResponse].unitId))
        packets.append(packet)

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
            print(Fore.YELLOW + Style.BRIGHT + "[+] Source MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
            print(Fore.YELLOW + Style.BRIGHT + "[+] Destination MAC: " + Fore.WHITE + Style.BRIGHT + mac_dst)

            vendor_src = get_mac_vendor(mac_src)
            vendor_dst = get_mac_vendor(mac_dst)

            print(Fore.MAGENTA + Style.BRIGHT + "[*] Source Vendor: " + Fore.WHITE + Style.BRIGHT + vendor_src)
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Destination Vendor: " + Fore.WHITE + Style.BRIGHT + vendor_dst)
        if packet.haslayer(IP):
            print(Fore.YELLOW + Style.BRIGHT + "[+] Source IP: " + Fore.WHITE + Style.BRIGHT + packet[IP].src)
            print(Fore.YELLOW + Style.BRIGHT + "[+] Destination IP: " + Fore.WHITE + Style.BRIGHT + packet[IP].dst)
        if packet.haslayer(TCP):
            print(Fore.WHITE + Style.BRIGHT + "[+] Source TCP Port: " + Fore.WHITE + Style.BRIGHT + str(packet[TCP].sport))
            print(Fore.WHITE + Style.BRIGHT + "[+] Destination TCP Port: " + Fore.WHITE + Style.BRIGHT + str(packet[TCP].dport))

    # OMRON
    if packet.haslayer(UDP) and packet[UDP].dport == 9600:
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Possible OMRON packet detection")
        print(Fore.YELLOW + Style.BRIGHT + "[!] SCADA device may have been detected")
        packets.append(packet)
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
            print(Fore.YELLOW + Style.BRIGHT + "[+] Source MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
            print(Fore.YELLOW + Style.BRIGHT + "[+] Destination MAC: " + Fore.WHITE + Style.BRIGHT + mac_dst)

            vendor_src = get_mac_vendor(mac_src)
            vendor_dst = get_mac_vendor(mac_dst)
            
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Source Vendor: " + Fore.WHITE + Style.BRIGHT + vendor_src)
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Destination Vendor: " + Fore.WHITE + Style.BRIGHT + vendor_dst)
        if packet.haslayer(IP):
            print(Fore.YELLOW + Style.BRIGHT + "[+] Source IP: " + Fore.WHITE + Style.BRIGHT + packet[IP].src)
            print(Fore.YELLOW + Style.BRIGHT + "[+] Destination IP: " + Fore.WHITE + Style.BRIGHT + packet[IP].dst)
        if packet.haslayer(UDP):
            print(Fore.WHITE + Style.BRIGHT + "[+] Source UDP Port: " + Fore.WHITE + Style.BRIGHT + str(packet[UDP].sport))
            print(Fore.WHITE + Style.BRIGHT + "[+] Destination UDP Port: " + Fore.WHITE + Style.BRIGHT + str(packet[UDP].dport))

    # S7COMM
    if packet.haslayer(TCP) and packet[TCP].dport == 102:
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Possible S7COMM packet detection")
        print(Fore.YELLOW + Style.BRIGHT + "[!] SCADA device may have been detected")
        packets.append(packet)
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
            print(Fore.YELLOW + Style.BRIGHT + "[+] Source MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
            print(Fore.YELLOW + Style.BRIGHT + "[+] Destination MAC: " + Fore.WHITE + Style.BRIGHT + mac_dst)

            vendor_src = get_mac_vendor(mac_src)
            vendor_dst = get_mac_vendor(mac_dst)
            
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Source Vendor: " + Fore.WHITE + Style.BRIGHT + vendor_src)
            print(Fore.MAGENTA + Style.BRIGHT + "[*] Destination Vendor: " + Fore.WHITE + Style.BRIGHT + vendor_dst)
        if packet.haslayer(IP):
            print(Fore.YELLOW + Style.BRIGHT + "[+] Source IP: " + Fore.WHITE + Style.BRIGHT + packet[IP].src)
            print(Fore.YELLOW + Style.BRIGHT + "[+] Destination IP: " + Fore.WHITE + Style.BRIGHT + packet[IP].dst)
        if packet.haslayer(TCP):
            print(Fore.WHITE + Style.BRIGHT + "[+] Source TCP Port: " + Fore.WHITE + Style.BRIGHT + str(packet[TCP].sport))
            print(Fore.WHITE + Style.BRIGHT + "[+] Destination TCP Port: " + Fore.WHITE + Style.BRIGHT + str(packet[TCP].dport))

    # TACACS+
    if packet.haslayer(TacacsHeader):
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected TACACS Packet")
        packets.append(packet)
        header = packet[TacacsHeader]
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki")
        print(Fore.YELLOW + Style.BRIGHT + "[!] Warning: MITM is required to capture TACACS+ traffic before brute-forcing the key!")
        print(Fore.GREEN + Style.BRIGHT + "[+] TACACS Type: " + Fore.WHITE + Style.BRIGHT + f"{header.type}")
        print(Fore.GREEN + Style.BRIGHT + "[+] TACACS Flags: " + Fore.WHITE + Style.BRIGHT + f"{header.flags}")
        print(Fore.GREEN + Style.BRIGHT + "[+] TACACS Session ID: " + Fore.WHITE + Style.BRIGHT + f"{header.session_id}")
        print(Fore.GREEN + Style.BRIGHT + "[+] TACACS Length: " + Fore.WHITE + Style.BRIGHT + f"{header.length}")

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print(Fore.GREEN + Style.BRIGHT + "[*] Source IP: " + Fore.WHITE + Style.BRIGHT + f"{src_ip}")
            print(Fore.GREEN + Style.BRIGHT + "[*] Destination IP: " + Fore.WHITE + Style.BRIGHT + f"{dst_ip}")

        # Further analysis
        if packet[TacacsHeader].type == 1:  # Authentication
            print(Fore.YELLOW + Style.BRIGHT + "[*] TACACS Authentication Request Detected")

        elif packet[TacacsHeader].type == 2:  # Authorization
            print(Fore.YELLOW + Style.BRIGHT + "[*] TACACS Authorization Request Detected")

        elif header.type == 3:  # Accounting
            print(Fore.YELLOW + Style.BRIGHT + "[*] TACACS Accounting Request Detected")

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use strong passwords, monitor unusual activities")

    # SNMP
    if packet.haslayer(UDP) and packet[UDP].dport == 161:
        print(Fore.WHITE + Style.BRIGHT + '=' * 30)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected SNMP Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "onesixtyone, snmpwalk, snmp_enum from Metasploit")
        packets.append(packet)

        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            print(Fore.GREEN + Style.BRIGHT + "[*] Source IP: " + Fore.WHITE + Style.BRIGHT + f"{ip_src}")
            print(Fore.GREEN + Style.BRIGHT + "[*] Destination IP: " + Fore.WHITE + Style.BRIGHT + f"{ip_dst}")

        # Checking for SNMP community string
        if packet.haslayer(SNMP):
            community_string = str(packet[SNMP].community)
            print(Fore.GREEN + Style.BRIGHT + "[*] SNMP Community String: " + Fore.WHITE + Style.BRIGHT + f"{community_string}")
            
            # Warning for default community strings
            if community_string.lower() in ["public", "private"]:
                print(Fore.YELLOW + Style.BRIGHT + "[!] Warning: Default SNMP community string used ('public' or 'private'). This is a security risk!")

        # Mitigation
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Restrict SNMP access, use strong community strings, monitor SNMP traffic")

# list for packets processing
packets = []

# Passive ARP #
arp_table = defaultdict(lambda: {"mac": "", "type": ""})

# write ips and macs to file
def save_to_file_passive_arp(file_name="above_passive_arp.txt"):
    # write file
    with open(file_name, "w") as file:
        # timestamps
        file.write("Above: Passive ARP Host Discovery\n")
        file.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write("-" * 50 + "\n")
        
        # write ips and macs
        for ip, info in arp_table.items():
            file.write(f"{ip} - {info['mac']}\n")

# ARP Frames Sniffing
def passive_arp_monitor(packet):
    # Displaying Table
    def display_arp_table():
        print("\033c", end="")
        # Table Header
        print(Fore.WHITE + Style.BRIGHT + "+" + "-" * 20 + "+" + "-" * 30 + "+" + "-" * 20 + "+")
        print(f"|{'IP Address':<20}|{'MAC Address':<30}|{'ARP Type':<20}|")
        print(Fore.WHITE + Style.BRIGHT + "+" + "-" * 20 + "+" + "-" * 30 + "+" + "-" * 20 + "+")
        
        for ip, info in arp_table.items():
            mac = info["mac"]
            arp_type = info["type"]
            print(f"|{ip:<20}|{mac:<30}|{arp_type:<20}|")
        
        # Bottom
        print(Fore.WHITE + Style.BRIGHT + "+" + "-" * 20 + "+" + "-" * 30 + "+" + "-" * 20 + "+")

    if packet.haslayer(ARP):
        ip_address = packet[ARP].psrc
        mac_address = packet[ARP].hwsrc
        
        # types of ARP frames
        if packet[ARP].op == 1:
            arp_type = "ARP Request"
        elif packet[ARP].op == 2:
            arp_type = "ARP Response"
        else:
            arp_type = "Unknown"
        
        # dict update
        arp_table[ip_address] = {"mac": mac_address, "type": arp_type}
        # info update
        display_arp_table()
        # save to text file
        save_to_file_passive_arp()

# Dict for VLAN ID
vlan_table = defaultdict(int)

# Search VLAN ID (802.1Q)
def search_vlan(packet):
    if packet.haslayer(Dot1Q):
        vlan_id = packet[Dot1Q].vlan
        vlan_table[vlan_id] += 1
        display_vlan_table()

# Record VLAN ID's to file "above_discovered_vlan.txt"
def save_vlan_to_file_vlan_id(file_name="above_discovered_vlan.txt"):
    with open(file_name, "w") as file:
        # Header
        file.write("Above: Discovered VLAN ID\n")
        file.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write("-" * 80 + "\n")
        file.write(f"{'VLAN ID':<30}{'Frames Count':<15}{'How to Jump':<40}\n")
        file.write("-" * 80 + "\n")
        # writing data
        for vlan_id, count in vlan_table.items():
            jump_command = f"sudo vconfig add eth0 {vlan_id}"
            file.write(f"{vlan_id:<30}{count:<15}{jump_command:<40}\n")
        
        file.write("-" * 80 + "\n")

# VLAN ID Table Display
def display_vlan_table():
    print("\033c", end="")
    print(Fore.WHITE + Style.BRIGHT + "+" + "-" * 30 + "+" + "-" * 15 + "+" + "-" * 40 + "+")
    print(f"|{'VLAN ID':<30}|{'Frames Count':<15}|{'How to Jump':<40}|")
    print(Fore.WHITE + Style.BRIGHT + "+" + "-" * 30 + "+" + "-" * 15 + "+" + "-" * 40 + "+")
    
    for vlan_id, count in vlan_table.items():
        jump_command = f"sudo vconfig add eth0 {vlan_id}"
        print(f"|{vlan_id:<30}|{count:<15}|{jump_command:<40}|")
    
    print(Fore.WHITE + Style.BRIGHT + "+" + "-" * 30 + "+" + "-" * 15 + "+" + "-" * 40 + "+")
    save_vlan_to_file_vlan_id()

# Parse VLAN ID from pcaps
def analyze_pcap_for_vlan(pcap_path):
    packets = rdpcap(pcap_path)
    for packet in packets:
        search_vlan(packet)
    display_vlan_table() 

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', type=str, required=False, help='Interface for traffic listening')
    parser.add_argument('--timer', type=int, help='Time in seconds to capture packets, default: not set')
    parser.add_argument('--output', type=str, help='File name where the traffic will be recorded, default: not set')
    parser.add_argument('--input', type=str, help='File name of the traffic dump')
    parser.add_argument('--passive-arp', action='store_true', help='Passive ARP (Host Discovery)')
    parser.add_argument('--search-vlan', action='store_true', help='VLAN Search')
    args = parser.parse_args()

    def signal_handler(sig, frame):
        print("\n[!] CTRL+C pressed. Exiting...")
        if args.output and packets:
            try:
                wrpcap(args.output, packets)
                print(Fore.YELLOW + Style.BRIGHT + f"\n[*] Saved {len(packets)} packets to {args.output}")
            except Exception as e:
                print(Fore.RED + Style.BRIGHT + f"Error saving packets to {args.output}: {e}")
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)

    if args.output and (args.passive_arp or args.search_vlan):
        print(Fore.RED + "[!] The '--output' argument cannot be used with '--passive-arp' or '--search-vlan'")
        return
    if args.passive_arp and args.input:
        print(Fore.RED + "[!] The '--passive-arp' argument cannot be used with '--input'")
        return
    if not any(vars(args).values()):
        print(indent + "[*] Use --help to see usage instructions")
        return
    if args.input:
        if args.search_vlan:
            print(indent + "[+] Analyzing pcap file for VLAN tags...\n")
            analyze_pcap_for_vlan(args.input)
        else:
            print(indent + "[+] Analyzing pcap file...\n")
            analyze_pcap(args.input)
        return
    if os.getuid() != 0:
        print(indent + "[!] Sniffing traffic requires root privileges. Please run as root.")
        return
    if args.passive_arp:
        print(indent + "[+] Starting Host Discovery...")
        print(Fore.CYAN + "[*] IP and MAC addresses will be saved to 'above_passive_arp.txt'")
        sniff(iface=args.interface, timeout=args.timer, prn=passive_arp_monitor, store=0)
    elif args.search_vlan:
        print(indent + "[+] Searching for VLAN tags...")
        sniff(iface=args.interface, timeout=args.timer, prn=search_vlan, store=0)
        display_vlan_table()
    elif args.interface:
        print("-----------------------------------------------------------------------------------------")
        print("[+] Start sniffing...\n")
        print("[*] After the protocol is detected - all necessary information about it will be displayed")
        sniff(iface=args.interface, timeout=args.timer if args.timer is not None else None, prn=packet_detection, store=0)

    if packets and args.output:
            try:
                wrpcap(args.output, packets)
                print(Fore.YELLOW + Style.BRIGHT + f"\n[*] Saved {len(packets)} packets to {args.output}")
            except Exception as e:
                print(Fore.RED + Style.BRIGHT + f"Error saving packets to {args.output}: {e}")

if __name__ == "__main__":
    main()
