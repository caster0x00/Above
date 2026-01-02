#!/usr/bin/env python3

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
from collections import defaultdict
from datetime import datetime
from scapy.layers.snmp import SNMP
from above.above_oui_dict import above_oui
import socket
import signal
import sys
import os
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import argparse

# For colors (colorama)
init(autoreset=True)

# banner
banner = r"""                                         
        ___    __                  
       /   |  / /_  ____ _   _____ 
      / /| | / __ \/ __ \ | / / _ \
     / ___ |/ /_/ / /_/ / |/ /  __/
    /_/  |_/_.___/\____/|___/\___/ 
"""

indent = "    "

print(indent + banner)
print(indent + "Above: Network Security Sniffer")
print(indent + "Developer: " + Style.RESET_ALL + "Mahama Bazarov (Caster)")
print(indent + "Contact: " + Style.RESET_ALL + "mahamabazarov@mailbox.org")
print(indent + "Version: " + Style.RESET_ALL + "2.8.1")
print(indent + "Codename: " + Style.RESET_ALL + "Rubens Barrichello")
print(indent + "Documentation & Usage: " + Style.RESET_ALL + "https://github.com/caster0x00/Above\n")

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
        print()
        print(Fore.WHITE + "[*] Detected MACSec")
        print(Fore.YELLOW + "[*] Most likely the infrastructure used is 802.1X-2010, keep in mind")
        packets.append(packet)
        try:
            print(Fore.GREEN + "[*] System Identifier: " + Fore.WHITE + packet[0][MACsec][MACsecSCI].system_identifier)
        except:
            print(Fore.GREEN + "[*] System Identifier: " + Fore.WHITE + "Not Found")

    # OSPF
    if packet.haslayer(OSPF_Hdr):
        def hex_to_string(hex):
            if hex[:2] == '0x':
                hex = hex[2:]
            string_value = bytes.fromhex(hex).decode('utf-8')
            return string_value
        print()
        print(Fore.WHITE + "[+] Detected OSPF Packet")
        print(Fore.GREEN + "[+] Attack Impact: " + Fore.YELLOW + "Subnets Discovery, Route Injection, Routing Table Overflow")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki, Scapy, FRRouting")
        print(Fore.GREEN + "[*] OSPF Area ID: " + Fore.WHITE + str(packet[OSPF_Hdr].area))
        print(Fore.GREEN + "[*] OSPF Neighbor IP: " + Fore.WHITE + str(packet[OSPF_Hdr].src))
        packets.append(packet)

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + "[*] OSPF Neighbor MAC: " + Fore.WHITE + mac_src)

        # Authentication Checking
        if packet[OSPF_Hdr].authtype == 0x0:
            print(Fore.YELLOW + "[!] Authentication: No")
        elif packet[OSPF_Hdr].authtype == 0x1:
            raw = packet[OSPF_Hdr].authdata
            hex_value = hex(raw)
            string = hex_to_string(hex_value)
            print(Fore.YELLOW + "[!] Authentication: Plaintext Phrase: " + string)
        elif packet[OSPF_Hdr].authtype == 0x02:
            print(Fore.YELLOW + "[!] Authentication: MD5 or SHA-256")
            print(Fore.YELLOW + "[*] Tools for bruteforce: Ettercap, John the Ripper")
            print(Fore.GREEN + "[*] OSPF Key ID: " + Fore.WHITE + str(packet[OSPF_Hdr].keyid))

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Passive interfaces, Authentication, Extended ACL")
        # Vendor
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # BGP
    if packet.haslayer(BGPHeader):
        print()
        print(Fore.WHITE + "[+] Detected BGP Packet")
        print(Fore.GREEN + "[+] Attack Impact: " + Fore.YELLOW + "Route Hijacking")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Scapy, FRRouting")
        packets.append(packet)

        bgp_header = packet.getlayer(BGPHeader)
        if bgp_header:
            print(Fore.GREEN + "[*] BGP Header Fields: " + Fore.WHITE + str(bgp_header.fields))

        if packet.haslayer(BGPOpen):
            bgp_open = packet.getlayer(BGPOpen)
            print(Fore.GREEN + "[*] Source AS Number: " + Fore.WHITE + str(bgp_open.my_as))
            print(Fore.GREEN + "[*] Peer IP: " + Fore.WHITE + str(packet[IP].src))
            print(Fore.GREEN + "[*] Hold Time: " + Fore.WHITE + str(bgp_open.hold_time))

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + "[*] Peer MAC: " + Fore.WHITE + mac_src)

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Use authentication, filter routes")
        # Vendor
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # HSRP (v1)
    if packet.haslayer(HSRP) and packet[HSRP].state == 16:
        print()
        print(Fore.WHITE + "[+] Detected HSRP Packet")
        print(Fore.GREEN + "[*] HSRP Active Router Priority: " + Fore.WHITE + str(packet[HSRP].priority))
        print(Fore.GREEN + "[+] Attack Impact: " + Fore.YELLOW + "MITM")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki, Scapy, Yersinia")
        print(Fore.GREEN + "[*] HSRP Group Number: " + Fore.WHITE + str(packet[HSRP].group))
        print(Fore.GREEN + "[+] HSRP Virtual IP Address: " + Fore.WHITE + str(packet[HSRP].virtualIP))
        print(Fore.GREEN + "[*] HSRP Sender IP: " + Fore.WHITE + str(packet[IP].src))
        packets.append(packet)

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        print(Fore.GREEN + "[*] HSRP Sender MAC: " + Fore.WHITE + mac_src)

        # Authentication Checking
        if packet.haslayer(HSRPmd5):
            print(Fore.YELLOW + "[!] Authentication: " + Fore.WHITE + "MD5")
            print(Fore.YELLOW + "[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
        elif packet[HSRP].auth:
            hsrpv1_plaintext = packet[HSRP].auth
            simplehsrppass = hsrpv1_plaintext.decode("UTF-8")
            print(Fore.YELLOW + "[!] Authentication: " + Fore.WHITE + "Plaintext Phrase: " + simplehsrppass)

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Priority 255, Authentication, Extended ACL")
        # Vendor
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # HSRP (v2)
    if packet.haslayer(IP) and packet.haslayer(UDP):
        if packet[IP].dst == "224.0.0.102" and packet[UDP].dport == 1985:
            print()
            print(Fore.WHITE + "[+] Detected HSRPv2 Packet")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "MITM")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki, Scapy")
            # Caution
            print(Fore.YELLOW + "[!] HSRPv2 has not yet been implemented in Scapy")
            print(Fore.YELLOW + "[!] Check priority and state manually using Wireshark")
            print(Fore.YELLOW + "[!] If the Active Router priority is less than 255 and you were able to break MD5 authentication, you can do a MITM")
            packets.append(packet)

            if packet.haslayer(Ether):
                mac_src = packet[Ether].src
            elif packet.haslayer(CookedLinux):
                mac_src = 'Unknown (Cooked Capture)'
            else:
                mac_src = 'Unknown'

            mac_src = get_mac_from_packet(packet)
            vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

            print(Fore.GREEN + "[*] HSRPv2 Sender MAC: " + Fore.WHITE + mac_src)
            print(Fore.GREEN + "[*] HSRPv2 Sender IP: " + Fore.WHITE + str(packet[IP].src))
            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Priority 255, Authentication, Extended ACL")
            # Vendor
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # VRRPv2
    if packet.haslayer(VRRP):
        print()
        print(Fore.WHITE + "[+] Detected VRRPv2 Packet")
        packets.append(packet)
        
        if packet.haslayer(AH):
            print (Fore.YELLOW + "[!] Authentication: AH Header detected, VRRP packet is encrypted")
            return 0
        
        if packet.haslayer(VRRP):
            print(Fore.GREEN + "[*] VRRPv2 Master Router Priority: " + Fore.WHITE + str(packet[VRRP].priority))
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "MITM")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Scapy, Loki")
            print(Fore.GREEN + "[*] VRRPv2 Group Number: " + Fore.WHITE + str(packet[VRRP].vrid))
            print(Fore.GREEN + "[*] VRRPv2 Sender IP: " + Fore.WHITE + str(packet[IP].src))
            print(Fore.GREEN + "[*] VRRPv2 Virtual IP Address: " + Fore.WHITE + ', '.join(packet[VRRP].addrlist))

            if packet.haslayer(Ether):
                mac_src = packet[Ether].src
            elif packet.haslayer(CookedLinux):
                mac_src = 'Unknown (Cooked Capture)'
            else:
                mac_src = 'Unknown'

            mac_src = get_mac_from_packet(packet)
            vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

            print(Fore.GREEN + "[*] VRRPv2 Sender MAC: " + Fore.WHITE + mac_src)

            if packet[VRRP].authtype == 0:
                print(Fore.YELLOW + "[!] Authentication: No")
            elif packet[VRRP].authtype == 0x1:
                print(Fore.WHITE + "[*] Authentication: Plaintext")
                try:
                    auth1_bytes = packet[VRRP].auth1.to_bytes(4, byteorder='big')
                    auth2_bytes = packet[VRRP].auth2.to_bytes(4, byteorder='big')
                    plaintext_password = (auth1_bytes + auth2_bytes).decode(errors="ignore").strip("\x00")
                    print(Fore.YELLOW + "[!] Extracted VRRP Password: " + Fore.WHITE + plaintext_password)
                except Exception as e:
                    print(Fore.RED + "[!] Failed to extract password: " + str(e))
            elif packet[VRRP].authtype == 254:
                print(Fore.YELLOW + "[!] Authentication: MD5")

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Authentication, Filter VRRP traffic using ACL")
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)


    # VRRPv3
    if packet.haslayer(VRRPv3):
        print()
        print(Fore.WHITE + "[+] Detected VRRPv3 Packet")
        print(Fore.GREEN + "[*] VRRPv3 master router priority: " + Fore.WHITE + str(packet[VRRPv3].priority))
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "MITM")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Scapy, Loki")
        print(Fore.GREEN + "[*] VRRPv3 Group Number: " + Fore.WHITE + str(packet[VRRPv3].vrid))
        print(Fore.GREEN + "[*] VRRPv3 Sender IP: " + Fore.WHITE + str(packet[IP].src))
        packets.append(packet)
        
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + "[*] VRRPv3 Sender MAC: " + Fore.WHITE + mac_src)
        print(Fore.GREEN + "[*] VRRPv3 Virtual IP Address: " + Fore.WHITE + ', '.join(packet[VRRPv3].addrlist))
        
        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Filter VRRP traffic using ACL")
        # Vendor
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # GLBP
    if packet.haslayer(IP) and packet.haslayer(UDP):
        if packet[IP].dst == "224.0.0.102" and packet[UDP].dport == 3222:
            print()
            print(Fore.WHITE + "[+] Detected GLBP Packet")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "MITM")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki")
            # Caution
            print(Fore.YELLOW + "[!] GLBP has not yet been implemented by Scapy")
            print(Fore.YELLOW + "[!] Check AVG router priority values manually using Wireshark")
            print(Fore.YELLOW + "[!] If the AVG router's priority value is less than 255, you have a chance of launching a MITM attack.")
            packets.append(packet) 

            if packet.haslayer(Ether):
                mac_src = packet[Ether].src
            elif packet.haslayer(CookedLinux):
                mac_src = 'Unknown (Cooked Capture)'
            else:
                mac_src = 'Unknown'

            mac_src = get_mac_from_packet(packet)
            vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
    
            print(Fore.GREEN + "[*] GLBP Sender MAC: " + Fore.WHITE + mac_src)
            print(Fore.GREEN + "[*] GLBP Sender IP: " + Fore.WHITE + str(packet[IP].src))

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Priority 255, Authentication")
            # Vendor
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)        

    # DTP
    if packet.haslayer(DTP):
        print()
        print(Fore.WHITE + "[+] Detected DTP Frame")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "VLAN Segmentation Bypass")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Yersinia, Scapy")
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

        print(Fore.GREEN + "[*] DTP Neighbor MAC: " + Fore.WHITE + mac_src)

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable DTP")
        # Vendor
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)


    # STP
    if packet.haslayer(STP):
        print()
        print(Fore.WHITE + "[+] Detected STP Frame")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Partial MITM")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Yersinia, Scapy")
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

        print(Fore.GREEN + "[*] STP Root Switch MAC: " + Fore.WHITE + root_switch_mac)
        print(Fore.GREEN + "[*] STP Root ID: " + Fore.WHITE + str(packet[STP].rootid))
        print(Fore.GREEN + "[*] STP Root Path Cost: " + Fore.WHITE + str(packet[STP].pathcost))

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Enable BPDU Guard or Portfast")
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)
 
    # CDP
    if packet.haslayer(CDPv2_HDR):
        print()
        print(Fore.WHITE + "[+] Detected CDP Frame")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Information Gathering, CDP Flood/Spoofing")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Wireshark, Yersinia")

        hostname = packet[CDPMsgDeviceID].val.decode() if packet.haslayer(CDPMsgDeviceID) else "Unknown"
        os_version = packet[CDPMsgSoftwareVersion].val.decode() if packet.haslayer(CDPMsgSoftwareVersion) else "Unknown"
        platform = packet[CDPMsgPlatform].val.decode() if packet.haslayer(CDPMsgPlatform) else "Unknown"
        port_id = packet[CDPMsgPortID].iface.decode() if packet.haslayer(CDPMsgPortID) else "Unknown"
        ip_address = packet[CDPAddrRecordIPv4].addr if packet.haslayer(CDPAddrRecordIPv4) else "Not Found"

        print(Fore.GREEN + "[*] Hostname: " + Fore.WHITE + hostname)
        print(Fore.GREEN + "[*] OS Version: " + Fore.WHITE + os_version)
        print(Fore.GREEN + "[*] Platform: " + Fore.WHITE + platform)
        print(Fore.GREEN + "[*] Port ID: " + Fore.WHITE + port_id)
        print(Fore.GREEN + "[*] IP Address: " + Fore.WHITE + ip_address)

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

        print(Fore.GREEN + "[*] CDP Neighbor MAC: " + Fore.WHITE + mac_src)
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable CDP if not required, be careful with VoIP")


    # EIGRP
    if packet.haslayer(EIGRP):
        print()
        print(Fore.WHITE + "[+] Detected EIGRP Packet")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Subnets Discovery, Route Injection, Routing Table Overflow")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki, Scapy, FRRouting")
        print(Fore.GREEN + "[*] AS Number: " + Fore.WHITE + str(packet[EIGRP].asn))
        packets.append(packet)

        if packet.haslayer(IP):
            print(Fore.GREEN + "[*] EIGRP Neighbor IP: " + Fore.WHITE + str(packet[IP].src))
        elif packet.haslayer(IPv6):
            print(Fore.GREEN + "[*] EIGRP Neighbor IP: " + Fore.WHITE + str(packet[IPv6].src))

        if packet.haslayer(Ether):
            neighbor_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            neighbor_mac = 'Unknown (Cooked Capture)' 
        else:
            neighbor_mac = 'Unknown'

        neighbor_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(neighbor_mac) if neighbor_mac != 'Unknown' else 'N/A'
           
        print(Fore.GREEN + "[*] EIGRP Neighbor MAC: " + Fore.WHITE + neighbor_mac)

        # Authentication Checking
        if packet.haslayer(EIGRPAuthData):
            print(Fore.YELLOW + "[!] There is EIGRP Authentication")
            authtype = packet[EIGRPAuthData].authtype
            if authtype == 2:
                print(Fore.YELLOW + "[!] Authentication: MD5")
                print(Fore.GREEN + "[*] Tools for bruteforce: eigrp2john.py, John the Ripper")
            elif authtype == 3:
                print(Fore.YELLOW + "[!] Authentication: SHA-256")
        else:
            print(Fore.YELLOW + "[!] Authentication: No")

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Enable passive interfaces, use authentication")
        # Vendor
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # LLMNR
    if packet.haslayer(UDP) and packet[UDP].dport == 5355:
        print()
        print(Fore.WHITE + "[+] Detected LLMNR Packet")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "LLMNR Spoofing, Credentials Interception")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Responder")
        packets.append(packet)

        try:
            llmnr_query_name = packet[LLMNRQuery].qd.qname.decode()
        except:
            llmnr_query_name = "Not Found"
        print(Fore.GREEN + "[*] LLMNR Query Name: " + Fore.WHITE + llmnr_query_name)

        try:
            llmnr_trans_id = packet[LLMNRQuery].id
        except:
            llmnr_trans_id = "Not Found"
        print(Fore.GREEN + "[*] LLMNR Packet Transaction ID: " + Fore.WHITE + str(llmnr_trans_id))

        if packet.haslayer(IP):
            ip_src = packet[IP].src
        elif packet.haslayer(IPv6):
            ip_src = packet[IPv6].src
        else:
            print(Fore.RED + "[!] No IP layer found")
            return
        
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

        print(Fore.GREEN + "[*] LLMNR Sender IP: " + Fore.WHITE + ip_src)
        print(Fore.GREEN + "[*] LLMNR Sender MAC: " + Fore.WHITE + mac_src)

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable LLMNR")
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # NBT-NS
    if packet.haslayer(UDP) and packet[UDP].dport == 137:
        print()
        print(Fore.WHITE + "[+] Detected NBT-NS Packet")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "NBT-NS Spoofing, Credentials Interception")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Responder")
        packets.append(packet)

        try:
            print(Fore.GREEN + "[*] NBT-NS Question Name: " + Fore.WHITE + str(packet[0]["NBNS registration request"].QUESTION_NAME.decode()))
        except:
            print(Fore.GREEN + "[*] NBT-NS Question Name: " + Fore.WHITE + "Not Found")

        try:
            print(Fore.GREEN + "[*] NBT-NS Packet Transaction ID: " + Fore.WHITE + str(packet[0]["NBNS Header"].NAME_TRN_ID))
        except:
            print(Fore.GREEN + "[*] NBT-NS Packet Transaction ID: " + Fore.WHITE + "Not Found")

        print(Fore.GREEN + "[*] NBT-NS Sender IP: " + Fore.WHITE + str(packet[0][IP].src))

        if packet.haslayer(Ether):
            Sender_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            Sender_mac = 'Unknown (Cooked Capture)'
        else:
            Sender_mac = 'Unknown'

        Sender_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(Sender_mac) if Sender_mac != 'Unknown' else 'N/A'

        print(Fore.GREEN + "[*] NBT-NS Sender MAC: " + Fore.WHITE + Sender_mac)

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable NBT-NS")
        # Vendor
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # MDNS
    if packet.haslayer(UDP) and packet[UDP].dport == 5353:
        print()
        print(Fore.WHITE + "[+] Detected MDNS Packet")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "MDNS Spoofing, Credentials Interception")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Responder")
        print(Fore.YELLOW + "[*] MDNS Spoofing works specifically against Windows machines")
        print(Fore.YELLOW + "[*] You cannot get NetNTLMv2-SSP from Apple devices")
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

        print(Fore.GREEN + "[*] MDNS Sender IP: " + Fore.WHITE + str(ip_src))
        print(Fore.GREEN + "[*] MDNS Sender MAC: " + Fore.WHITE + mac_src)

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE +  "Monitor mDNS traffic with IDS, this protocol can't just be turned off")
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # EAPOL
    if packet.haslayer(EAPOL):
        print()
        print(Fore.WHITE + "[+] Detected EAPOL")
        packets.append(packet)
        if packet[EAPOL].version == 3:
            print (Fore.YELLOW + "[*] 802.1X Version: 2010")     
        elif packet[EAPOL].version == 2:
            print (Fore.YELLOW + "[*] 802.1X Version: 2004")   
        elif packet[EAPOL].version == 1:
            print (Fore.YELLOW + "[*] 802.1X Version: 2001")  
        else:
            print (Fore.YELLOW + "[*] 802.1X Version: Unknown")
      
    # DHCP Discover
    if packet.haslayer(UDP) and packet[UDP].dport == 67 and packet.haslayer(DHCP):
        packets.append(packet)
        dhcp_options = packet[DHCP].options
        for option in dhcp_options:
            if option[0] == 'message-type' and option[1] == 1: 
                print()
                print(Fore.WHITE + "[+] Detected DHCP Discovery")
                print(Fore.YELLOW + "[*] DHCP Discovery can lead to unauthorized network configuration")
                print(Fore.GREEN + "[*] DHCP Client IP: " + Fore.WHITE + "0.0.0.0 (Broadcast)")

                if packet.haslayer(Ether):
                    mac_src = packet[Ether].src
                elif packet.haslayer(CookedLinux):
                    mac_src = 'Unknown (Cooked Capture)'
                else:
                    mac_src = 'Unknown'

                mac_src = get_mac_from_packet(packet)
                vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'

                print(Fore.GREEN + "[*] DHCP Sender MAC: " + Fore.WHITE + mac_src)

                # Mitigation
                print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Use DHCP Snooping")
                # Vendor
                print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # IGMP
    if packet.haslayer(IGMP):
        igmp_type = packet[IGMP].type
        igmp_types = {
            0x11: "Membership Query", 0x12: "Version 1 - Membership Report",
            0x16: "Version 2 - Membership Report", 0x17: "Leave Group", 0x22: "Version 3 - Membership Report"
        }
        packets.append(packet)
        igmp_type_description = igmp_types.get(igmp_type, "Unknown IGMP Type")
        print()
        print(Fore.WHITE + f"[+] Detected IGMP Packet: {igmp_type_description}")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "IGMP Sniffing, IGMP Flood")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Scapy, Wireshark")
        print(Fore.YELLOW + "[*] IGMP is used to manage multicast groups")
        print(Fore.YELLOW + "[*] IGMP types include queries, reports, and leaves")
        print(Fore.GREEN + "[*] IGMP Sender IP: " + Fore.WHITE + str(packet[IP].src))
        print(Fore.GREEN + "[*] Multicast Address: " + Fore.WHITE + str(packet[IP].dst))

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "If there is a lot of multicast traffic, use IGMP Snooping")  
    
    # ICMPv6 RS
    if packet.haslayer(ICMPv6ND_RS):
        print()
        print(Fore.WHITE + "[+] Detected ICMPv6 Router Solicitation (RS)")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Potential for DoS attacks and network reconnaissance")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Scapy")
        print(Fore.YELLOW + "[*] ICMPv6 RS messages are used by devices to locate routers")
        print(Fore.GREEN + "[*] IPv6 Source Address: " + Fore.WHITE + str(packet[IPv6].src))
        print(Fore.GREEN + "[*] Target of Solicitation: " + Fore.WHITE + "All Routers Multicast Address (typically ff02::2)")
        packets.append(packet)
    
    # LLDP
    if packet.haslayer(LLDPDU):
        print()
        print(Fore.WHITE + "[+] Detected LLDP Frame")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Information Gathering")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Wireshark")
        packets.append(packet)

        hostname = packet[LLDPDUSystemName].system_name.decode() if packet.haslayer(LLDPDUSystemName) and isinstance(packet[LLDPDUSystemName].system_name, bytes) else packet[LLDPDUSystemName].system_name if packet.haslayer(LLDPDUSystemName) else "Not Found"
        os_version = packet[LLDPDUSystemDescription].description.decode() if packet.haslayer(LLDPDUSystemDescription) and isinstance(packet[LLDPDUSystemDescription].description, bytes) else packet[LLDPDUSystemDescription].description if packet.haslayer(LLDPDUSystemDescription) else "Not Found"
        port_id = packet[LLDPDUPortID].id.decode() if packet.haslayer(LLDPDUPortID) and isinstance(packet[LLDPDUPortID].id, bytes) else packet[LLDPDUPortID].id if packet.haslayer(LLDPDUPortID) else "Not Found"
        print(Fore.GREEN + "[*] Hostname: " + Fore.WHITE + hostname)
        print(Fore.GREEN + "[*] OS Version: " + Fore.WHITE + os_version)
        print(Fore.GREEN + "[*] Port ID: " + Fore.WHITE + port_id)

        try:
            lldp_mgmt_address_bytes = packet[LLDPDUManagementAddress].management_address
            decoded_mgmt_address = socket.inet_ntoa(lldp_mgmt_address_bytes)
            print(Fore.GREEN + "[*] IP Address: " + Fore.WHITE + decoded_mgmt_address)
        except:
            print(Fore.GREEN + "[*] IP Address: " + Fore.WHITE + "Not Found")

        if packet.haslayer(Ether):
            source_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            source_mac = 'Unknown (Cooked Capture)'
        else:
            source_mac = 'Unknown'

        source_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(source_mac) if source_mac != 'Unknown' else 'N/A'

        print(Fore.GREEN + "[*] LLDP Source MAC: " + Fore.WHITE + source_mac)

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable LLDP if not required, be careful with VoIP")
        # Vendor
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # MNDP
    if packet.haslayer(UDP) and packet[UDP].sport == 5678 and packet[UDP].dport == 5678:
        print()
        print(Fore.WHITE + "[+] Detected MNDP Packet")
        print(Fore.WHITE + "[*] MikroTik device may have been detected")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Information Gathering")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Wireshark")
        packets.append(packet)

        if packet.haslayer(IP):
            Sender_ip = str(packet[IP].src)
        elif packet.haslayer(IPv6):
            Sender_ip = str(packet[IPv6].src)
        else:
            Sender_ip = "Unknown"
        print(Fore.GREEN + "[*] MNDP Sender IP: " + Fore.WHITE + Sender_ip)

        if packet.haslayer(Ether):
            Sender_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            Sender_mac = 'Unknown (Cooked Capture)'
        else:
            Sender_mac = 'Unknown'

        Sender_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(Sender_mac) if Sender_mac != 'Unknown' else 'N/A'
        
        print(Fore.GREEN + "[*] MNDP Sender MAC: " + Fore.WHITE + Sender_mac)

        print(Fore.YELLOW + "[*] You can get more information from the packet in Wireshark")
        print(Fore.YELLOW + "[*] The MNDP protocol is not yet implemented in Scapy")

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable MNDP if not required")
        # Vendor
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # DHCPv6
    if packet.haslayer(UDP) and (packet[UDP].sport == 546):
        print()
        print(Fore.WHITE + "[+] Detected DHCPv6 Solicit Packet. It seems that someone is trying to obtain an address via DHCPv6.")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "DHCPv6 Spoofing, DNS Spoofing with mitm6")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "mitm6")
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

        print(Fore.GREEN + "[*] DHCPv6 Sender MAC: " + Fore.WHITE + mac_src)
        print(Fore.GREEN + "[*] DHCPv6 Sender IP: " + Fore.WHITE + ip_src)

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Enable DHCPv6 Snooping, Monitor DHCPv6 traffic with IDS")
        # Vendor
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # SSDP
    if packet.haslayer(UDP) and packet[UDP].dport == 1900:
        print()
        print(Fore.WHITE + "[+] Detected SSDP Packet")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Potential for UPnP Device Exploitation, MITM")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "evil-ssdp")
        print(Fore.YELLOW + "[*] Not every SSDP packet tells you that an attack is possible")
        packets.append(packet)

        if packet.haslayer(IP):
            print(Fore.GREEN + "[*] SSDP Source IP: " + Fore.WHITE + str(packet[IP].src))
        elif packet.haslayer(IPv6):
            print(Fore.GREEN + "[*] SSDP Source IP: " + Fore.WHITE + str(packet[IPv6].src))

        if packet.haslayer(Ether):
            source_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            source_mac = 'Unknown (Cooked Capture)'
        else:
            source_mac = 'Unknown'

        source_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(source_mac) if source_mac != 'Unknown' else 'N/A'   
        
        print(Fore.GREEN + "[*] SSDP Source MAC: " + Fore.WHITE + source_mac)

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: "+ Fore.WHITE +  "Ensure UPnP is disabled on all devices unless absolutely necessary, monitor UPnP and SSDP traffic")
        # Vendor
        print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # Modbus TCP (Request & Response Detecton)
    if packet.haslayer(ModbusADURequest):
        print()
        print(Fore.WHITE + "[+] Detected Modbus ADU Request Packet")
        print(Fore.YELLOW + "[!] SCADA device may have been detected")
        print(Fore.GREEN + "[*] Transaction ID: " + Fore.WHITE + str(packet[ModbusADURequest].transId))
        print(Fore.GREEN + "[*] Protocol ID: " + Fore.WHITE + str(packet[ModbusADURequest].protoId))
        print(Fore.GREEN + "[*] Unit ID: " + Fore.WHITE + str(packet[ModbusADURequest].unitId))
        packets.append(packet)
    
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
            print(Fore.YELLOW + "[+] Source MAC: " + Fore.WHITE + mac_src)
            print(Fore.YELLOW + "[+] Destination MAC: " + Fore.WHITE + mac_dst)

            vendor_src = get_mac_vendor(mac_src)
            vendor_dst = get_mac_vendor(mac_dst)
            
            print(Fore.MAGENTA + "[*] Source Vendor: " + Fore.WHITE + vendor_src)
            print(Fore.MAGENTA + "[*] Destination Vendor: " + Fore.WHITE + vendor_dst)
        if packet.haslayer(IP):
            print(Fore.YELLOW + "[+] Source IP: " + Fore.WHITE + packet[IP].src)
            print(Fore.YELLOW + "[+] Destination IP: " + Fore.WHITE + packet[IP].dst)
        if packet.haslayer(TCP):
            print(Fore.WHITE + "[+] Source TCP Port: " + Fore.WHITE + str(packet[TCP].sport))
            print(Fore.WHITE + "[+] Destination TCP Port: " + Fore.WHITE + str(packet[TCP].dport))

    if packet.haslayer(ModbusADUResponse):
        print()
        print(Fore.WHITE + "[+] Detected Modbus ADU Response Packet")
        print(Fore.YELLOW + "[!] SCADA device may have been detected")
        print(Fore.GREEN + "[*] Transaction ID: " + Fore.WHITE + str(packet[ModbusADUResponse].transId))
        print(Fore.GREEN + "[*] Protocol ID: " + Fore.WHITE + str(packet[ModbusADUResponse].protoId))
        print(Fore.GREEN + "[*] Unit ID: " + Fore.WHITE + str(packet[ModbusADUResponse].unitId))
        packets.append(packet)

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
            print(Fore.YELLOW + "[+] Source MAC: " + Fore.WHITE + mac_src)
            print(Fore.YELLOW + "[+] Destination MAC: " + Fore.WHITE + mac_dst)

            vendor_src = get_mac_vendor(mac_src)
            vendor_dst = get_mac_vendor(mac_dst)

            print(Fore.MAGENTA + "[*] Source Vendor: " + Fore.WHITE + vendor_src)
            print(Fore.MAGENTA + "[*] Destination Vendor: " + Fore.WHITE + vendor_dst)
        if packet.haslayer(IP):
            print(Fore.YELLOW + "[+] Source IP: " + Fore.WHITE + packet[IP].src)
            print(Fore.YELLOW + "[+] Destination IP: " + Fore.WHITE + packet[IP].dst)
        if packet.haslayer(TCP):
            print(Fore.WHITE + "[+] Source TCP Port: " + Fore.WHITE + str(packet[TCP].sport))
            print(Fore.WHITE + "[+] Destination TCP Port: " + Fore.WHITE + str(packet[TCP].dport))

    # OMRON
    if packet.haslayer(UDP) and packet[UDP].dport == 9600:
        print()
        print(Fore.WHITE + "[+] Possible OMRON packet detection")
        print(Fore.YELLOW + "[!] SCADA device may have been detected")
        packets.append(packet)
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
            print(Fore.YELLOW + "[+] Source MAC: " + Fore.WHITE + mac_src)
            print(Fore.YELLOW + "[+] Destination MAC: " + Fore.WHITE + mac_dst)

            vendor_src = get_mac_vendor(mac_src)
            vendor_dst = get_mac_vendor(mac_dst)
            
            print(Fore.MAGENTA + "[*] Source Vendor: " + Fore.WHITE + vendor_src)
            print(Fore.MAGENTA + "[*] Destination Vendor: " + Fore.WHITE + vendor_dst)
        if packet.haslayer(IP):
            print(Fore.YELLOW + "[+] Source IP: " + Fore.WHITE + packet[IP].src)
            print(Fore.YELLOW + "[+] Destination IP: " + Fore.WHITE + packet[IP].dst)
        if packet.haslayer(UDP):
            print(Fore.WHITE + "[+] Source UDP Port: " + Fore.WHITE + str(packet[UDP].sport))
            print(Fore.WHITE + "[+] Destination UDP Port: " + Fore.WHITE + str(packet[UDP].dport))

    # S7COMM
    if packet.haslayer(TCP) and packet[TCP].dport == 102:
        print()
        print(Fore.WHITE + "[+] Possible S7COMM packet detection")
        print(Fore.YELLOW + "[!] SCADA device may have been detected")
        packets.append(packet)
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst
            print(Fore.YELLOW + "[+] Source MAC: " + Fore.WHITE + mac_src)
            print(Fore.YELLOW + "[+] Destination MAC: " + Fore.WHITE + mac_dst)

            vendor_src = get_mac_vendor(mac_src)
            vendor_dst = get_mac_vendor(mac_dst)
            
            print(Fore.MAGENTA + "[*] Source Vendor: " + Fore.WHITE + vendor_src)
            print(Fore.MAGENTA + "[*] Destination Vendor: " + Fore.WHITE + vendor_dst)
        if packet.haslayer(IP):
            print(Fore.YELLOW + "[+] Source IP: " + Fore.WHITE + packet[IP].src)
            print(Fore.YELLOW + "[+] Destination IP: " + Fore.WHITE + packet[IP].dst)
        if packet.haslayer(TCP):
            print(Fore.WHITE + "[+] Source TCP Port: " + Fore.WHITE + str(packet[TCP].sport))
            print(Fore.WHITE + "[+] Destination TCP Port: " + Fore.WHITE + str(packet[TCP].dport))

    # TACACS+
    if packet.haslayer(TacacsHeader):
        print()
        print(Fore.WHITE + "[+] Detected TACACS Packet")
        packets.append(packet)
        header = packet[TacacsHeader]
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki")
        print(Fore.YELLOW + "[!] To capture TACACS+ traffic and brute force the key, you need MITM")
        print(Fore.GREEN + "[+] TACACS Type: " + Fore.WHITE + f"{header.type}")
        print(Fore.GREEN + "[+] TACACS Flags: " + Fore.WHITE + f"{header.flags}")
        print(Fore.GREEN + "[+] TACACS Session ID: " + Fore.WHITE + f"{header.session_id}")
        print(Fore.GREEN + "[+] TACACS Length: " + Fore.WHITE + f"{header.length}")

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print(Fore.GREEN + "[*] Source IP: " + Fore.WHITE + f"{src_ip}")
            print(Fore.GREEN + "[*] Destination IP: " + Fore.WHITE + f"{dst_ip}")

        # Further analysis
        if packet[TacacsHeader].type == 1:  # Authentication
            print(Fore.YELLOW + "[*] TACACS Authentication Request Detected")

        elif packet[TacacsHeader].type == 2:  # Authorization
            print(Fore.YELLOW + "[*] TACACS Authorization Request Detected")

        elif header.type == 3:  # Accounting
            print(Fore.YELLOW + "[*] TACACS Accounting Request Detected")

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Use strong passwords, monitor unusual activities")

    # SNMP
    if packet.haslayer(UDP) and packet[UDP].dport == 161:
        print()
        print(Fore.WHITE + "[+] Detected SNMP Packet")
        print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Information Gathering")
        print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "onesixtyone, snmpwalk, snmp_enum (Metasploit)")
        packets.append(packet)

        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            print(Fore.GREEN + "[*] Source IP: " + Fore.WHITE + f"{ip_src}")
            print(Fore.GREEN + "[*] Destination IP: " + Fore.WHITE + f"{ip_dst}")

        # Checking for SNMP community string
        if packet.haslayer(SNMP):
            community_string = str(packet[SNMP].community)
            print(Fore.GREEN + "[*] SNMP Community String: " + Fore.WHITE + f"{community_string}")
            
            # Warning for default community strings
            if community_string.lower() in ["public", "private"]:
                print(Fore.YELLOW + "[!] Warning: Default SNMP community string used ('public' or 'private'). This is a security risk!")

        # Mitigation
        print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Restrict SNMP access, use strong community strings, monitor SNMP traffic")

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
        print(Fore.WHITE + "+" + "-" * 20 + "+" + "-" * 30 + "+" + "-" * 20 + "+")
        print(f"|{'IP Address':<20}|{'MAC Address':<30}|{'ARP Type':<20}|")
        print(Fore.WHITE + "+" + "-" * 20 + "+" + "-" * 30 + "+" + "-" * 20 + "+")
        
        for ip, info in arp_table.items():
            mac = info["mac"]
            arp_type = info["type"]
            print(f"|{ip:<20}|{mac:<30}|{arp_type:<20}|")
        
        # Bottom
        print(Fore.WHITE + "+" + "-" * 20 + "+" + "-" * 30 + "+" + "-" * 20 + "+")

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
    print(Fore.WHITE + "+" + "-" * 30 + "+" + "-" * 15 + "+" + "-" * 40 + "+")
    print(f"|{'VLAN ID':<30}|{'Frames Count':<15}|{'How to Jump':<40}|")
    print(Fore.WHITE + "+" + "-" * 30 + "+" + "-" * 15 + "+" + "-" * 40 + "+")
    
    for vlan_id, count in vlan_table.items():
        jump_command = f"sudo vconfig add eth0 {vlan_id}"
        print(f"|{vlan_id:<30}|{count:<15}|{jump_command:<40}|")
    
    print(Fore.WHITE + "+" + "-" * 30 + "+" + "-" * 15 + "+" + "-" * 40 + "+")
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
                print(Fore.YELLOW + f"\n[*] Saved {len(packets)} packets to {args.output}")
            except Exception as e:
                print(Fore.RED + f"Error saving packets to {args.output}: {e}")
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
        print("[*] Start Sniffing")
        sniff(iface=args.interface, timeout=args.timer if args.timer is not None else None, prn=packet_detection, store=0)

    if packets and args.output:
            try:
                wrpcap(args.output, packets)
                print(Fore.YELLOW + f"\n[*] Saved {len(packets)} packets to {args.output}")
            except Exception as e:
                print(Fore.RED + f"Error saving packets to {args.output}: {e}")

if __name__ == "__main__":
    main()
