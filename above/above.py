#!/usr/bin/env python3

import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.all import sniff, rdpcap, wrpcap, PcapReader, Ether, Dot1Q, IP, VRRP, VRRPv3, STP, IPv6, AH, Dot3, ARP, TCP, UDP, CookedLinux
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
import ipaddress
import multiprocessing
import socket
import signal
import time
import sys
import os
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
    global _shared_packets, _progress_counter, packets

    t0 = time.time()
    file_size = os.path.getsize(pcap_path)
    _shared_packets = []
    with PcapReader(pcap_path) as reader:
        count = 0
        for pkt in reader:
            _shared_packets.append(pkt)
            count += 1
            if count % 2000 == 0:
                try:
                    pos = reader.f.tell()
                except Exception:
                    pos = 0
                _print_loading_bar(pos, file_size, time.time() - t0, count)
    t_load = time.time() - t0
    total = len(_shared_packets)
    _print_loading_bar(file_size, file_size, t_load, total)
    print()

    if total == 0:
        print(indent + "[*] No packets found.")
        return

    num_workers = min(3, total)
    print(indent + f"[*] Analyzing with {num_workers} workers...\n")

    chunk_size = total // num_workers
    chunks = []
    for i in range(num_workers):
        start = i * chunk_size
        end = total if i == num_workers - 1 else (i + 1) * chunk_size
        chunks.append((start, end))

    _progress_counter = multiprocessing.Value('i', 0)
    t_analysis = time.time()

    try:
        with multiprocessing.Pool(num_workers) as pool:
            async_result = pool.map_async(_process_chunk, chunks)

            while not async_result.ready():
                time.sleep(0.15)
                elapsed = time.time() - t_analysis
                _print_progress_bar(_progress_counter.value, total, elapsed)

            _print_progress_bar(total, total, time.time() - t_analysis)
            print()

            results = async_result.get()
    except Exception:
        # Fallback to single-threaded if multiprocessing fails
        _progress_counter = None
        for i, pkt in enumerate(_shared_packets):
            packet_detection(pkt)
            if (i + 1) % 2000 == 0:
                _print_progress_bar(i + 1, total, time.time() - t_analysis)
        _print_progress_bar(total, total, time.time() - t_analysis)
        print()
        results = None

    if results is not None:
        _merge_worker_results(results)

    # Rebuild packets list for --output (single append per matched packet)
    packets = []
    for pkt in _shared_packets:
        if _matches_filter(pkt):
            packets.append(pkt)

    t_total = time.time() - t0
    print(indent + f"[*] Analysis complete in {t_total:.1f}s")

    _shared_packets = None  # Free memory
    print_summary()

# Packet Processing
def packet_detection(packet):
    # Passive VLAN collection
    if packet.haslayer(Dot1Q):
        discovered_vlans[packet[Dot1Q].vlan] += 1

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
        packets.append(packet)
        try:
            system_id = packet[0][MACsec][MACsecSCI].system_identifier
        except:
            system_id = "Not Found"
        if not is_duplicate("MACSec", (system_id,)):
            print()
            print(Fore.WHITE + "[*] Detected MACSec")
            print(Fore.YELLOW + "[*] Most likely the infrastructure used is 802.1X-2010, keep in mind")
            print(Fore.GREEN + "[*] System Identifier: " + Fore.WHITE + str(system_id))

    # OSPF
    if packet.haslayer(OSPF_Hdr):
        packets.append(packet)
        src_router = str(packet[OSPF_Hdr].src)
        area = str(packet[OSPF_Hdr].area)
        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        if packet.haslayer(IP):
            track_host(packet[IP].src, mac_src, "OSPF")
        if not is_duplicate("OSPF", (src_router, area)):
            def hex_to_string(hex):
                if hex[:2] == '0x':
                    hex = hex[2:]
                string_value = bytes.fromhex(hex).decode('utf-8')
                return string_value
            print()
            print(Fore.WHITE + "[+] Detected OSPF Packet")
            print(Fore.GREEN + "[+] Attack Impact: " + Fore.YELLOW + "Subnets Discovery, Route Injection, Routing Table Overflow")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki, Scapy, FRRouting")
            print(Fore.GREEN + "[*] OSPF Area ID: " + Fore.WHITE + area)
            print(Fore.GREEN + "[*] OSPF Neighbor IP: " + Fore.WHITE + src_router)
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
        packets.append(packet)
        peer_ip = str(packet[IP].src) if packet.haslayer(IP) else 'Unknown'
        my_as = str(packet[BGPOpen].my_as) if packet.haslayer(BGPOpen) else 'N/A'
        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        track_host(peer_ip, mac_src, "BGP")
        if not is_duplicate("BGP", (peer_ip, my_as)):
            print()
            print(Fore.WHITE + "[+] Detected BGP Packet")
            print(Fore.GREEN + "[+] Attack Impact: " + Fore.YELLOW + "Route Hijacking")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Scapy, FRRouting")

            bgp_header = packet.getlayer(BGPHeader)
            if bgp_header:
                print(Fore.GREEN + "[*] BGP Header Fields: " + Fore.WHITE + str(bgp_header.fields))

            if packet.haslayer(BGPOpen):
                bgp_open = packet.getlayer(BGPOpen)
                print(Fore.GREEN + "[*] Source AS Number: " + Fore.WHITE + str(bgp_open.my_as))
                print(Fore.GREEN + "[*] Peer IP: " + Fore.WHITE + peer_ip)
                print(Fore.GREEN + "[*] Hold Time: " + Fore.WHITE + str(bgp_open.hold_time))

            print(Fore.GREEN + "[*] Peer MAC: " + Fore.WHITE + mac_src)

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Use authentication, filter routes")
            # Vendor
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # HSRP (v1)
    if packet.haslayer(HSRP) and packet[HSRP].state == 16:
        packets.append(packet)
        group = str(packet[HSRP].group)
        virtual_ip = str(packet[HSRP].virtualIP)
        priority = str(packet[HSRP].priority)
        src_ip = str(packet[IP].src) if packet.haslayer(IP) else 'Unknown'
        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        track_host(src_ip, mac_src, "HSRP")
        if not is_duplicate("HSRP", (group, virtual_ip, priority)):
            print()
            print(Fore.WHITE + "[+] Detected HSRP Packet")
            print(Fore.GREEN + "[*] HSRP Active Router Priority: " + Fore.WHITE + priority)
            print(Fore.GREEN + "[+] Attack Impact: " + Fore.YELLOW + "MITM")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki, Scapy, Yersinia")
            print(Fore.GREEN + "[*] HSRP Group Number: " + Fore.WHITE + group)
            print(Fore.GREEN + "[+] HSRP Virtual IP Address: " + Fore.WHITE + virtual_ip)
            print(Fore.GREEN + "[*] HSRP Sender IP: " + Fore.WHITE + src_ip)
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
            packets.append(packet)
            src_ip = str(packet[IP].src)
            mac_src = get_mac_from_packet(packet)
            vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
            track_host(src_ip, mac_src, "HSRPv2")
            if not is_duplicate("HSRPv2", (src_ip, mac_src)):
                print()
                print(Fore.WHITE + "[+] Detected HSRPv2 Packet")
                print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "MITM")
                print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki, Scapy")
                # Caution
                print(Fore.YELLOW + "[!] HSRPv2 has not yet been implemented in Scapy")
                print(Fore.YELLOW + "[!] Check priority and state manually using Wireshark")
                print(Fore.YELLOW + "[!] If the Active Router priority is less than 255 and you were able to break MD5 authentication, you can do a MITM")
                print(Fore.GREEN + "[*] HSRPv2 Sender MAC: " + Fore.WHITE + mac_src)
                print(Fore.GREEN + "[*] HSRPv2 Sender IP: " + Fore.WHITE + src_ip)
                # Mitigation
                print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Priority 255, Authentication, Extended ACL")
                # Vendor
                print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # VRRPv2
    if packet.haslayer(VRRP):
        packets.append(packet)

        if packet.haslayer(AH):
            src_ip_ah = str(packet[IP].src) if packet.haslayer(IP) else 'Unknown'
            if not is_duplicate("VRRPv2", ("AH", src_ip_ah)):
                print()
                print(Fore.WHITE + "[+] Detected VRRPv2 Packet")
                print(Fore.YELLOW + "[!] Authentication: AH Header detected, VRRP packet is encrypted")
            return 0

        vrid = str(packet[VRRP].vrid)
        src_ip = str(packet[IP].src) if packet.haslayer(IP) else 'Unknown'
        priority = str(packet[VRRP].priority)
        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        track_host(src_ip, mac_src, "VRRPv2")
        if not is_duplicate("VRRPv2", (vrid, src_ip, priority)):
            print()
            print(Fore.WHITE + "[+] Detected VRRPv2 Packet")
            print(Fore.GREEN + "[*] VRRPv2 Master Router Priority: " + Fore.WHITE + priority)
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "MITM")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Scapy, Loki")
            print(Fore.GREEN + "[*] VRRPv2 Group Number: " + Fore.WHITE + vrid)
            print(Fore.GREEN + "[*] VRRPv2 Sender IP: " + Fore.WHITE + src_ip)
            print(Fore.GREEN + "[*] VRRPv2 Virtual IP Address: " + Fore.WHITE + ', '.join(packet[VRRP].addrlist))
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
        packets.append(packet)
        vrid = str(packet[VRRPv3].vrid)
        src_ip = str(packet[IP].src) if packet.haslayer(IP) else 'Unknown'
        priority = str(packet[VRRPv3].priority)
        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        track_host(src_ip, mac_src, "VRRPv3")
        if not is_duplicate("VRRPv3", (vrid, src_ip, priority)):
            print()
            print(Fore.WHITE + "[+] Detected VRRPv3 Packet")
            print(Fore.GREEN + "[*] VRRPv3 master router priority: " + Fore.WHITE + priority)
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "MITM")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Scapy, Loki")
            print(Fore.GREEN + "[*] VRRPv3 Group Number: " + Fore.WHITE + vrid)
            print(Fore.GREEN + "[*] VRRPv3 Sender IP: " + Fore.WHITE + src_ip)
            print(Fore.GREEN + "[*] VRRPv3 Sender MAC: " + Fore.WHITE + mac_src)
            print(Fore.GREEN + "[*] VRRPv3 Virtual IP Address: " + Fore.WHITE + ', '.join(packet[VRRPv3].addrlist))

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Filter VRRP traffic using ACL")
            # Vendor
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # GLBP
    if packet.haslayer(IP) and packet.haslayer(UDP):
        if packet[IP].dst == "224.0.0.102" and packet[UDP].dport == 3222:
            packets.append(packet)
            src_ip = str(packet[IP].src)
            mac_src = get_mac_from_packet(packet)
            vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
            track_host(src_ip, mac_src, "GLBP")
            if not is_duplicate("GLBP", (src_ip, mac_src)):
                print()
                print(Fore.WHITE + "[+] Detected GLBP Packet")
                print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "MITM")
                print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki")
                # Caution
                print(Fore.YELLOW + "[!] GLBP has not yet been implemented by Scapy")
                print(Fore.YELLOW + "[!] Check AVG router priority values manually using Wireshark")
                print(Fore.YELLOW + "[!] If the AVG router's priority value is less than 255, you have a chance of launching a MITM attack.")
                print(Fore.GREEN + "[*] GLBP Sender MAC: " + Fore.WHITE + mac_src)
                print(Fore.GREEN + "[*] GLBP Sender IP: " + Fore.WHITE + src_ip)

                # Mitigation
                print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Priority 255, Authentication")
                # Vendor
                print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)        

    # DTP
    if packet.haslayer(DTP):
        packets.append(packet)
        mac_src = get_mac_from_packet(packet, protocol="DTP")
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        if not is_duplicate("DTP", (mac_src,)):
            print()
            print(Fore.WHITE + "[+] Detected DTP Frame")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "VLAN Segmentation Bypass")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Yersinia, Scapy")
            print(Fore.GREEN + "[*] DTP Neighbor MAC: " + Fore.WHITE + mac_src)

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable DTP")
            # Vendor
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)


    # STP
    if packet.haslayer(STP):
        packets.append(packet)
        root_switch_mac = get_mac_from_packet(packet, protocol="STP")
        root_id = str(packet[STP].rootid)
        vendor = get_mac_vendor(root_switch_mac) if root_switch_mac != 'Unknown' else 'N/A'
        if not is_duplicate("STP", (root_switch_mac, root_id)):
            print()
            print(Fore.WHITE + "[+] Detected STP Frame")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Partial MITM")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Yersinia, Scapy")
            print(Fore.GREEN + "[*] STP Root Switch MAC: " + Fore.WHITE + root_switch_mac)
            print(Fore.GREEN + "[*] STP Root ID: " + Fore.WHITE + root_id)
            print(Fore.GREEN + "[*] STP Root Path Cost: " + Fore.WHITE + str(packet[STP].pathcost))

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Enable BPDU Guard or Portfast")
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)
 
    # CDP
    if packet.haslayer(CDPv2_HDR):
        packets.append(packet)
        hostname = packet[CDPMsgDeviceID].val.decode() if packet.haslayer(CDPMsgDeviceID) else "Unknown"
        os_version = packet[CDPMsgSoftwareVersion].val.decode() if packet.haslayer(CDPMsgSoftwareVersion) else "Unknown"
        platform = packet[CDPMsgPlatform].val.decode() if packet.haslayer(CDPMsgPlatform) else "Unknown"
        port_id = packet[CDPMsgPortID].iface.decode() if packet.haslayer(CDPMsgPortID) else "Unknown"
        ip_address = packet[CDPAddrRecordIPv4].addr if packet.haslayer(CDPAddrRecordIPv4) else "Not Found"
        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        if not is_duplicate("CDP", (hostname, port_id)):
            print()
            print(Fore.WHITE + "[+] Detected CDP Frame")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Information Gathering, CDP Flood/Spoofing")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Wireshark, Yersinia")
            print(Fore.GREEN + "[*] Hostname: " + Fore.WHITE + hostname)
            print(Fore.GREEN + "[*] OS Version: " + Fore.WHITE + os_version)
            print(Fore.GREEN + "[*] Platform: " + Fore.WHITE + platform)
            print(Fore.GREEN + "[*] Port ID: " + Fore.WHITE + port_id)
            print(Fore.GREEN + "[*] IP Address: " + Fore.WHITE + ip_address)
            print(Fore.GREEN + "[*] CDP Neighbor MAC: " + Fore.WHITE + mac_src)
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable CDP if not required, be careful with VoIP")


    # EIGRP
    if packet.haslayer(EIGRP):
        packets.append(packet)
        asn = str(packet[EIGRP].asn)
        if packet.haslayer(IP):
            neighbor_ip = str(packet[IP].src)
        elif packet.haslayer(IPv6):
            neighbor_ip = str(packet[IPv6].src)
        else:
            neighbor_ip = 'Unknown'
        neighbor_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(neighbor_mac) if neighbor_mac != 'Unknown' else 'N/A'
        track_host(neighbor_ip, neighbor_mac, "EIGRP")
        if not is_duplicate("EIGRP", (asn, neighbor_ip)):
            print()
            print(Fore.WHITE + "[+] Detected EIGRP Packet")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Subnets Discovery, Route Injection, Routing Table Overflow")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki, Scapy, FRRouting")
            print(Fore.GREEN + "[*] AS Number: " + Fore.WHITE + asn)
            print(Fore.GREEN + "[*] EIGRP Neighbor IP: " + Fore.WHITE + neighbor_ip)
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
        packets.append(packet)

        try:
            llmnr_query_name = packet[LLMNRQuery].qd.qname.decode()
        except:
            llmnr_query_name = "Not Found"

        try:
            llmnr_trans_id = packet[LLMNRQuery].id
        except:
            llmnr_trans_id = "Not Found"

        if packet.haslayer(IP):
            ip_src = packet[IP].src
        elif packet.haslayer(IPv6):
            ip_src = packet[IPv6].src
        else:
            return

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        track_host(ip_src, mac_src, "LLMNR")
        if llmnr_query_name != "Not Found":
            discovered_hostnames[llmnr_query_name].add(ip_src)
        if not is_duplicate("LLMNR", (llmnr_query_name, ip_src)):
            print()
            print(Fore.WHITE + "[+] Detected LLMNR Packet")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "LLMNR Spoofing, Credentials Interception")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Responder")
            print(Fore.GREEN + "[*] LLMNR Query Name: " + Fore.WHITE + llmnr_query_name)
            print(Fore.GREEN + "[*] LLMNR Packet Transaction ID: " + Fore.WHITE + str(llmnr_trans_id))
            print(Fore.GREEN + "[*] LLMNR Sender IP: " + Fore.WHITE + ip_src)
            print(Fore.GREEN + "[*] LLMNR Sender MAC: " + Fore.WHITE + mac_src)

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable LLMNR")
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # NBT-NS
    if packet.haslayer(UDP) and packet[UDP].dport == 137:
        packets.append(packet)

        try:
            question_name = str(packet[0]["NBNS registration request"].QUESTION_NAME.decode())
        except:
            question_name = "Not Found"

        try:
            trans_id = str(packet[0]["NBNS Header"].NAME_TRN_ID)
        except:
            trans_id = "Not Found"

        sender_ip = str(packet[0][IP].src) if packet.haslayer(IP) else 'Unknown'
        Sender_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(Sender_mac) if Sender_mac != 'Unknown' else 'N/A'
        track_host(sender_ip, Sender_mac, "NBT-NS")
        if question_name != "Not Found":
            discovered_hostnames[question_name].add(sender_ip)
        if not is_duplicate("NBT-NS", (question_name, sender_ip)):
            print()
            print(Fore.WHITE + "[+] Detected NBT-NS Packet")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "NBT-NS Spoofing, Credentials Interception")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Responder")
            print(Fore.GREEN + "[*] NBT-NS Question Name: " + Fore.WHITE + question_name)
            print(Fore.GREEN + "[*] NBT-NS Packet Transaction ID: " + Fore.WHITE + trans_id)
            print(Fore.GREEN + "[*] NBT-NS Sender IP: " + Fore.WHITE + sender_ip)
            print(Fore.GREEN + "[*] NBT-NS Sender MAC: " + Fore.WHITE + Sender_mac)

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable NBT-NS")
            # Vendor
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # MDNS
    if packet.haslayer(UDP) and packet[UDP].dport == 5353:
        packets.append(packet)

        if packet.haslayer(IP):
            ip_src = str(packet[IP].src)
        elif packet.haslayer(IPv6):
            ip_src = str(packet[IPv6].src)
        else:
            ip_src = 'Unknown'

        mac_src = get_mac_from_packet(packet)
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        track_host(ip_src, mac_src, "mDNS")
        if not is_duplicate("mDNS", (ip_src, mac_src)):
            print()
            print(Fore.WHITE + "[+] Detected MDNS Packet")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "MDNS Spoofing, Credentials Interception")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Responder")
            print(Fore.YELLOW + "[*] MDNS Spoofing works specifically against Windows machines")
            print(Fore.YELLOW + "[*] You cannot get NetNTLMv2-SSP from Apple devices")
            print(Fore.GREEN + "[*] MDNS Sender IP: " + Fore.WHITE + ip_src)
            print(Fore.GREEN + "[*] MDNS Sender MAC: " + Fore.WHITE + mac_src)

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE +  "Monitor mDNS traffic with IDS, this protocol can't just be turned off")
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # EAPOL
    if packet.haslayer(EAPOL):
        packets.append(packet)
        version = packet[EAPOL].version
        if not is_duplicate("EAPOL", (version,)):
            print()
            print(Fore.WHITE + "[+] Detected EAPOL")
            if version == 3:
                print (Fore.YELLOW + "[*] 802.1X Version: 2010")
            elif version == 2:
                print (Fore.YELLOW + "[*] 802.1X Version: 2004")
            elif version == 1:
                print (Fore.YELLOW + "[*] 802.1X Version: 2001")
            else:
                print (Fore.YELLOW + "[*] 802.1X Version: Unknown")
      
    # DHCP Discover
    if packet.haslayer(UDP) and packet[UDP].dport == 67 and packet.haslayer(DHCP):
        packets.append(packet)
        dhcp_options = packet[DHCP].options
        for option in dhcp_options:
            if option[0] == 'message-type' and option[1] == 1:
                mac_src = get_mac_from_packet(packet)
                vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
                if not is_duplicate("DHCP", (mac_src,)):
                    print()
                    print(Fore.WHITE + "[+] Detected DHCP Discovery")
                    print(Fore.YELLOW + "[*] DHCP Discovery can lead to unauthorized network configuration")
                    print(Fore.GREEN + "[*] DHCP Client IP: " + Fore.WHITE + "0.0.0.0 (Broadcast)")
                    print(Fore.GREEN + "[*] DHCP Sender MAC: " + Fore.WHITE + mac_src)

                    # Mitigation
                    print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Use DHCP Snooping")
                    # Vendor
                    print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # IGMP
    if packet.haslayer(IGMP):
        packets.append(packet)
        igmp_type = packet[IGMP].type
        igmp_types = {
            0x11: "Membership Query", 0x12: "Version 1 - Membership Report",
            0x16: "Version 2 - Membership Report", 0x17: "Leave Group", 0x22: "Version 3 - Membership Report"
        }
        igmp_type_description = igmp_types.get(igmp_type, "Unknown IGMP Type")
        sender_ip = str(packet[IP].src) if packet.haslayer(IP) else 'Unknown'
        dst_ip = str(packet[IP].dst) if packet.haslayer(IP) else 'Unknown'
        mac_src = get_mac_from_packet(packet)
        track_host(sender_ip, mac_src, "IGMP")
        if not is_duplicate("IGMP", (sender_ip, str(igmp_type), dst_ip)):
            print()
            print(Fore.WHITE + f"[+] Detected IGMP Packet: {igmp_type_description}")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "IGMP Sniffing, IGMP Flood")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Scapy, Wireshark")
            print(Fore.YELLOW + "[*] IGMP is used to manage multicast groups")
            print(Fore.YELLOW + "[*] IGMP types include queries, reports, and leaves")
            print(Fore.GREEN + "[*] IGMP Sender IP: " + Fore.WHITE + sender_ip)
            print(Fore.GREEN + "[*] Multicast Address: " + Fore.WHITE + dst_ip)

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "If there is a lot of multicast traffic, use IGMP Snooping")  
    
    # ICMPv6 RS
    if packet.haslayer(ICMPv6ND_RS):
        packets.append(packet)
        source_ipv6 = str(packet[IPv6].src) if packet.haslayer(IPv6) else 'Unknown'
        mac_src = get_mac_from_packet(packet)
        track_host(source_ipv6, mac_src, "ICMPv6 RS")
        if not is_duplicate("ICMPv6 RS", (source_ipv6,)):
            print()
            print(Fore.WHITE + "[+] Detected ICMPv6 Router Solicitation (RS)")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Potential for DoS attacks and network reconnaissance")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Scapy")
            print(Fore.YELLOW + "[*] ICMPv6 RS messages are used by devices to locate routers")
            print(Fore.GREEN + "[*] IPv6 Source Address: " + Fore.WHITE + source_ipv6)
            print(Fore.GREEN + "[*] Target of Solicitation: " + Fore.WHITE + "All Routers Multicast Address (typically ff02::2)")
    
    # LLDP
    if packet.haslayer(LLDPDU):
        packets.append(packet)
        hostname = packet[LLDPDUSystemName].system_name.decode() if packet.haslayer(LLDPDUSystemName) and isinstance(packet[LLDPDUSystemName].system_name, bytes) else packet[LLDPDUSystemName].system_name if packet.haslayer(LLDPDUSystemName) else "Not Found"
        os_version = packet[LLDPDUSystemDescription].description.decode() if packet.haslayer(LLDPDUSystemDescription) and isinstance(packet[LLDPDUSystemDescription].description, bytes) else packet[LLDPDUSystemDescription].description if packet.haslayer(LLDPDUSystemDescription) else "Not Found"
        port_id = packet[LLDPDUPortID].id.decode() if packet.haslayer(LLDPDUPortID) and isinstance(packet[LLDPDUPortID].id, bytes) else packet[LLDPDUPortID].id if packet.haslayer(LLDPDUPortID) else "Not Found"
        source_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(source_mac) if source_mac != 'Unknown' else 'N/A'

        try:
            lldp_mgmt_address_bytes = packet[LLDPDUManagementAddress].management_address
            decoded_mgmt_address = socket.inet_ntoa(lldp_mgmt_address_bytes)
        except:
            decoded_mgmt_address = "Not Found"

        if not is_duplicate("LLDP", (hostname, port_id)):
            print()
            print(Fore.WHITE + "[+] Detected LLDP Frame")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Information Gathering")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Wireshark")
            print(Fore.GREEN + "[*] Hostname: " + Fore.WHITE + hostname)
            print(Fore.GREEN + "[*] OS Version: " + Fore.WHITE + os_version)
            print(Fore.GREEN + "[*] Port ID: " + Fore.WHITE + port_id)
            print(Fore.GREEN + "[*] IP Address: " + Fore.WHITE + decoded_mgmt_address)
            print(Fore.GREEN + "[*] LLDP Source MAC: " + Fore.WHITE + source_mac)

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable LLDP if not required, be careful with VoIP")
            # Vendor
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # MNDP
    if packet.haslayer(UDP) and packet[UDP].sport == 5678 and packet[UDP].dport == 5678:
        packets.append(packet)

        if packet.haslayer(IP):
            Sender_ip = str(packet[IP].src)
        elif packet.haslayer(IPv6):
            Sender_ip = str(packet[IPv6].src)
        else:
            Sender_ip = "Unknown"

        Sender_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(Sender_mac) if Sender_mac != 'Unknown' else 'N/A'
        track_host(Sender_ip, Sender_mac, "MNDP")
        if not is_duplicate("MNDP", (Sender_ip, Sender_mac)):
            print()
            print(Fore.WHITE + "[+] Detected MNDP Packet")
            print(Fore.WHITE + "[*] MikroTik device may have been detected")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Information Gathering")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Wireshark")
            print(Fore.GREEN + "[*] MNDP Sender IP: " + Fore.WHITE + Sender_ip)
            print(Fore.GREEN + "[*] MNDP Sender MAC: " + Fore.WHITE + Sender_mac)

            print(Fore.YELLOW + "[*] You can get more information from the packet in Wireshark")
            print(Fore.YELLOW + "[*] The MNDP protocol is not yet implemented in Scapy")

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Disable MNDP if not required")
            # Vendor
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # DHCPv6
    if packet.haslayer(UDP) and (packet[UDP].sport == 546):
        packets.append(packet)
        mac_src = get_mac_from_packet(packet)
        ip_src = str(packet[IPv6].src) if packet.haslayer(IPv6) else 'Unknown'
        vendor = get_mac_vendor(mac_src) if mac_src != 'Unknown' else 'N/A'
        track_host(ip_src, mac_src, "DHCPv6")
        if not is_duplicate("DHCPv6", (mac_src, ip_src)):
            print()
            print(Fore.WHITE + "[+] Detected DHCPv6 Solicit Packet. It seems that someone is trying to obtain an address via DHCPv6.")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "DHCPv6 Spoofing, DNS Spoofing with mitm6")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "mitm6")
            print(Fore.GREEN + "[*] DHCPv6 Sender MAC: " + Fore.WHITE + mac_src)
            print(Fore.GREEN + "[*] DHCPv6 Sender IP: " + Fore.WHITE + ip_src)

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Enable DHCPv6 Snooping, Monitor DHCPv6 traffic with IDS")
            # Vendor
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # SSDP
    if packet.haslayer(UDP) and packet[UDP].dport == 1900:
        packets.append(packet)

        if packet.haslayer(IP):
            ip_src = str(packet[IP].src)
        elif packet.haslayer(IPv6):
            ip_src = str(packet[IPv6].src)
        else:
            ip_src = 'Unknown'

        source_mac = get_mac_from_packet(packet)
        vendor = get_mac_vendor(source_mac) if source_mac != 'Unknown' else 'N/A'
        track_host(ip_src, source_mac, "SSDP")
        if not is_duplicate("SSDP", (ip_src, source_mac)):
            print()
            print(Fore.WHITE + "[+] Detected SSDP Packet")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Potential for UPnP Device Exploitation, MITM")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "evil-ssdp")
            print(Fore.YELLOW + "[*] Not every SSDP packet tells you that an attack is possible")
            print(Fore.GREEN + "[*] SSDP Source IP: " + Fore.WHITE + ip_src)
            print(Fore.GREEN + "[*] SSDP Source MAC: " + Fore.WHITE + source_mac)

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: "+ Fore.WHITE +  "Ensure UPnP is disabled on all devices unless absolutely necessary, monitor UPnP and SSDP traffic")
            # Vendor
            print(Fore.MAGENTA + "[*] Vendor: " + Fore.WHITE + vendor)

    # Modbus TCP (Request & Response Detecton)
    if packet.haslayer(ModbusADURequest):
        packets.append(packet)
        src_ip = packet[IP].src if packet.haslayer(IP) else 'Unknown'
        dst_ip = packet[IP].dst if packet.haslayer(IP) else 'Unknown'
        dport = str(packet[TCP].dport) if packet.haslayer(TCP) else 'Unknown'
        mac_src = packet[Ether].src if packet.haslayer(Ether) else 'Unknown'
        mac_dst = packet[Ether].dst if packet.haslayer(Ether) else 'Unknown'
        track_host(src_ip, mac_src, "Modbus Req")
        track_host(dst_ip, mac_dst, "Modbus Req")
        if not is_duplicate("Modbus Req", (src_ip, dst_ip, dport)):
            print()
            print(Fore.WHITE + "[+] Detected Modbus ADU Request Packet")
            print(Fore.YELLOW + "[!] SCADA device may have been detected")
            print(Fore.GREEN + "[*] Transaction ID: " + Fore.WHITE + str(packet[ModbusADURequest].transId))
            print(Fore.GREEN + "[*] Protocol ID: " + Fore.WHITE + str(packet[ModbusADURequest].protoId))
            print(Fore.GREEN + "[*] Unit ID: " + Fore.WHITE + str(packet[ModbusADURequest].unitId))

            if packet.haslayer(Ether):
                print(Fore.YELLOW + "[+] Source MAC: " + Fore.WHITE + mac_src)
                print(Fore.YELLOW + "[+] Destination MAC: " + Fore.WHITE + mac_dst)
                print(Fore.MAGENTA + "[*] Source Vendor: " + Fore.WHITE + get_mac_vendor(mac_src))
                print(Fore.MAGENTA + "[*] Destination Vendor: " + Fore.WHITE + get_mac_vendor(mac_dst))
            if packet.haslayer(IP):
                print(Fore.YELLOW + "[+] Source IP: " + Fore.WHITE + src_ip)
                print(Fore.YELLOW + "[+] Destination IP: " + Fore.WHITE + dst_ip)
            if packet.haslayer(TCP):
                print(Fore.WHITE + "[+] Source TCP Port: " + Fore.WHITE + str(packet[TCP].sport))
                print(Fore.WHITE + "[+] Destination TCP Port: " + Fore.WHITE + dport)

    if packet.haslayer(ModbusADUResponse):
        packets.append(packet)
        src_ip = packet[IP].src if packet.haslayer(IP) else 'Unknown'
        dst_ip = packet[IP].dst if packet.haslayer(IP) else 'Unknown'
        dport = str(packet[TCP].dport) if packet.haslayer(TCP) else 'Unknown'
        mac_src = packet[Ether].src if packet.haslayer(Ether) else 'Unknown'
        mac_dst = packet[Ether].dst if packet.haslayer(Ether) else 'Unknown'
        track_host(src_ip, mac_src, "Modbus Resp")
        track_host(dst_ip, mac_dst, "Modbus Resp")
        if not is_duplicate("Modbus Resp", (src_ip, dst_ip, dport)):
            print()
            print(Fore.WHITE + "[+] Detected Modbus ADU Response Packet")
            print(Fore.YELLOW + "[!] SCADA device may have been detected")
            print(Fore.GREEN + "[*] Transaction ID: " + Fore.WHITE + str(packet[ModbusADUResponse].transId))
            print(Fore.GREEN + "[*] Protocol ID: " + Fore.WHITE + str(packet[ModbusADUResponse].protoId))
            print(Fore.GREEN + "[*] Unit ID: " + Fore.WHITE + str(packet[ModbusADUResponse].unitId))

            if packet.haslayer(Ether):
                print(Fore.YELLOW + "[+] Source MAC: " + Fore.WHITE + mac_src)
                print(Fore.YELLOW + "[+] Destination MAC: " + Fore.WHITE + mac_dst)
                print(Fore.MAGENTA + "[*] Source Vendor: " + Fore.WHITE + get_mac_vendor(mac_src))
                print(Fore.MAGENTA + "[*] Destination Vendor: " + Fore.WHITE + get_mac_vendor(mac_dst))
            if packet.haslayer(IP):
                print(Fore.YELLOW + "[+] Source IP: " + Fore.WHITE + src_ip)
                print(Fore.YELLOW + "[+] Destination IP: " + Fore.WHITE + dst_ip)
            if packet.haslayer(TCP):
                print(Fore.WHITE + "[+] Source TCP Port: " + Fore.WHITE + str(packet[TCP].sport))
                print(Fore.WHITE + "[+] Destination TCP Port: " + Fore.WHITE + dport)

    # OMRON
    if packet.haslayer(UDP) and packet[UDP].dport == 9600:
        packets.append(packet)
        src_ip = packet[IP].src if packet.haslayer(IP) else 'Unknown'
        dst_ip = packet[IP].dst if packet.haslayer(IP) else 'Unknown'
        mac_src = packet[Ether].src if packet.haslayer(Ether) else 'Unknown'
        mac_dst = packet[Ether].dst if packet.haslayer(Ether) else 'Unknown'
        track_host(src_ip, mac_src, "OMRON")
        track_host(dst_ip, mac_dst, "OMRON")
        if not is_duplicate("OMRON", (src_ip, dst_ip)):
            print()
            print(Fore.WHITE + "[+] Possible OMRON packet detection")
            print(Fore.YELLOW + "[!] SCADA device may have been detected")
            if packet.haslayer(Ether):
                print(Fore.YELLOW + "[+] Source MAC: " + Fore.WHITE + mac_src)
                print(Fore.YELLOW + "[+] Destination MAC: " + Fore.WHITE + mac_dst)
                print(Fore.MAGENTA + "[*] Source Vendor: " + Fore.WHITE + get_mac_vendor(mac_src))
                print(Fore.MAGENTA + "[*] Destination Vendor: " + Fore.WHITE + get_mac_vendor(mac_dst))
            if packet.haslayer(IP):
                print(Fore.YELLOW + "[+] Source IP: " + Fore.WHITE + src_ip)
                print(Fore.YELLOW + "[+] Destination IP: " + Fore.WHITE + dst_ip)
            if packet.haslayer(UDP):
                print(Fore.WHITE + "[+] Source UDP Port: " + Fore.WHITE + str(packet[UDP].sport))
                print(Fore.WHITE + "[+] Destination UDP Port: " + Fore.WHITE + str(packet[UDP].dport))

    # S7COMM
    if packet.haslayer(TCP) and packet[TCP].dport == 102:
        packets.append(packet)
        src_ip = packet[IP].src if packet.haslayer(IP) else 'Unknown'
        dst_ip = packet[IP].dst if packet.haslayer(IP) else 'Unknown'
        mac_src = packet[Ether].src if packet.haslayer(Ether) else 'Unknown'
        mac_dst = packet[Ether].dst if packet.haslayer(Ether) else 'Unknown'
        track_host(src_ip, mac_src, "S7COMM")
        track_host(dst_ip, mac_dst, "S7COMM")
        if not is_duplicate("S7COMM", (src_ip, dst_ip)):
            print()
            print(Fore.WHITE + "[+] Possible S7COMM packet detection")
            print(Fore.YELLOW + "[!] SCADA device may have been detected")
            if packet.haslayer(Ether):
                print(Fore.YELLOW + "[+] Source MAC: " + Fore.WHITE + mac_src)
                print(Fore.YELLOW + "[+] Destination MAC: " + Fore.WHITE + mac_dst)
                print(Fore.MAGENTA + "[*] Source Vendor: " + Fore.WHITE + get_mac_vendor(mac_src))
                print(Fore.MAGENTA + "[*] Destination Vendor: " + Fore.WHITE + get_mac_vendor(mac_dst))
            if packet.haslayer(IP):
                print(Fore.YELLOW + "[+] Source IP: " + Fore.WHITE + src_ip)
                print(Fore.YELLOW + "[+] Destination IP: " + Fore.WHITE + dst_ip)
            if packet.haslayer(TCP):
                print(Fore.WHITE + "[+] Source TCP Port: " + Fore.WHITE + str(packet[TCP].sport))
                print(Fore.WHITE + "[+] Destination TCP Port: " + Fore.WHITE + str(packet[TCP].dport))

    # TACACS+
    if packet.haslayer(TacacsHeader):
        packets.append(packet)
        header = packet[TacacsHeader]
        session_id = header.session_id
        type_val = header.type
        src_ip = packet[IP].src if packet.haslayer(IP) else 'Unknown'
        dst_ip = packet[IP].dst if packet.haslayer(IP) else 'Unknown'
        mac_src = get_mac_from_packet(packet)
        track_host(src_ip, mac_src, "TACACS+")
        if not is_duplicate("TACACS+", (str(session_id), str(type_val))):
            print()
            print(Fore.WHITE + "[+] Detected TACACS Packet")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "Loki")
            print(Fore.YELLOW + "[!] To capture TACACS+ traffic and brute force the key, you need MITM")
            print(Fore.GREEN + "[+] TACACS Type: " + Fore.WHITE + f"{type_val}")
            print(Fore.GREEN + "[+] TACACS Flags: " + Fore.WHITE + f"{header.flags}")
            print(Fore.GREEN + "[+] TACACS Session ID: " + Fore.WHITE + f"{session_id}")
            print(Fore.GREEN + "[+] TACACS Length: " + Fore.WHITE + f"{header.length}")

            if packet.haslayer(IP):
                print(Fore.GREEN + "[*] Source IP: " + Fore.WHITE + f"{src_ip}")
                print(Fore.GREEN + "[*] Destination IP: " + Fore.WHITE + f"{dst_ip}")

            # Further analysis
            if type_val == 1:  # Authentication
                print(Fore.YELLOW + "[*] TACACS Authentication Request Detected")
            elif type_val == 2:  # Authorization
                print(Fore.YELLOW + "[*] TACACS Authorization Request Detected")
            elif type_val == 3:  # Accounting
                print(Fore.YELLOW + "[*] TACACS Accounting Request Detected")

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Use strong passwords, monitor unusual activities")

    # SNMP
    if packet.haslayer(UDP) and packet[UDP].dport == 161:
        packets.append(packet)
        src_ip = str(packet[IP].src) if packet.haslayer(IP) else 'Unknown'
        dst_ip = str(packet[IP].dst) if packet.haslayer(IP) else 'Unknown'
        community = str(packet[SNMP].community) if packet.haslayer(SNMP) else 'Unknown'
        mac_src = get_mac_from_packet(packet)
        track_host(src_ip, mac_src, "SNMP")
        if not is_duplicate("SNMP", (src_ip, community)):
            print()
            print(Fore.WHITE + "[+] Detected SNMP Packet")
            print(Fore.GREEN + "[*] Attack Impact: " + Fore.YELLOW + "Information Gathering")
            print(Fore.GREEN + "[*] Tools: " + Fore.WHITE + "onesixtyone, snmpwalk, snmp_enum (Metasploit)")

            if packet.haslayer(IP):
                print(Fore.GREEN + "[*] Source IP: " + Fore.WHITE + f"{src_ip}")
                print(Fore.GREEN + "[*] Destination IP: " + Fore.WHITE + f"{dst_ip}")

            # Checking for SNMP community string
            if packet.haslayer(SNMP):
                print(Fore.GREEN + "[*] SNMP Community String: " + Fore.WHITE + f"{community}")

                # Warning for default community strings
                if community.lower() in ["public", "private"]:
                    print(Fore.YELLOW + "[!] Warning: Default SNMP community string used ('public' or 'private'). This is a security risk!")

            # Mitigation
            print(Fore.CYAN + "[*] Mitigation: " + Fore.WHITE + "Restrict SNMP access, use strong community strings, monitor SNMP traffic")

# list for packets processing
packets = []

# Deduplication
seen_findings = set()                    # (protocol, key_tuple)
finding_counts = defaultdict(int)        # protocol -> total packet count

# Network intelligence (collected during packet_detection)
discovered_hosts = {}                    # ip -> {"macs": set(), "protocols": set(), "vendor": str}
discovered_vlans = defaultdict(int)      # vlan_id -> frame count
discovered_hostnames = defaultdict(set)  # hostname -> set of IPs that queried it

# Processing mode
_quiet_mode = False
_shared_packets = None
_progress_counter = None

def is_duplicate(protocol, key):
    """Returns True if already seen (or in quiet mode). Always tracks state."""
    finding_counts[protocol] += 1
    finding_key = (protocol, key)
    already_seen = finding_key in seen_findings
    if not already_seen:
        seen_findings.add(finding_key)
    if _quiet_mode:
        return True  # Suppress prints but keep tracking
    return already_seen

def track_host(ip, mac, protocol):
    """Records host in discovered_hosts. Skips multicast/broadcast."""
    if not ip or ip == 'Unknown':
        return
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_multicast or ip in ('255.255.255.255', '0.0.0.0'):
            return
    except ValueError:
        return

    if ip not in discovered_hosts:
        discovered_hosts[ip] = {"macs": set(), "protocols": set(), "vendor": "Unknown Vendor"}
    discovered_hosts[ip]["protocols"].add(protocol)
    if mac and mac not in ('Unknown', 'Unknown (Cooked Capture)'):
        discovered_hosts[ip]["macs"].add(mac)
        discovered_hosts[ip]["vendor"] = get_mac_vendor(mac)

def print_summary():
    """Print network intelligence summary."""
    if not finding_counts and not discovered_hosts:
        return

    print()
    print(Fore.WHITE + "=" * 60)
    print(Fore.WHITE + "[*] Network Intelligence Summary")
    print(Fore.WHITE + "=" * 60)

    # Host table
    if discovered_hosts:
        print()
        print(Fore.WHITE + f"[*] Discovered Hosts ({len(discovered_hosts)} total):")
        print(Fore.GREEN + f"  {'IP Address':<18}{'MAC Address':<20}{'Vendor':<22}{'Protocols'}")
        def _ip_sort_key(ip):
            try:
                addr = ipaddress.ip_address(ip)
                return (addr.version, int(addr))
            except ValueError:
                return (99, 0)
        for ip in sorted(discovered_hosts.keys(), key=_ip_sort_key):
            info = discovered_hosts[ip]
            mac = ', '.join(sorted(info['macs'])) if info['macs'] else 'N/A'
            vendor = info['vendor'][:20]
            protocols = ', '.join(sorted(info['protocols']))
            print(Fore.WHITE + f"  {ip:<18}{mac:<20}{vendor:<22}{protocols}")

    # VLANs
    if discovered_vlans:
        print()
        print(Fore.WHITE + "[*] VLAN IDs Found:")
        for vlan_id, count in sorted(discovered_vlans.items()):
            print(Fore.GREEN + f"  VLAN {vlan_id:<14}{count} frames")

    # Queried hostnames
    if discovered_hostnames:
        print()
        print(Fore.WHITE + "[*] Queried Hostnames:")
        for hostname, ips in sorted(discovered_hostnames.items()):
            queriers = ', '.join(sorted(ips))
            print(Fore.GREEN + f"  {hostname:<25}queried by {queriers}")

    # Protocol detection counts
    if finding_counts:
        print()
        print(Fore.WHITE + "[*] Protocol Detections:")
        for protocol, total in sorted(finding_counts.items(), key=lambda x: -x[1]):
            unique = sum(1 for k in seen_findings if k[0] == protocol)
            print(Fore.GREEN + f"  {protocol:<25}{unique} unique, {total} packets")

    # Discovered subnets (last)
    if discovered_hosts:
        subnets = defaultdict(int)
        for ip in discovered_hosts:
            try:
                addr = ipaddress.ip_address(ip)
                if isinstance(addr, ipaddress.IPv4Address):
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    subnets[str(network)] += 1
            except ValueError:
                pass
        if subnets:
            print()
            print(Fore.WHITE + "[*] Discovered Subnets:")
            for subnet, count in sorted(subnets.items()):
                print(Fore.GREEN + f"  {subnet:<25}{count} hosts")

    print(Fore.WHITE + "=" * 60)

_PROTOCOL_INFO = {
    "MACSec":      {"impact": "802.1X-2010 infrastructure detected",                    "tools": "Wireshark",                                        "mitigation": "N/A"},
    "OSPF":        {"impact": "Subnets Discovery, Route Injection, Routing Table Overflow", "tools": "Loki, Scapy, FRRouting",                      "mitigation": "Passive interfaces, Authentication, Extended ACL"},
    "BGP":         {"impact": "Route Hijacking",                                        "tools": "Scapy, FRRouting",                                 "mitigation": "Use authentication, filter routes"},
    "HSRP":        {"impact": "MITM",                                                   "tools": "Loki, Scapy, Yersinia",                            "mitigation": "Priority 255, Authentication, Extended ACL"},
    "HSRPv2":      {"impact": "MITM",                                                   "tools": "Loki, Scapy",                                     "mitigation": "Priority 255, Authentication, Extended ACL"},
    "VRRPv2":      {"impact": "MITM",                                                   "tools": "Scapy, Loki",                                     "mitigation": "Authentication, Filter VRRP traffic using ACL"},
    "VRRPv3":      {"impact": "MITM",                                                   "tools": "Scapy, Loki",                                     "mitigation": "Filter VRRP traffic using ACL"},
    "GLBP":        {"impact": "MITM",                                                   "tools": "Loki",                                            "mitigation": "Priority 255, Authentication"},
    "DTP":         {"impact": "VLAN Segmentation Bypass",                               "tools": "Yersinia, Scapy",                                  "mitigation": "Disable DTP"},
    "STP":         {"impact": "Partial MITM",                                           "tools": "Yersinia, Scapy",                                  "mitigation": "Enable BPDU Guard or Portfast"},
    "CDP":         {"impact": "Information Gathering, CDP Flood/Spoofing",              "tools": "Wireshark, Yersinia",                              "mitigation": "Disable CDP if not required"},
    "EIGRP":       {"impact": "Subnets Discovery, Route Injection, Routing Table Overflow", "tools": "Loki, Scapy, FRRouting",                      "mitigation": "Enable passive interfaces, use authentication"},
    "LLMNR":       {"impact": "LLMNR Spoofing, Credentials Interception",               "tools": "Responder",                                       "mitigation": "Disable LLMNR"},
    "NBT-NS":      {"impact": "NBT-NS Spoofing, Credentials Interception",             "tools": "Responder",                                       "mitigation": "Disable NBT-NS"},
    "mDNS":        {"impact": "mDNS Spoofing, Credentials Interception",               "tools": "Responder",                                       "mitigation": "Monitor mDNS traffic with IDS"},
    "EAPOL":       {"impact": "802.1X authentication detected",                         "tools": "N/A",                                             "mitigation": "N/A"},
    "DHCP":        {"impact": "Unauthorized network configuration",                     "tools": "N/A",                                             "mitigation": "Use DHCP Snooping"},
    "IGMP":        {"impact": "IGMP Sniffing, IGMP Flood",                              "tools": "Scapy, Wireshark",                                 "mitigation": "Use IGMP Snooping"},
    "ICMPv6 RS":   {"impact": "DoS, Network Reconnaissance",                           "tools": "Scapy",                                           "mitigation": "N/A"},
    "LLDP":        {"impact": "Information Gathering",                                  "tools": "Wireshark",                                        "mitigation": "Disable LLDP if not required"},
    "MNDP":        {"impact": "Information Gathering (MikroTik)",                       "tools": "Wireshark",                                        "mitigation": "Disable MNDP if not required"},
    "DHCPv6":      {"impact": "DHCPv6 Spoofing, DNS Spoofing",                         "tools": "mitm6",                                           "mitigation": "Enable DHCPv6 Snooping, Monitor with IDS"},
    "SSDP":        {"impact": "UPnP Device Exploitation, MITM",                        "tools": "evil-ssdp",                                       "mitigation": "Disable UPnP unless necessary"},
    "Modbus Req":  {"impact": "SCADA device detected",                                 "tools": "N/A",                                             "mitigation": "Network segmentation, monitor OT traffic"},
    "Modbus Resp": {"impact": "SCADA device detected",                                 "tools": "N/A",                                             "mitigation": "Network segmentation, monitor OT traffic"},
    "OMRON":       {"impact": "SCADA device detected",                                 "tools": "N/A",                                             "mitigation": "Network segmentation, monitor OT traffic"},
    "S7COMM":      {"impact": "SCADA device detected",                                 "tools": "N/A",                                             "mitigation": "Network segmentation, monitor OT traffic"},
    "TACACS+":     {"impact": "Credentials at risk",                                    "tools": "Loki",                                            "mitigation": "Use strong passwords, monitor unusual activities"},
    "SNMP":        {"impact": "Information Gathering",                                  "tools": "onesixtyone, snmpwalk, snmp_enum",                 "mitigation": "Restrict SNMP access, use strong community strings"},
}

_FINDING_KEY_LABELS = {
    "MACSec": ["System ID"], "OSPF": ["Router IP", "Area"], "BGP": ["Peer IP", "AS Number"],
    "HSRP": ["Group", "Virtual IP", "Priority"], "HSRPv2": ["Source IP", "MAC"],
    "VRRPv2": ["VRID", "Source IP", "Priority"], "VRRPv3": ["VRID", "Source IP", "Priority"],
    "GLBP": ["Source IP", "MAC"], "DTP": ["Neighbor MAC"], "STP": ["Root MAC", "Root ID"],
    "CDP": ["Hostname", "Port ID"], "EIGRP": ["ASN", "Neighbor IP"],
    "LLMNR": ["Query Name", "Sender IP"], "NBT-NS": ["Question Name", "Sender IP"],
    "mDNS": ["Sender IP", "Sender MAC"], "EAPOL": ["Version"], "DHCP": ["Sender MAC"],
    "IGMP": ["Sender IP", "Type", "Dst IP"], "ICMPv6 RS": ["Source IPv6"],
    "LLDP": ["Hostname", "Port ID"], "MNDP": ["Sender IP", "Sender MAC"],
    "DHCPv6": ["Sender MAC", "Sender IP"], "SSDP": ["Source IP", "Source MAC"],
    "Modbus Req": ["Src IP", "Dst IP", "Port"], "Modbus Resp": ["Src IP", "Dst IP", "Port"],
    "OMRON": ["Src IP", "Dst IP"], "S7COMM": ["Src IP", "Dst IP"],
    "TACACS+": ["Session ID", "Type"], "SNMP": ["Source IP", "Community"],
}

def export_excel(filepath):
    """Export findings to an Excel workbook."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
    except ImportError:
        print(Fore.RED + "[!] openpyxl required for Excel export: pip install openpyxl")
        return

    wb = Workbook()
    hdr_font = Font(bold=True, color="FFFFFF", size=11)
    hdr_fill = PatternFill(start_color="2F4F4F", end_color="2F4F4F", fill_type="solid")
    hdr_align = Alignment(horizontal="center")

    def _write_headers(ws, headers):
        for col, h in enumerate(headers, 1):
            c = ws.cell(row=1, column=col, value=h)
            c.font = hdr_font
            c.fill = hdr_fill
            c.alignment = hdr_align
        ws.freeze_panes = "A2"

    def _auto_width(ws):
        for col_cells in ws.columns:
            max_len = max((len(str(c.value or "")) for c in col_cells), default=8)
            ws.column_dimensions[col_cells[0].column_letter].width = min(max_len + 3, 60)

    def _ip_sort_key(ip):
        try:
            addr = ipaddress.ip_address(ip)
            return (addr.version, int(addr))
        except ValueError:
            return (99, 0)

    # --- Sheet 1: Findings ---
    ws = wb.active
    ws.title = "Findings"
    _write_headers(ws, ["Protocol", "Details", "Attack Impact", "Tools", "Mitigation"])
    row = 2
    for protocol, key in sorted(seen_findings):
        labels = _FINDING_KEY_LABELS.get(protocol, [])
        parts = [f"{labels[i] if i < len(labels) else 'Field'}: {v}" for i, v in enumerate(key)]
        info = _PROTOCOL_INFO.get(protocol, {})
        ws.cell(row=row, column=1, value=protocol)
        ws.cell(row=row, column=2, value=", ".join(parts))
        ws.cell(row=row, column=3, value=info.get("impact", ""))
        ws.cell(row=row, column=4, value=info.get("tools", ""))
        ws.cell(row=row, column=5, value=info.get("mitigation", ""))
        row += 1
    _auto_width(ws)

    # --- Sheet 2: Hosts ---
    ws2 = wb.create_sheet("Hosts")
    _write_headers(ws2, ["IP Address", "MAC Address", "Vendor", "Protocols"])
    row = 2
    for ip in sorted(discovered_hosts.keys(), key=_ip_sort_key):
        info = discovered_hosts[ip]
        ws2.cell(row=row, column=1, value=ip)
        ws2.cell(row=row, column=2, value=', '.join(sorted(info['macs'])) if info['macs'] else 'N/A')
        ws2.cell(row=row, column=3, value=info['vendor'])
        ws2.cell(row=row, column=4, value=', '.join(sorted(info['protocols'])))
        row += 1
    _auto_width(ws2)

    # --- Sheet 3: Protocol Stats ---
    ws3 = wb.create_sheet("Protocol Stats")
    _write_headers(ws3, ["Protocol", "Unique Findings", "Total Packets"])
    row = 2
    for protocol, total in sorted(finding_counts.items(), key=lambda x: -x[1]):
        unique = sum(1 for k in seen_findings if k[0] == protocol)
        ws3.cell(row=row, column=1, value=protocol)
        ws3.cell(row=row, column=2, value=unique)
        ws3.cell(row=row, column=3, value=total)
        row += 1
    _auto_width(ws3)

    # --- Sheet 4: VLANs ---
    if discovered_vlans:
        ws4 = wb.create_sheet("VLANs")
        _write_headers(ws4, ["VLAN ID", "Frame Count"])
        row = 2
        for vlan_id, count in sorted(discovered_vlans.items()):
            ws4.cell(row=row, column=1, value=vlan_id)
            ws4.cell(row=row, column=2, value=count)
            row += 1
        _auto_width(ws4)

    # --- Sheet 5: Hostnames ---
    if discovered_hostnames:
        ws5 = wb.create_sheet("Hostnames")
        _write_headers(ws5, ["Hostname", "Queried By"])
        row = 2
        for hostname, ips in sorted(discovered_hostnames.items()):
            ws5.cell(row=row, column=1, value=hostname)
            ws5.cell(row=row, column=2, value=', '.join(sorted(ips)))
            row += 1
        _auto_width(ws5)

    # --- Sheet 6: Subnets ---
    subnets = defaultdict(int)
    for ip in discovered_hosts:
        try:
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv4Address):
                subnets[str(ipaddress.ip_network(f"{ip}/24", strict=False))] += 1
        except ValueError:
            pass
    if subnets:
        ws6 = wb.create_sheet("Subnets")
        _write_headers(ws6, ["Subnet", "Host Count"])
        row = 2
        for subnet, count in sorted(subnets.items()):
            ws6.cell(row=row, column=1, value=subnet)
            ws6.cell(row=row, column=2, value=count)
            row += 1
        _auto_width(ws6)

    wb.save(filepath)
    print(Fore.YELLOW + f"[*] Excel report saved to {filepath}")

def _matches_filter(packet):
    """Check if packet matches any protocol filter (mirrors top of packet_detection)."""
    return (packet.haslayer(OSPF_Hdr) or packet.haslayer(CDPv2_HDR) or packet.haslayer(MACsec) or packet.haslayer(EAPOL)
        or packet.haslayer(EIGRP) or packet.haslayer(DTP) or packet.haslayer(STP) or packet.haslayer(LLDPDU)
        or packet.haslayer(HSRP) or packet.haslayer(VRRP) or packet.haslayer(VRRPv3) or packet.haslayer(ModbusADURequest)
        or packet.haslayer(ModbusADUResponse) or packet.haslayer(BGPOpen) or packet.haslayer(BGPHeader)
        or packet.haslayer(Dot1Q) or packet.haslayer(Dot3) or packet.haslayer(BOOTP) or packet.haslayer(DHCP)
        or packet.haslayer(IGMP) or packet.haslayer(ICMPv6ND_RS) or packet.haslayer(IPv6)
        or (packet.haslayer(UDP) and packet[UDP].dport in [137, 161, 5353, 5355, 5678, 3222, 546, 547, 1900, 9600])
        or (packet.haslayer(TCP) and packet[TCP].dport == 102)
        or (packet.haslayer(IP) and packet.haslayer(UDP) and packet[IP].dst == "224.0.0.102" and packet[UDP].dport == 1985))

def _get_term_width():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80

def _print_loading_bar(bytes_read, total_bytes, elapsed, pkt_count):
    """Progress bar for pcap loading phase."""
    bar_width = 30
    progress = bytes_read / total_bytes if total_bytes > 0 else 0
    filled = int(bar_width * progress)
    bar = '█' * filled + '░' * (bar_width - filled)
    pct = int(progress * 100)
    mb_read = bytes_read / (1024 * 1024)
    mb_total = total_bytes / (1024 * 1024)
    rate = mb_read / elapsed if elapsed > 0.01 else 0
    line = f'  Loading [{bar}] {pct}% {mb_read:.0f}/{mb_total:.0f}MB {rate:.0f}MB/s {pkt_count:,} pkts'
    sys.stdout.write(f'\x1b[2K\r{line[:_get_term_width() - 1]}')
    sys.stdout.flush()

def _print_progress_bar(current, total, elapsed):
    """Progress bar for analysis phase."""
    bar_width = 30
    progress = current / total if total > 0 else 0
    filled = int(bar_width * progress)
    bar = '█' * filled + '░' * (bar_width - filled)
    pct = int(progress * 100)
    rate = int(current / elapsed) if elapsed > 0.01 else 0
    eta = int((total - current) / rate) if rate > 0 else 0
    line = f'  Analyze [{bar}] {pct}% {current:,}/{total:,} pkts {rate:,}/s ETA:{eta}s'
    sys.stdout.write(f'\x1b[2K\r{line[:_get_term_width() - 1]}')
    sys.stdout.flush()

def _process_chunk(range_tuple):
    """Worker function: process a range of packets from _shared_packets."""
    global seen_findings, finding_counts, discovered_hosts, discovered_vlans, discovered_hostnames, packets, _quiet_mode

    # Reset module-level state for this worker (independent copy due to fork)
    seen_findings = set()
    finding_counts = defaultdict(int)
    discovered_hosts = {}
    discovered_vlans = defaultdict(int)
    discovered_hostnames = defaultdict(set)
    packets = []
    _quiet_mode = True

    start, end = range_tuple
    for i in range(start, end):
        packet_detection(_shared_packets[i])
        _progress_counter.value += 1

    return {
        'seen': seen_findings,
        'counts': dict(finding_counts),
        'hosts': {ip: {'macs': info['macs'], 'protocols': info['protocols'], 'vendor': info['vendor']}
                  for ip, info in discovered_hosts.items()},
        'vlans': dict(discovered_vlans),
        'hostnames': {k: v for k, v in discovered_hostnames.items()},
    }

def _merge_worker_results(results):
    """Merge results from parallel workers into module-level state."""
    global seen_findings, finding_counts, discovered_hosts, discovered_vlans, discovered_hostnames

    seen_findings = set()
    finding_counts = defaultdict(int)
    discovered_hosts = {}
    discovered_vlans = defaultdict(int)
    discovered_hostnames = defaultdict(set)

    for r in results:
        seen_findings.update(r['seen'])
        for k, v in r['counts'].items():
            finding_counts[k] += v
        for ip, info in r['hosts'].items():
            if ip not in discovered_hosts:
                discovered_hosts[ip] = {'macs': set(info['macs']), 'protocols': set(info['protocols']), 'vendor': info['vendor']}
            else:
                discovered_hosts[ip]['macs'].update(info['macs'])
                discovered_hosts[ip]['protocols'].update(info['protocols'])
                if info['vendor'] != 'Unknown Vendor':
                    discovered_hosts[ip]['vendor'] = info['vendor']
        for vlan_id, count in r['vlans'].items():
            discovered_vlans[vlan_id] += count
        for hostname, ips in r['hostnames'].items():
            discovered_hostnames[hostname].update(ips)

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
    parser.add_argument('--excel', type=str, help='Export findings to an Excel file (.xlsx)')
    parser.add_argument('--passive-arp', action='store_true', help='Passive ARP (Host Discovery)')
    parser.add_argument('--search-vlan', action='store_true', help='VLAN Search')
    args = parser.parse_args()

    def signal_handler(sig, frame):
        print("\n[!] CTRL+C pressed. Exiting...")
        print_summary()
        if args.excel:
            export_excel(args.excel)
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
            analyze_pcap(args.input)
            if packets and args.output:
                try:
                    wrpcap(args.output, packets)
                    print(Fore.YELLOW + f"\n[*] Saved {len(packets)} packets to {args.output}")
                except Exception as e:
                    print(Fore.RED + f"Error saving packets to {args.output}: {e}")
            if args.excel:
                export_excel(args.excel)
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
        print_summary()
        if args.excel:
            export_excel(args.excel)

    if packets and args.output:
            try:
                wrpcap(args.output, packets)
                print(Fore.YELLOW + f"\n[*] Saved {len(packets)} packets to {args.output}")
            except Exception as e:
                print(Fore.RED + f"Error saving packets to {args.output}: {e}")

if __name__ == "__main__":
    main()
