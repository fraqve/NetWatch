from scapy import packet
import scapy.all as scapy
from scapy.plist import PacketList


def load_pcap(file_name:str) -> PacketList:
        packets = scapy.rdpcap(file_name)
        return packets

# created a fucntion for init the base strcutrre too lazy to alwasy write it lol
def init_data() -> dict:
    data = {
        "IPs": {

        }
    }
    return data

def analyze_pcap_IP(pac:scapy.Packet, data:dict) -> dict: # Note this func should run first in main.py
    if "IP" in pac:
        # Grabbing the source and destination ip from the packet
        src_ip = pac["IP"].src
        dst_ip = pac["IP"].dst

        # Checking if the ip is already in the dict 
        if src_ip in data["IPs"]:
            data["IPs"][src_ip]["packet_count"] += 1
            # Checking if dst_ip is not in the list
            if dst_ip not in data["IPs"][src_ip]["targeted_hosts"]:
                data["IPs"][src_ip]["targeted_hosts"].append(dst_ip)
        else:
            
            # initilizing the structure of the IP and ICMP to keep it concistent so no problems later on
            data["IPs"][src_ip] ={
                "packet_count":1,
                "targeted_hosts":[dst_ip],
                "ICMP_targets":[],
                "redirect_detected":False,
                "unreachable_count":0,
                "TCP_ports_scanned":[],
                "UDP_ports_scanned":[],
                "DNS_tuneling_atempts":0
            }
    return data


def analyze_pcap_ICMP(pac:scapy.Packet,data:dict) -> dict:
    if "ICMP" in pac and "IP" in pac: # i realized there is IPv6 which maybe doesnt have the IP layer thats why we check to prevet keyerros
        # Grabbing the source and destination ip from the packet
        src_ip = pac["IP"].src
        dst_ip = pac["IP"].dst
        src_type = pac["ICMP"].type

        # Checking if the ip is already in the dict 
        if src_ip in data["IPs"]:
            # type 8 is echo request keeping a list of uniqe ip pinged
            if src_type == 8:
                # checking if dst_ip already exists
                if dst_ip not in data["IPs"][src_ip]["ICMP_targets"]:
                    data["IPs"][src_ip]["ICMP_targets"].append(dst_ip)

            # type 5 redirect possible man in the middle attack
            elif src_type == 5:
                data["IPs"][src_ip]["redirect_detected"] = True
            
            # type 3 destination unreachble possible DDOS attack
            elif src_type == 3:
                # checking if the key exitsts
                data["IPs"][src_ip]["unreachable_count"] += 1
    return data


def analyze_pcap_TCP(pac:scapy.Packet,data:dict) -> dict:
    if "TCP" in pac and "IP" in pac:
        src_ip = pac["IP"].src
        flags_ip = pac["TCP"].flags
        port = pac["TCP"].dport

        # Checking if the flag of packet is SYN
        if "S" in flags_ip:
                # checking if port already exists
                if port not in data["IPs"][src_ip]["TCP_ports_scanned"]:
                    data["IPs"][src_ip]["TCP_ports_scanned"].append(port)
    return data


def analyze_pcap_UDP(pac:scapy.Packet,data:dict) -> dict:
    if "UDP" in pac and "IP" in pac:
        src_ip = pac["IP"].src
        port = pac["UDP"].dport

        # checking if port already exists
        if port not in data["IPs"][src_ip]["UDP_ports_scanned"]:
            data["IPs"][src_ip]["UDP_ports_scanned"].append(port)

    return data
           


def analyze_pcap_DNS(pac:scapy.Packet,data:dict) -> dict:
    if "DNS" in pac and "IP" in pac:
        src_ip = pac["IP"].src

        try: # DNS query might not be present if it is an answer
            dns_query = pac["DNS"].qd.qname

            # checking query lentgh if it is equal or more than 200 possible dns tuneling atempt
            # if the dns tuenling atempt is lower then 200 bytes the tool wont catch it out of scope for v1
            if len(dns_query) >= 200:
                    data["IPs"][src_ip]["DNS_tuneling_atempts"] += 1

        except AttributeError: # If it is an answer we skip it
            pass
    return data    
