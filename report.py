from datetime import datetime

def generate_report(data:dict,threat:dict,filename:str):
    ip_found = len(data["IPs"])
    ip_flagged = 0
    report_name = f"report_{filename.replace('.pcap', '')}.txt"
    for ip in threat:
        if any(threat[ip]["is_flagged"].values()):
            ip_flagged += 1

    with open(report_name,"w") as report:
        report.write("==================================================\n")
        report.write("          THREATPROFILE DETECTION REPORT          \n")
        report.write("==================================================\n")
        report.write(f"Generated on      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"Target PCAP File  : {filename}\n")
        report.write(f"Total Unique IPs  : {ip_found}\n")
        report.write(f"Flagged Hosts     : {ip_flagged}\n")
        report.write("--------------------------------------------------\n\n")

        # Section 1: Flagged Dangerous Hosts
        report.write("FLAGGED SUSPICIOUS HOSTS:\n")
        report.write("--------------------------------------------------\n")
        if ip_flagged <= 0:
            report.write("No severe threats flags triggered.\n")
        else:
            for ip in threat:
                profile = threat[ip]
                if not any(profile["is_flagged"].values()):
                    continue

                mod_flags = ""
                for flag in profile["is_flagged"]:
                    if profile["is_flagged"][flag]:
                        mod_flags += f"{flag},"

                report.write(f"[*] IP Address: {ip}\n")
                report.write(f"    - Risk Score  : {profile['points']} pts\n")
                report.write(f"    - Modules flagged    : {mod_flags}\n")
                report.write(f"    - Indicators  : {', '.join(profile['risk_factors'])}\n")
                if profile["error"] == None:
                    report.write(f"    - Abuseipdb score  : {profile['abuseConfidenceScore']}\n")
                else:
                    report.write(f"    - Abuseipdb error  : {profile['error']}\n")

                report.write(f"    - TCP Ports Hit    : {data['IPs'][ip]['TCP_ports_scanned']}\n")
                report.write(f"    - UDP Ports Hit    : {data['IPs'][ip]['UDP_ports_scanned']}\n")
                report.write(f"    - ICMP Hosts Hit   : {data['IPs'][ip]['ICMP_targets']}\n")
                report.write("\n")

        report.write("ALL CAPTURED NETWORK TRAFFIC METRICS:\n")
        report.write("--------------------------------------------------\n")
        for ip in data["IPs"]:
            report.write(f"IP: {ip}\n")
            report.write(f"  -> Total Packets Sent : {data['IPs'][ip]['packet_count']}\n")
            report.write(f"  -> Unique IPs Targeted: {len(data['IPs'][ip]['targeted_hosts'])}\n")
            report.write(f"  -> Ports Hit (TCP/UDP): {len(data['IPs'][ip]['TCP_ports_scanned'])} / {len(data['IPs'][ip]['UDP_ports_scanned'])} ICMP target hits: {len(data['IPs'][ip]['ICMP_targets'])}\n")
            report.write(".-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-\n")
    return report_name