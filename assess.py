def assess_ICMP(data:dict,ip:str,config:dict,threat:dict) -> dict:
    if ip not in threat:
        threat[ip] = {
            "is_flagged":False,
            "points":0,
            "risk_factors":[]
        }

    # Getting how much unique ip the mahcine pinged
    ICMP_targets_count = len(data["IPs"][ip]["ICMP_targets"])

    # we have the first amount(config) pings are free no flag poitns asigned if we go above thershold we add 2 points for each ip possible ping sweep
    result = max(0,((ICMP_targets_count - config["ICMP_tolerance"]) * config["ICMP_risk_factor"]))
    if result > 0:
        threat[ip]["points"] += result
        threat[ip]["risk_factors"].append("excessive ping sweep")

    # we have the first 6 pings are free anythig above we strt adding two points because of possibel DDos
    result = max(0,((data["IPs"][ip]["unreachable_count"] - config["unreachable_tolerance"]) * config["unreachble_risk_factor"]))
    if result > 0:
        threat[ip]["points"] += result
        threat[ip]["risk_factors"].append("possible DDos attack")

    # if we detect redirect icmp red flag
    if data["IPs"][ip]["redirect_detected"]:
        threat[ip]["points"] += config["risk_thershold_ICMP"]
        threat[ip]["risk_factors"].append("redirect attack")
    

    if threat[ip]["points"] >= config["risk_thershold_ICMP"]:
        threat[ip]["is_flagged"] = True

    return threat


def assess_TCP(data:dict,ip:str,config:dict,threat:dict) -> dict:
    if ip not in threat:
        threat[ip] = {
            "is_flagged":False,
            "points":0,
            "risk_factors":[]
        }
    # Getting how much unique ports the machine scanned
    TCP_ports_count = len(data["IPs"][ip]["TCP_ports_scanned"])
    result = max(0,((TCP_ports_count - config["TCP_tolerance"]) * config["TCP_risk_factor"]))

    if result > 0:
        threat[ip]["points"] += result
        threat[ip]["risk_factors"].append("port scan detected")

    if threat[ip]["points"] >= config["risk_thershold_TCP"]:
        threat[ip]["is_flagged"] = True
    
    return threat


