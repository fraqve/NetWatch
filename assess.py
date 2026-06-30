import requests

def init_data_threat(ip:str,threat:dict) -> dict:
    threat[ip] = {
        "is_flagged":{},
        "points":0,
        "risk_factors":[],
        "abuseConfidenceScore":0,
        "error":None
    }
    return threat

def calc_score_risk(result:int,threat_dict:dict,ip_adr:str,motif:str):
    if result > 0:
        threat_dict[ip_adr]["points"] += result
        threat_dict[ip_adr]["risk_factors"].append(motif)


def assess_ICMP(data:dict,ip:str,config:dict,threat:dict) -> dict:
    if ip not in threat:
        init_data_threat(ip,threat)

    # Getting how much unique ip the mahcine pinged
    ICMP_targets_count = len(data["IPs"][ip]["ICMP_targets"])

    local_result = 0
    # we have the first amount(config) pings are free no flag poitns asigned if we go above thershold we add 2 points for each ip possible ping sweep
    math_result = max(0,((ICMP_targets_count - config["ICMP_tolerance"]) * config["ICMP_risk_factor"]))
    local_result += math_result
    calc_score_risk(math_result,threat,ip,"excessive ping sweep")

    # we have the first 6 pings are free anythig above we strt adding two points because of possibel DDos
    math_result = max(0,((data["IPs"][ip]["unreachable_count"] - config["unreachable_tolerance"]) * config["unreachble_risk_factor"]))
    local_result += math_result
    calc_score_risk(math_result,threat,ip,"possible DDOS attack")

    # if we detect redirect icmp red flag
    if data["IPs"][ip]["redirect_detected"]:
        threat[ip]["points"] += config["risk_thershold_ICMP"]
        local_result += config["risk_thershold_ICMP"]
        threat[ip]["risk_factors"].append("redirect attack")
    
    threat[ip]["is_flagged"].setdefault("ICMP",False)
    if local_result >= config["risk_thershold_ICMP"]:
        threat[ip]["is_flagged"]["ICMP"] = True

    return threat


def assess_port_protocol(data:dict,ip:str,config:dict,threat:dict,protocol:str) -> dict:
    if ip not in threat:
        init_data_threat(ip,threat)

    local_result = 0
    # Getting how much unique ports the machine scanned
    ports_count = len(data["IPs"][ip][f"{protocol}_ports_scanned"])
    math_result = max(0,((ports_count - config[f"{protocol}_tolerance"]) * config[f"{protocol}_risk_factor"]))
    local_result += math_result
    calc_score_risk(math_result,threat,ip,"port scan detected")

    threat[ip]["is_flagged"].setdefault(f"{protocol}",False)
    if local_result >= config[f"risk_thershold_{protocol}"]:
        threat[ip]["is_flagged"][f"{protocol}"] = True
    
    return threat

def assess_DNS(data:dict,ip:str,config:dict,threat:dict) -> dict:
    if ip not in threat:
        init_data_threat(ip,threat)
    local_result = 0

    dns_tuneling_atempts = data["IPs"][ip]["DNS_tuneling_atempts"]
    math_result = max(0,((dns_tuneling_atempts - config["DNS_tolerance"]) * config["DNS_risk_factor"]))
    local_result += math_result
    calc_score_risk(math_result,threat,ip,"possible DNS tunneling attempt")
     
    threat[ip]["is_flagged"].setdefault("DNS",False)
    if local_result >= config["risk_thershold_DNS"]:
        threat[ip]["is_flagged"]["DNS"] = True
    
    return threat


def assess_TCP(data:dict,ip:str,config:dict,threat:dict):
    assess_port_protocol(data,ip,config,threat,"TCP")

def assess_UDP(data:dict,ip:str,config:dict,threat:dict) :
    assess_port_protocol(data,ip,config,threat,"UDP")

def check_abuseipdb(ip:str,api:str,threat:dict):
    threat[ip].setdefault("abuseConfidenceScore",0)
    threat[ip].setdefault("error",None)


    try:
        url = f"https://api.abuseipdb.com/api/v2/check"
        query_params = {
            "ipAddress":ip,
            "maxAgeInDays": "90"
        }

        query_headers = {
            'Accept': 'application/json',
            'Key': api
        }

        response = requests.get(url,headers=query_headers,params=query_params)

        if response.status_code == 200:
            raw_data = response.json()
            threat[ip]["abuseConfidenceScore"] = raw_data["data"]["abuseConfidenceScore"]
            return threat
        
        else:
            threat[ip]["error"] = f"Error:{response.status_code}"
            return threat

    except requests.ConnectionError:
        threat[ip]["error"] = "Error: no internet connexion"
        return threat

    except Exception as e:
        threat[ip]["error"] = f"An error has occured: {e}"
        return threat


def assess_all(data:dict,ip:str,config,threat:dict) -> dict:
    assess_DNS(data,ip,config,threat)
    assess_ICMP(data,ip,config,threat)
    assess_TCP(data,ip,config,threat)
    assess_UDP(data,ip,config,threat)
    return threat
