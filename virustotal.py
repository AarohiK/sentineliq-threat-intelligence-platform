import requests
# reads variables from a .env file and sets them in os.environ
import os 
from dotenv import load_dotenv
import ipaddress
import re

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

def check_type(ioc_value):
    try:
        ipaddress.ip_address(ioc_value)
        return extract_vt_data(check_virustotal_ip(ioc_value))
    except ValueError:
        # if not ip, check if url
        url_pattern = r"^https?://(?:www\.)?[\w.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?$"
        domain_pattern = r"^(?!https?://)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
        hash_pattern = r'^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$'

        if re.match(url_pattern, ioc_value):
            return extract_vt_data(check_virustotal_url(ioc_value))

        elif re.match(hash_pattern, ioc_value):
            return extract_vt_data(check_virustotal_hash(ioc_value))

        elif re.match(domain_pattern, ioc_value):
            return extract_vt_data(check_virustotal_domain(ioc_value))

        else:
            return None


def check_virustotal_ip(ioc):
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    headers = {"accept": "application/json",
               "x-apikey": f"{API_KEY}"}
    response = requests.get(url, headers=headers)
    return response.json()

def check_virustotal_url(ioc):

    url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": ioc}
    headers = {"accept": "application/json",
        "x-apikey": API_KEY,
        "content-type": "application/x-www-form-urlencoded"}
    response = requests.post(url,data=payload,headers=headers)
    return response.json()

def check_virustotal_hash(ioc):
    
    url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    headers = {"accept": "application/json",
               "x-apikey": f"{API_KEY}"}
    response = requests.get(url, headers=headers)
    return response.json()

def check_virustotal_domain(ioc):
    
    url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    headers = {"accept": "application/json",
               "x-apikey": f"{API_KEY}"}
    response = requests.get(url, headers=headers)
    return response.json()


def extract_vt_data(virustotal_result):

    attributes = virustotal_result["data"]["attributes"]

    return {
        "malicious": attributes["last_analysis_stats"]["malicious"],
        "suspicious": attributes["last_analysis_stats"]["suspicious"],
        "harmless": attributes["last_analysis_stats"]["harmless"],
        "undetected": attributes["last_analysis_stats"]["undetected"],

        "reputation": attributes.get("reputation"),

        "tags": attributes.get("tags",[]),

        "asn": attributes.get("asn"),
        "organization": attributes.get("as_owner"),
        "country": attributes.get("country"),

        "threat_context": attributes.get("crowdsourced_context", [])
    }


# check_type("8.8.8.8")
# check_type("google.com")
# check_type("44d88612fea8a8f36de82e1278abb02f")
# check_type("https://example.com")
# print(check_type("8.8.8.8"))