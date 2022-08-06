import requests
import json
#import time

def check_hash_vt(hash_value):
    common_file_name = ""
    session = requests.Session()
    session.headers = {'X-Apikey': '759a538f47e65a3bdb14659b05f07c98ffadcbcd75040989ff546bf36367631a'}
    response = session.get("https://www.virustotal.com/api/v3/files/"+hash_value)
    if(response.status_code==200):
        output = json.loads(response.text)
        md5 = output["data"]["attributes"]["md5"]
        sha1 = output["data"]["attributes"]["sha1"]
        sha256 = output["data"]["attributes"]["sha256"]
        malicious = output["data"]["attributes"]["last_analysis_stats"]["malicious"]
        try:
            common_file_name = output["data"]["attributes"]["meaningful_name"]
        except:
            common_file_name = "None"
        cve = output["data"]["attributes"]["tags"]
        try:
            popular_threat_category = output["data"]["attributes"]["popular_threat_classification"]["popular_threat_category"]
        except:
            popular_threat_category = "None"
        try:
            popular_threat_category = popular_threat_category[0][0]
        except:
            popular_threat_category = "None"
        try:
            popular_threat_name = output["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"]
        except:
            popular_threat_name = "None"
        hash_result = str(malicious)+" secutiry vendors flagges this hash as malicious."
        if common_file_name:
            com_file_name = "Name with which this file has been submitted or seen in the wild : "+common_file_name
        vulnerability = "Vulnerability exploited by the submitted file : " + str(cve)
        threat_category = "Popular threat category :"+popular_threat_category
        threat_name = "Malware name : "+popular_threat_name
        md5 = "MD5: "+md5
        sha1 = "SHA1: "+sha1
        sha256 = "SHA256: "+sha256
        return(hash_result, com_file_name, vulnerability, threat_category, threat_name, malicious, md5, sha1, sha256)
    else:
        pass


