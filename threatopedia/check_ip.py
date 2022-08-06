# -*- coding: utf-8 -*-
"""
Created on Mon Feb  8 16:38:22 2021

@author: Harshal
"""
import json
import requests

def check_abuse(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
            'ipAddress': ip
    }
    headers = {
            'Accept': 'application/json',
            'Key': '429c5fd06d3e58fba29c0d4301c256b754841cf3ffe58d7afe28fcc912dae52bb6f0dba4b8e9c504'
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    if(response.headers['X-RateLimit-Remaining'] == 0 or response.status_code == 429):
        print("Rate Limiting reached. Got 429 error!")
        exit()
    response = json.loads(response.text)
    try:
        if(response['errors'] is not None):
            return "AbuseIPDB returned an error for " + ip + " "+ response['errors'][0]['detail']
    except:
        ip = str(response['data']['ipAddress'])
        domain = str(response['data']['domain'])
        country_code = str(response['data']['countryCode'])
        isp = str(response['data']['isp'])
        score = str(response['data']['abuseConfidenceScore'])
        no_of_reported = str(response['data']['totalReports'])
        last_reported = str(response['data']['lastReportedAt'])
        data = [ip, domain, country_code, isp , score , no_of_reported , last_reported]
        return data

def check_vt(ip):
    '''function doc'''
    #We cant direct request URL to VT API. First we have to encode it into base64
    #url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    #Creating a session
    session = requests.Session()
    #Request Header
    session.headers = {
        'X-Apikey':'759a538f47e65a3bdb14659b05f07c98ffadcbcd75040989ff546bf36367631a'
        }
    #Making Actual API call
    response = session.get("https://www.virustotal.com/api/v3/ip_addresses/"+ip)
    if response.status_code == 200:
        #Converting the output into JSON format
        output = json.loads(response.text)
        malicious = output['data']['attributes']['last_analysis_stats']['malicious']
        network = output['data']['attributes']['network']
        country = output['data']['attributes']['country']
        if malicious > 0:
            return(malicious, ""+str(malicious)+" security vendor flagged this IP address "+ip+" as malicious", network, country)
        else:
            return(malicious, "No security vendor flagged this IP address "+ip+" as malicious", network, country)
    else:
        pass
