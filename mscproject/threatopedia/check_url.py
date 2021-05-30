# -*- coding: utf-8 -*-
"""
Created on Thu Mar 25 12:02:40 2021

@author: Harshal
"""
import time
import base64
import json
import requests
import xmltodict
import pandas as pd

def check_vt(url):
    '''function doc'''
    #We cant direct request URL to VT API. First we have to encode it into base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    #Creating a session
    session = requests.Session()
    #Request Header
    session.headers = {
        'X-Apikey':'759a538f47e65a3bdb14659b05f07c98ffadcbcd75040989ff546bf36367631a'
        }
    #Making Actual API call
    response = session.get("https://www.virustotal.com/api/v3/urls/"+url_id)
    if response.status_code == 200:
        #Converting the output into JSON format
        output = json.loads(response.text)
        #Traversing the JSON data
        reputation = output["data"]["attributes"]["last_analysis_results"]
        malicious_count = 0
        category = []
        for key in reputation:
            if reputation[key]["category"] == "malicious":
                malicious_count += 1
                category.append(reputation[key]["result"])
        if malicious_count > 0:
            return(malicious_count, set(category), ""+str(malicious_count)+" security vendor flagged this URL as malicious")
        else:
            return(malicious_count, set(category), "No security vendor flagged this URL as malicious")
    else:
        pass

def check_ibm(url):
    '''function doc'''
    categories = []
    base_url = 'https://api.xforce.ibmcloud.com/url/'+url
    auth = ('7ba4f325-0822-4494-bb64-2e89e322d6cb', 'f54c8d4f-55da-4385-b284-a0a4b65b0650')
    response = requests.get(base_url, auth=auth)
    if response.status_code == 200:
        result = response.json()
        url = result['result']['url']
        category = result['result']['cats']
        score = result['result']['score']
        for key, value in category.items():
        	categories.append(key)
        if score > 0:
            return("The URL is malicious with a risk sore of "+str(score), score, categories)
        else:
            return("The URL is not identified as malicious.", score, categories)
    else:
        pass

def is_phish(url):
    '''function doc'''
    base_url = 'http://checkurl.phishtank.com/checkurl/'
    #We cant direct request URL to PhishTank. First we have to encode it.
    if "https:" in url or "http:" in url:
    #We cant direct request URL to PhishTank. First we have to encode it.
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    else:
        full_url = "http://"+url
        url_id = base64.urlsafe_b64encode(full_url.encode()).decode().strip("=")
    headers = {
        'app_key': 'a0e719d98a7923b3df8e610f278c1ca83dacd5d553af5f0806025d43526a8c72'
        }
    #Making Actual API call
    response = requests.get(base_url+url_id, headers=headers) #The received data is in XML format
    if response.status_code == 200:
        xml = response.text
        my_dict = xmltodict.parse(xml) #Converting XML to Json
        json_data = json.dumps(my_dict)
        json_data = json.loads(json_data)
        detection = json_data['response']['results']['url0']['in_database']
        if detection == 'false':
            return('The url '+url+' is not found in the PhishTank database.')
        elif detection == 'true':
            verified = json_data['response']['results']['url0']['verified']
            #reference = json_data['response']['results']['url0']['phish_detail_page']
            if verified == 'true':
                return("The url is found in the PhishTank database and verified as a phishing URL.")
            else:
                return('The url is found in the PhishTank database but not verified as a phishing URL.')
    else:
        pass
