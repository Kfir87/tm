from datetime import datetime
from time import strftime
import pandas as pd
import requests
import json


#constants
url_df = None
API_key = 'a0449e73de29487ecf451c1f10cdab40b41b17359e37e455ed29409f3823794d'
result_df = None
headers = {
    "Accept": "application/json",
    "x-apikey": API_key}

def open_csv(file_name):
    url_df = pd.read_csv(file_name, header=None)
    return url_df.values.tolist()

def get_response(site):
    url_cat = "https://www.virustotal.com/api/v3/domains/"
    url_cat = url_cat + site
    try:
        response = requests.request("GET", url_cat, headers=headers).json()
        return response
    except:
        exit(1)

# get last time the url scanned (assumption - time is UTC)
def get_last_scan(site):
    api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': API_key, 'resource': site}
    try:
        response = requests.get(api_url, params=params)
        res_json = json.loads(response.content)
        scan_time = datetime.strptime(res_json['scan_date'], '%Y-%m-%d %I:%M:%S')
        return scan_time
    except:
        exit(1)


#define risk stat
def get_risky(response):
    risky_status = response['data']['attributes']['last_analysis_stats']
    if 'malicious' in risky_status and risky_status['malicious'] > 0:
        risky_finally = 'Risk'
    elif 'phishing' in risky_status and risky_status['phishing'] > 0:
        risky_finally = 'Risk'
    elif 'malware' in risky_status and risky_status['malware'] > 0:
        risky_finally = 'Risk'
    else:
        risky_finally = 'Safe'
    return risky_finally

#get category name
#assumption - I pull the first category under categories section
def get_category(response):
    cat_status = response['data']['attributes']['categories']
    if  cat_status:
        return list(cat_status.values())[1]

#get number of votes
def get_tot_vote(response):
    votes_status = response['data']['attributes']['last_analysis_results']
    if votes_status:
        return len(votes_status) + 1

def main():
    Urls = open_csv('urls.csv')
    data = []
    for site in Urls:
        last_scan = get_last_scan(site)
        diff =  (datetime.utcnow() - last_scan).total_seconds()
        diff_min = diff/60
        if diff_min < 30:
            response = get_response(site[0])
            site_name = site[0]
            risky_status = get_risky(response)
            cat_status = get_category(response)
            tot_vot = get_tot_vote(response)
            data.append([site_name,risky_status,cat_status,tot_vot])
    result_df = pd.DataFrame(data, columns=["Site name","Risk Status","Category","Number Of Votes"])
    result_df.to_csv('results')

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
