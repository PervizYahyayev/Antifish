import bs4
import time
import json
import pandas
import requests
import sys

csv_doc = pandas.read_csv("domain.csv")
url_list = csv_doc['domain'].tolist()

API_KEY = '9be84f1aed6d157b7ebb6a3ee5cee7dea70abd1d5d6bdd9c98ed390aebf15fa3'
VIRUS_TOTAL_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
input_url = sys.argv[1]

url_list = []

url_list.append(input_url)

for url in url_list:
    try:
        parameters = {'apikey': API_KEY, 'resource': url}
        response = requests.get(VIRUS_TOTAL_URL, params=parameters)
        response_json = json.loads(response.text)

        code = response_json.get("response_code")

        if (code == 0):
            continue

        positives = response_json.get('positives')

        with open("responses.txt", "a") as vt:
            vt.write(str(response_json)) and vt.write('\n')

        if positives <= 0:
            print(url + " is not MALICIOUS")

        elif positives <= 3 and positives >= 1:
            print(url + " is maybe MALICIOUS")

        elif positives >= 4:
            print(url + " is MALICIOUS")

        else:
            print(url + " not found on database!")

    except ValueError:
        print("error happened")

    time.sleep(15)