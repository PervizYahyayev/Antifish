import requests
from bs4 import BeautifulSoup

print("Enter IP Address")
ip_add = input()
api_key = '9be84f1aed6d157b7ebb6a3ee5cee7dea70abd1d5d6bdd9c98ed390aebf15fa3'

r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/%s" % ip_add, headers={'User-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0', 'x-apikey': '%s' % api_key}).json()
dict_web = r["data"]["attributes"]["last_analysis_results"]
tot_engine_c = 0
tot_detect_c = 0
result_eng = []
eng_name = []
count_harmless = 0 
for i in dict_web:
    tot_engine_c = 1 + tot_engine_c
    if dict_web[i]["category"] == "malicious" or dict_web[i]["category"] == "suspicious":
         result_eng.append(dict_web[i]["result"])
         eng_name.append(dict_web[i]["engine_name"])
         tot_detect_c = 1 + tot_detect_c
res = []
for i in result_eng:
    if i not in res:
        res.append(i)
result_eng = res
if tot_detect_c > 0:
    print("The %s was rated for" % ip_add + str(result_eng)[1:-1] + " on " + str(tot_detect_c) + "engines out of" + str(tot_engine_c) + " engines. the engines which reported this are: " +str(eng_name)[1:-1] + " . ")
else:
    print("The IP address has been harmless and clean on virustotal")