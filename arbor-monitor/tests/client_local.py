import json
import demjson
import requests
import sys 
import jsonschema
from jsonschema import validate
from attack import Attack
from datetime import datetime


import client_config as cfg 

#disable Warning for SSL.
requests.packages.urllib3.disable_warnings()





def read_file():

    f = open("attack_payload","r")
    data = f.read()
    f.close()
    #print(data)
    payload = json.loads(data)
    payload_data = payload["data"]
    attack_attributes = payload_data["attributes"]
    print("PAYLOAD:{}".format(payload))

    #check if ongoing
    if attack_attributes["ongoing"] == "True":
        try:
            print("New/Ongoing Attack ID :{} \n Ongoing waiting".format(payload_data['id']))
        except:
            print(payload_data)
    else:
        attack_id = payload_data["id"]
        attack = Attack(attack_id)
        start_time = attack_attributes["start_time"]
        attack.start_time = attack_attributes["start_time"] 
        attack.stop_time = attack_attributes["stop_time"] 
        attack_subobjects = attack_attributes["subobject"]
        attack.peak_pps = attack_subobjects["impact_pps"]
        attack.peak_bps = attack_subobjects["impact_bps"]
        attack.misuse_types = attack_subobjects["misuse_types"]
        attack.source_ips = get_source_ips(attack_id=attack.id)
        print("Attack ID:{} \n Finished".format(attack_id))
        print("JSON:{}".format(attack.output()))

        send_event(attack)
    return 'hello'

def send_event(attack):
    post_url = "{}:{}{}{}&api_key={}".format(cfg.crits_api_url,cfg.crits_api_port,cfg.crits_api_path,cfg.crits_api_user,cfg.crits_api_token)
    print(post_url)
    #event = json.loads("{}".format(attack.output()))
    event = json.loads(attack.output())
    r = requests.post(url=post_url,json=event)
    print (r.content) 

def get_source_ips(attack_id):
    response = requests.get("https://lab-arbos01.cablelabs.com/api/sp/v6/alerts/{}/source_ip_addresses".format(attack_id),
            verify=False,headers={"X-Arbux-APIToken":cfg.arbor_token}) 
    json_response = response.json()
    print(json_response)
    source_ips = json_response['data']['attributes']['source_ips']
    print ("Source IPS:{}".format(source_ips))
    return source_ips

def get_misuse_type(attack_id):
    response = requests.get("https://lab-arbos01.cablelabs.com/api/sp/v6/alerts/{}/traffic/misuse_types".format(attack_id),
            verify=False,headers={"X-Arbux-APIToken":cfg.arbor_token}) 
    json_response = response.json()
    print(json_response)
    source_ips = json_response['data']['attributes']['source_ips']
    print ("Source IPS:{}".format(source_ips))
    return source_ips

read_file()



