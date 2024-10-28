import requests
import json
import urllib.parse

import client_config as cfg

test_string = """
{
  "ProviderName": "CableLabs",
  "ingestData": [
    {
      "IPaddress": "5.7.3.8",
      "attackStartTime": "2015-08-17T15:54:11.0Z",
      "attackStopTime": "2015-08-18T15:54:11.0Z",
      "attackTypes": [
        "DNS",
        "SSDP Amplification",
        "Total Traffic"
      ],
      "totalBytesSent": 22248441867,
      "totalPacketsSent": 5976297,
      "peakBPS": 943756,
      "peakPPS": 85769,
      "sourcePort": 24355,
      "destinationPort": 5934,
      "protocol": "UDP"
    },
    {
      "IPaddress": "fd0c:eea1:601e::",
      "attackStartTime": "2015-08-17T22:35:49.0Z",
      "attackStopTime": "2015-08-18T22:35:49.0Z",
      "attackTypes": [
        "DNS Amplification",
        "TCP RST"
      ],
      "totalBytesSent": 12966108956,
      "totalPacketsSent": 3500648,
      "peakBPS": 1715682,
      "peakPPS": 56416,
      "sourcePort": 36567,
      "destinationPort": 29843,
      "protocol": "UDP"
    }
  ]
}
"""
real_string = """
{ 
   "ProviderName":"CableLabs",
   "ingestData":[ 
      { 
         "IPaddress":"51.161.12.231",
         "attackStartTime":"2020-01-22T19:48:54.0Z",
         "attackStopTime":"2020-01-22T19:54:36.0Z",
         "attackTypes":[ 
            "TCP SYN"
         ],
         "peakBPS":56416,
         "peakPPS":56416
      },
      { 
         "IPaddress":"77.247.108.77",
         "attackStartTime":"2020-01-22T19:48:54.0Z",
         "attackStopTime":"2020-01-22T19:54:36.0Z",
         "attackTypes":[ 
            "TCP SYN"
         ],
         "peakBPS":56416,
         "peakPPS":56416
      }
   ]
}




"""

event = json.loads(real_string)


post_url = "{}:{}{}{}&api_key={}".format(cfg.crits_api_url,cfg.crits_api_port,cfg.crits_api_path,cfg.crits_api_user,cfg.crits_api_token)
print(post_url)
#formatted_url=urllib.parse.quote(post_url)
r = requests.post(url=post_url,json=event)
print (r.content)
