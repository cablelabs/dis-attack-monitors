DISCLAIMER: This is a very rough README and should be replaced with a more complete README.md.

This is the tree for the mock netscout API files:
 
mock-netscout-api
├── lighttpd.conf.template
├── server-root
│   └── api
│       ├── sp
│       │   └── v6
│       │       └── alerts
│       │           ├── 5790151
│       │           │   ├── source_ip_addresses.json
│       │           │   └── traffic
│       │           │       └── src_prefixes.json
│       │           ├── 5790188
│       │           │   ├── source_ip_addresses.json
│       │           │   └── traffic
│       │           │       └── src_prefixes.json
│       │           ├── 5790226
│       │           │   ├── source_ip_addresses.json
│       │           │   └── traffic
│       │           │       └── src_prefixes.json
│       │           ├── 5790472
│       │           │   ├── source_ip_addresses.json
│       │           │   └── traffic
│       │           │       └── src_prefixes.json
│       │           ├── 5791446
│       │           │   ├── source_ip_addresses.json
│       │           │   └── traffic
│       │           │       └── src_prefixes.json
│       │           ├── 5791549
│       │           │   ├── source_ip_addresses.json
│       │           │   └── traffic
│       │           │       └── src_prefixes.json
│       │           └── 5791552
│       │               ├── source_ip_addresses.json
│       │               └── traffic
│       │                   └── src_prefixes.json
│       └── sp.json
├── start_server
├── stop_server
├── uploads
└── webhook-files
    ├── 5790188-API-get.txt
    ├── Attack-5790226-WebHook.json
    ├── Attack-5790472-WebHook.json
    ├── Attack-5791446-WebHook.json
    ├── Attack-5791549-WebHook.json
    ├── Attack-5791552-WebHook.json
    └── AttackAlert-5790151.json
 
You can sanity check the mock server by using something like:
 
curl -s http://localhost:8088/api/sp/v6/alerts/5790472/traffic/src_prefixes | head
 
Then start the client, pointing it to the local mock netscout API. e.g. from the dis-arbor-monitor directory, in a separate terminal window:
 
./setup-virtualenv
python arbor-monitor --bind-port 9080 --arbor-api-prefix http://localhost:8088 --arbor-api-token "mocktoken" --arbor-api-insecure --report-consumer-api-uri "https://api.my-dis-server" --report-consumer-api-key “myapikey” --debug
 
Then invoke a webhook for one of the attacks. E.g. from the mock-netscout-api directory
 
curl -X POST http://localhost:9080//dis/sl-webhook --data webhook-files/Attack-5790226-WebHook.json 
 
In the terminal window where you’re running the client, you should see it process the notification, access the mock netscout endpoint, and attempt to generate a report.
 
You should see something like:
 
2021-01-15 17:44:38,223 dis-arbor-sl-monitor: INFO Attack ID 5790226: Staged event IDs: ['a07b5c9a-f588-4f8d-a4ed-8002c474e55c']
2021-01-15 17:44:38,223 dis-arbor-sl-monitor: INFO Attack ID 5790226: Sending report to DIS server
2021-01-15 17:44:38,255 urllib3.connectionpool: DEBUG Starting new HTTPS connection (1): api.dissarm.net:443
2021-01-15 17:44:38,958 urllib3.connectionpool: DEBUG https://api.dissarm.net:443 "POST /v1/data?api_key=38286310-c00c-48b1-b06c-ae19813953f1 HTTP/1.1" 413 192
2021-01-15 17:44:38,961 dis-arbor-sl-monitor: WARNING Caught an exception uploading the report for attack 5790226 (server returned status code 413 (Request Entity Too Large))
Traceback (most recent call last):
  File "arbor-monitor/__main__.py", line 81, in process_sightline_webhook_notification
    source_ip_list = send_report_to_dis_server(attack_id, payload, src_traffic_report)
  File "arbor-monitor/__main__.py", line 183, in send_report_to_dis_server
    dis_client.send()
  File "arbor-monitor/dis_client_sdk/DisClient.py", line 124, in send
    raise Exception(f"server returned status code {res.status_code} ({res.reason})")
Exception: server returned status code 413 (Request Entity Too Large)

