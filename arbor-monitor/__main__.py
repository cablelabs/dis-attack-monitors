from quart import Quart,request
import json, requests, logging, os, argparse
from attack import Attack

logging_filename=None
logging_filemode=None
logging.basicConfig (level=logging.DEBUG, filename=logging_filename, filemode=logging_filemode,
                     format='%(asctime)s %(name)s: %(levelname)s %(message)s')
logger = logging.getLogger ('dis-arbor-monitor')

#disable Warning for SSL.
requests.packages.urllib3.disable_warnings()

app = Quart(__name__)


@app.route('/',methods=['POST'])

async def index():
    """
    This awaits data from Arbor and then parses it into an attack object.
    Once an attack has been finished ie ongoing is False, then the code goes back out and queries for
    Source IPs and adds that to the attack object.

    """
    data = await request.data
    payload = json.loads(data)
    payload_data = payload["data"]
    attack_attributes = payload_data["attributes"]
    attack_id = payload_data.get("id")
    logger.debug("Arbor notification payload:" + json.dumps(payload, indent=3))

    if attack_attributes["ongoing"]:
        logger.info(f"Received notification of ONGOING attack (ID: {attack_id})")
    else:
        logger.info(f"Received notification of COMPLETED attack (ID: {attack_id})")
        attack = Attack(attack_id, args.report_provider_name)
        attack.start_time = attack_attributes["start_time"]
        attack.stop_time = attack_attributes["stop_time"]
        attack.stop_time = attack_attributes["stop_time"]
        attack_subobjects = attack_attributes["subobject"]
        attack.peak_pps = attack_subobjects["impact_pps"]
        attack.peak_bps = attack_subobjects["impact_bps"]
        attack.misuse_types = attack_subobjects["misuse_types"]
        attack.source_ips = get_source_ips(attack_id=attack.id)
        if len(attack.source_ips):
            event_object = attack.output()
            send_event(event_object, args.report_consumer_url)
        else:
            logger.warning(f"No source IPs found for attack {attack_id}")

    return 'hello'

def send_event(event_object, post_url):
    """
    Sends event to consumer URL.

    Parameters:
    json data to post

    Returns:
    POST request response.

    """
    logger.info(f"POSTing to {post_url}")
    logger.debug(json.dumps(event_object, indent=3))
    r = requests.post(url=post_url, json=event_object, headers={"Content-Type": "application/json"})
    logger.debug("POST response: " + r.text)

def get_source_ips(attack_id):
    """
    Makes a request to Arbor instance for the source IP that match the Attack ID:

    Parameters:
    attack_id 

    Returns:

    Array of source IPs

    """

    response = requests.get(f"{args.arbor_api_prefix}/api/sp/v6/alerts/{attack_id}/source_ip_addresses",
                            verify=False,headers={"X-Arbux-APIToken":args.arbor_api_token})
    json_response = response.json()
    source_ips = json_response['data']['attributes']['source_ips']
    logger.debug(f"Found Source IPs for attack ID {attack_id}: {source_ips}")
    return source_ips


arg_parser = argparse.ArgumentParser(description='Monitors for Arbor attack events and posts source address reports "'
                                                 'to the specified event consumer')

arg_parser.add_argument ('--bind-address', "-a", required=False, action='store', type=str,
                         default=os.environ.get('DIS_ARBOR_MON_BIND_ADDRESS') or "0.0.0.0",
                         help="specify the address to bind the monitor to for Arbor webook notifications"
                              "(or set DIS_ARBOR_MON_BIND_ADDRESS)")
arg_parser.add_argument ('--bind-port', "-p", required=False, action='store', type=int,
                         default = os.environ.get('DIS_ARBOR_MON_BIND_PORT') or 443,
                         help="specify the port to bind the HTTP/HTTPS server to "
                              "(or set DIS_ARBOR_MON_BIND_PORT)")
arg_parser.add_argument ('--cert-chain-file', "-ccf", required=False, action='store', type=open,
                         default = os.environ.get('DIS_ARBOR_MON_CERT_FILE'),
                         help="the file path containing the certificate chain to use for HTTPS connections "
                              "(or set DIS_ARBOR_MON_CERT_FILE)")
arg_parser.add_argument ('--cert-key-file', "-ckf", required=False, action='store', type=open,
                         default = os.environ.get('DIS_ARBOR_MON_KEY_FILE'),
                         help="the file path containing the key for the associated certificate file " 
                              "(or DIS_ARBOR_MON_KEY_FILE)")
arg_parser.add_argument ('--arbor-api-prefix', "-aap,", required=False, action='store', type=str,
                         default = os.environ.get('DIS_ARBOR_MON_REST_API_PREFIX'),
                         help="Specify the Arbor API prefix to use for REST calls "
                              "(e.g. 'https://arbor001.acme.com') "
                              "(or set DIS_ARBOR_MON_REST_API_PREFIX)")
arg_parser.add_argument ('--arbor-api-token', "-aat,", required=False, action='store', type=str,
                         default = os.environ.get('DIS_ARBOR_MON_REST_API_TOKEN'),
                         help="Specify the Arbor API token to use for REST calls "
                              "(or DIS_ARBOR_MON_REST_API_TOKEN)")
arg_parser.add_argument ('--report-consumer-url', "-rcu,", required=False, action='store', type=str,
                         default = os.environ.get('DIS_ARBOR_MON_REPORT_CONSUMER_URL'),
                         help="Specifies the API prefix to use for posting the attack report"
                              "(e.g. 'https://my-report-server.acme.com:8080/api/v1/data_ingester_resource/?username=crituser&api_key=abcd') "
                              "(or DIS_ARBOR_MON_REPORT_CONSUMER_URL)")
arg_parser.add_argument ('--report-provider-name', "-rpn,", required=False, action='store', type=str,
                         default = os.environ.get('DIS_ARBOR_MON_REPORT_PROVIDER_NAME'),
                         help="Specify the name of the data provider to include in the consumer reports "
                              "(or DIS_ARBOR_MON_REPORT_PROVIDER_NAME)")
arg_parser.add_argument ('--debug', "-d,", required=False, action='store_true',
                         default = os.environ.get('DIS_ARBOR_DEBUG') == "True",
                         help="Enables debugging output/checks")

args = arg_parser.parse_args ()

cert_chain_filename = args.cert_chain_file.name if args.cert_chain_file else None
cert_key_filename = args.cert_key_file.name if args.cert_key_file else None

logger.info(f"Bind address: {args.bind_address}")
logger.info(f"Bind port: {args.bind_port}")
logger.info(f"Cert chain file: {cert_chain_filename}")
logger.info(f"Cert key file: {cert_key_filename}")
logger.info(f"Arbor API prefix: {args.arbor_api_prefix}")
logger.info(f"Arbor API token: {args.arbor_api_token}")
logger.info(f"Provider name: {args.report_provider_name}")
logger.info(f"Consumer URL: {args.report_consumer_url}")
logger.info(f"Debug: {args.debug}")

app.run(debug=args.debug, host=args.bind_address, port=args.bind_port,
        certfile=cert_chain_filename, keyfile=cert_key_filename)