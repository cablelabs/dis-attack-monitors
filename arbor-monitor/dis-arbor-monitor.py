from quart import Quart,request, jsonify
import json, requests, logging, logging.handlers, socket, asyncio, os, argparse, dateutil.parser, time, setproctitle
from ipaddress import IPv4Address, IPv4Network, IPv6Network, ip_network, ip_address
from dis_client_sdk import DisClient
from pathlib import Path
from typing import List, Union

#disable Warning for SSL.
requests.packages.urllib3.disable_warnings()

default_log_prefix = "dis-arbor-sl-monitor"

app = Quart(__name__)
app.config['app_start_timestamp'] = time.time()

@app.route('/health', methods=['GET'])
async def stats():
    """
    Return basic information about running application.
    :return: JSON with health status
    """
    uptime: int = round(time.time() - app.config['app_start_timestamp'])
    return jsonify({"total_reports_sent": total_reports_sent,
                    "total_source_ips_reported": total_source_ips_reported,
                    "uptime_sec": uptime
                    })


@app.route('/dis/sl-webhook',methods=['POST'])
async def process_sightline_webhook_notification():
    """
    This awaits data from Sightline and then parses it into an attack object.
    Once an attack has been finished (ie ongoing is False), the client will
    query Sightline for the attack Source IPs and adds them to the attack object.

    Note: Returning a 4XX status code from this invocation can signal to Sightline
          that the webhook needs to be reinvoked.
    """
    global total_reports_sent
    global total_source_ips_reported
    global report_storage_path

    if args.webhook_token:
        token = request.args.get('token')
        if args.webhook_token != token:
            logger.warning(f"Webhook invoked with missing/invalid token - IGNORING (url requested: {request.url})")
            return jsonify({"error": "token mismatch error"}), 404, {'Content-Type': 'application/json'}

    data = await request.data
    payload = json.loads(data)
    logger.debug("Sightline notification payload:" + json.dumps(payload, indent=3))

    payload_data = payload["data"]
    attack_id = payload_data.get("id")

    attack_attributes = payload_data["attributes"]
    alert_class = attack_attributes.get("alert_class")
    alert_type = attack_attributes.get("alert_type")

    if not (alert_class == "dos" and alert_type == "dos_host_detection"):
        logger.info(f"Ignoring alert regarding non-DOS attack "
                    f"(attack ID {attack_id} is a {alert_class}/{alert_type} alert)")
        return f"Ignoring non-DOS attack report (attack {attack_id})", 200, {'Content-Type': 'text/plain'}

    if attack_attributes["ongoing"]:
        logger.info(f"Received notification of ONGOING attack (attack ID {attack_id})")
        return f"Ignoring ongoing DOS attack report (attack {attack_id})", 200, {'Content-Type': 'text/plain'}

    logger.info(f"Processing notification of COMPLETED DOS attack (Attack ID: {attack_id})")

    attack_subobjects = attack_attributes["subobject"]

    destination_ip = ip_address(attack_subobjects['host_address'])
    if any([destination_ip in network for network in args.ignore_destinations]):
        logger.info(f"Ignoring alert {attack_id}. Destination {destination_ip} is in ignore list.")
        return "Ignoring due to destination IP", 200, {'Content-Type': 'text/plain'}

    start_time = attack_attributes.get("start_time")
    stop_time = attack_attributes.get("stop_time")
    misuse_types = attack_subobjects.get("misuse_types")
    impact_bps = attack_subobjects.get("impact_bps")
    impact_pps = attack_subobjects.get("impact_pps")

    logger.info(f"Attack ID {attack_id}: Misuse Types: {misuse_types}")
    logger.info(f"Attack ID {attack_id}: Start/stop time: {start_time}/{stop_time}")
    logger.debug(f"Attack ID {attack_id}: Impact BPS: {impact_bps}")
    logger.debug(f"Attack ID {attack_id}: Impact PPS: {impact_pps}")

    response = get_src_traffic_report(attack_id)
    if response.status_code != 200:
        msg=f"Error retrieving the source traffic report for attack {attack_id}: (HTTP Status: {response.status_code} ({response.reason})) ({response.content}))"
        logger.warning(msg)
        # Returning a 404 so Netscout so we can try to retrieve the report again
        return jsonify({"error": msg}), 404, {'Content-Type': 'application/json'}

    src_traffic_report = response.json()

    if args.dry_run:
        logger.info(f"Attack ID {attack_id}: Running in DRY RUN mode - not posting/saving attack report")
    else:
        warn_msg = None
        try:
            source_ip_list = send_report_to_dis_server(attack_id, payload, src_traffic_report)
            total_reports_sent += 1
            total_source_ips_reported += len(source_ip_list)
            # TODO: These stats may reflect queuing - need to revisit
        except Exception as ex:
            warn_msg = f"Caught an exception uploading the report for attack {attack_id} ({ex})"
            logger.warning(warn_msg)

        if report_storage_path:
            try:
                save_attack_report_file(report_storage_path, args.report_store_format,
                                        attack_id, payload, src_traffic_report)
            except Exception as ex:
                warn_msg = f"Caught an exception saving the report for attack {attack_id} ({ex})"
                logger.warning(warn_msg)

    if warn_msg:
        # Not returning a 400 here so Netscout doesn't keep attempting to redeliver this attack
        #  notification (causing potential duplicate reports and backing up Netscout's notify queue)
        return jsonify({"warning": warn_msg}), 200, {'Content-Type': 'application/json'}
    else:
        return f"Thank you Netscout for the DDOS report! (attack ID {attack_id})", 200, {'Content-Type': 'text/plain'}

def check_sightline_api_supported():
    """
    Checks to ensure the Arbor SP API can be accessed and is a compatible version

    Return:
        True if the API checks out, and False otherwise
    """

    response = requests.get(f"{args.arbor_api_prefix}/api/sp",
                            verify=not args.arbor_api_insecure,
                            headers={"X-Arbux-APIToken":args.arbor_api_token})
    if response.status_code != requests.codes.ok:
        logger.error(f"Error retrieving {response.url}: (HTTP Status: {response.status_code} ({response.reason}))")
        return False

    json_response = response.json()
    api_type = json_response['meta']['api']
    api_version = int(json_response['meta']['api_version'])

    if api_type != 'SP':
        logger.error(f"Found unsupported Sightline API (found '{api_type}', expected 'SP'")
        return False

    if api_version < 6:
        logger.error(f"Found unsupported Sightline API version ({api_version} < 6)")
        return False

    logger.info(f"Found Arbor Sightline SP API version {api_version} at {response.url}")

    return True


def get_src_traffic_report(attack_id):
    # The default for this query is normally 5 source IPs. So need to make sure to over-ride the default limit
    prefix_query_limit=1000000
    response = requests.get(f"{args.arbor_api_prefix}/api/sp/v10/alerts/{attack_id}/traffic/src_prefixes/"
                            f"?query_unit=bps&query_limit={prefix_query_limit}&query_view=network",
                            verify=not args.arbor_api_insecure,
                            headers={"X-Arbux-APIToken":args.arbor_api_token})
    return response


def send_report_to_dis_server(attack_id, attack_payload, src_traffic_report):
    attack_attributes = attack_payload.get("data").get("attributes")

    attack_subobjects = attack_attributes.get("subobject")
    start_time = attack_attributes.get("start_time")
    stop_time = attack_attributes.get("stop_time")
    impact_bps = attack_subobjects.get("impact_bps")
    impact_pps = attack_subobjects.get("impact_pps")

    start_timestamp = int(dateutil.parser.isoparse(start_time).timestamp())
    stop_timestamp = int(dateutil.parser.isoparse(stop_time).timestamp())
    logger.debug(f"Attack ID {attack_id}: Start/stop timestamp: {start_timestamp}/{stop_timestamp}")

    try:
        dis_event = dis_client.add_attack_event(start_timestamp=start_timestamp,
                                                end_timestamp=stop_timestamp,
                                                attack_type=attack_subobjects.get("misuse_types"))

        # Add attributes to the attack event
        dis_client.add_attribute_to_event(event_uuid=dis_event,
                                          name="impact_bps", enum="BPS", value=impact_bps)
        dis_client.add_attribute_to_event(event_uuid=dis_event,
                                          name="impact_pps", enum="PPS", value=impact_pps)
        dis_client.add_attribute_to_event(event_uuid=dis_event,
                                          name="local_attack_id", enum="BIGINT", value=attack_id)

        # Add the source address info from the report to the event
        source_ip_list = add_source_ips_v2(dis_client, dis_event, attack_id, src_traffic_report)
        logger.info(f"Attack ID {attack_id}: Found {len(source_ip_list)} source IPs")
        logger.info(f"Attack ID {attack_id}: First 50 source IPs: {source_ip_list[0:50]}")
    except Exception as ex:
        logger.warning(f"Caught an exception adding attack report for attack ID {attack_id} ({ex})")

    try:
        staged_event_ids = dis_client.get_staged_event_ids()
        logger.info(f"Attack ID {attack_id}: Staged event IDs: {staged_event_ids}")
        # TODO: Add accessor for the DIS client base URL so we can log it
        logger.info(f"Attack ID {attack_id}: Sending report to DIS server")
        msg = dis_client.send()
        logger.info(f"Attack ID {attack_id}: Report sent/queued to DIS server ({msg})")
    except Exception as ex:
        logger.warning(f"Caught an exception uploading attack(s) ({ex})")

    return source_ip_list

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


def add_source_ips_v1(dis_event, attack_id):
    """
    Makes a request to Arbor instance for the source IP that match the Attack ID:

    Parameters:
    attack_id
    dis_client

    Returns:

    The list of source IPs added

    """
    response = requests.get(f"{args.arbor_api_prefix}/api/sp/v10/alerts/{attack_id}/source_ip_addresses",
                            verify=not args.arbor_api_insecure,
                            headers={"X-Arbux-APIToken":args.arbor_api_token})
    json_response = response.json()
    attack_source_ips = json_response['data']['attributes']['source_ips']

    if args.dry_run:
        logger.info(f"Attack ID {attack_id}: Running in DRY RUN mode - not posting attack")

    if dis_client and dis_event:
        for attack_source_ip in attack_source_ips:
            dis_client.add_attack_source_to_event(dis_event, ip=attack_source_ip)
    return attack_source_ips


def add_source_ips_v2(dis_client, dis_event, attack_id, src_traffic_report):
    """
    Populate a DIS report from a Arbor sightline traffic report

    Parameters:
        dis_event: The DIS event to populate with src data
        src_traffic_report: The Arbor Sightline source traffic report

    Returns:
        An array containing the IP addresses that were added to the DIS report

    """
    ip_list=[]
    for data_elem in src_traffic_report['data']:
        elem_id = "unknown"
        try:
            elem_id = data_elem['id']
            logger.debug(f"Attack {attack_id}: Processing network src prefix " + elem_id)
            bps_elem = data_elem['attributes']['view']['network']['unit']['bps']
            elem_name = bps_elem['name']
            elem_max_bps = bps_elem['max_value']
            logger.debug(f"    name: {elem_name}, max bps: {elem_max_bps}")
            ip_net = ip_network(elem_name)
            if isinstance(ip_net, IPv4Network):
                if ip_net.prefixlen != 32:
                    logger.debug(f"Attack {attack_id}: Found IPv4 network {elem_name} (in {elem_id}) - skipping")
                    continue
            elif isinstance(ip_net, IPv6Network):
                if ip_net.prefixlen != 128:
                    logger.debug(f"Attack {attack_id}: Found IPv6 network {elem_name} (in {elem_id}) - skipping")
                    continue
            else:
                logger.info(f"Found unexpected IP network object {ip_net} - skipping")
                continue
            # Assert: ip_net is a IPv4 or IPv6 address (not a network)
            ip_net_addr_str = str(ip_net.network_address)
            dis_client.add_attack_source_to_event(dis_event,
                                                  ip=ip_net_addr_str,
                                                  attribute_list=[
                                                      {
                                                          "enum": "BPS",
                                                          "name": "Bytes per second",
                                                          "value": str(elem_max_bps)
                                                      }])
            ip_list.append(ip_net_addr_str)
        except Exception as ex:
            logger.info(f"Error processing '{elem_id}': {ex}")

    return ip_list


def save_attack_report_file(report_storage_path, report_storage_format,
                            attack_id, attack_payload, src_traffic_report):
    """
    Create an attack report file from a Arbor sightline traffic report

    Parameters:
        report_storage_path: The directory to store the report into
        report_storage_format: "all-attributes" or "only-source-attributes
        attack_id: The Arbor Sightline attack ID
        src_traffic_report: The Arbor Sightline source traffic report

    Returns:
        The JSON that was written to the file
    """

    src_ip_info = []
    for data_elem in src_traffic_report['data']:
        elem_id = "unknown"
        try:
            elem_id = data_elem['id']
            logger.debug("Saving network src prefix " + elem_id)
            bps_elem = data_elem['attributes']['view']['network']['unit']['bps']
            elem_name = bps_elem['name']
            elem_max_bps = bps_elem['max_value']
            logger.debug(f"    name: {elem_name}, max bps: {elem_max_bps}")
            ip_net = ip_network(elem_name)
            if isinstance(ip_net, IPv4Network):
                if ip_net.prefixlen != 32:
                    logger.debug(f"Attack {attack_id}: Found IPv4 network {elem_name} (in {elem_id}) - skipping")
                    continue
            elif isinstance(ip_net, IPv6Network):
                if ip_net.prefixlen != 128:
                    logger.debug(f"Attack {attack_id}: Found IPv6 network {elem_name} (in {elem_id}) - skipping")
                    continue
            else:
                logger.info(f"Found unexpected IP network object {ip_net} - skipping")
                continue
            # Assert: ip_net is a IPv4 or IPv6 address (not a network)
            ip_net_addr_str = str(ip_net.network_address)
            src_ip_info.append({"address": ip_net_addr_str, "max_bps": elem_max_bps})
        except Exception as ex:
            logger.info(f"Error saving '{elem_id}' to file: {ex}")

    report_filepath = report_storage_path.joinpath(f"attack-src-report.{attack_id}.json")
    attack_attributes = attack_payload.get("data").get("attributes")
    attack_subobject = attack_attributes.get("subobject")
    start_time = attack_attributes.get("start_time")
    stop_time = attack_attributes.get("stop_time")

    with report_filepath.open('w') as reportfile:
        attack_report = {"attack_id": attack_id,
                         "start_time": start_time,
                         "stop_time": stop_time,
                         "source_ips": src_ip_info,
                         "report-format": report_storage_format,
                         "report-version": {"major": 1, "minor": 0}}
        if report_storage_format == "all-attributes":
            attributes = attack_subobject
        elif report_storage_format == "only-source-attributes":
            impact_bps = attack_subobject.get("impact_bps")
            impact_pps = attack_subobject.get("impact_pps")
            misuse_types = attack_subobject.get("misuse_types")
            attributes = {"impact_bps": impact_bps,
                          "impact_pps": impact_pps,
                          "misuse_types": misuse_types}
        else:
            raise ValueError(f"Unknown report_storage_format \"{report_storage_format}\"")

        attack_report.update({"attributes": attributes})

        json.dump(attack_report, reportfile, indent=4)
        logger.info(f"Saved report on attack {attack_id} to {report_filepath.absolute()}")

def start_status_reporting(report_interval_mins):
    report_task = asyncio.get_event_loop().create_task(perform_periodic_status_reports(report_interval_mins))

async def perform_periodic_status_reports(report_interval_mins):
    logger.info(f"Performing status reporting every {report_interval_mins} minutes")
    while True:
        pre_time = time.time()
        pre_count_reports = total_reports_sent
        pre_count_ips = total_source_ips_reported
        await asyncio.sleep(report_interval_mins * 60)
        time_delta = time.time() - pre_time
        report_count_delta = total_reports_sent - pre_count_reports
        ip_count_delta = total_source_ips_reported - pre_count_ips
        logger.info(f"STATUS REPORT: Sent {report_count_delta} reports (with {ip_count_delta} source IPs) in {(time_delta/60):.3} minutes")

# MAIN


def get_list_of_networks(data: str) -> List[Union[IPv4Network, IPv6Network]]:
    """
    Split sting of IP networks to a list of IP Network Objects
    >>> assert [IPv4Network('10.0.0.0/24'), IPv6Network('2001:db8::/64')] == get_list_of_networks('10.0.0.0/24 2001:db8::/64')
    >>> assert [] == get_list_of_networks('')
    :param data:
    :return:
    """
    if not data:
        return []
    return [ip_network(net) for net in data.split(' ')]


arg_parser = argparse.ArgumentParser(description='Monitors for Arbor attack events and posts source address reports "'
                                                 'to the specified event consumer')

arg_parser.add_argument ('--debug', "-d,", required=False, action='store_true',
                         default = os.environ.get('DIS_ARBORMON_DEBUG') == "True",
                         help="Enables debugging output/checks")
arg_parser.add_argument ('--dry-run', "-dr,", required=False, action='store_true',
                         default = os.environ.get('DIS_ARBORMON_DRY_RUN') == "True",
                         help="Enables a dry-tun test (doesn't upload to a server - just logs)")
arg_parser.add_argument ('--bind-address', "-a", required=False, action='store',
                         type=str, metavar="bind_address",
                         default=os.environ.get('DIS_ARBORMON_BIND_ADDRESS', "0.0.0.0"),
                         help="specify the address to bind the HTTP/HTTPS server to for receiving "
                              "Arbor SP webhook notifications (or set DIS_ARBORMON_BIND_ADDRESS)")
arg_parser.add_argument ('--bind-port', "-p", required=False, action='store', type=int,
                         default = os.environ.get('DIS_ARBORMON_BIND_PORT', 443), metavar="bind_port",
                         help="specify the port to bind the HTTP/HTTPS server to for receiving "
                              "Arbor SP webhook notifications (or set DIS_ARBORMON_BIND_PORT)")
arg_parser.add_argument ('--webhook-token', "-wt", required=False, action='store', type=str,
                         default = os.environ.get('DIS_ARBORMON_WEBHOOK_TOKEN'), metavar="token",
                         help="specify an optional token URI parameter the HTTP/HTTPS server will "
                              "require for Arbor SP webhook notifications (e.g. /dis/sl-webhook&token=abcd)"
                              "(or set DIS_ARBORMON_WEBHOOK_TOKEN)")
arg_parser.add_argument ('--cert-chain-file', "-ccf", required=False, action='store', type=open,
                         default = os.environ.get('DIS_ARBORMON_CERT_FILE'), metavar="cert_file",
                         help="the file path containing the certificate chain to use for the "
                              "HTTPS server connection for receiving Arbor SP webhook notifications "
                              "(or set DIS_ARBORMON_CERT_FILE). If not set, only HTTP webhook "
                              "connections will be supported (HTTPS will be disabled).")
arg_parser.add_argument ('--cert-key-file', "-ckf", required=False, action='store', type=open,
                         default = os.environ.get('DIS_ARBORMON_KEY_FILE'), metavar="cert_key_file",
                         help="the file path containing the key for the associated leaf certificate " 
                              "contained in the certificate chain file for the HTTPS server connection"
                              "for receiving Arbor SP webhook notification (or DIS_ARBORMON_KEY_FILE)")
arg_default = os.environ.get('DIS_ARBORMON_REST_API_PREFIX')
arg_parser.add_argument ('--arbor-api-prefix', "-aap", required=not arg_default,
                         action='store', type=str, default=arg_default, metavar="url_prefix",
                         help="Specify the Arbor API prefix to use for REST calls "
                              "(e.g. 'https://arbor001.acme.com') "
                              "(or set DIS_ARBORMON_REST_API_PREFIX)")
arg_default=os.environ.get('DIS_ARBORMON_REST_API_TOKEN')
arg_parser.add_argument ('--arbor-api-token', "-aat,", required=not arg_default,
                         action='store', type=str, default=arg_default, metavar="api_token",
                         help="Specify the Arbor API token to use for REST calls "
                              "(or DIS_ARBORMON_REST_API_TOKEN)")
arg_parser.add_argument ('--arbor-api-insecure', "-aai", required=False,
                         action='store_true', default=os.environ.get('DIS_ARBORMON_REST_API_INSECURE',False),
                         help="Disable cert checks when invoking Arbor SP API REST calls "
                              "(or DIS_ARBORMON_REST_API_INSECURE)")
arg_default=os.environ.get('DIS_ARBORMON_REPORT_API_URI')
arg_parser.add_argument ('--report-consumer-api-uri', "-rcuri", required=not arg_default,
                         action='store', type=str, default=arg_default, metavar="api_uri",
                         help="Specify the API prefix of the DIS server to submit DIS attack reports to"
                              "(or DIS_ARBORMON_REPORT_API_URI)")
arg_default=os.environ.get('DIS_ARBORMON_REPORT_API_KEY')
arg_parser.add_argument ('--report-consumer-api-key', "-rckey", required=not arg_default,
                         action='store', type=str, default=arg_default, metavar="api_key",
                         help="Specify the API key to use for submitting attack reports "
                              "(or DIS_ARBORMON_REPORT_API_KEY)")
arg_parser.add_argument ('--http-proxy', "-hpu,", required=False, action='store',
                         type=str, metavar="http_proxy",
                         default=os.environ.get('DIS_ARBORMON_HTTP_PROXY'),
                         help="Specify the HTTP/HTTPS proxy URL for sending reports to the DIS server "
                              "(or DIS_ARBORMON_HTTP_PROXY). e.g. 'http://10.0.1.11:1234', 'https://proxy.acme.com:8080'")
arg_parser.add_argument ('--max-queued-reports', "-rcmqr,", required=False, action='store',
                         type=int, metavar="max_num_queued",
                         default=os.environ.get('DIS_ARBORMON_MAX_QUEUED_REPORTS', 0),
                         help="Specify the maximum number of DIS reports to queue if/when there's a transient "
                              "issue sending a report(s) to the DIS server (or DIS_ARBORMON_MAX_QUEUED_REPORTS)")
arg_parser.add_argument ('--syslog-server', "-slsu", required=False, action='store',
                         type=str, metavar="server",
                         default=os.environ.get('DIS_ARBORMON_SYSLOG_SERVER'),
                         help="Specify a syslog server for logging error/info messages using UDP "
                              "datagrams (or DIS_ARBORMON_SYSLOG_SERVER) in the format \"server\" "
                              "or \"server:udp-port\"")
arg_parser.add_argument ('--syslog-tcp-server', "-slst", required=False, action='store',
                         type=str, metavar="tcp_server",
                         default=os.environ.get('DIS_ARBORMON_SYSLOG_TCP_SERVER'),
                         help="Specify a syslog server for logging error/info messages using a TCP "
                              "connection (or DIS_ARBORMON_SYSLOG_TCP_SERVER) in the format \"server\" "
                              "or \"server:udp-port\"")
arg_parser.add_argument ('--syslog-socket', "-sls", required=False, action='store',
                         type=str, metavar="socket_file",
                         default=os.environ.get('DIS_ARBORMON_SYSLOG_SOCKET'),
                         help="Specify a syslog named socket for logging error/info messages "
                              "(or DIS_ARBORMON_SYSLOG_SOCKET)")
arg_parser.add_argument ('--syslog-facility', "-slf", required=False, action='store',
                         type=int, metavar="syslog_facility_code",
                         default=os.environ.get('DIS_ARBORMON_SYSLOG_FACILITY',
                                                logging.handlers.SysLogHandler.LOG_USER),
                         help="Specify a syslog facility code for all syslog messages  "
                              f"(or DIS_ARBORMON_SYSLOG_FACILITY). Default: LOG_USER")
arg_parser.add_argument ('--log-prefix', "-lp", required=False, action='store',
                         type=str, metavar="prefix_string",
                         default=os.environ.get('DIS_ARBORMON_LOG_PREFIX', default_log_prefix),
                         help="Specify a prefix string for logging error/info messages "
                              "(or DIS_ARBORMON_LOG_PREFIX)")
arg_parser.add_argument ('--log-report-stats', "-lrs", required=False, action='store',
                         type=int, metavar="interval_minutes",
                         default=os.environ.get('DIS_ARBORMON_LOG_REPORT_STATS'),
                         help="Enable info-level periodic reporting of attack/report statistics "
                              "(or set DIS_ARBORMON_LOG_REPORT_STATS)")
arg_parser.add_argument ('--report-store-dir', "-repd", required=False, action='store',
                         type=str, metavar="dest-directory",
                         default=os.environ.get('DIS_ARBORMON_REPORT_STORE_DIR'),
                         help="Specify a directory to store generated json reports to "
                              "(or DIS_ARBORMON_REPORT_STORE_DIR)")
storage_format_choices=["only-source-attributes","all-attributes"]
arg_parser.add_argument ('--report-store-format', "-repf", required=False, action='store',
                         type=str, metavar="format-name", choices=storage_format_choices,
                         default=os.environ.get('DIS_ARBORMON_REPORT_STORE_FORMAT', "only-source-attributes"),
                         help="Specify the report format to use when writing reports "
                              f"(or DIS_ARBORMON_REPORT_STORE_FORMAT). One of {storage_format_choices}")
arg_parser.add_argument('--ignore-destinations', required=False, nargs='+', type=ip_network,
                        default=get_list_of_networks(os.environ.get('DIS_ARBORMON_IGNORE_DESTINATIONS')),
                        help="Specify space-separated list of DOS destination IPs to ignore. "
                        " (or DIS_ARBORMON_IGNORE_DESTINATIONS)")

args = arg_parser.parse_args()

logging_filename=None
logging_filemode=None
logging.basicConfig (level=(logging.DEBUG if args.debug else logging.INFO),
                     filename=logging_filename, filemode=logging_filemode,
                     format='%(asctime)s %(name)s: %(levelname)s %(message)s')
logger = logging.getLogger(args.log_prefix)

cert_chain_filename = args.cert_chain_file.name if args.cert_chain_file else None
cert_key_filename = args.cert_key_file.name if args.cert_key_file else None

logger.info(f"Debug: {args.debug}")
logger.info(f"Dry run: {args.dry_run}")
logger.info(f"Bind address: {args.bind_address}")
logger.info(f"Bind port: {args.bind_port}")
logger.info(f"Webhook token: ... ...{args.webhook_token[-4:] if args.webhook_token else ''}")
logger.info(f"Cert chain file: {cert_chain_filename}")
logger.info(f"Cert key file: {cert_key_filename}")
logger.info(f"Arbor API prefix: {args.arbor_api_prefix}")
logger.info(f"Arbor API token: ... ...{args.arbor_api_token[-4:] if args.arbor_api_token else ''}")
logger.info(f"DIS server API URI: {args.report_consumer_api_uri}")
logger.info(f"DIS server API key: ... ...{args.report_consumer_api_key[-4:] if args.report_consumer_api_key else ''}")
logger.info(f"DIS server max queued reports: {args.max_queued_reports}")
logger.info(f"HTTP Proxy: {args.http_proxy}")
logger.info(f"Periodic report stats logging interval (minutes): {args.log_report_stats}")
logger.info(f"Syslog UDP server: {args.syslog_server}")
logger.info(f"Syslog TCP server: {args.syslog_tcp_server}")
logger.info(f"Syslog socket: {args.syslog_socket}")
logger.info(f"Report storage directory: {args.report_store_dir}")
logger.info(f"Report storage format: {args.report_store_format}")
logger.info(f"Ignore DOS destinations list: {args.ignore_destinations}")

if args.dry_run:
    logger.info("RUNNING IN DRY-RUN MODE (not connecting/reporting to the DIS server)")
else:
    dis_client = DisClient(api_uri=args.report_consumer_api_uri, api_key=args.report_consumer_api_key,
                           staged_limit=args.max_queued_reports, http_proxy=args.http_proxy)
    try:
        dis_client_info = dis_client.get_info()
        logger.info(f"DIS client name: {dis_client_info.get('name')}")
        org = dis_client_info.get("organization")
        logger.info(f"DIS client organization: {org.get('name') if org else 'Unknown'}")
        logger.info(f"DIS client description: {dis_client_info.get('shortDescription')}")
        logger.info(f"DIS client contact: {org.get('contactEmail')}")
        client_type = dis_client_info.get("clientType")
        logger.info(f"Client type name: {client_type.get('name')}")
        logger.info(f"Client type maker: {client_type.get('maker')}")
        logger.info(f"Client type version: {client_type.get('version')}")
        # TODO: Check the maker (and version?)
    except Exception as ex:
        logger.warning(f"Error getting client info from DIS server: {ex}")

# Note: Setting up syslog after logging above here - so the above doesn't go into syslog
syslog_formatter = logging.Formatter("%(name)s: %(message)s")

if args.syslog_server:
    server_split = args.syslog_server.split(':')
    if len(server_split) > 2:
        logger.error(f"Error: The syslog hostname param cannot have more than one colon (found \"{args.syslog_server}\")")
        exit(10)
    try:
        syslog_hostname = server_split[0]
        if len(server_split) == 2:
            syslog_port = int(server_split[1])
        else:
            syslog_port = logging.handlers.SYSLOG_UDP_PORT

        syslog_handler = logging.handlers.SysLogHandler(address=(syslog_hostname, syslog_port),
                                                        facility=args.syslog_facility,
                                                        socktype=socket.SOCK_DGRAM)
        syslog_handler.setFormatter(syslog_formatter)
        logger.addHandler(syslog_handler)
    except Exception as ex:
        logger.info(f"Error creating datagram syslog handler for {args.syslog_server}: {ex}")
        exit(11)

if args.syslog_tcp_server:
    server_split = args.syslog_tcp_server.split(':')
    if len(server_split) != 2:
        logger.error(f"Error: Expecting syslog TCP server option form server:port (found \"{args.syslog_tcp_server}\")")
        exit(20)
    try:
        syslog_hostname = server_split[0]
        syslog_port = int(server_split[1])
        syslog_handler = logging.handlers.SysLogHandler(address=(syslog_hostname, syslog_port),
                                                        facility=args.syslog_facility,
                                                        socktype=socket.SOCK_STREAM)
        syslog_handler.setFormatter(syslog_formatter)
        logger.addHandler(syslog_handler)
    except Exception as ex:
        logger.info(f"Error creating syslog TCP handler for {args.syslog_tcp_server}: {ex}")
        exit(21)

if args.syslog_socket:
    try:
        syslog_handler = logging.handlers.SysLogHandler(address=args.syslog_socket,
                                                        facility=args.syslog_facility)
        syslog_handler.setFormatter(syslog_formatter)
        logger.addHandler(syslog_handler)
    except Exception as ex:
        logger.info(f"Error creating syslog named socket handler for {args.syslog_socket}: {ex}")
        exit(21)

if args.report_store_dir:
    report_storage_path = Path(args.report_store_dir)
    if not report_storage_path.is_dir():
        logger.error(f"Error: The report storage path is not a directory (dest: \"{args.report_store_dir}\")")
        exit(30)
    if not os.access(report_storage_path.absolute(), os.W_OK):
        logger.error(f"Error: The report storage path is not writable (dest: \"{args.report_store_dir}\")")
        exit(30)
else:
    report_storage_path = None

if not check_sightline_api_supported():
    logger.error("Exiting due to lack of Arbor SP API support")
    exit(0)

total_reports_sent = 0
total_source_ips_reported = 0

if args.log_report_stats:
    start_status_reporting(args.log_report_stats)

# Hide sensitive command line arguments
cur_proc_title = setproctitle.getproctitle()

if args.arbor_api_token:
    cur_proc_title = cur_proc_title.replace(args.arbor_api_token, "[token hidden]")

if args.report_consumer_api_key:
    cur_proc_title = cur_proc_title.replace(args.report_consumer_api_key, "[key hidden]")

if args.webhook_token:
    cur_proc_title = cur_proc_title.replace(args.webhook_token, "[token hidden]")

setproctitle.setproctitle(cur_proc_title)

app.run(debug=args.debug, host=args.bind_address, port=args.bind_port,
        certfile=cert_chain_filename, keyfile=cert_key_filename)
