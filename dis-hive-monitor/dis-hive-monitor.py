#!/usr/bin/env python3

#
# This software is made available according to the terms in the LICENSE.txt accompanying this code
#

import argparse
import asyncio
import copy
import pathlib
from datetime import datetime
from pathlib import Path

import json
import os
import logging
import time
import pprint
from ipaddress import IPv4Network
import setproctitle

# Import the concrete classes
from arborWsApiCaptureMonitor import ArborWsApiTrafficMonitor
# from nfacctdCaptureMonitor import NfacctdTrafficMonitor
from asnResolver import AsnResolver
from hiveMonitor import HiveMonitor
from disReportUploader import DisReportUploader

# TODO: Add proxy support for accessing Arbor/Sightline

arg_parser = argparse.ArgumentParser(description='Connects to the HIVE server and performs local scanning '
                                                 'for ongoing forged attack traffic signalled by the HIVE server. '
                                                 'Matching forged traffic sources can be reported and uploaded '
                                                 'to assist with forged traffic traceback. This service can use '
                                                 'nfacctd, Arbor NetScout, or other services to identify matching '
                                                 'flows.')
#
# General options
#
arg_parser.add_argument('--debug', '-d', required=False, action='store_true',
                        default=os.environ.get('DIS_HIVEMON_DEBUG', False),
                        help="Enable debug output/checks")
arg_parser.add_argument('--log-file', '-lf', required=False, action='store', type=open,
                        default=os.environ.get('DIS_HIVEMON_LOG_FILE'),
                        help='Specify the path and filename of the log file to write')
arg_parser.add_argument('--log-prefix', "-lp", required=False, action='store', type=str, dest="prefix_string",
                        default=os.environ.get('DIS_HIVEMON_LOG_PREFIX', ""),
                        help="Specify a prefix string for logging error/info messages "
                             "(or DIS_HIVEMON_LOG_PREFIX)")
arg_parser.add_argument('--report-status-interval', "-rsi", required=False, action='store', type=int,
                        dest='report_status_interval_s',
                        default=os.environ.get('DIS_HIVEMON_STATUS_REPORT_INTERVAL_S', 0),
                        help="the amount of time to wait between generating status reports "
                             "(or DIS_HIVEMON_STATUS_REPORT_INTERVAL_S) (0: disabled)")
arg_parser.add_argument('--dump-list-updates', "-du", required=False, action='store_true',
                        default=False, help="Print the complete attack list after every update message.")
arg_parser.add_argument('--drop-routers', "-dr", required=False, action='store', type=str,
                        default=os.environ.get('DIS_HIVEMON_DROP_ROUTERS'), dest="drop_routers",
                        help="Specify a list of one or more router names and/or IP addresses, separated with commas, "
                             f"to skip for forged traffic scanning and reporting (or DIS_HIVEMON_DROP_ROUTERS).")
arg_parser.add_argument('--only-routers', "-or", required=False, action='store', type=str,
                        default=os.environ.get('DIS_HIVEMON_ONLY_ROUTERS'), dest="only_routers",
                        help="Specify a list of one or more router names and/or IP addresses, separated with commas, "
                             f"to skip for forged traffic scanning and reporting (or DIS_HIVEMON_DROP_ROUTERS).")
arg_parser.add_argument('--drop-interface-types', "-dit", required=False, action='store', type=str,
                        default=os.environ.get('DIS_HIVEMON_DROP_INT_TYPES'), dest="drop_interface_types",
                        help="Specify a list of one or more interface type strings, separated with commas, "
                             f"to skip for forged traffic scanning and reporting (or DIS_HIVEMON_DROP_INT_TYPES).")
arg_parser.add_argument('--only-interface-types', "-oit", required=False, action='store', type=str,
                        default=os.environ.get('DIS_HIVEMON_ONLY_INT_TYPES'), dest="only_interface_types",
                        help="Specify a list of one or more interface type strings, separated with commas, "
                             f"to scan for forged traffic scanning and reporting (or DIS_HIVEMON_ONLY_INT_TYPES).")
arg_parser.add_argument('--drop-interface-asns', "-diasn", required=False, action='store', type=str,
                        default=os.environ.get('DIS_HIVEMON_DROP_INTERFACE_ASNS'), dest="drop_interface_asns",
                        help="Specify a list of interfaces, by ASN, to skip for forged traffic scanning and  "
                             f"reporting (or DIS_HIVEMON_DROP_ROUTER_NAMES).")
arg_parser.add_argument('--drop-interface-regex', "-dir", required=False, action='store', type=str,
                        default=os.environ.get('DIS_HIVEMON_DROP_INT_REGEX'), dest="drop_interface_regex",
                        help="Skip scanning router interfaces with SNMP description strings which match the "
                             f"designated regular expression. (or DIS_HIVEMON_DROP_INT_REGEX).")
arg_parser.add_argument('--only-interface-regex', "-oir", required=False, action='store', type=str,
                        default=os.environ.get('DIS_HIVEMON_ONLY_INT_REGEX'), dest="only_interface_regex",
                        help="Only scan router interfaces with SNMP description strings which match the "
                             f"designated regular expression. (or DIS_HIVEMON_ONLY_INT_REGEX).")
#
# HIVE connection options
#
hive_opt_group = arg_parser.add_argument_group(
                         title="Options for connecting to the HIVE server")
arg_default = os.environ.get('DIS_HIVEMON_HIVE_URL')
hive_opt_group.add_argument('--hive-url', "-hu", required=not arg_default,
                            action='store', type=str, default=arg_default,
                            help="Specify the URL to the HIVE server to receive honeypot attack reports "
                                 "(e.g. 'https://arbor001.acme.com') "
                                 "(or set DIS_HIVEMON_HIVE_URL)")
hive_opt_group.add_argument('--hive-client-cert-file', "-ccf", required=False, action='store', type=open,
                            default=os.environ.get('DIS_HIVEMON_HIVE_CLIENT_CERT_FILE'),
                            help="the client cert file to use when connecting to the HIVE server"
                                 "when an https HIVE URL is specified. Note that this will only "
                                 "be used if/when the server requires client cert validation. "
                                 "(or set DIS_HIVEMON_HIVE_CLIENT_CERT_FILE)")
hive_opt_group.add_argument('--hive-client-cert-key-file', "-cckf", required=False, action='store', type=open,
                            default=os.environ.get('DIS_HIVEMON_HIVE_CLIENT_CERT_KEY_FILE'),
                            help="the file containing the private key associated witn the public "
                                 "key in the specified client cert when an https HIVE URL is "
                                 "specified. Note that this will only be used if/when the server "
                                 "requires client cert validation. (or set DIS_HIVEMON_HIVE_CLIENT_CERT_KEY_FILE)")
hive_opt_group.add_argument('--hive-ca-certs-file', "-caf", required=False, action='store', type=open,
                            default=os.environ.get('DIS_HIVEMON_HIVE_CA_CERTS_FILE'),
                            help="the file containing a list of CA certificates for validating the server"
                                 "(or set DIS_HIVEMON_HIVE_CA_CERTS_FILE)")
hive_opt_group.add_argument('--hive-retry-interval', "-p", required=False, action='store', type=int,
                            default = os.environ.get('DIS_HIVEMON_HIVE_URL_RETRY_S', 30),
                            help="the retry interval for retrying the connection to the HIVE server"
                                 "if/when the connection fails (or set DIS_HIVEMON_HIVE_URL_RETRY_S)")
hive_opt_group.add_argument('--hive-proxy-url', "-hpu", required=False, action='store', type=str,
                            default=os.environ.get('DIS_HIVEMON_HIVE_PROXY',
                                                   os.environ.get('HTTPS_PROXY', os.environ.get('HTTP_PROXY'))),
                            help="Specify a proxy server to use to make the websocket connection to the HIVE server"
                                 " (or set DIS_HIVEMON_HIVE_PROXY, HTTPS_PROXY or HTTP_PROXY environment variables)")
hive_opt_group.add_argument('--add-attack-entry', "-aae", required=False, action='append', type=str,
                            dest='test_entries', default=os.environ.get('DIS_HIVEMON_ATTACK_ENTRIES'),
                            help="one or more attack entries of the form:"
                                 "{'attackId': int, 'durationMinutes': int, 'srcNetwork': str, 'destPort':int}"
                                 "(or DIS_HIVEMON_ATTACK_ENTRIES separated by ';')")
#
# ASN resolver options
#

# TODO: Add option to use Arbor to resolve ASNs
# TODO: Add options to ignore given ASNs, routers, and/or interface names/types
asn_lookup_options = arg_parser.add_argument_group(
                         title="Options for determining an ASN from a router interface name or description",
                         description="These options provide a variety of ways to map or extract "
                                     "an ASN from an interface name or description - so the source "
                                     "of captured traffic can be associated with an ASN.")
ex_asn_group = asn_lookup_options.add_mutually_exclusive_group(required=True)
ex_asn_group.add_argument('--int-name-asn-regex', "-inameregex", required=False, action='store', type=str,
                          default=os.environ.get('DIS_HIVEMON_INT_NAME_ASN_REGEX'), dest="int_name_regex",
                          help="Specify a regular expression that can be used to extract ASNs from "
                               "interface names (as group 1 of the regex) (or set DIS_HIVEMON_INT_NAME_ASN_REGEX)")
ex_asn_group.add_argument('--int-name-asn-lookup-file', "-inlfile", required=False, action='store', type=open,
                          default=os.environ.get('DIS_ HIVEMON_INT_NAME_LOOKUP_FILE'), dest="int_name_lookup_file",
                          help="Specify the file containing a list of ruleset used to determine ASN names "
                               "from interface names (or set DIS_HIVEMON_INT_NAME_LOOKUP_FILE)")
ex_asn_group.add_argument('--int-desc-asn-regex', "-idescregex", required=False, action='store', type=str,
                          default=os.environ.get('DIS_HIVEMON_INT_DESC_ASN_REGEX'), dest="int_desc_regex",
                          help="Specify the regular expression to extract the ASN from the interface description "
                               "(or DIS_HIVEMON_INT_DESC_ASN_REGEX)")
ex_asn_group.add_argument('--int-desc-asn-lookup-file', "-idlfile", required=False, action='store', type=open,
                          default=os.environ.get('DIS_HIVEMON_INT_DESC_LOOKUP_FILE'), dest="int_desc_lookup_file",
                          help="Specify the file containing a list of ruleset used to determine ASN names "
                               "from interface descriptions (or set DIS_HIVEMON_INT_DESC_LOOKUP_FILE)")
#
# Observed forged traffic report storing/forwarding options
#
reporting_options = arg_parser.add_argument_group(
                         title="Options for the storing and forwarding of Forged Address Source Traffic Reports")
reporting_options.add_argument('--dis-server-api-uri', "-dsuri", required=True, action='store', type=str,
                               default=os.environ.get('DIS_HIVEMON_DIS_API_URI'), metavar="dis_api_uri",
                               help="Specify the API prefix of the DIS server to submit DIS Forged Address "
                                    "Source Traceback (FAST) Reports (or DIS_HIVEMON_REPORT_API_URI)")
reporting_options.add_argument('--dis-server-http-proxy', "-dshp,", required=False, action='store',
                               type=str, metavar="dis_api_http_proxy",
                               default=os.environ.get('DIS_HIVEMON_DIS_API_HTTP_PROXY'),
                               help="Specify the HTTP/HTTPS proxy URL for connecting to the DIS server "
                                    "(or DIS_HIVEMON_DIS_API_HTTP_PROXY). e.g. 'http://10.0.1.11:1234'")
reporting_options.add_argument('--dis-server-client-key', "-dsckey", required=True, action='store', type=str,
                               default=os.environ.get('DIS_HIVEMON_DIS_API_CLIENT_KEY'), metavar="dis_api_client_key",
                               help="Specify the API key to use for submitting DIS FAST reports "
                                    "(or DIS_HIVEMON_DIS_API_CLIENT_KEY)")
reporting_options.add_argument ('--report-store-dir', "-repd", required=False, action='store', type=str,
                         default=os.environ.get('DIS_HIVEMON_REPORT_STORE_DIR'), dest="report_store_dir",
                         help="Specify a directory to store generated Observed Forged Source Traffic Reports reports "
                              "(or DIS_HIVEMON_REPORT_STORE_DIR)")
storage_format_choices=["only-source-attributes", "all-attributes"]
reporting_options.add_argument ('--report-store-format', "-repf", required=False, action='store', type=str,
                         default=os.environ.get('DIS_HIVEMON_REPORT_STORE_FORMAT', "only-source-attributes"),
                         dest="report_store_format", choices=storage_format_choices,
                         help="Specify the report options for writing Observed Forged Source Traffic Reports reports "
                              f"(or DIS_HIVEMON_REPORT_STORE_FORMAT). One of {storage_format_choices}")
#
# NetFlow SQL Capture Options (nfacctd schema)
#
nfsql_group = arg_parser.add_argument_group(
                  title="NetFlow SQL DB Options",
                  description="Options for connecting to a SQL DB containing nfacctd-schema netflow data.")
nfsql_group.add_argument('--nfsql-db-host', "-dbsh", required=False, action='store', type=str,
                         default=os.environ.get('DIS_HIVEMON_NFSQL_DB_HOST'), dest="nfsql_db_host",
                         help="Specify the hostname of the database server to connect to for finding "
                              "captured traffic reports corresponding to a HIVE attack "
                              "(or set DIS_HIVEMON_DB_HOST)")
nfsql_group.add_argument('--nfsql-db-port', "-dbp", required=False, action='store', type=int,
                         default=os.environ.get('DIS_HIVEMON_NFSQL_DB_PORT'), dest="nfsql_db_port",
                         help="Specify the port of the database server to connect to for finding "
                              "captured traffic reports corresponding to a HIVE attack "
                              "(or set DIS_HIVEMON_DB_PORT)")
nfsql_group.add_argument('--nfsql-db-name', "-dbn", required=False, action='store', type=str,
                         default=os.environ.get('DIS_HIVEMON_NFSQL_DB_NAME'), dest="nfsql_db_name",
                         help="Specify the name of the database to connect to for finding "
                              "captured traffic reports corresponding to a HIVE attack "
                              "(or set DIS_HIVEMON_DB_NAM)")
nfsql_group.add_argument('--nfsql-db-user', "-dbu", required=False, action='store', type=str,
                         default=os.environ.get('DIS_HIVEMON_NFSQL_DB_USER'), dest="nfsql_db_user",
                         help="Specify the username for the SQL DB server to connect to for finding "
                              "captured traffic reports corresponding to a HIVE attack "
                              "(or set DIS_HIVEMON_DB_USER)")
nfsql_group.add_argument('--nfsql-db-password', "-dbpass", required=False, action='store', type=str,
                         default=os.environ.get('DIS_HIVEMON_NFSQL_DB_PASSWORD'), dest="nfsql_db_pass",
                         help="Specify the password for the DB server to connect to for finding "
                              "captured traffic reports corresponding to a HIVE attack "
                              "(or set DIS_HIVEMON_DB_PASSWORD)")
#
# Router interrogation options
#
nfsql_group.add_argument('--nfsql-router-list-file', "-nfrlf", required=False, action='store', type=open,
                         default=os.environ.get('DIS_HIVEMON_NFSQL_SNMP_ROUTER_LIST_FILE'), dest="nfsql_router_list_file",
                         help="Specify the file containing the list of routers to poll using SNMP "
                              "(or set DIS_HIVEMON_NFSQL_SNMP_ROUTER_LIST_FILE)")
nfsql_group.add_argument('--nfsql-snmp-community', "-nfsc", required=False, action='store', type=str,
                         default=os.environ.get('DIS_HIVEMON_NFSQL_SNMP_COMMUNITY'), dest="nfsql_router_list_file",
                         help="Specify the SNMP v2 community string for polling routers "
                              "(or set DIS_HIVEMON_NFSQL_SNMP_COMMUNITY)")
nfsql_group.add_argument('--nfacctd-map-file', "-nfmap", required=False, action='store', type=str,
                         default=os.environ.get('DIS_HIVEMON_NFACCTD_MAP_FILE', '/etc/pmacct/pretag.map'),
                         dest="nfsql_nfacctd_map_file",
                         help="Specify the nfacctd map file to be written with entries corresponding "
                              "to the attacks signaled by the HIVE server. (or set DIS_HIVEMON_NFACCTD_MAP_FILE)")
nfsql_group.add_argument('--nfacctd-signal-map-cmd', "-nfsig", required=False, action='store_true',
                         default=os.environ.get('DIS_HIVEMON_NFACCTD_SIGNAL_MAP', False),
                         dest="nfsql_nfacctd_mapreload_cmd",
                         help="The nfacctd process will be signaled to reload map files a new  "
                              "nfacctd map file is written. (or set DIS_HIVEMON_NFACCTD_SIGNAL_MAP)")

#
# Arbor/Sightline Traffic Scanning Options
#
arborws_group = arg_parser.add_argument_group(
                  title="Arbor Forensics API-based Capture Options",
                  description="Options for performing forged traffic scanning using the Arbor/Sightline Forensics "
                              "webservice.")
arborws_group.add_argument('--arbor-ws-uri-prefix', "-awsuri", required=True, dest="arborws_url_prefix",
                           action='store', type=str, default=os.environ.get('DIS_HIVEMON_ARBORWS_URI_PREFIX'),
                           help="Specify the Arbor API prefix to use (or set DIS_HIVEMON_ARBORWS_URI_PREFIX)")
arborws_group.add_argument('--arbor-ws-http-proxy', "-awshp,", required=False, action='store',
                           type=str, metavar="arborws_http_proxy",
                           default=os.environ.get('DIS_HIVEMON_ARBORWS_HTTP_PROXY'),
                           help="Specify the HTTP/HTTPS proxy URL for connecting to the Arbor Web Services API "
                                "(or DIS_HIVEMON_ARBORWS_HTTP_PROXY). e.g. 'http://10.0.1.11:1234'")
arborws_group.add_argument('--arbor-ws-api-key', "-awskey", required=True, dest="arborws_api_key",
                           action='store', type=str, default=os.environ.get('DIS_HIVEMON_ARBORWS_API_KEY'),
                           help="Specify the Arbor API token to use for REST calls "
                                "(or DIS_HIVEMON_ARBORWS_API_KEY)")
arborws_group.add_argument('--arbor-ws-api-insecure', "-aai", required=False, dest="arborws_api_insecure",
                           action='store_true', default=os.environ.get('DIS_HIVEMON_ARBORWS_API_INSECURE'),
                           help="Disable cert checks when invoking Arbor SP API REST calls against https URI prefixes "
                                "(or DIS_HIVEMON_ARBORWS_API_INSECURE)")
# TODO: Add support for multi-unit value parsing (e.g. "30s", "30m", "2h", "12h", "2d")
arborws_group.add_argument('--arbor-ws-api-router-scan-period', "-awsrsp", required=False,
                           dest="arborws_router_scan_period_s", action='store', type=int,
                           default=os.environ.get('DIS_HIVEMON_ARBORWS_ROUTER_SCAN_PERIOD_S', 600),
                           help="The period to scan the Arbor router and interface APIs for the refreshing "
                                "of router/interface metadata (in seconds)")
arborws_group.add_argument('--arbor-ws-api-router-savefile', "-awsrsf", required=False,
                           dest="arborws_router_savefile", action='store', type=pathlib.Path,
                           default=os.environ.get('DIS_HIVEMON_ARBORWS_ROUTER_SAVEFILE', "arbor-router-info.json"),
                           help="A filename to load router/interface metadata from and save into when refreshing")
arborws_group.add_argument('--arbor-ws-api-forensics-scan-period', "-awsfsp", required=False,
                           dest="arborws_forensics_scan_period_s", action='store', type=int,
                           default=os.environ.get('DIS_HIVEMON_ARBORWS_FORENSICS_SCAN_PERIOD_S'),
                           help="The period to check the Arbor forensics API for HIVE-signalled attacks (in seconds)")
arborws_group.add_argument('--arbor-ws-api-forensics-scan-overlap', "-awsfso", required=False,
                           dest="arborws_forensics_scan_overlap_s", action='store', type=int,
                           default=os.environ.get('DIS_HIVEMON_ARBORWS_FORENSICS_SCAN_OVERLAP_S', 240),
                           help="The amount of time, in seconds, to check before the scan period to pickup latent "
                                "entries in the flow scan (default 240)")

args = arg_parser.parse_args()

logging_filename = None
logging_filemode = None
logging.basicConfig(level=(logging.DEBUG if args.debug else logging.INFO),
                    filename=logging_filename, filemode=logging_filemode,
                    format='%(asctime)s %(name)s: %(levelname)s %(message)s')
logger = logging.getLogger("DIS HIVEMON")

# Log all arguments except sensitive values
redacted_args = ["nfsql_db_pass", "arborws_api_key"]
logger.info("Arguments: ")
for arg, value in vars(args).items():
    redact = arg in redacted_args
    logger.info(f"   {arg}: {'<<redacted>>' if value and redact else value}")

# Hide sensitive command line arguments
cur_proc_title = setproctitle.getproctitle()

# Uncomment when attack upload support is added
# if args.report_consumer_api_key:
#     cur_proc_title = cur_proc_title.replace(args.report_consumer_api_key, "[key hidden]")

if args.nfsql_db_pass:
    cur_proc_title = cur_proc_title.replace(args.nfsql_db_pass, "[token hidden]")

if args.arborws_api_key:
    cur_proc_title = cur_proc_title.replace(args.arborws_api_key, "[token hidden]")

setproctitle.setproctitle(cur_proc_title)

hive_monitor = None

# Determine which capture monitor to instantiate based on the supplied parameters
capture_monitor = None
arborws_params = args.arborws_url_prefix or args.arborws_api_key or args.arborws_api_insecure \
                 or args.arborws_forensics_scan_period_s or args.arborws_router_scan_period_s \
                 or args.arborws_forensics_scan_overlap_s
nfsql_params = args.nfsql_db_host or args.nfsql_db_port or args.nfsql_db_name or args.nfsql_db_user \
               or args.nfsql_db_pass or args.nfsql_router_list_file or args.nfsql_nfacctd_mapreload_cmd
asn_res_params = args.int_name_regex or args.int_name_regex or args.int_name_lookup_file or args.int_desc_regex

# Process report options
if args.report_store_dir:
    report_storage_path = Path(args.report_store_dir)
    if not report_storage_path.is_dir():
        logger.error(f"The report storage path is not a directory (dest: \"{args.report_store_dir}\")")
        exit(30)
    if not os.access(report_storage_path.absolute(), os.W_OK):
        logger.error(f"The report storage path is not writable (dest: \"{args.report_store_dir}\")")
        exit(31)
else:
    report_storage_path = None


# Since vararg doesn't support mutually exclusive parameter groups, we need to do the checks here
# Note: This don't always have to be mutually exclusive. We could support monitoring of multiple
#       NetFlow sources
if arborws_params:
    if nfsql_params:
        print("Only SQL/nfacctd or Arbor-based capturing is supported currently - not both.")
        exit(1)
    if not args.arborws_url_prefix:
        print("The Arbor web services URL must be specified for Arbor WS-based packet capture.")
        exit(1)
    if not args.arborws_api_key:
        print("The Arbor web services API key must be specified for Arbor WS-based packet capture.")
        exit(1)

if arborws_params:
    if not args.arborws_forensics_scan_period_s:
        args.arborws_forensics_scan_period_s = 60
    if not args.arborws_api_insecure:
        args.arborws_api_insecure = False


event_loop = None


# Callback function to handle traffic found event
async def on_forged_traffic_found(report_info_list):
    print(f"OBSERVED FORGED ATTACK TRAFFIC: ")
    print(pprint.pformat(report_info_list))

    redacted_report_info_list = create_redacted_report_info_list(report_info_list)

    if report_storage_path:
        report_list = report_info_list if args.report_store_format == "all-attributes" else redacted_report_info_list
        asyncio.create_task(save_forged_traffic_report_file(report_storage_path, report_list))

    await queue_report_for_upload(redacted_report_info_list)


def make_redacted_report(report):
    redacted_report = copy.deepcopy(report)
    redacted_report['numDestIps'] = len(report['destIps'])
    del redacted_report['destIps']
    redacted_report['asn'] = redacted_report['interfaceInfo']['asn']
    del redacted_report['interfaceInfo']
    return redacted_report


def create_redacted_report_info_list(report_info_list):
    return [make_redacted_report(report) for report in report_info_list]


async def save_forged_traffic_report_file(path, report_info_list):
    class SetEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, set):
                return list(obj)
            if isinstance(obj, IPv4Network):
                return str(obj)
            return json.JSONEncoder.default(self, obj)

    for report in report_info_list:
        try:
            attack_id = report['attackInfo']['attackId']
            router_id = report['routerId']
            interface_id = report['interfaceId']
            dest_filename = f"forged-traffic-report.attack-{attack_id}.router-{router_id}.int-{interface_id}.json"
            report_filepath = report_storage_path.joinpath(dest_filename)
            with report_filepath.open('w') as reportfile:
                json.dump(report, reportfile, indent=4, cls=SetEncoder)
                reportfile.write("\n")
                reportfile.close()
                logger.info(f"Saved report on attack {attack_id} to {report_filepath.absolute()}")
        except Exception as ex:
            warn_msg = f"Caught an exception saving the report for attack ({ex}): \n{report}"
            logger.warning(warn_msg)


async def main():
    logger.info("main(): Starting")
    global hive_monitor
    global capture_monitor
    event_loop = asyncio.get_event_loop()

    if not asn_res_params:
        print("You must specify at least one parameter to determine an ASN from a router interface name.")
        exit(2)
    if nfsql_params:
        print("NetFlow extraction from SQL not yet supported - exiting.")
        exit(2)
    if args.int_name_lookup_file or args.int_desc_lookup_file:
        print("Interface name/description lookup files not yet supported - exiting.")
        exit(2)

    asn_resolver = AsnResolver(args)
    hive_monitor = HiveMonitor(args, logger)

    if arborws_params:
        capture_monitor = ArborWsApiTrafficMonitor(args, logger, asn_resolver, hive_monitor)
    elif nfsql_params:
        capture_monitor = NfacctdTrafficMonitor(args, logger, asn_resolver, hive_monitor)
    else:
        print("No capture parameters specified.")
        exit(2)

    hive_monitor.add_capture_monitor(capture_monitor)

    capture_monitor.register_traffic_found_callback(on_forged_traffic_found)

    dis_report_uploader = DisReportUploader(args, logger)

    await capture_monitor.startup(event_loop)
    await hive_monitor.startup(event_loop)
    await dis_report_uploader.startup(event_loop)

if __name__ == "__main__":
    asyncio.run(main())
