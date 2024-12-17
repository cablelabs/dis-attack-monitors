#!/usr/bin/env python3

#
# This software is made available according to the terms in the LICENSE.txt accompanying this code
#
import argparse
import asyncio
import copy
import json
import os
import logging
import pprint
import setproctitle

# Import the concrete classes
from arborWsApiCaptureMonitor import ArborWsApiTrafficMonitor
# from nfacctdCaptureMonitor import NfacctdTrafficMonitor
from asnResolver import AsnResolver
from hiveMonitor import HiveMonitor
from localFileReportWriter import LocalFileReportWriter
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
                               default=os.environ.get('DIS_HIVEMON_DIS_API_URI'), dest="dis_api_uri",
                               help="Specify the API prefix of the DIS server to submit DIS Forged Address "
                                    "Source Traceback (FAST) Reports (or DIS_HIVEMON_REPORT_API_URI)")
reporting_options.add_argument('--dis-server-http-proxy', "-dshp,", required=False, action='store',
                               type=str, dest="dis_api_http_proxy",
                               default=os.environ.get('DIS_HIVEMON_DIS_API_HTTP_PROXY'),
                               help="Specify the HTTP/HTTPS proxy URL for connecting to the DIS server "
                                    "(or DIS_HIVEMON_DIS_API_HTTP_PROXY). e.g. 'http://10.0.1.11:1234'")
reporting_options.add_argument('--dis-server-client-key', "-dsckey", required=True, action='store', type=str,
                               default=os.environ.get('DIS_HIVEMON_DIS_API_CLIENT_KEY'), dest="dis_api_client_key",
                               help="Specify the API key to use for submitting DIS FAST reports "
                                    "(or DIS_HIVEMON_DIS_API_CLIENT_KEY)")
reporting_options.add_argument('--report-store-dir', "-repd", required=False, action='store', type=str,
                               default=os.environ.get('DIS_HIVEMON_REPORT_STORE_DIR'), dest="report_store_dir",
                               help="Specify a directory to store generated Observed Forged Source Traffic Reports "
                                    "reports (or DIS_HIVEMON_REPORT_STORE_DIR)")
storage_format_choices=["file-per-report", "file-per-report-date-subdirs", "combined-report-file"]
reporting_options.add_argument('--report-store-format', "-repf", required=False, action='store', type=str,
                               default=os.environ.get('DIS_HIVEMON_REPORT_STORE_FORMAT', "file-per-report"),
                               dest="report_store_format", choices=storage_format_choices,
                               help="Specify the report options for writing Observed Forged Source Traffic Reports "
                                    f"reports (or DIS_HIVEMON_REPORT_STORE_FORMAT). One of {storage_format_choices}")

# TODO: Make this selectable
enabled_traffic_monitor_class = ArborWsApiTrafficMonitor

enabled_traffic_monitor_class.add_supported_arguments(arg_parser)

args = arg_parser.parse_args()

logging_filename = None
logging_filemode = None
logging.basicConfig(level=(logging.DEBUG if args.debug else logging.INFO),
                    filename=logging_filename, filemode=logging_filemode,
                    format='%(asctime)s %(name)s: %(levelname)s %(message)s')
logger = logging.getLogger("DIS HIVEMON")

# Log all arguments except sensitive values
redacted_args = ["report_consumer_api_key"] + enabled_traffic_monitor_class.get_redacted_args()
cur_proc_title = setproctitle.getproctitle()
logger.info("Arguments: ")
for arg, value in vars(args).items():
    redact = arg in redacted_args
    logger.info(f"   {arg}: {'<<redacted>>' if value and redact else value}")
    if redact:  # Remove the value associated with the redacted argument name
        cur_proc_title = cur_proc_title.replace(value, "[value hidden]")


local_report_writer = LocalFileReportWriter(args, logger)
dis_report_uploader = DisReportUploader(args, logger)


# Callback function to handle traffic found event
async def on_forged_traffic_found(report_list):
    logger.info(f"OBSERVED FORGED ATTACK TRAFFIC: ")
    logger.info(pprint.pformat(report_list))

    if local_report_writer:
        logger.info(f"Saving {len(report_list)} reports to local storage")
        asyncio.create_task(local_report_writer.save_forged_traffic_report(report_list))

    if dis_report_uploader:
        logger.info(f"Uploading {len(report_list)} reports to DIS")
        await dis_report_uploader.queue_reports_for_upload(report_list)


def make_redacted_report(report):
    redacted_report = copy.deepcopy(report)
    redacted_report['numDestIps'] = len(report['destIps'])
    del redacted_report['destIps']
    redacted_report['asn'] = redacted_report['interfaceInfo']['asn']
    del redacted_report['interfaceInfo']
    return redacted_report


def create_redacted_report_info_list(report_info_list):
    return [make_redacted_report(report) for report in report_info_list]


async def main():
    try:
        logger.info("main(): Starting")

        event_loop = asyncio.get_event_loop()

        if args.int_name_lookup_file or args.int_desc_lookup_file:
            print("Interface name/description lookup files not yet supported - exiting.")
            exit(2)

        asn_resolver = AsnResolver(args)
        hive_monitor = HiveMonitor(args, logger)
        capture_monitor = ArborWsApiTrafficMonitor(args, logger, asn_resolver, hive_monitor)

        hive_monitor.add_capture_monitor(capture_monitor)
        capture_monitor.register_traffic_found_callback(on_forged_traffic_found)

        await local_report_writer.startup(event_loop)
        await dis_report_uploader.startup(event_loop)
        await capture_monitor.startup(event_loop)
        await hive_monitor.startup(event_loop)
    except Exception as ex:
        logger.error(f"Caught exception on startup: {ex}")
        exit(1)

if __name__ == "__main__":
    asyncio.run(main())
