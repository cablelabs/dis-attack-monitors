import os
import sys
import requests
import urllib3
import argparse
import pandas as pd
import xml.etree.ElementTree as ET
from urllib.parse import urlencode

class ArborForensicsApiReportGenerator(ReportGenerationDelegate):
    def init(self, args, dis_report_uploader, verbose=False):
        self.arbor_hostname = args.whatever
        self.verbose = verbose
        self.disReportUploader = disReportUploader
        self.arbor_wsapikey = args.api_ws_api_key
        self.router_regex = args.etc
        self.description_regex = args.etc
        self.verify = args.etc
        self.verbose = args.etc
        self.dis_report_uploader = dis_report_uploader
        self.logger = logger
    def ws_query(self, xml_query_stub):
        """
        Executes a query against the Arbor Web Services API with the provided XML query stub.

        Args:
            xml_query_stub (str): XML stub defining the query parameters
            arbor_hostname (str): FQDN of your arbor instance
            arbor_wsapikey (str): API key for Arbor Web Services
            verify: (optional, bool) Verify TLS certificate. Default is True.

        Returns:
            requests.response object
        """

        # constants for building the XML query
        XML_STUB_HEADER = '<?xml version="1.0" encoding="utf-8"?><peakflow version="1.0" release="9.1">'
        XML_STUB_FOOTER = '</peakflow>'

        # set up the url, endpoint, and request parameters to execute a query
        url = "https://{}/arborws/traffic/".format(self.arbor_hostname)
        parameters = {'api_key': self.arbor_wsapikey,
                      'query': XML_STUB_HEADER + xml_query_stub + XML_STUB_FOOTER}

        # we know when we're being bad, no need for TLS shaming
        if self.verify == False:
            urllib3.disable_warnings()

        # urlencode the parameters dictionary, make the request, return the result
        response = requests.get(url, params=urlencode(parameters), verify=verify)
        return response


    def generateReportForTraceback(self, src_address, dest_port, start_time, end_time):
        """
        Traceback the network flows for a given fingerprint within a specified time range.

        This function queries the Arbor Web Services API to find network flows associated with a given fingerprint
        within a specified time range. It then enriches the flow data with router and interface information and
        applies optional filters based on router and interface descriptions.

        Args:
            fingerprint (str): The fingerprint to trace.
            start_time (str): The start time for the query (format: YYYY-MM-DD HH:MM:SS).
            end_time (str): The end time for the query (format: YYYY-MM-DD HH:MM:SS).
            arbor_hostname (str): The hostname of the Arbor server. NOTE: Overrides environment variables.
            arbor_wsapikey (str): The API key for the Arbor Web Services. NOTE: Overrides environment variables.
            router_regex (str, optional): Regex to filter routers. Defaults to None.
            description_regex (str, optional): Regex to filter interface descriptions. Defaults to None.
            verify (bool, optional): Whether to verify SSL certificates. Defaults to True.
            verbose (bool, optional): Enable verbose mode for additional debug information. Defaults to False.

        Returns:
            pandas.DataFrame: A DataFrame containing the enriched flow data.
            dict: A dictionary containing router information.

        Raises:
            Exception: If any step in the process fails, an exception is raised with a message indicating the step and the error.
        """
        # STEP 1 - Find flows for provided source IP and timeframe
        try:
            fingerprint = f"src {src_address} and dst port {dest_port} and proto udp"
            query_xml = """<query id="query1" type="traffic_raw">
                           <time start_ascii="{}" end_ascii="{}"/>
                           <unit type="bps"/>
                           <search limit="500" timeout="60" ip_ver="4"/>
                           <filter type="fcap">
                             <instance value="{}"/>
                           </filter>
                           </query>""".format(start_time, end_time, fingerprint)
            response = self.ws_query(query_xml)

            # parse the response content into an ElementTree object
            t_root = ET.fromstring(response.text)

            # parse results for flows into a dataframe
            rows = []
            for collector in t_root.findall('query-reply/collector'):
                for flow in collector.findall('flow'):
                    rows.append(flow.attrib)

            # exit if no results, otherwise build a dataframe with placeholders to enrich
            if len(rows) == 0:
                print("No flows found for {} between {} and {}".format(fingerprint, start_time, end_time))
                return False
            else:
                print("Found {} flows for {} between {} and {}".format(len(rows), fingerprint, start_time, end_time))
                df = pd.DataFrame(rows)
                df['router_name'] = "None"
                df['interface_name'] = "None"
                df['interface_description'] = "None"
        except Exception as e:
            print("- Traceback failed at STEP 1 (find flows). Exception: {}: {}".format(type(e).__name__, e))
            raise e

        # STEP 2: Build an enrichment dataframe with router information found in flow data
        try:
            routers = {}
            for router_gid in df['router_gid'].unique():
                query_xml = """<query id="query1" type="status">
                <time start_ascii="{}" end_ascii="{}"/>
                <unit type="bps"/>
                <search limit="100" timeout="30"/>
                <filter type="router">
                  <instance value="{}"/>
                </filter> 
                <filter type="interface_status" binby="1"/>
                </query>""".format(start_time, end_time, router_gid)
                response = self.ws_query(query_xml)
                # Parse the XML data into an object
                r_root = ET.fromstring(response.text)

                # Populate the dictionary for this router and its interfaces
                for interface in r_root.findall('query-reply/interface'):
                    # router info
                    router_name = interface.attrib['router']
                    router_gid = interface.attrib['router_gid']

                    # interface info
                    interface_name = interface.attrib['name']
                    interface_index = interface.attrib['snmp_index']
                    try:
                        interface_desc = "|".join([a.text for a in interface.findall('description')])
                    except TypeError:
                        interface_desc = None

                    # build entries for each interface
                    try:
                        routers[router_gid][interface_index] = {'name': interface_name, 'desc': interface_desc}
                    except KeyError:
                        routers[router_gid] = {'name': router_name,
                                               interface_index: {'name': interface_name, 'desc': interface_desc}}
        except Exception as e:
            print(
                "- Traceback failed at STEP 2 (build enrichment dataframe). Exception: {}: {}".format(type(e).__name__,
                                                                                                      e))
            raise e

        # STEP 3 - Enrich flow data using the completed lookup table
        try:
            for router_id, interface_id in df.groupby(['router_gid', 'in']).count().index:
                try:
                    # map each unique pair of router gid and interface index to the router name and interface name/description
                    df.loc[df['router_gid'] == router_id, 'router_name'] = routers[router_id]['name']
                    df.loc[(df['router_gid'] == router_id) & (df['in'] == interface_id), 'interface_name'] = \
                    routers[router_id][interface_id]['name']
                    df.loc[(df['router_gid'] == router_id) & (df['in'] == interface_id), 'interface_description'] = \
                    routers[router_id][interface_id]['desc']
                except KeyError:
                    if self.verbose: print("#### Interface number {} not found on router {}".format(interface_id, router_id))
        except Exception as e:
            print("- Traceback failed at STEP 3 (enrich flow dataframe). Exception: {}: {}".format(type(e).__name__, e))
            raise e

            # STEP 4: Apply optional filters to enriched dataframe:
        if self.router_regex:
            df.loc[df['router_name'].isna(), 'router_name'] = 'none'
            df = df.loc[df['router_name'].str.match(self.router_regex)]
        if self.description_regex:
            df.loc[df['interface_description'].isna(), 'interface_description'] = 'none'  # na values break regex
            df = df.loc[df['interface_description'].str.match(self.description_regex)]

        return df

