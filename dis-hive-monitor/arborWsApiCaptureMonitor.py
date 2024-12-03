#
# This software is made available according to the terms in the LICENSE.txt accompanying this code
#

import os
import sys
from captureMonitorBase import TrafficMonitorBase
import asyncio
from pathlib import Path
import re
from typing import Callable, Awaitable
import aiohttp
import time
import datetime as dt
import ipaddress
import xml.etree.ElementTree as ET
import json
import logging
import pprint
import setproctitle


class ArborWsApiTrafficMonitor(TrafficMonitorBase):
    @staticmethod
    def add_supported_arguments(arg_parser):
        """Add any options supported by the Arbor traffic monitor"""
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
                                   dest="arborws_router_savefile", action='store', type=Path,
                                   default=os.environ.get('DIS_HIVEMON_ARBORWS_ROUTER_SAVEFILE',
                                                          "arbor-router-info.json"),
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

    @staticmethod
    def get_redacted_args():
        return ["arborws_api_key"]

    def __init__(self, args, logger, asn_resolver, hive_monitor):
        self.asn_resolver = asn_resolver
        self.hive_monitor = hive_monitor
        self.arborws_url_prefix = args.arborws_url_prefix
        self.arborws_api_key = args.arborws_api_key
        self.arborws_api_insecure = getattr(args, 'arborws_api_insecure', False)
        self.router_scan_initial_delay_s = 10
        self.router_scan_period_s = args.arborws_router_scan_period_s
        self.router_savefile = args.arborws_router_savefile
        self.router_metadata_loaded = asyncio.Event()
        self.drop_routers = set(args.drop_routers.split(',')) if args.drop_routers else None
        self.only_routers = set(args.only_routers.split(',')) if args.only_routers else None
        self.drop_interface_types = set(args.drop_interface_types.split(',')) if args.drop_interface_types else None
        self.only_interface_types = set(args.only_interface_types.split(',')) if args.only_interface_types else None
        self.drop_interface_asns = {int(x) for x in args.drop_interface_asns.split(',')} if args.drop_interface_asns else None
        self.drop_interface_regex = re.compile(args.drop_interface_regex) if args.drop_interface_regex else None
        self.only_interface_regex = re.compile(args.only_interface_regex) if args.only_interface_regex else None
        self.int_filtering_needed = bool(self.drop_interface_types or self.only_interface_types
                                         or self.drop_interface_asns or self.drop_interface_regex
                                         or self.only_interface_regex)
        self.forensics_scan_initial_delay_s = 10
        self.forensics_scan_period_s = getattr(args, 'arborws_forensics_scan_period_s', 60)
        self.forensics_scan_overlap_s = args.arborws_forensics_scan_overlap_s
        self.data_found_callback = None
        self.forensics_scan_task = None
        self.router_info_collection_task = None
        self.event_loop = None
        self.attack_table = {}
        self.attack_tracking_table = {}
        self.router_gid_interface_map = {}
        self.max_ips_per_fingerprint = 100
        self.print_ex_backtraces = True
        self.logger = logging.getLogger(logger.name + ":Arbor Capture")
        self.logger.info(f"Initialized with \n{pprint.pformat(self.__dict__)}")

    async def startup(self, event_loop):
        self.event_loop = event_loop
        self.logger.debug(f"ArborWsApiTrafficMonitor: Performing startup")
        if self.arborws_api_key:
            cur_proc_title = setproctitle.getproctitle()
            cur_proc_title = cur_proc_title.replace(self.arborws_api_key, "[token hidden]")

        # Hide sensitive command line arguments
        cur_proc_title = setproctitle.getproctitle()

        setproctitle.setproctitle(cur_proc_title)

        await self._check_arborws_access()
        loaded = await self._load_router_metadata()
        self.router_info_collection_task = asyncio.create_task(self._periodic_router_metadata_collector(not loaded))
        self.forensics_scan_task = event_loop.create_task(self._periodic_arbor_forensics_scan())

    def register_traffic_found_callback(self, callback: Callable[[dict], Awaitable[None]]):
        self.data_found_callback = callback

    async def start_monitoring_for(self, attack_id: int, attack_entry):
        self.logger.debug(f"ArborWsApiTrafficMonitor: Starting monitoring for attack {attack_id}: {attack_entry}")
        new_entry = self._create_new_entry(attack_entry)
        self.attack_table[attack_id] = new_entry
        # self._dump_attack_entries({attack_id: new_entry}, desc_string="NEW ")

    async def start_monitoring_for_list(self, attack_table, replace_existing=False):
        if replace_existing:
            self.attack_table = {}
        for attack_id, attack_entry in attack_table.items():
            try:
                new_entry = self._create_new_entry(attack_entry)
                self.attack_table[attack_id] = new_entry
            except Exception as ex:
                self.logger.warning(f"arborWsApiCaptureMonitor: Error creating new attack entry for {attack_entry}: "
                                    f"{ex}", exc_info=self.print_ex_backtraces)
        self._dump_attack_entries(self.attack_table, "INITIAL ")

    async def stop_monitoring_for(self, attack_id: int, attack_end_time: int):
        self.logger.debug(f"ArborWsApiTrafficMonitor: Stopping monitoring for attack {attack_id} at {attack_end_time}")
        self.attack_table[attack_id]['endTime'] = attack_end_time
        # self._dump_attack_entries({attack_id: self.attack_table[attack_id]}, desc_string="COMPLETED ")
        # We'll process and remove entries with set endTime during the sweep

    async def stop_all_monitoring(self):
        curtime = time.time()
        for attack_id, attack in self.attack_table.items():
            attack['endTime'] = curtime

    def _create_new_entry(self, attack_entry):
        src_ip_network = ipaddress.ip_network(attack_entry['srcNetwork'], strict=False)
        new_entry = attack_entry.copy()
        new_entry['srcNetwork'] = src_ip_network
        return new_entry

    def _dump_attack_entries(self, attack_table, desc_string=""):
        self.logger.info(f"DUMPING {len(attack_table)} {desc_string}ATTACK ENTRIES")
        self.logger.info(f"  ID       SRC NETWORK          DPORT     START TIME     DURATION       END TIME")
        cur_time = int(time.time())
        for a_id, a_entry in attack_table.items():
            # Attack entry fields: attackId, startTime, srcNetwork, destPort, reporters, count
            # For accounting: srcNetwork, matchCount, destIps, lastWindowFlowTime, maxFlowTime,
            #                 routers, asns
            sts = a_entry['startTime']
            st = dt.datetime.utcfromtimestamp(a_entry['startTime']).strftime("%y-%m-%d %H:%M")
            ets = a_entry.get('endTime')
            et = dt.datetime.utcfromtimestamp(ets).strftime("%y-%m-%d %H:%M") if ets else "          TBD"
            dur_str = str(dt.timedelta(seconds=(ets if ets else cur_time) - sts)).replace(" day, ", "d ")
            # self.logger.info(f"{a_id}: {a_entry}")
            self.logger.info(f"  {a_id:<8} {str(a_entry['srcNetwork']):<20} {a_entry['destPort']:<5} "
                             f"{st:>14}  {dur_str:>11} {et:>14}")

    @staticmethod
    def _resolve_router_names_to_gids(router_refs, router_name_gid_map):
        router_gids = set()
        if not router_refs:
            return router_gids
        for router_id_or_name in router_refs:
            if isinstance(router_id_or_name, int):
                router_gids.add(router_id_or_name)
            elif isinstance(router_id_or_name, str) and router_id_or_name.isdigit():
                router_gids.add(int(router_id_or_name))
            else:  # Assume the entry is a router name
                router_gids.add(router_name_gid_map.get(router_id_or_name))
        return router_gids

    async def _dump_attack_tracking_entries(self, attack_tracking_table, desc_string=""):
        self.logger.info(f"DUMPING {len(attack_tracking_table)} {desc_string}ATTACK TRACKING ENTRIES")
        self.logger.info(f" ATTACK ID SRC NETWORK          DPORT     START TIME     DURATION       END TIME  MATCH  PACKETS                 ROUTER    INT    ASN DESTS")
        cur_time = int(time.time())
        for (attack_id, router_gid, interface_index), attack_tracking_entry in attack_tracking_table.items():
            try:
                attack_entry = self.attack_table[attack_id]
                router_entry = self.router_gid_interface_map.get(router_gid)
                if router_entry:
                    interface_map = router_entry.get('interfaces')
                if not router_entry or not interface_map:
                    interface_map = {interface_index: {"routerName": f"NR {router_gid}!", "asn": 0, "name": "unknown"}}
                interface_entry = interface_map.get(interface_index, {"routerName": f"NI {router_gid}!",
                                                                      "asn": 0, "name": "unknown"})
                # Attack entry fields: attackId, startTime, srcNetwork, destPort, reporters, count
                # Attack tracking fields: (attack_id, router_gid, interface_id) srcNetwork, matchCount,
                #                         matchPackets, destIps, lastScanEndTime, maxFlowTime
                sts = attack_entry['startTime']
                st = dt.datetime.utcfromtimestamp(attack_entry['startTime']).strftime("%y-%m-%d %H:%M")
                ets = attack_entry.get('endTime')
                et = dt.datetime.utcfromtimestamp(ets).strftime("%y-%m-%d %H:%M") if ets else "          TBD"
                dur_str = str(dt.timedelta(seconds=(ets if ets else cur_time) - sts)).replace(" day, ", "d ")
                asn_str = str(interface_entry.get('asn'))
                if not asn_str:
                    asn_str = "no asn"
                self.logger.info(f"  {attack_id:>8} {str(attack_entry['srcNetwork']):<20} {attack_entry['destPort']:<5} "
                                 f"{st:>14} {dur_str:>12} {et:>15} "
                                 f"{attack_tracking_entry.get('matchCount','none'):>5} "
                                 f"{attack_tracking_entry.get('matchPackets','none'):>8} "
                                 f"{interface_entry.get('routerName', 'none'):>22} {str(interface_index):>6} " 
                                 f"{asn_str:>6} "
                                 f"{len(attack_tracking_entry.get('destIps', 0)):>5}")
            except Exception as ex:
                self.logger.info(f"  {attack_id:>8} {str(attack_entry['srcNetwork']):<20} {attack_entry['destPort']:<5} "
                                 f"{ex}", exc_info=self.print_ex_backtraces)

    async def _create_observation_report(self, attack_tracking_table):
        observed_forgery_list = []
        for (attack_id, router_gid, interface_index), attack_tracking_entry in attack_tracking_table.items():
            attack_entry = self.attack_table[attack_id]
            router_entry = self.router_gid_interface_map.get(router_gid)
            if router_entry:
                interface_entry = router_entry['interfaces'].get(interface_index, {})
            else:
                interface_entry = {}
            # Attack entry fields: attackId, startTime, srcNetwork, destPort, reporters, count
            # Attack tracking fields: (attack_id, router_gid, interface_id) srcNetwork, matchCount,
            #                         matchPackets, destIps, lastScanEndTime, maxFlowTime
            # Interface fields: asn, description, id, ip, name, routerName, speed, type
            observed_forgery_info = {"routerId": router_gid,
                                     "interfaceId": interface_index,
                                     "matchCount": attack_tracking_entry['matchCount'],
                                     "matchedPackets": attack_tracking_entry['matchPackets'],
                                     "destIps": attack_tracking_entry['destIps'],
                                     "attackInfo": attack_entry,
                                     "interfaceInfo": interface_entry}
            observed_forgery_list.append(observed_forgery_info)
        return observed_forgery_list

    def _router_map_summary_str(self, prefix=""):
        if self.router_gid_interface_map is None:
            return f"{prefix}NO ROUTER INTERFACE MAP"
        if len(self.router_gid_interface_map) == 0:
            return f"{prefix}0 ROUTER INTERFACE MAP ENTRIES"
        router_summary = f"{prefix}ROUTER INTERFACE MAP FOR {len(self.router_gid_interface_map.keys())} ROUTERS:\n"
        for (router_id, router_entry) in self.router_gid_interface_map.items():
            router_name = router_entry['info']['name']
            interfaces = router_entry['interfaces']
            router_summary += f"{prefix}  ROUTER {router_name} (gid {router_id}) " \
                              f"has {len(list(interfaces.keys()))} interfaces:\n"
            for interface_id, interface in interfaces.items():
                router_summary += f"{prefix}    INTERFACE {interface['name']}: index {interface_id}, " \
                                  f"type {interface['type']}, asn {interface.get('asn','none')}, desc \"{interface['description']}\"\n"
        return router_summary

    async def _load_router_metadata(self):
        def dictsKeysToInts(x):
            if isinstance(x, dict):
                return {int(k) if k.isdigit() else k: v for k, v in x.items()}
            return x

        start_time = time.time()
        if self.router_savefile and self.router_savefile.exists():
            self.logger.info(f"LOADING router metadata from savefile {self.router_savefile.name}...")
            try:
                with self.router_savefile.open("r") as router_info_file:
                    self.router_gid_interface_map = json.load(router_info_file, object_hook=dictsKeysToInts)
                    self.router_name_gid_map = {router["info"].get("name"): router_gid
                                                for router_gid, router in self.router_gid_interface_map.items()}
                    self.logger.debug(f"Router name-to-gid table for {len(self.router_name_gid_map)} routers: "
                                      f"{pprint.pformat(self.router_name_gid_map)}")
                    self.logger.info(f"LOADED router metadata savefile {self.router_savefile.name} in "
                                     f"{time.time()-start_time:0.1f} seconds")
                    self.logger.info(self._router_map_summary_str())
                    self.router_metadata_loaded.set()
                    return True
            except Exception as ex:
                self.logger.warning(f"Could not open router metadata file {self.router_savefile.name}: {ex}",
                                    exc_info=self.print_ex_backtraces)
        return False

    async def _save_router_metadata(self):
        try:
            self.logger.info(f"SAVING router metadata to savefile {self.router_savefile.name}...")
            start_time = time.time()
            with self.router_savefile.open("w") as router_info_file:
                json.dump(self.router_gid_interface_map, router_info_file, indent=4)
                self.logger.info(f"SAVED router metadata to file {self.router_savefile.name} in "
                                 f"{time.time()-start_time:0.1f}s")
                self.logger.info(self._router_map_summary_str())
            return True
        except Exception as ex:
            self.logger.warning(f"Could not write router metadata file {self.router_savefile.name} for reading: {ex}",
                                exc_info=self.print_ex_backtraces)
            return False

    async def _periodic_router_metadata_collector(self, perform_initial_acquisition):
        # Call the Arbor WS API periodically to collect router and interface metadata
        self.logger.info(f"_periodic_router_metadata_collector: Performing router/interface scans every "
                         f"{self.router_scan_period_s} seconds")
        initial_delay_s = self.router_scan_initial_delay_s if perform_initial_acquisition else self.router_scan_period_s
        self.logger.info(f"_periodic_router_metadata_collector: Waiting {initial_delay_s}s to perform initial "
                         f"router metadata acquisition...")
        await asyncio.sleep(initial_delay_s)
        router_map_update = {}
        while True:
            try:
                async with aiohttp.ClientSession() as http_session:
                    self.logger.info("Refreshing router metadata...")
                    start_time = time.time()
                    router_query = ArborWsApiRouterQuery(self.arborws_url_prefix, self.arborws_api_key,
                                                         validate_tls=not self.arborws_api_insecure)
                    await router_query.run_query(http_session)
                    query_result = router_query.get_router_metadata()
                    self.logger.debug("RETRIEVED router list:\n" + pprint.pformat(query_result))

                    # Router dict will be keyed on the router gid, with "info" containing the RouterQuery
                    #  metadata and "interfaces" containing a dict of interfaces, keyed on the SNMP interface index
                    for router_info in query_result['data']:
                        router_map_update[int(router_info.get('gid'))] = {'info': router_info, 'interfaces': {}}
                    router_gids = set(router_map_update.keys())
                    self.logger.info(f"RETRIEVED metadata for {len(router_gids)} routers: {router_gids}")
                    router_name_gid_map = {router["info"].get("name"): router_gid
                                           for router_gid, router in router_map_update.items()}
                    self.logger.debug(f"Router name-to-gid table for {len(router_name_gid_map)} routers: "
                                      f"{pprint.pformat(router_name_gid_map)}")
                    if self.only_routers:  # Only include elements in both lists
                        only_router_gids = self._resolve_router_names_to_gids(self.only_routers, router_name_gid_map)
                        router_gids = router_gids.intersection(only_router_gids)
                    elif self.drop_routers:  # Remove self.drop_routers from the list
                        drop_router_gids = self._resolve_router_names_to_gids(self.only_routers, router_name_gid_map)
                        router_gids = router_gids.difference(drop_router_gids)

                    # Since router interface queries can be very large (for operational routers), we'll just
                    #  query one router at a time
                    self.logger.info(f"RETRIEVING interface metadata for {len(router_gids)} routers "
                                     f"(filtered): {router_gids}")
                    for router_gid in router_gids:
                        tb = time.time()
                        # Get the interface metadata for router with router_gid
                        interface_query = ArborWsApiInterfaceQuery(self.arborws_url_prefix, self.arborws_api_key,
                                                                   f"{self.forensics_scan_period_s} seconds ago",
                                                                   "now",
                                                                   validate_tls=not self.arborws_api_insecure)
                        result = await interface_query.run_query(http_session, routers=[router_gid])
                        ints_for_router = interface_query.get_interface_metadata(asn_resolver=self.asn_resolver)
                        self.logger.info(f"_periodic_router_metadata_collector: RETRIEVED list of "
                                         f"{len(ints_for_router.get('router_gid',[]))} interfaces for "
                                         f"router {router_gid} in {time.time()-tb:.1f}s")
                        self.logger.debug(f"_periodic_router_metadata_collector: Interfaces for router "
                                          f"{router_gid}:\n{pprint.pformat(ints_for_router)}")
                        ints_for_gid = ints_for_router.get(int(router_gid), {})
                        router_map_update[router_gid]['interfaces'] = ints_for_gid

                    self.router_gid_interface_map = router_map_update
                    self.router_name_gid_map = router_name_gid_map
                    self.logger.info(f"_periodic_router_metadata_collector: REFRESHED router metadata in "
                                     f"{time.time()-start_time:.1f}s")
                    self.logger.debug(f"_periodic_router_metadata_collector: REFRESHED router interface map: \n"
                                      + pprint.pformat(self.router_gid_interface_map))
                    self.router_metadata_loaded.set()
                    await self._save_router_metadata()
            except Exception as ex:
                self.logger.warning(f"Caught exception trying to refresh router metadata: {ex}",
                                    exc_info=self.print_ex_backtraces)
            self.logger.debug(f"_periodic_router_metadata_collector: SLEEPING for {self.router_scan_period_s}s")
            await asyncio.sleep(self.router_scan_period_s)

    async def _periodic_arbor_forensics_scan(self):
        # Call the Arbor WS API periodically and check the results against the list of ongoing attacks
        # Call the data available callback if/when data is found
        self.logger.info(f"ArborWsApiTrafficMonitor: Performing forensics scans every {self.forensics_scan_period_s} "
                         f"seconds ({self.forensics_scan_initial_delay_s}s startup delay)")
        start_time = time.time()
        await asyncio.sleep(self.forensics_scan_initial_delay_s)
        while True:
            end_time = time.time()
            self.logger.info(f"Performing forensics scan for {len(self.attack_table)} ongoing attacks...")
            await self._perform_forensics_scan(start_time, end_time)
            start_time = end_time
            await self._process_completed_attacks()
            await asyncio.sleep(self.forensics_scan_period_s)

    async def _perform_forensics_scan(self, start_time, end_time):
        try:
            scan_window_size = int(end_time - start_time + self.forensics_scan_overlap_s)
            if not self.router_metadata_loaded.is_set():
                self.logger.info(f"WAITING for router metadata to be loaded/acquired...")
            await self.router_metadata_loaded.wait()
            self.logger.info(f"STARTING WS API forensics scan from \"{scan_window_size} seconds ago\" to \"now\"...")
            fcap_prefix = "proto udp"
            if self.only_routers:
                only_router_gids = self._resolve_router_names_to_gids(self.only_routers, self.router_name_gid_map)
                router_ips = {self.router_gid_interface_map.get(rid, {}).get('info', {}).get('flow_export_ip')
                              for rid in only_router_gids}
                fcap_prefix += " and (rtr " + " or rtr ".join(ip for ip in router_ips if ip) + ")"
            elif self.drop_routers:
                drop_router_gids = self._resolve_router_names_to_gids(self.drop_routers, self.router_name_gid_map)
                router_ips = {self.router_gid_interface_map.get(rid, {}).get('info', {}).get('flow_export_ip')
                              for rid in drop_router_gids}
                fcap_prefix += " and not (rtr " + " or rtr ".join(ip for ip in router_ips if ip) + ")"

            async with aiohttp.ClientSession() as session:
                ongoing_attack_list = list(self.attack_table.values())

                # Chunk attack list into batches so each query doesn't exceed the max URL length limit
                for range_start in range(0, len(ongoing_attack_list), self.max_ips_per_fingerprint):
                    attack_table_fingerprint = "undefined"
                    try:
                        range_end = min(range_start+self.max_ips_per_fingerprint, len(ongoing_attack_list))
                        self.logger.info(f"SCANNING FOR ATTACK FINGERPRINTS {range_start}-{range_end} "
                                         f"IN LAST {scan_window_size} seconds...")
                        traffic_query = ArborWsApiTrafficQuery(self.arborws_url_prefix, self.arborws_api_key,
                                                               f"{scan_window_size} seconds ago", "now",
                                                               validate_tls=not self.arborws_api_insecure)
                        # Create a combined fingerprint for the chunk of the attack list
                        # Example fingerprint/filter: proto udp and ((src 1.2.3.4 and dst port 53) or (src 1.2.3.5 and dst port 123))
                        ip_filter = "".join(f"(src net {attack.get('srcNetwork')} "
                                            f"and dst port {attack.get('destPort')}) or "
                                            for attack in ongoing_attack_list[range_start:range_end])[:-4]
                        attack_table_fingerprint = f"{fcap_prefix} and ({ip_filter})"
                        self.logger.debug(f"Running traffic flow query for attacks {range_start}-{range_end} - fingerprint: "
                                          + attack_table_fingerprint)

                        # Run the traffic query
                        response = await traffic_query.run_query(session, fcap_filter=attack_table_fingerprint)

                        # Process flows matching chunk fingerprint for current time window
                        flows = traffic_query.get_matching_flows()
                        self.logger.info(f"FOUND {len(flows)} MATCHING FLOWS FOR CHUNK {range_start}-{range_end}")
                        if len(flows) == 0:
                            continue

                        # Assert: We have flows in the time window matching this chunk of fingerprints

                        # Match the flow entries up with the corresponding attack entries
                        attack_update_count = trailing_flows_skipped = overlapping_flows_skipped = 0
                        for flow_entry in flows:
                            # Flow entry fields: time, router_gid, src_ip, dst_ip, src_port, dst_port, proto, in, out,
                            #                    bytes, packets, tcp_flags, blobs, avg_pkt_len
                            self.logger.debug("   " + str(flow_entry))
                            flow_entry_time = int(flow_entry['time'])
                            flow_entry_src = ipaddress.ip_network(flow_entry['src_ip'])
                            flow_entry_dest_port = int(flow_entry['dst_port'])
                            flow_entry_router_gid = int(flow_entry['router_gid'])
                            flow_entry_int_index = int(flow_entry['in'])

                            if not self._interface_allowed_by_rule(flow_entry_router_gid, flow_entry_int_index):
                                continue

                            # Find the attack entry for this flow entry
                            for attack_id, attack_entry in self.attack_table.items():
                                # Assert: Every flow entry should match an attack (but some may overlap)
                                if flow_entry_src.overlaps(attack_entry['srcNetwork']) \
                                   and flow_entry_dest_port == attack_entry['destPort']:
                                    # FOUND a flow entry that matches a fingerprint

                                    # Check to see if the packet capture time is after the end of the attack window
                                    attack_end_time = attack_entry.get('endTime')
                                    if attack_end_time and flow_entry_time > attack_end_time:
                                        trailing_flows_skipped += 1
                                        continue
                                    self.logger.debug(f"Flow entry with time {flow_entry_time} MATCHED attack {attack_id}")
                                    self.logger.debug(f"  FLOW ENTRY: {flow_entry}")

                                    # We'll track matches accd to attackID+routerID+interfaceID
                                    attack_tracking_index = (attack_id, flow_entry_router_gid, flow_entry_int_index)
                                    attack_tracking_entry = self.attack_tracking_table.get(attack_tracking_index)
                                    if not attack_tracking_entry:
                                        attack_tracking_entry = {"matchCount": 0,
                                                                 "matchPackets": 0,
                                                                 "destIps": set(),
                                                                 "lastScanEndTime": 0,
                                                                 "maxFlowTime": 0,
                                                                 "asn": 0}
                                        self.attack_tracking_table[attack_tracking_index] = attack_tracking_entry
                                    # Make sure the flow entry wasn't accounted for in the last search window
                                    if flow_entry_time <= attack_tracking_entry['lastScanEndTime']:
                                        overlapping_flows_skipped += 1
                                        continue
                                    attack_tracking_entry['matchCount'] += 1
                                    attack_tracking_entry['matchPackets'] += int(flow_entry['packets'])
                                    attack_tracking_entry['destIps'].add(flow_entry['dst_ip'])
                                    if flow_entry_time > attack_tracking_entry['maxFlowTime']:
                                        attack_tracking_entry['maxFlowTime'] = flow_entry_time
                                    self.logger.debug(f"  ATTACK TRACKING ENTRY: {attack_tracking_entry}")
                                    attack_update_count += 1
                        self.logger.info(f"PERFORMED {attack_update_count} attack updates for chunk "
                                         f"{range_start}-{range_end} (skipped {overlapping_flows_skipped} overlaps, "
                                         f"{trailing_flows_skipped} trailers)")
                    except Exception as ex:
                        self.logger.warning(f"Caught exception processing flow request: {ex}",
                                            exc_info=self.print_ex_backtraces)

                    updated_tracking_entries = {k: v for k, v in self.attack_tracking_table.items()
                                                if not v['lastScanEndTime'] == v['maxFlowTime']}

                    if len(updated_tracking_entries) > 0:
                        # Get information about all the router interfaces referenced in the last time window
                        await self._dump_attack_tracking_entries(updated_tracking_entries, desc_string="UPDATED ")

                # Move time windows forward
                for a_id, attack_tracking_entry in self.attack_tracking_table.items():
                    attack_tracking_entry['lastWindowFlowTime'] = attack_tracking_entry['maxFlowTime']
        except Exception as ex:
            self.logger.warning(f"Caught exception while processing flow from forensics API: {ex}",
                                exc_info=self.print_ex_backtraces)

    def _interface_allowed_by_rule(self, router_gid, int_index):
        if not self.int_filtering_needed:
            return True
        try:
            int_entry = self.router_gid_interface_map[router_gid]['interfaces'].get(int_index)
            # self.logger.debug(f"_interface_allowed_by_rule(router gid {router_gid}, interface {int_index}): {int_entry}")
            if self.only_interface_types:
                result = int_entry['type'] in self.only_interface_types
                # self.logger.debug(f"  Interface {'ALLOWED' if result else 'DENIED'} via only_interface_types "
                #                   f"{self.only_interface_types}")
                return result
            if self.only_interface_regex:
                result = self.only_interface_regex.match(int_entry['description'])
                # self.logger.debug(f"  Interface {'ALLOWED' if result else 'DENIED'} via only_interface_regex "
                #                   f"{self.only_interface_regex}")
                return result
            if self.drop_interface_types and int_entry['type'] in self.drop_interface_types:
                # self.logger.debug(f"  Interface DROPPED via drop_interface_types {self.drop_interface_types}")
                return False
            if self.drop_interface_asns and int_entry['asn'] in self.drop_interface_asns:
                # self.logger.debug(f"  Interface DROPPED via drop_interface_asns {self.drop_interface_asns}")
                return False
            if self.drop_interface_regex and self.drop_interface_regex.match(int_entry['description']):
                # self.logger.debug(f"  Interface DROPPED via drop_interface_regex {self.drop_interface_regex}")
                return False
            return True
        except Exception as ex:
            self.logger.warning(f"Caught exception checking interface against rules: {ex}",
                                exc_info=self.print_ex_backtraces)

    async def _process_completed_attacks(self):
        horizon = time.time() - self.forensics_scan_overlap_s  # Need to account for latency of packets showing up in forensics
        completed_attacks = {k: v for k, v in self.attack_table.items() if v.get('endTime', sys.maxsize) < horizon}
        # self._dump_attack_entries(completed_attacks, desc_string="COMPLETED ")

        observed_attacks = {k: v for k, v in self.attack_tracking_table.items() if v.get('matchCount') > 0}
        await self._dump_attack_tracking_entries(observed_attacks, desc_string="OBSERVED ")

        completed_observed_attacks = {(a,r,i): v for (a,r,i), v in observed_attacks.items() if a in completed_attacks}
        await self._dump_attack_tracking_entries(completed_observed_attacks, desc_string="COMPLETED ")

        if len(completed_observed_attacks) > 0:
            self.logger.info(f"Creating attack report with {len(completed_observed_attacks)} entries")
            completed_observed_attack_report = await self._create_observation_report(completed_observed_attacks)
            asyncio.create_task(self.data_found_callback(completed_observed_attack_report))
            self.logger.info(f"Signalled data_found_callback with {len(completed_observed_attacks)} entries")
            for attack_track_index in completed_observed_attacks.keys():
                del self.attack_tracking_table[attack_track_index]

        # We've reported the attack, now we can stop tracking it
        for attack_id in completed_attacks.keys():
            del self.attack_table[attack_id]

    async def _check_arborws_access(self):
        # TODO
        pass


class ArborWsApiTrafficQuery:
    def __init__(self, url_prefix, arbor_wsapikey, start_time_expression, end_time_expression,
                 validate_tls=True, unit_type_str="bps", ip_ver=4):
        self.url_prefix = url_prefix
        self.peakflow_version="1.0"
        self.peakflow_release="9.1"
        self.arbor_wsapikey = arbor_wsapikey
        self.start_time_expression = start_time_expression
        self.end_time_expression = end_time_expression
        self.logger = logging.getLogger("ArborWsApiTrafficQuery")
        self.validate_tls = validate_tls
        self.unit_type_str = unit_type_str
        self.ip_ver = ip_ver
        self.ints_for_gids = {}
        self.flow_list = []

    async def run_query(self, client_session, fcap_filter=None, search_limit=5000, timeout=300):
        if fcap_filter:
            fcap_filter_section = f'''
                <filter type="fcap">
                    <instance value="{fcap_filter}"/>
                </filter>
            '''
        else:
            fcap_filter_section = ""

        query_string = f'''<?xml version="1.0" encoding="utf-8"?>
        <peakflow version="{self.peakflow_version}" release="{self.peakflow_release}"> 
            <query id="query1" type="traffic_raw">
                <time start_ascii="{self.start_time_expression}" end_ascii="{self.end_time_expression}"/>
                <unit type="{self.unit_type_str}"/>
                <search limit="{search_limit}" timeout="{timeout}" ip_ver="{self.ip_ver}"/>
                {fcap_filter_section}
            </query>
        </peakflow>        
        '''

        # set up the url, endpoint, and request parameters to execute a query
        url = f"{self.url_prefix }/arborws/traffic/"
        parameters = {'api_key': self.arbor_wsapikey,
                      'query': query_string}

        # urlencode the parameters dictionary, make the request, return the result
        self.logger.debug(f"Sending query to {url}: \n{query_string}")

        time_before_request = time.time()
        async with client_session.get(url, params=parameters, ssl=self.validate_tls, raise_for_status=True) as response:
            time_after_request = time.time()
            content_types = response.headers['Content-Type'].split(";")
            if "text/xml" not in content_types:
                raise ValueError(f"Response from GET {url} was not XML (Content-Type returned was {content_types})")

            response_body = await response.text()
            time_after_xfer = time.time()
            self.logger.info(f"Received {len(response_body)}-byte response from {url} "
                             f"after {time_after_xfer-time_before_request:0.2} seconds")

            root = ET.fromstring(response_body)
            query_reply = root.find("query-reply")

            time_elem = query_reply.find("time")
            time_vals = time_elem.attrib
            self.logger.debug(f"Query-reply time: {time_vals}")

            time_elem = query_reply.find("time")
            time_vals = time_elem.attrib
            self.logger.debug(f"Time attributes: {time_vals}")

            collector_replies = query_reply.findall("collector")
            self.logger.debug(f"COLLECTOR FLOW REPLIES ({len(collector_replies)} collectors):")
            #   <query-reply>
            #     <time start="1727781900" end="1727868300" start_ascii="10/01/2024 11:25:00 +0000" end_ascii="10/02/2024 11:25:00 +0000"/>
            #     <collector name="10.80.25.30">
            #       <flow time="1727782268" router_gid="122" src_ip="0.0.0.0" dst_ip="224.0.0.1" src_port="0" dst_port="0" proto="2" in="6" out="1" bytes="36" packets="1" tcp_flags="0" blobs="11" avg_pkt_len="36"/>
            ints_for_gids = {}
            flow_list = []
            for collector in collector_replies:
                collector_name = collector.get('name')
                self.logger.debug(f"COLLECTOR {collector_name}:")
                flow_entries = collector.findall("flow")
                for flow in flow_entries:
                    self.logger.debug(f"   FLOW: {flow.attrib}")
                    router_gid = flow.get('router_gid')
                    recv_int = flow.get('in')
                    int_list = ints_for_gids.get(router_gid)
                    if int_list:
                        int_list.add(recv_int)
                    else:
                        ints_for_gids[router_gid] = set(recv_int)
                    flow_list.append({**flow.attrib, **{"collector": collector_name}})

            self.logger.debug(f"INTERFACES FOR GIDS: {ints_for_gids}")
            self.ints_for_gids = ints_for_gids

            self.logger.debug(f"FOUND {len(flow_list)} MATCHING FLOWS")
            self.flow_list = flow_list

            return response

    def get_referenced_router_interfaces(self):
        return self.ints_for_gids

    def get_matching_flows(self, int_metadata=None):
        return self.flow_list


class ArborWsApiRouterQuery:
    # This will query interface data for one or more routers using the Arbor Web Services API
    def __init__(self, url_prefix, arbor_wsapikey, validate_tls=True):
        self.url_prefix = url_prefix
        self.peakflow_version="1.0"
        self.peakflow_release="9.1"
        self.arbor_wsapikey = arbor_wsapikey
        self.logger = logging.getLogger(str(__class__))
        self.validate_tls = validate_tls
        self.router_metadata = {}
        self.query_limit = 1000000
        # curl -ks "https://dis-vl-sightline-1/arborws/admin/routers/" \
        #      -d "api_key=OLT8mCbnZRbVwI9L" -d "action=list" -d "sort=name:ascending"

    async def run_query(self, client_session, search_limit=25000, timeout=300):
        # set up the url, endpoint, and request parameters to execute a query
        url = f"{self.url_prefix }/arborws/admin/routers/"
        parameters = {'api_key': self.arbor_wsapikey,
                      'action': "list",
                      'limit': self.query_limit}
        self.logger.debug(f"Performing router query to {url}...")
        time_before_request = time.time()
        async with client_session.get(url, params=parameters, ssl=self.validate_tls, raise_for_status=True) as response:
            time_after_request = time.time()
            self.logger.debug(f"Query to {url} took {time_after_request-time_before_request} seconds.")
            content_types = response.headers['Content-Type'].split(";")
            if "application/json" not in content_types:
                raise ValueError(f"Response from GET {url} was not JSON (Content-Type returned was {content_types})")
            response_body = await response.json()
            self.router_metadata = response_body

    def get_router_metadata(self):
        return self.router_metadata


class ArborWsApiInterfaceQuery:
    # This will query interface data for one or more routers using the Arbor Web Services API
    def __init__(self, url_prefix, arbor_wsapikey, start_time_expression, end_time_expression,
                 validate_tls=True, unit_type_str="bps", ip_ver=4):
        self.url_prefix = url_prefix
        self.peakflow_version="1.0"
        self.peakflow_release="9.1"
        self.arbor_wsapikey = arbor_wsapikey
        self.start_time_expression = start_time_expression
        self.end_time_expression = end_time_expression
        self.logger = logging.getLogger("ArborWsApiInterfaceQuery")
        self.validate_tls = validate_tls
        self.unit_type_str = unit_type_str
        self.ip_ver = ip_ver
        self.router_interface_metadata = {}

    async def run_query(self, client_session, routers=None, search_limit=25000, timeout=300):
        if routers:
            router_instance_stanza = ""
            for router in routers:
                router_instance_stanza += f'''
                  <instance value="{router}"/>'''
            router_filter_section = f'''
                <filter type="router" binby="1">
                {router_instance_stanza}
                </filter>'''
        else:
            router_filter_section = ""

        query_string = f'''<?xml version="1.0" encoding="utf-8"?>
        <peakflow version="{self.peakflow_version}" release="{self.peakflow_release}"> 
            <query id="query1" type="status">
                <time start_ascii="{self.start_time_expression}" end_ascii="{self.end_time_expression}"/>
                <unit type="{self.unit_type_str}"/>
                <search limit="{search_limit}" timeout="{timeout}" ip_ver="{self.ip_ver}"/>
                <filter type="interface_status" binby="1"/>
                {router_filter_section}
            </query>
        </peakflow>
        '''
        # set up the url, endpoint, and request parameters to execute a query
        url = f"{self.url_prefix }/arborws/traffic/"
        parameters = {'api_key': self.arbor_wsapikey,
                      'query': query_string}

        self.logger.debug(f"Sending query to {url}: \n{query_string}")
        time_before_request = time.time()
        async with client_session.get(url, params=parameters, ssl=self.validate_tls, raise_for_status=True) as response:
            time_after_request = time.time()
            content_types = response.headers['Content-Type'].split(";")
            if "text/xml" not in content_types:
                raise ValueError(f"Response from GET {url} was not XML (Content-Type returned was {content_types})")

            response_body = await response.text()
            time_after_xfer = time.time()
            self.logger.info(f"Received {len(response_body)}-byte response from {url} "
                             f"for routers {routers} after {time_after_xfer-time_before_request:0.2} seconds    ")

            root = ET.fromstring(response_body)
            query_reply = root.find("query-reply")

            interface_replies = query_reply.findall("interface")

            # Build a hash of router IDs with a hash of interface IDs
            ints_for_gids = {}
            for interface in interface_replies:
                router_gid = int(interface.get('router_gid'))
                snmp_index = int(interface.get('snmp_index'))
                new_int_entry = {"routerName": interface.get('router'),
                                 "name": interface.get('name'),
                                 "id": interface.get('interface_id'),
                                 "type": interface.find('type').text,
                                 "description": interface.find("description").text,
                                 "ip": interface.find("ip").text,
                                 "speed": int(interface.find("speed").text)}
                int_list = ints_for_gids.get(router_gid)
                if int_list:
                    int_list[snmp_index] = new_int_entry
                else:
                    ints_for_gids[router_gid] = {snmp_index: new_int_entry}
            self.logger.debug(f"ROUTER INTERFACE METADATA: \n{pprint.pformat(ints_for_gids)}")
            self.router_interface_metadata = ints_for_gids
            return response

    def get_interface_metadata(self, asn_resolver=None):
        if asn_resolver:
            # Add ASN field for each router interface (will be None for interfaces that don't resolve)
            for router_id, router_entry in self.router_interface_metadata.items():
                for interface_id, interface_entry in router_entry.items():
                    asn_for_int = asn_resolver.router_interface_to_asn(interface_entry['routerName'],
                                                                       interface_entry['name'],
                                                                       interface_entry['description'])
                    interface_entry['asn'] = asn_for_int
        return self.router_interface_metadata


async def main():
    # FOR TESTING
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(name)s: %(levelname)s %(message)s')
    print("main(): Running tests...")
    event_loop = asyncio.get_event_loop()

    async with aiohttp.ClientSession() as session:
        traffic_query_1 = ArborWsApiTrafficQuery(os.environ.get('BH_ARBORWS_URI_PREFIX'),
                                                 os.environ.get('BH_ARBORWS_API_KEY'),
                                                 "1 day ago", "now", validate_tls=False)
        response = await traffic_query_1.run_query(session, fcap_filter="proto 2")
        flows = traffic_query_1.get_matching_flows()
        print(f"MATCHING FLOWS: {len(flows)}")

        interface_refs = traffic_query_1.get_referenced_router_interfaces()
        print("REFERENCED ROUTER INTERFACES:\n" + pprint.pformat(interface_refs))

        router_query_1 = ArborWsApiInterfaceQuery(os.environ.get('BH_ARBORWS_URI_PREFIX'),
                                                  os.environ.get('BH_ARBORWS_API_KEY'),
                                               "1 hour ago", "now", validate_tls=False)
        res1 = await router_query_1.run_query(session, routers=interface_refs.keys())
        # res1 = await router_query_1.run_query(routers=[122,116])

        int_metadata = router_query_1.get_interface_metadata()
        print("INTERFACE METADATA:\n" + pprint.pformat(int_metadata))

if __name__ == "__main__":
    asyncio.run(main())

