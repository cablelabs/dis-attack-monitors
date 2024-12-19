#
# This software is made available according to the terms in the LICENSE.txt accompanying this code
#

import asyncio
import time
import logging
import pprint
import websockets
import ssl
import websockets_proxy
import json
from websockets_proxy import Proxy
from websockets import ConnectionClosed


class HiveMonitor:
    def __init__(self, args, logger):
        self.logger = logging.getLogger(logger.name + ":HIVE Monitor")
        self.event_loop = None
        self.captureMonitors = []
        self.websocket = None
        self.hive_url = args.hive_url
        self.hive_proxy_url = args.hive_proxy_url
        self.hive_client_cert_file = args.hive_client_cert_file
        self.hive_client_cert_key_file = args.hive_client_cert_file
        self.hive_ca_certs_file = args.hive_ca_certs_file
        self.hive_retry_interval = args.hive_retry_interval
        self.log_list_updates = args.log_list_updates
        self.test_entries = args.test_entries
        self.active_attacks_dict = {}
        self.add_test_attacks()
        self.hive_client_cert_file = args.hive_client_cert_file
        self.logger.info(f"Initialized with \n{pprint.pformat(self.__dict__)}")
        self.print_ex_backtraces = True

    async def startup(self, event_loop):
        self.event_loop = event_loop
        self.logger.debug(f"Performing startup")
        await self.connect_client()

    def add_capture_monitor(self, capture_monitor):
        self.captureMonitors.append(capture_monitor)

    def remove_capture_monitor(self, capture_monitor):
        self.captureMonitors.remove(capture_monitor)

    def add_test_attacks(self):
        retro_adjustment = 120
        if self.test_entries:
            for attack_entries_str in self.test_entries:
                for attack_entry_str in attack_entries_str.split(';'):
                    ae = json.loads(attack_entry_str)
                    startTime = int(time.time()) - retro_adjustment
                    attack = {'attackId': ae['attackId'],
                              'startTime': startTime, 'endTime': startTime + ae['durationMinutes'] * 60,
                              'srcNetwork': ae['srcNetwork'], 'destPort': ae['destPort'], 'reporters': [],
                              'messageType': 'HIVE:ATTACK_START'}
                    self.active_attacks_dict[attack['attackId']] = attack

    async def connect_client(self):
        if self.hive_client_cert_file:
            # Setup the client's cert
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            self.logger.info("Loading test client certificate from ", self.hive_client_cert_file.name)
            ssl_context.load_cert_chain(self.hive_client_cert_file.name)

            # Verify peer certs using the websocket root as the CA
            self.logger.info("Loading CA certificate from ", self.hive_ca_certs_file.name)

            ssl_context.load_verify_locations(cafile=self.hive_client_cert_file.name)
            ssl_context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
            ssl_context.check_hostname = False
        else:
            ssl_context = None

        try:
            if self.hive_proxy_url:
                proxy = Proxy.from_url(self.hive_proxy_url)
                self.logger.info(f"CONNECTING to {self.hive_url} via proxy {self.hive_proxy_url}...")
                ws_context = websockets_proxy.proxy_connect(self.hive_url, ssl=ssl_context, proxy=proxy)
            else:
                self.logger.info(f"CONNECTED to {self.hive_url}")
                ws_context = websockets.connect(self.hive_url, ssl=ssl_context)
        except Exception as Ex:
            self.logger.info(f"Caught an exception creating connection to {self.hive_url}"
                             f"{' via proxy ' + self.hive_proxy_url if self.hive_proxy_url else ''}: {Ex}")
            exit(-1)

        event_loop = asyncio.get_event_loop()

        while True:
            try:
                async with ws_context as websocket:
                    while True:
                        message = await websocket.recv()
                        await self.process_hive_message(message)
            except ConnectionClosed as ex:
                self.logger.info(f"Connection to {self.hive_url} closed")
            except Exception as Ex:
                self.logger.info(f"Caught an exception on connection to {self.hive_url}: {Ex}")
            finally:
                self.logger.info(f"Websocket closed. Reopening websocket connection in {self.hive_retry_interval} seconds...")
                await asyncio.sleep(self.hive_retry_interval)

    async def process_hive_message(self, hive_message):
        try:
            self.logger.debug(f"process_hive_message: {hive_message}")
            message_json = json.loads(hive_message)
            message = message_json['message']
            message_id = message['messageId']
            self.logger.debug(f"process_hive_message {message_id}: {json.dumps(message_json, indent=3)}")
            message_type = message['messageType']
            if message_type == 'HIVE:ATTACK_START':
                attack_id = message['attackId']
                self.logger.debug(f"Adding attack ID {attack_id} to tracked attack list")
                self.active_attacks_dict[attack_id] = message
                for capture_monitor in self.captureMonitors:
                    await capture_monitor.start_monitoring_for(attack_id, message)
                return
            if message_type == 'HIVE:ATTACK_END':
                attack_id = message['attackId']
                self.logger.debug(f"Removing attack ID {attack_id} from the tracked attack list")
                self.active_attacks_dict.pop(attack_id)
                for capture_monitor in self.captureMonitors:
                    await capture_monitor.stop_monitoring_for(attack_id, message['endTime'])
                return
            if message_type == 'HIVE:ATTACK_LIST':
                self.logger.debug(f"Received HIVE attack list message")
                attack_list = message['attackList']
                if message['supersedesPreviousAttacks']:
                    self.logger.debug(f"CLEARING the current attack list")
                    self.active_attacks_dict = {}
                    self.add_test_attacks()
                for attack in attack_list:
                    attack_id = attack['attackId']
                    self.active_attacks_dict[attack_id] = attack
                self.add_test_attacks()
                for capture_monitor in self.captureMonitors:
                    await capture_monitor.start_monitoring_for_list(self.active_attacks_dict, replace_existing=True)
                self.logger.info(f"ADDED {len(attack_list)} attacks to active attack list")
                return
            self.logger.info(f"process_hive_message: Ignoring unknown message: {message_json}")
        except Exception as Ex:
            self.logger.warning(f"process_hive_message: Caught an exception processing message {hive_message}: {Ex}",
                                exc_info=self.print_ex_backtraces)
        finally:
            if self.log_list_updates:
                self.dump_attack_entries()

    async def perform_periodic_connection_reports(self, report_status_interval_s):
        self.logger.info("Performing status reports every %s seconds", report_status_interval_s)
        last_num_attacks = len(self.active_attacks_dict)
        last_report_count = 0
        while True:
            await asyncio.sleep(report_status_interval_s)
            num_attacks = len(self.active_attacks_dict)
            self.logger.info(f"Tracking {num_attacks} active attacks ({num_attacks-last_num_attacks:+}), "
                             f"Uploaded {self.report_count-last_report_count} reports")
            last_num_attacks = num_attacks
            last_report_count = self.report_count
