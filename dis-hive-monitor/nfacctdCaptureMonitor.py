#
# This software is made available according to the terms in the LICENSE.txt accompanying this code
#

import asyncio
from ipaddress import IPv4Network
from typing import Callable, Awaitable
from captureMonitorBase import TrafficMonitorBase
import mysql.connector
import subprocess
import json
import logging
from datetime import datetime
import ifname
import pprint

class NfacctdTrafficMonitor(TrafficMonitorBase):
    @staticmethod
    def add_supported_arguments(arg_parser):
        """Add any options supported by the nfacct traffic monitor"""
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

    @staticmethod
    def get_redacted_args():
        return ["nfsql_db_user", "nfsql_db_pass"]

    def register_traffic_found_callback(self, callback: Callable[[int], Awaitable[None]]):
        self.data_found_callback = callback
        pass

    def __init__(self, args, logger):
        self.args = args
        self.data_found_callback = None
        self.logger = logging.getLogger("Arbor WsApi Capture")
        self.logger.info(f"Initialized with \n{pprint.pformat(self.__dict__)}")

    async def startup(self, event_loop):
        if not (self.args.db_host or self.args.db_user):
            self.logger.info("No DB host defined - SKIPPING DB check and report generation")
        else:
            await self.check_db_connection_loop()

    async def start_monitoring_for(self, attack_id: int, attack_entry):
        print(f"NfacctdTrafficMonitor: Start monitoring for attack {attack_id}: {attack_entry}")
        await asyncio.sleep(1)

    async def start_monitoring_for_list(self, attack_list, replace_existing=False):
        pass

    async def start_monitoring_for_all(self, attack_list):
        print(f"NfacctdTrafficMonitor: Start monitoring for {len(attack_list)} additional attacks")
        await asyncio.sleep(1)

    async def stop_monitoring_for(self, attack_id: int, attack_end_time: int):
        print(f"NfacctdTrafficMonitor: Stop monitoring for attack {attack_id} at {attack_end_time}")
        await asyncio.sleep(1)

        # Simulate data found and trigger callback if registered
        if self.data_found_callback:
            print(f"NfacctdTrafficMonitor: Data found for attack {attack_id}, invoking callback...")
            await self.data_found_callback(attack_id)

    async def stop_all_monitoring(self):
        print(f"NfacctdTrafficMonitor: Stopped monitoring")
        await asyncio.sleep(1)

    async def _check_db_connection_loop(self):
        for count in range(10):
            if await self._check_db_connection():
                return True
            await asyncio.sleep(5)
        self.logger.warning("Could not connect to DB!")
        return False

    async def _check_db_connection(self):
        if not (self.args.db_host or self.args.db_user):
            self.logger.info("No DB host defined - SKIPPING DB check and report generation")
            return
        self.logger.info("Checking DB connection...")
        try:
            # Define db_database connection
            cnx = mysql.connector.connect(
                host=self.args.db_host,
                user=self.args.db_user,
                password=self.args.db_password,
                database=self.args.db_name
            )
            cursor = cnx.cursor(buffered=True)
            result = cursor.execute("SELECT COUNT(*) FROM netflow")
            rows = cursor.fetchall()
            self.logger.info(f"DB check found {rows[0][0]} netflow entries")
            result = cursor.execute("SELECT COUNT(*) FROM honeypot_feed")
            rows = cursor.fetchall()
            self.logger.info(f"DB check found {rows[0][0]} honeypot_feed entries")
            cursor.close()
            cnx.close()
            return True
        except Exception as ex:
            self.logger.info("DB check failed: " + str(ex))
            return False;

    async def _update_nfacctd(self):
        nfacctd_filter = ''

        try:
            # Generate the pretag map
            nfacctd_filters = []
            for (attack_id, attack_entry) in self.active_attacks_dict.items():
                self.logger.debug(f"update_nfacctd: Looking at attack entry {attack_entry}")
                dest_port = attack_entry['destPort']
                source_net = attack_entry['srcNetwork']
                attack_start_time = datetime.fromtimestamp(attack_entry['startTime'])
                age = datetime.now() - attack_start_time
                age_hm = f"{age.seconds // 3600}h {age.seconds % 60}m"
                reporters = attack_entry.get('reporters')
                comment_line = f"! Attack {attack_id} started {attack_start_time.strftime('%m/%d %H:%M')} ({age_hm} ago): " \
                               f"source net {source_net} dest port {dest_port} reporters {reporters}\n"
                match dest_port:
                    case 53:
                        nfacctd_filter = 'set_label=dns src_net={} \n'.format(source_net)
                    case 123:
                        nfacctd_filter = 'set_label=ntp src_net={} \n'.format(source_net)
                    case 19:
                        nfacctd_filter = 'set_label=chargen src_net={} \n'.format(source_net)
                    case 389:
                        nfacctd_filter = 'set_label=ldap src_net={} \n'.format(source_net)
                    case 161:
                        nfacctd_filter = 'set_label=snmp src_net={} \n'.format(source_net)
                    case 1900:
                        nfacctd_filter = 'set_label=ssdp src_net={} \n'.format(source_net)
                    case 111:
                        nfacctd_filter = 'set_label=portmap src_net={} \n'.format(source_net)
                nfacctd_filters.append(comment_line)
                nfacctd_filters.append(nfacctd_filter)

            self.logger.debug(nfacctd_filters)

            # Write the changes to the file
            self.logger.info(f"update_nfacctd: Updating {self.args.nfacctd_map_file}")
            with open(self.args.nfacctd_map_file, 'w') as f:
                f.writelines(nfacctd_filters)

            # Hup the nfacctd process
            if self.args.nfacctd_signal_map:
                subprocess.run(['killall', '-USR2', 'nfacctd'])
                self.logger.debug('Signalled nfacctd processes')
        except Exception as Ex:
            self.logger.warning(f"update_nfacctd: Caught an exception generating updating nfacctd: {Ex}")

    # Function to translate the ASN of the interface that is used for peering from the router IP/input index number
    def _get_asn_for_interface(self, router, int_index):
        peer_key = router + ":" + str(int_index)
        try:
            asn = ifname.peer_name[peer_key]
        except:
            asn = 'N/A'
        return asn

    # Function to return the AS name (handle)
    def _get_asn_name(self, asn):
        # Construct URL
        url = 'https://stat.ripe.net/data/as-overview/data.json?resource=' + str(asn)
        # Make API call
        response = requests.get(url)
        # Put results into dict
        as_info = response.json()
        # Pick out the AS name
        asn_name = as_info['data']['holder']
        # Return it
        return asn_name

    async def _process_hive_message(self, hive_message):
        try:
            # print(f"process_hive_message: {hive_message}")
            global active_attacks_dict
            message_json = json.loads(hive_message)
            message = message_json['message']
            message_id = message['messageId']
            self.logger.debug(f"process_hive_message {message_id}: {json.dumps(message_json, indent=3)}")
            message_type = message['messageType']
            # print(f"process_hive_message: {json.dumps(message_json, indent=3)}")
            if message_type == 'HIVE:ATTACK_START':
                attack_id = message['attackId']
                self.logger.debug(f"Adding attack ID {attack_id} to tracked attack list")
                active_attacks_dict[attack_id] = message
                self.logger.debug(f"Tracking {len(active_attacks_dict)} attacks")
                # Add hook for attack start processing (manage nfacctd for sql capture, noop for Arbor forensics)
                await self._update_nfacctd()
                return
            if message_type == 'HIVE:ATTACK_END':
                attack_id = message['attackId']
                self.logger.debug(f"Removing attack ID {attack_id} from the tracked attack list")
                active_attacks_dict.pop(attack_id)
                self.logger.debug(f"Tracking {len(active_attacks_dict)} attacks")
                await self._update_nfacctd()
                # Add hook for attack end processing (manage nfacctd for sql capture)
                # Add hook for report processing
                # TODO:
                # await match_stats = generate_report(hive_message)
                return
            if message_type == 'HIVE:ATTACK_LIST':
                self.logger.debug(f"Received HIVE attack list message")
                attack_list = message['attackList']
                if message['supersedesPreviousAttacks']:
                    self.logger.debug(f"CLEARING the current attack list")
                    active_attacks_dict = {}
                for attack in attack_list:
                    attack_id = attack['attackId']
                    active_attacks_dict[attack_id] = attack
                self.logger.info(f"ADDED {len(attack_list)} attacks to active attack list")
                # Call an update function on the capture delegate (if any)
                await self._update_nfacctd()
                return
            self.logger.info(f"process_hive_message: Ignoring unknown message: {message_json}")
        except Exception as Ex:
            self.logger.warning(f"process_hive_message: Caught an exception processing message {hive_message}: {Ex}",
                                exc_info=True)

    # Function to get the netflow records corresponding to the attack that ended and upload them to the central server
    async def generate_report(self, event):
        if not (self.args.db_host or self.args.db_user):
            self.logger.debug(f"No DB specified - skipping report generation")
            return

        try:
            message_id = event['messageId']

            # Define db_database connection
            cnx = mysql.connector.connect(
                host=self.args.db_host,
                user=self.args.db_user,
                password=self.args.db_password,
                database=self.args.db_name
            )

            # Create a cursor
            cursor = cnx.cursor(buffered=True)

            # Create db_database query to get the list of netflow records that match the source IP and destination port during the start time and end time
            # query = 'select * from  acct_v9 where ip_src like \'%{}%\' and stamp_inserted between \'%{}%\' and \'%{}%\' '.format(event['srcnet'],event['startTime'],now)
            # Look at the events up to yesterday (for debugging)  DELETE this!
            # query = 'select * from  acct_v9 where ip_src like \'%{}%\' and stamp_inserted between \'{}\' and \'{}\' '.format(event['srcnet'],yesterday,now)
            # query = 'select COUNT(* ) as record_count, ip_src, dst_port, iface_in, peer_ip_src from  acct_v9 where ip_src like \'%{}%\' and stamp_inserted between \'{}\' and \'{}\' GROUP BY ip_src,dst_port,iface_in,peer_ip_src'.format(event['srcnet'],yesterday,now)
            query = """SELECT COUNT(*) AS record_count, ip_src, dst_port, iface_in, peer_ip_src FROM netflow WHERE ip_src LIKE %s AND stamp_inserted BETWEEN %s AND %s GROUP BY ip_src,dst_port,iface_in,peer_ip_src"""
            # query = 'select * from  acct_v9 where ip_src like \'%{}%\' '.format(event['srcnet'])

            # First param is IP network address (first 3 octets)
            # Second param is start time
            # Third param is end time
            data_tuple = (event['srcNetwork'][:-4] + '%',
                          str(datetime.fromtimestamp(int(event['startTime']))),
                          str(datetime.fromtimestamp(int(event['endTime']))))
            # logger.debug("Query: " + query)
            # logger.debug(f"Params: {data_tuple}")

            # Execute the SQL statement
            cursor.execute(query, data_tuple)

            # Commit the changes to the db_database
            cnx.commit()

            # Create a blank report
            report = {}

            # Count the number of rows returned
            row_count = cursor.rowcount
            # if row_count > 0:
            #    logger.debug(query)
            #    logger.debug(event)

            # logger.debug('SQL query returned {} rows.'.format(row_count))
            if row_count == 0:
                self.logger.debug(f"No local records found for completed attack event {message_id}")
                return

            # logger.debug(cursor)

            total_count = 0
            # for (as_src, as_dst,ip_src,ip_dst,src_port,dst_port,ip_proto,packets,bytes,stamp_inserted,stamp_updated,iface_in,iface_out,peer_ip_src) in cursor:
            for (record_count, ip_src, dst_port, iface_in, peer_ip_src) in cursor:
                if peer_ip_src not in ignore_list.routers:
                    self.logger.debug(f"Found {record_count} record(s) for ignored router IP {peer_ip_src}")
                    continue
                # Translate interfaces to AS/Peer
                asn = self._get_asn(peer_ip_src, iface_in)
                # If the ASN is not N/A then lookup the name
                if asn != 'N/A':
                    asn_name = get_asn_name(asn)
                else:
                    asn_name = 'N/A'
                # Set the peer name to the ASN + the ASN Name
                peer = asn + ' ' + asn_name
                # Generate the message to be logged
                now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                message = 'Found {} record(s) for attack {} from IP {} to dest port {} from peer {} on router {} ifindex {}' \
                          .format(record_count, message_id, ip_src, dst_port, peer, peer_ip_src, iface_in)
                self.logger.debug(message)
                total_count += record_count

            # Generate report to be sent
            # Send report
            # logger.debug(report)
            self.report_count += 1
            self.logger.debug(f"Found a total of {total_count} records for completed attack event {message_id}")
        except Exception as ex:
            self.logger.warning(f"Caught exception generating report for {message_id}: {ex}", exc_info=True)
        finally:
            if cursor:
                cursor.close()
            if cnx:
                cnx.close()
