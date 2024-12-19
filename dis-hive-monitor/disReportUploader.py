import logging
import pprint
import asyncio
import aiohttp
import time
import pprint
import json
import ipaddress
from asyncio import Event


class ReportJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj,(ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return str(obj)
        return super().default(obj)

class DisReportUploader:
    def __init__(self, args, base_logger):
        self.event_loop = None
        self.dis_api_base_url = args.dis_api_prefix
        self.dis_api_client_key = args.dis_api_client_key
        self.dis_api_http_proxy = args.dis_api_http_proxy
        self.report_uploader_task = None
        self.report_queue = []
        self.report_ready = Event()
        self.upload_retry_time_s = 120 # 2 minutes
        self.print_ex_backtraces = True
        self.logger = logging.getLogger(base_logger.name + " DIS-FAST Uploader")
        self.logger.debug(f"Initialized with \n{pprint.pformat(self.__dict__)}")

    async def startup(self, event_loop):
        self.logger.debug(f"Performing startup")
        self.event_loop = event_loop
        await self._check_dis_client_access()
        self.report_uploader_task = event_loop.create_task(self._report_uploader_loop())

    async def queue_reports_for_upload(self, reports):
        for observation_report in reports:
            fast_report = self._create_fast_report(observation_report)
            self.report_queue.append(fast_report)
            self.logger.info(f"Queued report for upload: \n{pprint.pformat(fast_report, compact=True)}")
            self.report_ready.set()

    async def _check_dis_client_access(self):
        url = f"{self.dis_api_base_url}/v1/client/me"
        query_params = {"api_key": self.dis_api_client_key}
        try:
            async with aiohttp.ClientSession() as http_session:
                async with http_session.get(url, params=query_params, raise_for_status=True) as response:
                    self.logger.info(f"_check_dis_client_access: SUCCESSFULLY verified DIS client")
                    return True
        except Exception as ex:
            self.logger.warning(f"_check_dis_client_access: DIS client FAILED to access {url} - "
                                f"check your connection and client key: {ex}",
                                exc_info=self.print_ex_backtraces)
            return False

    def _create_fast_report(self, report):
        # Note that sensitive data is not included (router names, IPs
        attack_info = report['attackInfo']
        interface_info = report['interfaceInfo']
        fast_report = {
            "attackId": attack_info['attackId'],
            "startTimestamp": attack_info['startTime'],
            "endTimestamp": attack_info['endTime'],
            "sourceAddress": attack_info['srcNetwork'],
            "destPort": attack_info['destPort'],
            "sourceInterfaceAsn": interface_info.get('asn', None),
            "numPackets": report['matchedPackets'],
            "attackType": ["forged-source"],
            "honeypotSource": attack_info['reporters']
        }
        return fast_report

    async def _upload_fast_reports(self, fast_reports):
        url = f"{self.dis_api_base_url}/v1/data/traceback-report"
        query_params = {"api_key": self.dis_api_client_key}
        self.logger.info(f"Attempting to upload {len(fast_reports)} reports to {url}")
        combined_fast_report = {"version": 1, "tracebackReports": fast_reports}
        fast_report_upload = json.dumps(combined_fast_report, cls=ReportJsonEncoder)
        try:
            async with aiohttp.ClientSession() as http_session:
                start_time = time.time()
                async with http_session.post(url, params=query_params, data=fast_report_upload,
                                             headers={"Content-type": "application/json"},
                                             raise_for_status=True) as response:
                    upload_time = time.time() - start_time
                    self.logger.info(f"Uploaded {len(fast_reports)} reports in {upload_time:0.2f} "
                                     f"(response: {response})")
                    return True
        except Exception as ex:
            self.logger.info(f"Could not upload {len(fast_reports)} reports to {url}: {ex}",
                             exc_info=self.print_ex_backtraces)
            return False

    async def _report_uploader_loop(self):
        self.logger.info("Report uploader loop started.")
        while True:
            try:
                wait_timeout = self.upload_retry_time_s if self.report_queue else None
                try:
                    await asyncio.wait_for(self.report_ready.wait(), timeout=wait_timeout)
                    self.report_ready.clear()
                    if await self._upload_fast_reports(self.report_queue):
                        self.report_queue = []
                except TimeoutError:
                    self.logger.info(f"Attempting upload retry of {len(self.report_queue)} pending report uploads")
            except Exception as ex:
                self.logger.warning(f"Caught exception uploading DIS-FAST report: {ex}",
                                    exc_info=self.print_ex_backtraces)
