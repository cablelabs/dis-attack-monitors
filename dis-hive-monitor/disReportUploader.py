import logging
import pprint
import asyncio
import aiohttp
import time
import pprint
from asyncio import Queue


class DisReportUploader:
    def __init__(self, args, base_logger):
        self.event_loop = None
        self.dis_api_base_url = args.dis_api_uri
        self.dis_api_client_key = args.dis_api_client_key
        self.dis_api_http_proxy = args.dis_api_http_proxy
        self.report_uploader_task = None
        self.report_queue = Queue()
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
            await self.report_queue.put(fast_report)
            self.logger.info(f"Queued report for upload: \n{pprint.pformat(fast_report, compact=True)}")

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
        fast_report_upload = {"version": 1, "tracebackReports": fast_reports}
        try:
            async with aiohttp.ClientSession() as http_session:
                start_time = time.time()
                async with http_session.post(url, params=query_params, json=fast_report_upload,
                                             raise_for_status=True) as response:
                    upload_time = time.time() - start_time
                    self.logger.info(f"Uploaded {len(fast_reports)} reports in {upload_time:0.2f}")
                    return True
        except Exception as ex:
            self.logger.info(f"Could not upload {len(fast_reports)} reports to {url}: {ex}",
                             exc_info=self.print_ex_backtraces)
            return False

    async def _report_uploader_loop(self):
        self.logger.info("Report uploader loop started.")
        pending_uploads = []
        while True:
            try:
                wait_timeout = self.upload_retry_time_s if pending_uploads else None
                try:
                    fast_report = await asyncio.wait_for(self.report_queue.get(), timeout=wait_timeout)
                    if fast_report:
                        pending_uploads.append(fast_report)
                except TimeoutError:
                    self.logger.info(f"Attempting upload retry of {len(pending_uploads)} pending report uploads")
                report_body = {"version": 1, "tracebackReports": pending_uploads}
            except Exception as ex:
                self.logger.warning(f"Caught exception uploading DIS-FAST report: {ex}",
                                    exc_info=self.print_ex_backtraces)
