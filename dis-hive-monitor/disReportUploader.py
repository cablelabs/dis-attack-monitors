import logging
import pprint
from asyncio import Queue


class DisReportUploader:
    def __init__(self, args, logger):
        self.event_loop = None
        self.dis_api_base_url = args.dis_api_uri
        self.dis_api_client_key = args.dis_api_client_key
        self.dis_api_http_proxy = args.dis_api_http_proxy
        self.report_uploader_task = None
        self.report_queue = Queue()
        self.print_ex_backtraces = True
        self.logger = logging.getLogger(logger.name + ":DIS-FAST Uploader")
        self.logger.info(f"Initialized with \n{pprint.pformat(self.__dict__)}")

    async def startup(self, event_loop):
        self.event_loop = event_loop
        self.logger.debug(f"Performing startup")
        await self._check_dis_client_access()
        self.report_uploader_task = event_loop.create_task(self._report_uploader_loop())

    async def queue_report_for_upload(self, redacted_report_info_list):
        #  curl -X POST "https://.../v1/data/traceback-report?api_key=..." -H "Content-Type: application/json" -d @report.json
        pass

    async def _report_uploader_loop(self):
        self.logger.info("Report uploader loop started.")


