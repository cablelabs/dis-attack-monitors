import os
import json
import logging
import ipaddress
from pathlib import Path
from datetime import datetime
import pprint


class LocalFileReportWriter:
    def __init__(self, args, logger):
        self.event_loop = None
        self.args = args
        self.report_store_dir = args.report_store_dir
        self.report_storage_path = None
        self.report_store_format = args.report_store_format
        self.logger = logging.getLogger("LocalFileReportWriter")
        self.logger.info(f"Initialized with \n{pprint.pformat(self.__dict__)}")
        self.per_report_filename_pattern = "forged-traffic-report.attack-{attack_id}.router-{router_id}.int-{interface_id}.json"
        # self.per_report_filename_pattern = "forged-traffic-report.{end_date}T{end_time}Z.json"
        self.per_report_dirname_pattern = "forged-traffic-reports.{end_date}"
        self.single_report_file_pattern = "aggregate-forged-traffic-reports.txt"

    async def startup(self, event_loop):
        self.logger.debug(f"Performing startup")
        self.event_loop = event_loop

        # Process report options
        if self.report_store_dir:
            report_storage_path = Path(self.report_store_dir)
            if not report_storage_path.is_dir():
                self.logger.error(f"The report storage path is not a directory (dest: \"{self.report_store_dir}\")")
                exit(30)
            if not os.access(report_storage_path.absolute(), os.W_OK):
                self.logger.error(f"The report storage path is not writable (dest: \"{self.report_store_dir}\")")
                exit(31)
            self.report_storage_path = report_storage_path

    class ReportJsonEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj,
                          (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)):
                return str(obj)
            if isinstance(obj, set):
                return list(obj)
            return super().default(obj)

    def filename_for_report(self, name_pattern, report):
        end_datetime = datetime.fromtimestamp(report['attackInfo']['endTime'])
        start_datetime = datetime.fromtimestamp(report['attackInfo']['endTime'])
        return name_pattern.format(**{"attack_id": report['attackInfo']['attackId'],
                                      "router_id": report['routerId'],
                                      "interface_id": report['interfaceId'],
                                      "start_time": start_datetime.strftime("%H:%M:%S"),
                                      "start_date": start_datetime.strftime("%Y-%m-%d"),
                                      "end_time": end_datetime.strftime("%H:%M:%S"),
                                      "end_date": end_datetime.strftime("%Y-%m-%d")})

    async def save_forged_traffic_report(self, report_list):
        for report in report_list:
            try:
                start_time = report['attackInfo']['startTime']
                report['attackInfo']['startDateTime'] = datetime.fromtimestamp(start_time).strftime("%Y-%m-%dT%H%M%SZ")
                end_time = report['attackInfo']['endTime']
                report['attackInfo']['endDateTime'] = datetime.fromtimestamp(end_time).strftime("%Y-%m-%dT%H%M%SZ")
            except Exception as ex:
                self.logger.warning(f"Error converting time on report {report['attackInfo']['attackId']}")

        if self.report_store_format == "file-per-report":
            for report in report_list:
                try:
                    report_filename = self.filename_for_report(self.per_report_filename_pattern, report)
                    report_filepath = self.report_storage_path.joinpath(report_filename)
                    with report_filepath.open('w') as reportfile:
                        json.dump(report, reportfile, indent=4, cls=self.ReportJsonEncoder)
                        reportfile.write("\n")
                        reportfile.close()
                        self.logger.info(f"Saved report on attack {report['attackInfo']['attackId']} "
                                         f"to {report_filepath.absolute()}")
                except Exception as ex:
                    warn_msg = f"Caught an exception saving report for attack ({ex}): \n{report}"
                    self.logger.warning(warn_msg)
        elif self.report_store_format == "file-per-report-date-subdirs":
            for report in report_list:
                try:
                    dir_filename = self.filename_for_report(self.per_report_dirname_pattern, report)
                    dir_filepath = self.report_storage_path.joinpath(dir_filename)
                    dir_filepath.mkdir(exist_ok=True)
                    report_filename = self.filename_for_report(self.per_report_filename_pattern, report)
                    report_filepath = dir_filepath.joinpath(report_filename)

                    with report_filepath.open('w') as reportfile:
                        json.dump(report, reportfile, indent=4, cls=self.ReportJsonEncoder)
                        reportfile.write("\n")
                        reportfile.close()
                        self.logger.info(f"Saved report on attack {report['attackInfo']['attackId']} "
                                         f"to {report_filepath.absolute()}")
                except Exception as ex:
                    warn_msg = f"Caught an exception saving report for attack ({ex}): \n{report}"
                    self.logger.warning(warn_msg)
        elif self.report_store_format == "combined-report-file":
            try:
                report_filepath = self.report_storage_path.joinpath(self.single_report_file_pattern)
                with report_filepath.open('a') as reportfile:
                    for report in report_list:
                        json.dump(report, reportfile, indent=4, cls=self.ReportJsonEncoder)
                        reportfile.write("\n")
                        attack_id = report['attackInfo']['attackId']
                        self.logger.info(f"Saved report on attack {attack_id} to {report_filepath.absolute()}")
                    reportfile.close()
            except Exception as ex:
                warn_msg = f"Caught an exception saving the report for attack ({ex}): \n{report}"
                self.logger.warning(warn_msg)
        else:
            self.logger.warning("UNKNOWN attack report format \"self.report_store_format\"!")

