#
# This software is made available according to the terms in the LICENSE.txt accompanying this code
#

from abc import ABC, abstractmethod
from ipaddress import IPv4Network
from typing import Callable, Awaitable


# Abstract base class for NetFlow traffic capture monitoring
class TrafficMonitorBase(ABC):
    @staticmethod
    def add_supported_arguments(self, arg_parser):
        """Add any options supported by the traffic monitor"""
        pass

    @staticmethod
    def get_redacted_args():
        return []

    @abstractmethod
    async def startup(self, event_loop):
        """Perform any startup. This should try to check for error conditions up-front and fail fast"""
        print("NetFlow extraction from SQL not yet supported - exiting.")
        exit(2)
        pass

    @abstractmethod
    def register_traffic_found_callback(self, callback: Callable[[int], Awaitable[None]]):
        """Register a callback function that will be invoked asynchronously when data is found."""
        pass

    @abstractmethod
    async def start_monitoring_for(self, attack_id: int, attack_entry):
        pass

    @abstractmethod
    async def start_monitoring_for_list(self, attack_list, replace_existing=False):
        pass

    @abstractmethod
    async def stop_monitoring_for(self, attack_id: int, attack_end_time: int):
        pass

    @abstractmethod
    async def stop_all_monitoring(self):
        pass
