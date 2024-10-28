import requests
from typing import Dict
from uuid import uuid4
from pydantic import IPvAnyAddress
from pydantic.types import Json, UUID4
from typing import List, Optional
from pydantic import BaseModel, Json, HttpUrl

try:
    from devtools import debug as print
except:
    pass


class EventAttribute(BaseModel):
    enum: str
    name: str
    value: Optional[str]
    metadata: Optional[Json]


class IpAttribute(BaseModel):
    enum: str
    name: str
    value: Optional[str]
    metadata: Optional[Json]


class DisClient(object):
    """SDK for the /data route for the DIS system.  Implements the REST API. """

    def __init__(self, api_uri: str, api_key: str, http_proxy=None, staged_limit=0):
        self._key = api_key
        self._base_url = api_uri
        if http_proxy:
            self._http_proxies = {'http': http_proxy, 'https': http_proxy}
        else:
            self._http_proxies = None
        self._staged_limit = staged_limit
        self._events = {}

    def get_info(self):
        request_uri = f"{self._base_url}/v1/client/me"
        res = requests.get(request_uri,
                           params={"api_key": self._key},
                           allow_redirects=True,
                           proxies=self._http_proxies)
        if res.status_code == 401:
            raise Exception("Not authorized.  Check that your API Key is correct.")

        if res.status_code != 200:
            raise Exception(f"DIS server returned (HTTP Status: {res.status_code} accessing {request_uri} ({res.reason})")

        return res.json()

    def get_dest(self):
        return self._dest_url

    def add_attack_event(self, start_timestamp: int,
                         end_timestamp: int,
                         attack_type: List[str] = None):
        """Stages an Event Attack to the outgoing DIS ingestion data.  Returns an ID to be used to reference the event in the SDK"""

        if self._staged_limit and len(self._events) == self._staged_limit:
            raise Exception(f"Too many staged events ({self._staged_limit})")

        event_uuid = str(uuid4())
        self._events[event_uuid] = {
            "startTimestamp": start_timestamp,
            "endTimestamp": end_timestamp,
            "attackType": attack_type,
            "ipAddressList": [],
            "attributeList": []
        }

        return event_uuid

    def update_event_end_timestamp(self, event_uuid: UUID4, end_timestamp: int):
        """Updates the end timestamp of an attack event"""
        self._events[event_uuid]["endTimestamp"] = end_timestamp

    def add_attribute_to_event(self, event_uuid: UUID4, name: str, enum: str, value: str, metadata: Dict = None):
        if not event_uuid in self._events:
            raise Exception("Event does not exist")

        self._events[event_uuid]["attributeList"].append({
            "enum": enum,
            "name": name,
            "value": value,
            "metadata": metadata
        })

    def add_attack_source_to_event(self,
                                   event_uuid: UUID4,
                                   ip: IPvAnyAddress,
                                   start_timestamp: int = None,
                                   end_timestamp: int = None,
                                   attack_type: List[str] = None,
                                   attribute_list: List[IpAttribute] = None):
        """Adds an IP Address (attack source) to an existing Attack Event"""
        if not event_uuid in self._events:
            raise Exception("Event does not exist")

        self._events[event_uuid]["ipAddressList"].append({
            "ipAddress": ip,
            "startTimestamp": start_timestamp,
            "endTimestamp": end_timestamp,
            "attackType": attack_type,
            "attributeList": attribute_list
        })

    def get_staged_event_ids(self):
        """Returns all staged event ids in DisClient"""
        return [k for k, v in self._events.items()]

    def send(self):
        """Sends all staged attack events to DIS and clears staged events"""

        events = []
        for k, v in self._events.items():
            events.append(v)

        upload_uri = f"{self._base_url}/v1/data?api_key={self._key}"
        res = requests.post(upload_uri, json={"events": events}, proxies=self._http_proxies)

        if 200 <= res.status_code < 400:
            self._events = {}
            return f"Sent {len(events)} events to {upload_uri} (HTTP Status: {res.status_code} ({res.reason}))"

        if 500 <= res.status_code < 600 or res.status_code == 401:
            # Can be remedied on the server side - throw an error but don't clear the queue
            raise Exception(f"DIS server returned recoverable server error (HTTP Status: "
                            f"{res.status_code} ({res.reason}) - {len(events)} reports queued")

        if 400 <= res.status_code < 500:
            # Not considered recoverable - so clear the queue
            self._events = {}
            raise Exception(f"DIS server returned client error (HTTP Status: {res.status_code} "
                            f"uploading to {upload_uri} ({res.reason})")

