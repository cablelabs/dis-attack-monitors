# Client SDK

The DIS Client SDK is a python wrapper intended to be used in conjunction with a DDoS reporting appliance such as Arbor. The SDK simply implements a simple interface for the [DIS REST API]().

For some of more common DDoS appliances, there is a [Docker Container]() available for that utilizes this SDK.

## Installation

DIS Client is a python package available via `pip` and requires Python 3+.

```
pip install dis-client-sdk
```

## Example:

After installing the SDK, retrieve your client [API Key from DIS]() and use it to instantiate the SDK:

```python
from dis_client_sdk import DisClient
from time import time

CLIENT_API_KEY="your-client-api-key-from-dis"

client = DisClient(api_key=CLIENT_API_KEY)
now = int(time())

# get info about the client
info = client.get_info()
print("Client Name: ", info["name"])


# Create an attack event that lasts for 10 seconds
ev_id = client.add_attack_event(start_timestamp=now,
                                end_timestamp=now+10,
                                attack_type=["ICMP_FLOOD", "POD"])

# Add an attribute to the attack event
client.add_attribute_to_event(event_uuid=ev_id,
                              name="myevent",
                              enum="MY_EVENT",
                              value="Test Value")

# Add an attack source (IP)
client.add_attack_source_to_event(ev_id,
                                  ip="1.0.0.0",
                                  attribute_list=[{
                                      "enum": "SEVERITY",
                                      "name": "Severity Level",
                                      "value": "high"
                                  },
                                      {
                                      "enum": "BPS",
                                      "name": "Bytes per second",
                                      "value": "1300"
                                  }])

# Gets all the event IDs staged for sending
event_ids = client.get_staged_event_ids()

# Send to DIS
client.send()

# Sent events are cleared from the staged events..check the dashboard to see your client metrics.


```

## API

The SDK has a few methods:

- `DisClient(api_key, base_url)` - constructor for the client. The `base_url` defaults to the DIS backend.
- `add_attack_event(start_timestamp, end_timestamp, [attack_type])` - Adds an attack event. `attack_type` is an optional array of strings. Returns a staged event ID.
- `add_attribute_to_event(event_id, name, enum, value, [metadata])` - Adds an attribute to an existing staged event and takes as an argument `name`, `enum`, and `value`. An optional `metadata` as JSON is included if desired.
- `get_info()` - Returns information about the client, organization, and client type attributes. See (Client GET)[] api docs for return spec.
- `add_attack_source_to_event(event_id, ip, [start_timestamp], [end_timestamp], [attack_type], [attribute_list])`. All optional parameters are included if ip information is different than the event. `attibuteList` takes a dictionary in the form `{name, enum, value, [metadata]}`.
- `update_event_end_timestamp(event_id, end_timestamp)` - updates an event end timestamp if not known upon creation.
- `get_staged_event_ids()` - returns list of staged event ids.
- `send()` - sends all staged events. Clears the staged events upon successful sending.

## License

MIT license
