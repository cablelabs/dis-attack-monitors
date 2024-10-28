
from datetime import datetime

d = "2015-04-30T23:59:59+00:00"
if ":" == d[-3:-2]:
    d = d[:-3]+d[-2:]
print(datetime.strptime(d, "%Y-%m-%dT%H:%M:%S%z"))

timestr = "2020-01-22T21:15:37+00:00"
if ":" == timestr[-3:-2]:
    timestr = timestr[:-3]+timestr[-2:]
print(timestr)
print(datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%S%z"))

