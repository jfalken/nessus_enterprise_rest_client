# Nessus Enterprise Cloud Client

This is a python library for interfacing with the Tenable Nessus Enterprise Cloud scanning service. This was created because I did not like the existing libraries for this. This is based on reversing the REST API that one uses while interfacing with the service via the web browser; it does NOT use the documented XML/RPC API, which is lacking features.

This library was originally made by reversing the web API as a user logged into the console. Since then, Tenable has released their v6 REST API. Modifications are needed to make this work with v6; those updates will be worked on and added here.

## Status

Only a few methods are implemented; this will be updated as I use it more and need more functionality. If you are using this, send me an issue/feature request and I'll work on it.

## Sample Usage

```python
from NessusClient import NessusRestClient

proxies = {
  "http": "http://127.0.0.1:8080",
  "https": "http://127.0.0.1:8080",
}

nrc = NessusRestClient(server   = server,
                       username = username,
                       password = password,
                       proxies  = proxies)

policy_id = nrc.get_scan_policy('Perimeter Scan (exhaustive)')['object_id']

resp = nrc.launch_scan(scan_name   = 'scan',
                       description = 'Automatic Scan',
                       targets     = ['example.com','google.com'],
                       policy_id   = policy_id,
                       emails      = ['noone@nowhere.net']

scan_uuid = resp['uuid']
```

## TODOs

* Add re-auth when login expires
* Better handling of 'non-OK' response messages
* Do more stuff
