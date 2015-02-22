# Nessus Enterprise Rest Client

This is a python library for interfacing with the Nessus v6 API.

This library was originally made by reversing the web API as a user logged into the console. Since then, Tenable has released their v6 REST API and this module has been adjusted to work with the v6 API.

Official API documentation can be obtained by connecting to your Nessus server under `:8834/nessus6-api.html`

Proxies are supported, and SSL Certification verification can be disabled if you are using a local build w/ self-signed certs.

## Installation

### via PIP

Inside a [virtualenv](http://docs.python-guide.org/en/latest/dev/virtualenvs/): 

```bash
$ pip install git+https://github.com/jfalken/nessus_enterprise_rest_client.git

$ pip freeze
NessusClient==0.1
requests==2.4.3
wsgiref==0.1.2
```

## Status

Not all documented methods are implemented; this will be updated as I use it more and need more functionality. If you are using this, send me an issue/feature request and I'll work on it.

## Known Issues

At the time of writing this, Tenable's Nessus server only suports TLSv1.0. `requests` must be forced to use TLS1.0. For more information, please [read this](https://github.com/jfalken/nessus_enterprise_rest_client/blob/master/ssl_readme.md)

## Sample Usage

Most methods are pretty self explanatory. Downloading a report is a three-step process
so a wrapper method `download_report` was created to simplify the process.

Creating a scan policy is complicated and is best done via the UI; I do not plan to support it via the API.

### Connection

```python
import NessusClient as NRC

proxies = {
  "http": "http://127.0.0.1:8080",
  "https": "http://127.0.0.1:8080",
}

nrc = NRC.NessusRestClient(server,username,password,proxies=proxies)

```

### Download a Report

```python

# `download_report` wraps the process of requesting a download,
# checking status until ready, and finally performing the download
report_contents = nrc.download_report(report_id, 'xml')
```

### Creating and Launching a New Scan

```python

# First, create a scan policy via the UI, or use pre-existing; get its uuid
policy = nrc.get_scan_policy_by_name('Perimeter Scan')
uuid = policy['template_uuid']
 
# Create the Settings
targets = ['10.0.0.1','10.0.0.2']
emails = ['boba.fett@kamino.net','anakin@tatooine.org']
settings = nrc.get_settings_dict(uuid, 'My Scan Name','Description', emails, targets)

# Create the Scan
scan = nrc.create_scan(settings)

# Launch It
scan_id = scan['id']
resp = nrc.launch_scan(scan_id)
```

### Getting Scan details and Inserting to MongoDB

Since the API allows retrieveing scan details and results in JSON format, its simple to insert this information into MongoDB.

The 'details' method produces alot of information; only a small set is shown here.

```python
from pymongo import MongoClient

# Get scan details
details = nrc.get_scan_details(scan_id)

# Insert into MongoDB
client = MongoClient()
col = client['nessus']['scans']
col.insert(details)

# Show the vulnerabilities
c = col.find({'info.name' : 'scan_name'}, { 'hosts.severitycount': 1})

pprint.pprint(c[0])
{u'_id': ObjectId('546e6f0c1d0e83058674331e'),
 u'hosts': [{u'severitycount': {u'item': [{u'count': 33,
                                           u'severitylevel': 0},
                                          {u'count': 0,
                                           u'severitylevel': 1},
                                          {u'count': 0,
                                           u'severitylevel': 2},
                                          {u'count': 0,
                                           u'severitylevel': 3},
                                          {u'count': 0,
                                           u'severitylevel': 4}]}},
```

