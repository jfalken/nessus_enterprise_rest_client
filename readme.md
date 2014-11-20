# Nessus Enterprise Rest Client

This is a python library for interfacing with the Nessus v6 API.

This library was originally made by reversing the web API as a user logged into the console. Since then, Tenable has released their v6 REST API and this module has been adjusted to work with the v6 API.

Official API documentation can be obtained by connecting to your Nessus server under `:8834/nessus6-api.html`

Proxies are supported, and SSL Certification verification can be disabled if you are using a local build w/ self-signed certs.

## Installation

1. Clone this repo
2. Inside a virtualenv, `pip install -r requirements.txt`

This library will be pip installable in the near future.

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

nrc = NRC(server,username,password,proxies=proxies)

```

### Download a Report

```python

# `download_report` wraps the process of requesting a download,
# checking status until ready, and finally performing the download
report_contents = nrc.download_report(report_id, 'xml')
```

### Creating and Launching a New Scan

```python

# Create a scan via the UI, or use pre-existing
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
