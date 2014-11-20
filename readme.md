# Nessus Enterprise Rest Client

This is a python library for interfacing with the Nessus v6 API. 

This library was originally made by reversing the web API as a user logged into the console. Since then, Tenable has released their v6 REST API and this module has been adjusted to work with the v6 API. 

## Status

Only a few methods are implemented; this will be updated as I use it more and need more functionality. If you are using this, send me an issue/feature request and I'll work on it.

## Known Issues

At the time of writing this, Tenable's Nessus server only suports TLSv1.0. `requests` must be forced to use TLS1.0. For more information, please [read this](https://github.com/jfalken/nessus_enterprise_rest_client/blob/master/ssl_readme.md)

## Sample Usage

TBD
