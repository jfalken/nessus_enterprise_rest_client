''' Nessus Rest API Client, for use with the Nessus v6 RESTful API
    by jfalken; https://github.com/jfalken/nessus_enterprise_rest_client
'''

import requests
import json
import time
import ssl
import sys
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager


class MyAdapter(HTTPAdapter):
    ''' via https://lukasa.co.uk/2013/01/Choosing_SSL_Version_In_Requests/
        At the time of writing this, *.nessus.org only accepts TLS1.0.
        This adapter forces requests to use TLS1.0
    '''
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1)

class NessusRestClient:
    ''' Uses the undocumented REST API for Nessus (ie, the web interface) '''

    def __init__(self, server, username, password, port=443, verify=True, proxies=None):
        ''' 'server' - https://nessus.server.org
            'username' - login username
            'password' - login password
            'verify' - SSL cert verification; set to False if using locally and self-signed certs
            'port' - optional; int of port, default is 443
            'proxies' - optional; dict of 'http' and 'https' proxies w port
        '''
        self.s = requests.Session()
        self.s.mount('https://', MyAdapter())
        self.server = server
        self.port = port
        self.url = '%s:%s' % (server, str(port))
        self.username = username
        self.password = password
        self.authenticated = False
        self.token = None
        self.verify = verify
        self.proxies = proxies


    def __request(self, url, data={}, method='POST'):
        ''' POST wrapper, returns response and .json()['reply']['contents'] 
            or ('error',error message) if an error occurs
        '''
        if self.authenticated == False:
            self.login()
        if method == 'GET':
            if self.proxies:
                r = self.s.get(url=url, data=data, proxies=self.proxies, verify=self.verify)
            else:
                r = self.s.get(url=url, data=data, verify=self.verify)
        if method == 'POST':
            if self.proxies:
                r = self.s.post(url=url, data=data, proxies=self.proxies, verify=self.verify)
            else:
                r = self.s.post(url=url, data=data, verify=self.verify)
        if method == 'DELETE':
            if self.proxies:
                r = self.s.delete(url=url, data=data, proxies=self.proxies, verify=self.verify)
            else:
                r = self.s.delete(url=url, data=data, verify=self.verify)
        if method == 'PUT':
            if self.proxies:
                r = self.s.put(url=url, data=data, proxies=self.proxies, verify=self.verify)
            else:
                r = self.s.put(url=url, data=data, verify=self.verify)

        return r


    def login(self):
        ''' login; does not use the __request wrapper since this is pre-auth '''
        self.authenticated = False
        self.token = None
        url = self.url + '/session'
        data = {'username' : self.username,
                'password' : self.password }
        if self.proxies:
            r = self.s.post(url=url, data=data, proxies=self.proxies, verify=self.verify)
        else:
            r = self.s.post(url=url, data=data, verify=self.verify)
        contents = r.json()
        self.token = contents['token']
        self.authenticated = True
        self.s.headers.update({'X-Cookie':'token=' + self.token})
        return r


    def logout(self):
        url = self.url + '/session'
        r = self.__request(url, method='DELETE')
        if r.status_code == 200:
            self.authenticated = False
            self.token = None
            self.s.headers.pop('X-Cookie')
            return r
        else:
            pass


    def get_scan_policies(self):
        ''' returns a list of all scan policies '''
        url = self.url + '/policies'
        r = self.__request(url, method='GET')
        if r.status_code == 200:
            return r.json()['policies']
        else:
            return r


    def get_scan_policy_by_id(self, policy_id):
        ''' returns single scan policy by policy_id '''
        url = self.url + '/policies/' + str(policy_id)
        r = self.__request(url, method='GET')
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            raise Exception('Scan Policy not found')
        else:
            raise Exception('Unknown Status')

    def get_scan_policy_by_name(self, policy_name):
        ''' return policy record with name of 'policy_name'; 
            first hit only 
        '''
        policies = self.get_scan_policies()
        for p in policies:
            if p['name'] == policy_name:
                return p
        return None


    def get_folders(self):
        ''' returns a list of folders '''
        url = self.url + '/folders'
        r = self.__request(url, method='GET')
        if r.status_code == 200:
            return r.json()['folders']
        elif r.status_code == 403:
            raise Exception('No Permission')
        else:
            return r


    def get_folder_by_name(self, folder_name):
        ''' return folder record with name of 'folder_name'; 
            first hit only 
        '''
        folders = self.get_folders()
        for f in folders:
            if f['name'] == folder_name:
                return f
        return None


    def get_scanners(self):
        ''' returns a list of scanners '''
        url = self.url + '/scanners'
        r = self.__request(url, method='GET')
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 403:
            raise Exception('No Permission')
        else:
            raise Exception('Unknown Status')


    def get_scans(self):
        '''  returns a list of scans '''
        url = self.url + '/scans'
        r = self.__request(url, method='GET')
        if r.status_code == 200:
            return r.json()['scans']
        else:
            raise Exception('Unknown Response')


    def get_scan_details(self, scan_id):
        '''  returns a list of scans '''
        url = self.url + '/scans/' + str(scan_id)
        r = self.__request(url, method='GET')
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            raise Exception('Scan does not exist')
        else:
            raise Exception('Unknown Response')


    def launch_scan(self, scan_id):
        ''' launch a scan by its scan_id '''
        url = self.url + '/scans/' + str(scan_id) + '/launch'
        r = self.__request(url, method='POST')
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            raise Exception('Scan does not exist')
        elif r.status_code == 403:
            raise Exception('Scan is disabled')
        else:
            raise Exception('Unknown Status')


