''' Nessus Rest API Client;
    by jfalken. written using requests sessions and because I did not like
    the existing nessus libraries on github
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

    def __init__(self, server, username, password, port=443, proxies=None):
        ''' 'server' - https://nessus.server.org
            'username' - login username
            'password' - login password
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
        self.proxies = proxies


    def __post(self, url, data):
        ''' POST wrapper, returns response and .json()['reply']['contents'] '''
        if self.authenticated == False:
            self.login()
        if self.proxies:
            r = self.s.post(url=url, data=data, proxies=self.proxies)
        else:
            r = self.s.post(url=url, data=data)
        if r.json()['reply']['status'] == 'OK':
            contents = r.json()['reply']['contents']
            return (r, contents)
        return None


    def login(self):
        ''' login; does not use the __post wrapper since this is pre-auth '''
        url = self.url + '/session/login'
        data = {'login'   : self.username,
                'password': self.password,
                'json'    : '1'}
        if self.proxies:
            r = self.s.post(url=url, data=data, proxies=self.proxies)
        else:
            r = self.s.post(url=url, data=data)
        contents = r.json()['reply']['contents']
        self.token = contents['token']
        self.authenticated = True
        self.s.headers.update({'X-Cookie':'token=' + self.token})
        return r


    def logout(self):
        url = self.url + '/session/logout'
        data = {'login': self.username,
                'token': self.token,
                'json' : '1'}
        r, contents = self.__post(url, data)
        return r


    def get_scan_policies(self):
        ''' returns a list of all scan policies '''
        url = self.url + '/policy/list/policies'
        data = {'token' : self.token,
                'json'  : '1'}
        r, contents = self.__post(url, data)
        return contents['policies']['policy']


    def get_scan_policy(self, policy_name):
        ''' return policy record with name of 'policy_name'; first hit only 
            use the 'object_id' in the response as the policy_id
        '''
        policies = self.get_scan_policies()
        for p in policies:
            if p['name'] == policy_name:
                return p
        return None


    def launch_scan(self,
                    scan_name,
                    description,
                    targets,
                    policy_id,
                    emails,
                    tag_id = 5,
                    scanner_id = 1):
        ''' Launch a scan 
            'scan_name' - string of name for the scan
            'description' - string of description for the scan
            'targets' - list of targets to scan
            'policy_id' - use 'get_scan_policy's object_id, of the scan policy
            'emails' - list of emails to send result(s) to
            'tag_id' - unknown; observed 5
            'scanner_id' - unknown; observed 1
        '''
        try:
            assert type(targets) is list
            assert type(emails) is list
        except:
            logging.error('Invalid type: %s' % sys.exc_info())
            return None
        targets = '\n'.join([str(i) for i in targets]) # must be \n delim string
        emails = '\n'.join([str(i) for i in emails]) # must be \n delim string
        url = self.url + '/scan/new'
        data = {'name'  : str(scan_name),
                'description' : str(description),
                'custom_targets': targets,
                'emails': emails,
                'policy_id' : str(policy_id),
                'token' : self.token,
                'tag_id' : tag_id,
                'scanner_id' : scanner_id,
                'notification_filter_type': 'and',
                'notification_filters': '[]',
                'json'  : '1'}
        r, contents = self.__post(url, data) # uuid is the scan id
        return contents['scan']


    def get_scan_info(self, uuid):
        ''' returns status of scan uuid '''
        url = self.url + '/result/details'
        data = {'id'    : str(uuid),
                'token' : self.token,
                'json'  : '1'}
        r, contents = self.__post(url, data)
        return contents['info']


    def __request_xml_download(self, uuid):
        ''' requests to download report uuid as xml; returns file-id '''
        url = self.url + '/result/export'
        data = {'id'    : str(uuid),
                'token' : self.token,
                'format': 'nessus.v2',
                'json'  : '1'}
        r, contents = self.__post(url, data)
        return contents['file']


    def __check_file_dl_status(self, file_id):
        ''' checks status of file_id; returns status '''
        url = self.url + '/result/export/status'
        data = {'rid'    : str(file_id),
                'token' : self.token,
                'json'  : '1'}
        r, contents = self.__post(url, data)
        return contents['status']


    def dl_xml_report(self, uuid):
        ''' downloads report for uuid; returns file '''
        file_id = self.__request_xml_download(uuid)
        status = ''
        count = 0
        while status != 'ready':
            if count > 10:
                return 'skipped'
            status = self.__check_file_dl_status(file_id)
            count += 1
            time.sleep(5)

        resp = self.s.get(self.url + '/result/export/download?rid=%s&token=%s' % (file_id, self.token))
        return resp


    def __request_html_download(self, uuid):
        ''' requests to download report uuid as xml; returns file-id '''
        url = self.url + '/result/export'
        data = {'id'      : str(uuid),
                'token'   : self.token,
                'format'  : 'nchapter.html',
                'chapters': 'vuln_hosts_summary;vuln_by_host',
                'json'    : '1'}
        r, contents = self.__post(url, data)
        return contents['file']


    def dl_html_report(self, uuid):
        ''' downloads report for uuid; returns file '''
        file_id = self.__request_html_download(uuid)
        status = ''
        count = 0
        while status != 'ready':
            if count > 10:
                return 'skipped'
            status = self.__check_file_dl_status(file_id)
            count += 1
            time.sleep(5)

        resp = self.s.get(self.url + '/result/export/download?rid=%s&token=%s' % (file_id, self.token))
        return resp




