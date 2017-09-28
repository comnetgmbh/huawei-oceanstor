#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# 2017, comNET GmbH, Ringo Hartmann

import logging
import requests
import ssl

try:
    import simplejson as json
except ImportError:
    import json

class APIError(Exception):
    def __init__(self, error, message=None):
        self.code = error['code']
        self.description = error['description']
        self.message = message

    def __str__(self):
        if self.message:
            return u'{}: {}: {}'.format(self.message, self.code, self.description)
        else:
            return u'{}: {}'.format(self.code, self.description)

class DeviceManager():
    def __init__(self, host, **kwargs):
        self.host = host
        try:
            self.port = int(kwargs.get('port', 8088))
            if self.port < 1 or self.port > 65534:
                raise ValueError()
        except:
            raise ValueError('Not a valid TCP port')

        self.insecure = bool(kwargs.get('insecure', False))
        self.timeout = int(kwargs.get('timeout', 10))

        self.device_id = None
        self.cookie = None # Session cookie
        self.token = None # Authentication token

    def authenticate(self, username, password, scope=0):
        data = {
            'username': username,
            'password': password,
            'scope': scope,
        }
        headers, response = self._request('sessions', method='POST', data=data)
        if response['error']['code'] != 0:
            raise APIError(response['error'], 'Authentication error')

        self.cookie = headers.get('set-cookie')

        self.device_id  = response['data']['deviceid']
        self.token      = response['data']['iBaseToken']

    def close(self):
        self.delete('sessions')

    def delete(self, resource):
        return self.request(resource, method='DELETE')

    def get(self, resource):
        return self.request(resource)

    def post(self, resource, data):
        return self.request(resource, method='POST', data=data)

    def put(self, resource, data):
        return self.request(resource, method='PUT', data=data)

    def request(self, resource, method='GET', data=None):
        headers, response = self._request(resource, method, data)
        if response['error']['code'] != 0:
            raise APIError(response['error'])
        return response['data']

    def _request(self, resource, method='GET', data=None):
        url = u'https://{host}:{port}/deviceManager/rest/{device_id}/{resource}'.format(
                host = self.host,
                port = self.port,
                device_id = self.device_id or 'xxxxx',
                resource = resource
            )

        headers = {}
        if self.cookie:
            headers['Cookie'] = self.cookie
        if self.token:
            headers['iBaseToken'] = self.token

        body = json.dumps(data)
        logging.info(u'Issueing request...')
        logging.debug(u'Method: {}'.format(method))
        logging.debug(u'URL: {}'.format(url))
        logging.debug(u'Headers: {}'.format(headers))
        logging.debug(u'Body: {}'.format(body))
        response = requests.request(method, url, data=body, headers=headers,
                    timeout=self.timeout, verify=not self.insecure)

        logging.info(u'Response: {} {}'.format(response.status_code, response.raw.reason))
        response.raise_for_status()

        headers = response.headers
        logging.debug(u'Headers: {}'.format(headers))

        json_response = response.json # Requests < 1.0
        if callable(json_response): # Requests > 1.0
            json_response = json_response()
        logging.debug(u'Response JSON content: {}'.format(json_response))

        return headers, json_response
