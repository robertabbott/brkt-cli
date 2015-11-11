# Copyright 2015 Bracket Computing, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# https://github.com/brkt/brkt-sdk-java/blob/master/LICENSE
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and
# limitations under the License.

import abc
import logging

import brkt_requests
import requests


log = logging.getLogger(__name__)


class BracketAuthError(Exception):
    pass


class BracketService(object):

    def __init__(self, api_root, username, password, verify_cert=True):
        self.api_root = api_root
        self.username = username
        self.password = password
        self.verify_cert = verify_cert

        # Session will be initialized during auth.
        self.session = None

    def authenticate(self):
        """ Authenticate with the bracket service.

        :raise BracketAuthError if the username or password is invalid
        """
        log.debug(
            'Authenticating with the Bracket service at %s as %s',
            self.api_root,
            self.username
        )
        r = requests.post(
            '%s/oauth/credentials' % self.api_root,
            json={
                'username': self.username,
                'password': self.password,
                'grant_type': 'password'
            },
            headers={'Content-Type': 'application/json'},
            verify=self.verify_cert
        )

        if r.status_code == 401:
            raise BracketAuthError()
        if r.status_code / 100 != 2:
            raise Exception('Error %d: %s' % (r.status_code, r.content))
        resp = r.json()
        self.session = brkt_requests.APISession(
            access_token=resp["access_token"],
            mac_key=resp["mac_key"],
            verify=self.verify_cert
        )

    def is_eula_accepted(self):
        r = self.session.get('%s/api/v1/customer/self' % self.api_root)

        if r.status_code / 100 != 2:
            raise Exception('Error %d: %s' % (r.status_code, r.content))
        return r.json.get('eula_accepted', False)

    def get_eula(self):
        r = requests.get(self.get_eula_url(), verify=False)
        if r.status_code / 100 != 2:
            raise Exception('Unable to download EULA: %d %s' % (
                r.status_code, r.content))
        return r.text

    def accept_eula(self):
        r = self.session.post(
            '%s/api/v1/customer/self' % self.api_root,
            json={
                'eula_accepted': True
            }
        )
        if r.status_code / 100 != 2:
            raise Exception('Error %d: %s' % (r.status_code, r.content))
