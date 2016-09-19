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

import time
import urllib
try:
    import urlparse
    # Make python2.x look like py3k
    urllib.parse = urlparse
    str = unicode
except ImportError:
    # Py3k
    pass

import requests
import requests.exceptions
from oauthlib.oauth2 import Client


RETRY_DELAY_SECONDS = 0.5
DEFAULT_MAC_ALGORITHM = 'hmac-sha-256'


class APISessionError(Exception):

    def __init__(self, error, error_description=''):
        super(APISessionError, self).__init__(error)
        self.error_description = error_description


class _ResponseWrapper(object):
    """For some reason the requests author changed the response object in that
    the json property is now a callable... grrr"""

    def __init__(self, response):
        self.response = response

    @property
    def json(self):
        try:
            return self.response.json()
        except:
            # New requests will throw an error on decode... old behavior is
            # to return None
            pass

    def __getattr__(self, attr):
        return getattr(self.response, attr)


class APISession(object):

    class OAuth2MACClient(object):

        def __init__(self, mac_key, access_token,
                     mac_algorithm=DEFAULT_MAC_ALGORITHM):

            self.client = Client(
                None,
                token_type='MAC',
                access_token=access_token,
                refresh_token=None,
                mac_key=mac_key,
                mac_algorithm=mac_algorithm)

        def __call__(self, r):
            # unquote the URL to make sure that the signature is computed based
            # on unquoted values, not quoted values.  The can cause headaches
            # if the unquoted values contain a '#' but we wouldn't allows
            # something like that... ugh.
            self.client.add_token(
                str(urllib.parse.unquote(r.url)),
                str(r.method),
                None,
                r.headers,
                draft=1)
            return r

    def __init__(self, mac_key, access_token, verify=True, retries=3):
        """Connect to the Bracket API directly with an access token.
            This is useful for clients which may not have access to a
            username/password
            :param access_token: The access token for the session,
                returned during authorization
            :param mac_key: The mac key for the session, returned during
                authorization
            :returns:
                An APISession
        """
        self._retries = retries
        self.session = requests.Session()
        self.session.verify = verify
        self._requests_auth = self.OAuth2MACClient(mac_key, access_token)

    def request(self, method, url, **kwargs):
        headers = {}
        if 'headers' in kwargs:
            headers = kwargs['headers']
            del kwargs['headers']
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        if 'Accept' not in headers:
            headers['Accept'] = 'application/json'

        retry = 0
        while True:
            try:
                resp = self.session.request(
                    method, url, headers=headers, auth=self._requests_auth,
                    **kwargs)
                break
            except requests.exceptions.ConnectionError:
                retry += 1
                if retry > self._retries:
                    raise
                time.sleep(RETRY_DELAY_SECONDS)

        if resp.status_code == 401:
            if not self._requests_auth.client.refresh_token:
                raise APISessionError('Access token expired, no refresh token')
            self._refresh()
            resp = self.session.request(
                method, url, headers=headers, auth=self._requests_auth,
                **kwargs)
        return _ResponseWrapper(resp)

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)

    def head(self, url, **kwargs):
        return self.request('HEAD', url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request('DELETE', url, **kwargs)
