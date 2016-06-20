# Copyright 2015 Bracket Computing, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# https://github.com/brkt/brkt-cli/blob/master/LICENSE
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and
# limitations under the License.
import email
import unittest
import zlib

from brkt_cli import proxy, user_data
from brkt_cli.proxy import Proxy
from brkt_cli.user_data import (
    UserDataContainer,
    BRKT_CONFIG_CONTENT_TYPE,
    BRKT_FILES_CONTENT_TYPE
)


class TestUserData(unittest.TestCase):

    def test_user_data_container(self):
        udc = UserDataContainer()
        udc.add_file('test.txt', '1 2 3', 'text/plain')
        mime = udc.to_mime_text()
        self.assertTrue('test.txt: {contents: 1 2 3}' in mime)

    def test_combine_user_data(self):
        """ Test combining Bracket config data with HTTP proxy config data.
        """
        brkt_config = {'foo': 'bar'}
        p = Proxy(host='proxy1.example.com', port=8001)
        proxy_config = proxy.generate_proxy_config(p)
        jwt = (
            'eyJhbGciOiAiRVMzODQiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiYnJrdC1jb'
            'GktMC45LjE3cHJlMSIsICJpYXQiOiAxNDYzNDI5MDg1LCAianRpIjogImJlN2J'
            'mYzYwIiwgImtpZCI6ICJhYmMifQ.U2lnbmVkLCBzZWFsZWQsIGRlbGl2ZXJlZA'
        )
        compressed_mime_data = user_data.combine_user_data(
            brkt_config,
            proxy_config=proxy_config,
            jwt=jwt
        )
        mime_data = zlib.decompress(compressed_mime_data, 16 + zlib.MAX_WBITS)

        msg = email.message_from_string(mime_data)
        found_brkt_config = False
        found_brkt_files = False

        for part in msg.walk():
            if part.get_content_type() == BRKT_CONFIG_CONTENT_TYPE:
                found_brkt_config = True
                content = part.get_payload(decode=True)
                self.assertEqual(
                    '{"foo": "bar", "brkt": {"identity_token": "%s"}}' % jwt,
                    content)
            if part.get_content_type() == BRKT_FILES_CONTENT_TYPE:
                found_brkt_files = True
                content = part.get_payload(decode=True)
                self.assertTrue('/var/brkt/ami_config/proxy.yaml:' in content)
                self.assertFalse('/var/brkt/ami_config/token.jwt:' in content)

        self.assertTrue(found_brkt_config)
        self.assertTrue(found_brkt_files)
