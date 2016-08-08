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

import json
import unittest

from brkt_cli.user_data import get_mime_part_payload, UserDataContainer


class TestUserData(unittest.TestCase):

    def test_add_part(self):
        udc = UserDataContainer()
        ct = 'text/brkt-config'
        cfg_json = '{"brkt": "identity_token": "foo"}'
        udc.add_part(ct, cfg_json)
        mime = udc.to_mime_text()
        actual_payload = get_mime_part_payload(mime, ct)
        self.assertEqual(actual_payload, cfg_json)

    def test_add_file(self):
        udc = UserDataContainer()
        ct = 'text/plain'
        udc.add_file('test.txt', '1 2 3', ct)
        mime = udc.to_mime_text()
        expected_payload = 'test.txt: {contents: 1 2 3}\n'
        actual_payload = get_mime_part_payload(mime, ct)
        self.assertEqual(actual_payload, expected_payload)

        bogus_payload = get_mime_part_payload(mime, 'text/bogus')
        self.assertEqual(bogus_payload, None)

    def test_add_files_and_config(self):
        udc = UserDataContainer()

        file1_contents = 'Never gonna give you up.'
        file2_contents = 'Never\ngonna\tlet you\n\ndown!!'
        udc.add_file('rick.html', file1_contents, 'text/html')
        udc.add_file('/var/brkt/roll.html', file2_contents, 'text/html')

        file3_contents = '{"all-I-wanted": "Pepsi"}'
        udc.add_file('/etc/motd.txt', file3_contents, 'text/brkt-config')

        mime = udc.to_mime_text()
        payload = get_mime_part_payload(mime, 'text/html')
        expected1 = 'rick.html: {contents: %s}\n' % file1_contents
        self.assertTrue(expected1 in payload,
                       '%s not found in:\n%s' % (expected1, payload))
        expected2 = '/var/brkt/roll.html: {contents: %s}\n' % \
                    json.dumps(file2_contents)
        self.assertTrue(expected2 in payload,
                       '%s not found in:\n%s' % (expected2, payload))

        payload = get_mime_part_payload(mime, 'text/brkt-config')
        expected3 = '/etc/motd.txt: {contents: \'%s' % file3_contents
        self.assertTrue(expected3 in payload,
                       '%s not found in:\n%s' % (expected3, payload))
