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

import unittest

from brkt_cli import util
from brkt_cli.validation import ValidationError


class TestUtil(unittest.TestCase):

    def test_append_suffix(self):
        """ Test that we append the suffix and truncate the original name.
        """
        name = 'Boogie nights are always the best in town'
        suffix = ' (except Tuesday)'
        encrypted_name = util.append_suffix(
            name, suffix, max_length=128)
        self.assertTrue(encrypted_name.startswith(name))
        self.assertTrue(encrypted_name.endswith(suffix))

        # Make sure we truncate the original name when it's too long.
        name += ('X' * 100)
        encrypted_name = util.append_suffix(
            name, suffix, max_length=128)
        self.assertEqual(128, len(encrypted_name))
        self.assertTrue(encrypted_name.startswith('Boogie nights'))

    def test_parse_name_value(self):
        self.assertEqual(
            ('foo', 'bar'),
            util.parse_name_value('foo=bar')
        )
        with self.assertRaises(ValidationError):
            util.parse_name_value('abc')


class TestBase64(unittest.TestCase):
    """ Test that our encoding code follows the spec used by JWT.  The
    encoded string must be URL-safe and not use padding. """

    def test_encode_and_decode(self):
        for length in xrange(0, 1000):
            content = 'x' * length
            encoded = util.urlsafe_b64encode(content)
            self.assertFalse('/' in encoded)
            self.assertFalse('_' in encoded)
            self.assertFalse('=' in encoded)
            self.assertEqual(
                content, util.urlsafe_b64decode(encoded))
