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

from datetime import datetime

import iso8601

from brkt_cli.validation import ValidationError
from ecdsa import SigningKey, NIST192p, NIST384p
import tempfile
import time
import unittest

from brkt_cli import jwt


class TestTimestamp(unittest.TestCase):

    def test_datetime_to_timestamp(self):
        now = time.time()
        dt = datetime.fromtimestamp(now, tz=iso8601.UTC)
        self.assertEqual(now, jwt._datetime_to_timestamp(dt))

    def test_parse_timestamp(self):
        ts = int(time.time())
        dt = datetime.fromtimestamp(ts, tz=iso8601.UTC)

        self.assertEqual(dt, jwt.parse_timestamp(str(ts)))
        self.assertEqual(dt, jwt.parse_timestamp(dt.isoformat()))


class TestSigningKey(unittest.TestCase):

    def test_read_signing_key(self):
        """ Test reading the signing key from a file. """
        # Write private key to a temp file.
        signing_key = SigningKey.generate(curve=NIST384p)
        pem = signing_key.to_pem()
        key_file = tempfile.NamedTemporaryFile()
        key_file.write(pem)
        key_file.flush()

        signing_key = jwt.read_signing_key(key_file.name)
        self.assertEqual(pem, signing_key.to_pem())
        key_file.close()

    def test_read_signing_key_invalid_curve(self):
        """ Test that we require NIST384p for the signing key. """
        # Write private key to a temp file.
        signing_key = SigningKey.generate(curve=NIST192p)
        pem = signing_key.to_pem()
        key_file = tempfile.NamedTemporaryFile()
        key_file.write(pem)
        key_file.flush()

        with self.assertRaises(ValidationError):
            jwt.read_signing_key(key_file.name)
        key_file.close()
