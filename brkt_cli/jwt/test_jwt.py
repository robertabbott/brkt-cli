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
from datetime import datetime, timedelta

import iso8601

from brkt_cli.validation import ValidationError
from ecdsa import SigningKey, NIST192p, NIST384p
import tempfile
import time
import unittest

import brkt_cli.jwt
import brkt_cli.jwt.jwk


class TestTimestamp(unittest.TestCase):

    def test_datetime_to_timestamp(self):
        now = time.time()
        dt = datetime.fromtimestamp(now, tz=iso8601.UTC)
        self.assertEqual(now, brkt_cli.jwt._datetime_to_timestamp(dt))

    def test_parse_timestamp(self):
        ts = int(time.time())
        dt = datetime.fromtimestamp(ts, tz=iso8601.UTC)

        self.assertEqual(dt, brkt_cli.jwt.parse_timestamp(str(ts)))
        self.assertEqual(dt, brkt_cli.jwt.parse_timestamp(dt.isoformat()))


class TestSigningKey(unittest.TestCase):

    def test_read_signing_key(self):
        """ Test reading the signing key from a file. """
        # Write private key to a temp file.
        signing_key = SigningKey.generate(curve=NIST384p)
        pem = signing_key.to_pem()
        key_file = tempfile.NamedTemporaryFile()
        key_file.write(pem)
        key_file.flush()

        signing_key = brkt_cli.jwt.read_signing_key(key_file.name)
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
            brkt_cli.jwt.read_signing_key(key_file.name)
        key_file.close()


class TestGenerateJWT(unittest.TestCase):

    def test_generate_jwt(self):
        # Generate the JWT.
        signing_key = SigningKey.generate(curve=NIST384p)
        now = datetime.now(tz=iso8601.UTC).replace(microsecond=0)
        nbf = now + timedelta(days=1)
        exp = now + timedelta(days=7)
        cnc = 10

        jwt = brkt_cli.jwt.generate_jwt(
            signing_key, nbf=nbf, exp=exp, cnc=cnc)
        after = datetime.now(tz=iso8601.UTC)

        # Decode the header and payload.
        header_b64, payload_b64, signature_b64 = jwt.split('.')
        header_json = brkt_cli.jwt._urlsafe_b64decode(header_b64)
        payload_json = brkt_cli.jwt._urlsafe_b64decode(payload_b64)
        signature = brkt_cli.jwt._urlsafe_b64decode(signature_b64)

        # Check the header.
        header = json.loads(header_json)
        self.assertEqual('JWT', header['typ'])
        self.assertEqual('ES384', header['alg'])

        # Check the payload
        payload = json.loads(payload_json)
        self.assertTrue('jti' in payload)
        self.assertTrue(payload['iss'].startswith('brkt-cli'))

        iat = brkt_cli.jwt._timestamp_to_datetime(payload['iat'])
        self.assertTrue(now <= iat <= after)

        nbf_result = brkt_cli.jwt._timestamp_to_datetime(payload['nbf'])
        self.assertEqual(nbf, nbf_result)

        exp_result = brkt_cli.jwt._timestamp_to_datetime(payload['exp'])
        self.assertEqual(exp, exp_result)

        self.assertTrue('kid' in payload)

        # Check signature.
        verifying_key = signing_key.get_verifying_key()
        verifying_key.verify(signature, '%s.%s' % (header_b64, payload_b64))


class TestBase64(unittest.TestCase):
    """ Test that our encoding code follows the spec used by JWT.  The
    encoded string must be URL-safe and not use padding. """

    def test_encode_and_decode(self):
        for length in xrange(0, 1000):
            content = 'x' * length
            encoded = brkt_cli.jwt._urlsafe_b64encode(content)
            self.assertFalse('/' in encoded)
            self.assertFalse('_' in encoded)
            self.assertFalse('=' in encoded)
            self.assertEqual(
                content, brkt_cli.jwt._urlsafe_b64decode(encoded))


class TestJWK(unittest.TestCase):

    def test_long_to_byte_array(self):
        l = long('deadbeef', 16)
        ba = brkt_cli.jwt.jwk._long_to_byte_array(l)
        self.assertEqual(bytearray.fromhex('deadbeef'), ba)
