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
import time
import unittest
import uuid
from datetime import datetime, timedelta

import iso8601

import brkt_cli.brkt_jwt
import brkt_cli.brkt_jwt.jwk
import brkt_cli.crypto
import brkt_cli.util
from brkt_cli.crypto import test_crypto
from brkt_cli.validation import ValidationError

_crypto = brkt_cli.crypto.from_private_key_pem(
    test_crypto.TEST_PRIVATE_KEY_PEM
)


class TestTimestamp(unittest.TestCase):

    def test_datetime_to_timestamp(self):
        now = time.time()
        dt = datetime.fromtimestamp(now, tz=iso8601.UTC)
        self.assertEqual(now, brkt_cli.brkt_jwt._datetime_to_timestamp(dt))

    def test_parse_timestamp(self):
        ts = int(time.time())
        dt = datetime.fromtimestamp(ts, tz=iso8601.UTC)

        self.assertEqual(dt, brkt_cli.brkt_jwt.parse_timestamp(str(ts)))
        self.assertEqual(dt, brkt_cli.brkt_jwt.parse_timestamp(dt.isoformat()))

        with self.assertRaises(ValidationError):
            brkt_cli.brkt_jwt.parse_timestamp('abc')


class TestGenerateJWT(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestGenerateJWT, self).__init__(*args, **kwargs)

    def test_make_jwt(self):
        # Generate the JWT.
        now = datetime.now(tz=iso8601.UTC).replace(microsecond=0)
        nbf = now + timedelta(days=1)
        exp = now + timedelta(days=7)
        cnc = 10
        customer = str(uuid.uuid4())

        jwt = brkt_cli.brkt_jwt.make_jwt(
            _crypto,
            nbf=nbf,
            exp=exp,
            cnc=cnc,
            customer=customer,
            claims={'one': 1, 'two': 2}
        )
        after = datetime.now(tz=iso8601.UTC)

        # Decode the header and payload.
        header_b64, payload_b64, signature_b64 = jwt.split('.')
        header_json = brkt_cli.util.urlsafe_b64decode(header_b64)
        payload_json = brkt_cli.util.urlsafe_b64decode(payload_b64)
        brkt_cli.util.urlsafe_b64decode(signature_b64)

        # Check the header.
        header = json.loads(header_json)
        self.assertEqual('JWT', header['typ'])
        self.assertEqual('ES384', header['alg'])
        self.assertTrue('kid' in header)

        # Check the payload
        payload = json.loads(payload_json)
        self.assertTrue('jti' in payload)
        self.assertTrue(payload['iss'].startswith('brkt-cli'))
        self.assertEqual(cnc, payload['cnc'])
        self.assertEqual(customer, payload['customer'])
        self.assertEqual(1, payload['one'])
        self.assertEqual(2, payload['two'])

        iat = brkt_cli.brkt_jwt._timestamp_to_datetime(payload['iat'])
        self.assertTrue(now <= iat <= after)

        nbf_result = brkt_cli.brkt_jwt._timestamp_to_datetime(payload['nbf'])
        self.assertEqual(nbf, nbf_result)

        exp_result = brkt_cli.brkt_jwt._timestamp_to_datetime(payload['exp'])
        self.assertEqual(exp, exp_result)

    def test_claims(self):
        """ Test that claims specified by name are embedded into the JWT. """
        # Generate the JWT.
        claims = {'foo': 'bar', 'count': 5}
        jwt = brkt_cli.brkt_jwt.make_jwt(_crypto, claims=claims)
        _, payload_b64, _ = jwt.split('.')
        payload_json = brkt_cli.util.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_json)

        self.assertEqual('bar', payload['foo'])
        self.assertEqual(5, payload['count'])


class TestJWK(unittest.TestCase):

    def test_long_to_byte_array(self):
        l = long('deadbeef', 16)
        ba = brkt_cli.brkt_jwt.jwk._long_to_byte_array(l)
        self.assertEqual(bytearray.fromhex('deadbeef'), ba)
