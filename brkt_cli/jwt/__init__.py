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
import re

from datetime import datetime
from ecdsa import SigningKey, NIST384p
import base64
import iso8601
import time

import brkt_cli
from brkt_cli import util
from brkt_cli.subcommand import Subcommand
from brkt_cli.validation import ValidationError


class JWTSubcommand(Subcommand):

    def name(self):
        return 'generate-jwt'

    def exposed(self):
        return False

    def register(self, subparsers):
        parser = subparsers.add_parser(
            'generate-jwt',
            description=(
                'Generate a JSON Web Token for launching an encrypted '
                'instance. A timestamp can be either a Unix timestamp in '
                'seconds or ISO 8601 (2016-05-10T19:15:36Z).'
            )
        )
        setup_generate_jwt_args(parser)

    def verbose(self, values):
        return values.generate_jwt_verbose

    def run(self, values):
        signing_key = read_signing_key(values.signing_key)
        exp = None
        if values.exp:
            exp = parse_timestamp(values.exp)
        nbf = None
        if values.nbf:
            nbf = parse_timestamp(values.nbf)
        print generate_jwt(signing_key, exp=exp, nbf=nbf)
        return 0


def _timestamp_to_datetime(ts):
    """ Convert a Unix timestamp to a datetime with timezone set to UTC. """
    return datetime.fromtimestamp(ts, tz=iso8601.UTC)


def _datetime_to_timestamp(dt):
    """ Convert a datetime to a Unix timestamp in seconds. """
    time_zero = _timestamp_to_datetime(0)
    return (dt - time_zero).total_seconds()


def get_subcommands():
    return [JWTSubcommand()]


def read_signing_key(path):
    with open(path) as f:
        key_string = f.read()
    signing_key = SigningKey.from_pem(key_string)
    if signing_key.curve != NIST384p:
        raise ValidationError(
            'Signing key uses the %s. %s is required.' % (
                signing_key.curve.name, NIST384p.name)
        )
    return signing_key


def parse_timestamp(ts_string):
    """ Return a datetime that represents the given timestamp
    string.  The string can be a Unix timestamp in seconds or an ISO 8601
    timestamp. """
    now = int(time.time())

    # Parse integer timestamp.
    m = re.match('\d+(\.\d+)?$', ts_string)
    if m:
        t = float(ts_string)
        if t < now:
            raise ValidationError(
                '%s is earlier than the current timestamp (%s).' % (
                    ts_string, now))
        return _timestamp_to_datetime(t)

    # Parse ISO 8601 timestamp.
    dt_now = _timestamp_to_datetime(now)
    dt = iso8601.parse_date(ts_string)
    if dt < dt_now:
        raise ValidationError(
            '%s is earlier than the current timestamp (%s).' % (
                ts_string, dt_now))
    return dt


def _urlsafe_b64encode(content):
    return base64.urlsafe_b64encode(content).replace(b'=', b'')


def _urlsafe_b64decode(content):
    removed = len(content) % 4
    if removed > 0:
        content += b'=' * (4 - removed)
    return base64.urlsafe_b64decode(content)


def generate_jwt(signing_key, exp=None, nbf=None, cnc=None):
    """ Generate a JWT.

    :param signing_key a SigningKey object
    :param exp expiration time as a datetime
    :param nbf not before as a datetime
    :param cnc maximum number of concurrent instances as an integer
    :return the JWT as a string
    """

    header_dict = {'typ': 'JWT', 'alg': 'ES384'}
    payload_dict = {
        'jti': util.make_nonce(),
        'iss': 'brkt-cli-' + brkt_cli.VERSION,
        'iat': int(time.time())
    }
    if exp:
        payload_dict['exp'] = _datetime_to_timestamp(exp)
    if nbf:
        payload_dict['nbf'] = _datetime_to_timestamp(nbf)
    if cnc is not None:
        payload_dict['cnc'] = cnc

    header_json = json.dumps(header_dict, sort_keys=True)
    header_b64 = _urlsafe_b64encode(header_json)
    payload_json = json.dumps(payload_dict, sort_keys=True)
    payload_b64 = _urlsafe_b64encode(payload_json)
    signature = signing_key.sign('%s.%s' % (header_b64, payload_b64))
    signature_b64 = _urlsafe_b64encode(signature)

    return '%s.%s.%s' % (header_b64, payload_b64, signature_b64)


def setup_generate_jwt_args(parser):
    parser.add_argument(
        '--cnc',
        metavar='N',
        type=int,
        help='Maximum number of concurrent instances'
    )
    parser.add_argument(
        '--exp',
        metavar='TIMESTAMP',
        help='Token expiration time'
    )
    parser.add_argument(
        '--nbf',
        metavar='TIMESTAMP',
        help='Token is not valid before this time'
    )
    parser.add_argument(
        '--signing-key',
        metavar='PATH',
        help=(
            'The private key that is used to sign the JWT. The key must be '
            'in PEM format.'),
        required=True
    )
    parser.add_argument(
        '-v',
        '--verbose',
        dest='generate_jwt_verbose',
        action='store_true',
        help='Print status information to the console'
    )
