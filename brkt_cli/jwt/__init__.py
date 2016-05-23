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
import logging
import re
import time
from datetime import datetime

import iso8601
from ecdsa import SigningKey, NIST384p

import brkt_cli
from brkt_cli import util
from brkt_cli.jwt import jwk
from brkt_cli.subcommand import Subcommand
from brkt_cli.util import urlsafe_b64encode
from brkt_cli.validation import ValidationError

log = logging.getLogger(__name__)


class MakeJWTSubcommand(Subcommand):

    def name(self):
        return 'make-jwt'

    def exposed(self):
        return False

    def register(self, subparsers):
        parser = subparsers.add_parser(
            self.name(),
            description=(
                'Generate a JSON Web Token for launching an encrypted '
                'instance. A timestamp can be either a Unix timestamp in '
                'seconds or ISO 8601 (2016-05-10T19:15:36Z).'
            )
        )
        setup_make_jwt_args(parser)

    def verbose(self, values):
        return values.make_jwt_verbose

    def run(self, values):
        signing_key = read_signing_key(values.signing_key)
        exp = None
        if values.exp:
            exp = parse_timestamp(values.exp)
        nbf = None
        if values.nbf:
            nbf = parse_timestamp(values.nbf)

        claims = {}
        if values.claims:
            for name_value in values.claims:
                name, value = util.parse_name_value(name_value)
                claims[name] = value

        print make_jwt(signing_key, exp=exp, nbf=nbf, claims=claims)
        return 0


def _timestamp_to_datetime(ts):
    """ Convert a Unix timestamp to a datetime with timezone set to UTC. """
    return datetime.fromtimestamp(ts, tz=iso8601.UTC)


def _datetime_to_timestamp(dt):
    """ Convert a datetime to a Unix timestamp in seconds. """
    time_zero = _timestamp_to_datetime(0)
    return (dt - time_zero).total_seconds()


def get_subcommands():
    return [MakeJWTSubcommand()]


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


def make_jwt(signing_key, exp=None, nbf=None, cnc=None, claims=None):
    """ Generate a JWT.

    :param signing_key a SigningKey object
    :param exp expiration time as a datetime
    :param nbf not before as a datetime
    :param cnc maximum number of concurrent instances as an integer
    :param claims a dictionary of claims
    :return the JWT as a string
    """

    header_dict = {'typ': 'JWT', 'alg': 'ES384'}

    payload_dict = {}
    if claims:
        payload_dict.update(claims)
    payload_dict.update({
        'jti': util.make_nonce(),
        'iss': 'brkt-cli-' + brkt_cli.VERSION,
        'iat': int(time.time()),
        'kid': jwk.get_thumbprint(signing_key.get_verifying_key())
    })

    if exp:
        payload_dict['exp'] = _datetime_to_timestamp(exp)
    if nbf:
        payload_dict['nbf'] = _datetime_to_timestamp(nbf)
    if cnc is not None:
        payload_dict['cnc'] = cnc

    header_json = json.dumps(header_dict, sort_keys=True)
    header_b64 = urlsafe_b64encode(header_json)
    payload_json = json.dumps(payload_dict, sort_keys=True)
    payload_b64 = urlsafe_b64encode(payload_json)
    signature = signing_key.sign('%s.%s' % (header_b64, payload_b64))
    signature_b64 = urlsafe_b64encode(signature)

    log.debug('Header: %s', header_json)
    log.debug('Payload: %s', payload_json)

    return '%s.%s.%s' % (header_b64, payload_b64, signature_b64)


def setup_make_jwt_args(parser):
    parser.add_argument(
        '--claim',
        metavar='NAME=VALUE',
        dest='claims',
        help=(
            'JWT claim specified by name and value.  May be specified '
            'multiple times.'),
        action='append'
    )
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
        dest='make_jwt_verbose',
        action='store_true',
        help='Print status information to the console'
    )
