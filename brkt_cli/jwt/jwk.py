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

import base64
import hashlib
import logging

log = logging.getLogger(__name__)


def _long_to_byte_array(long_int):
    bys = bytearray()
    while long_int:
        long_int, r = divmod(long_int, 256)
        bys.insert(0, r)
    return bys


def _long_to_base64(n):
    bys = _long_to_byte_array(n)
    if not bys:
        bys.append(0)
    s = base64.urlsafe_b64encode(bys).rstrip(b'=')
    return s.decode("ascii")


def ecdsa_to_jwk(verifying_key):
    """ Convert an ecdsa.VerifyingKey to the equivalent JWK. """
    x = _long_to_base64(verifying_key.pubkey.point.x())
    y = _long_to_base64(verifying_key.pubkey.point.y())
    return {
        'alg': 'ES384',
        'kty': 'EC',
        'crv': 'P-384',
        'x': x,
        'y': y
    }


def get_thumbprint(verifying_key):
    """ Get the thumbprint of an ecdsa.VerifyingKey. """
    jwk = ecdsa_to_jwk(verifying_key)
    thumbprint_json = \
        '{"crv":"%(crv)s","kty":"%(kty)s","x":"%(x)s","y":"%(y)s"}' % jwk
    log.debug('Thumbprint JSON: %s', thumbprint_json)
    return hashlib.sha256(thumbprint_json).hexdigest()
