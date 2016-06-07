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
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

SECP384R1 = ec.SECP384R1.name

log = logging.getLogger(__name__)


class SignatureAlgorithm(ec.EllipticCurveSignatureAlgorithm):

    def algorithm(self):
        return hashes.SHA384


class Crypto(object):
    def __init__(self):
        self.private_key = None
        self.public_key = None

        self.x = None
        self.y = None
        self.curve = None


def from_private_key_pem(pem, password=None):
    """ Load a Crypto object from a private key PEM file.

    :raise ValueError if the PEM is malformed
    :raise TypeError if the key is encrypted but a password is not specified
    """
    private_key = serialization.load_pem_private_key(
        # XXX
        pem, password=password, backend=default_backend()
    )

    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    crypto = Crypto()
    crypto.private_key = private_key
    crypto.public_key = public_key
    crypto.x = numbers.x
    crypto.y = numbers.y
    crypto.curve = numbers.curve.name

    return crypto


def is_encrypted_key(pem):
    return 'ENCRYPTED' in pem


def is_private_key(pem):
    return 'PRIVATE KEY' in pem
