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

import brkt_cli.crypto
from brkt_cli import util
from brkt_cli.subcommand import Subcommand


log = logging.getLogger(__name__)


class GetPublicKeySubcommand(Subcommand):

    def name(self):
        return 'get-public-key'

    def exposed(self):
        return False

    def register(self, subparsers, parsed_config):
        parser = subparsers.add_parser(
            self.name(),
            description=(
                'Print the public part of a private key.  If the private key '
                'is encrypted, prompt for a password and decrypt the key.'
            ),
            help='Print the public part of a private key',
            formatter_class=brkt_cli.SortingHelpFormatter
        )
        parser.add_argument(
            'private_key_path',
            metavar='PATH',
            help=(
                'Path to a 384-bit ECDSA private key (NIST P-384) in '
                'OpenSSL PEM format'
            )
        )
        parser.add_argument(
            '-v',
            '--verbose',
            dest='make_private_key_verbose',
            action='store_true',
            help='Print status information to the console'
        )

    def verbose(self, values):
        return values.make_private_key_verbose

    def run(self, values):
        crypto = util.read_private_key(values.private_key_path)
        print crypto.public_key_pem
        return 0


def get_subcommands():
    return [GetPublicKeySubcommand()]
