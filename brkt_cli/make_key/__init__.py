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
import getpass
import logging

from brkt_cli.validation import ValidationError

from brkt_cli.subcommand import Subcommand
import brkt_cli.crypto


log = logging.getLogger(__name__)


def _write_file(path, content):
    try:
        with open(path, 'w') as f:
            f.write(content)
    except IOError as e:
        if log.isEnabledFor(logging.DEBUG):
            log.exception('Unable to write to %s', path)
        raise ValidationError('Unable to write to %s: %s' % (path, e))


class MakeKeySubcommand(Subcommand):

    def name(self):
        return 'make-key'

    def register(self, subparsers, parsed_config):
        parser = subparsers.add_parser(
            self.name(),
            description=(
                'Generate a 384-bit ECDSA private key (NIST P-384) in OpenSSL '
                'PEM format and write the key to stdout.  Optionally write '
                'the associated public key to a file.'
            ),
            help='Make a PEM key',
            formatter_class=brkt_cli.SortingHelpFormatter
        )
        parser.add_argument(
            '--no-passphrase',
            dest='passphrase',
            action='store_false',
            default=True,
            help=(
                "Generate an unencrypted private key.  Don't prompt for a "
                "passphrase."
            )
        )
        parser.add_argument(
            '--public-out',
            metavar='PATH',
            help='Write the associated public key to a file'
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
        passphrase = None
        if values.passphrase:
            passphrase = getpass.getpass('Passphrase: ')
            reentered = getpass.getpass('Reenter passphrase: ')
            if passphrase != reentered:
                raise ValidationError('Passphrases do not match')

        crypto = brkt_cli.crypto.new()
        print crypto.get_private_key_pem(passphrase)
        if values.public_out:
            _write_file(values.public_out, crypto.public_key_pem)

        return 0


def get_subcommands():
    return [MakeKeySubcommand()]
