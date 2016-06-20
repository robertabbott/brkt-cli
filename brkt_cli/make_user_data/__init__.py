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

import brkt_cli
from brkt_cli.subcommand import Subcommand
from brkt_cli.user_data import combine_user_data

log = logging.getLogger(__name__)


class MakeUserDataSubcommand(Subcommand):

    def name(self):
        return 'make-user-data'

    def exposed(self):
        return False

    def register(self, subparsers):
        parser = subparsers.add_parser(
            self.name(),
            description=(
                'Generate MIME multipart user-data that is passed to '
                'Metavisor and cloud-init when running an instance.'
            )
        )
        parser.add_argument(
            '--jwt',
            help=(
                'JSON Web Token that the encrypted instance will use to '
                'authenticate with the Bracket service.  Use the make-jwt '
                'subcommand to generate a JWT.'
            )
        )
        parser.add_argument(
            '-v',
            '--verbose',
            dest='make_user_data_verbose',
            action='store_true',
            help='Print status information to the console'
        )

    def verbose(self, values):
        return values.make_user_data_verbose

    def run(self, values):
        with open(values.jwt, 'r') as f:
            token_val = f.read().rstrip()

        print combine_user_data(brkt_config={}, jwt=token_val, do_gzip=False)
        return 0


def get_subcommands():
    return [MakeUserDataSubcommand()]
