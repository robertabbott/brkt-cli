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
from brkt_cli.instance_config_args import (
    instance_config_from_values,
    setup_instance_config_args
)
log = logging.getLogger(__name__)


class MakeUserDataSubcommand(Subcommand):

    def name(self):
        return 'make-user-data'

    def register(self, subparsers, parsed_config):
        parser = subparsers.add_parser(
            self.name(),
            description=(
                'Generate MIME multipart user-data that is passed to '
                'Metavisor and cloud-init when running an instance.'
            ),
            help='Make user data for passing to Metavisor',
            formatter_class=brkt_cli.SortingHelpFormatter
        )

        setup_instance_config_args(parser)

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
        instance_cfg = instance_config_from_values(values)
        print instance_cfg.make_userdata()
        return 0


def get_subcommands():
    return [MakeUserDataSubcommand()]
