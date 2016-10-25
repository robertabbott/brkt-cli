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
import argparse
import logging
import os
import sys
import re

import brkt_cli
from brkt_cli.subcommand import Subcommand
from brkt_cli.instance_config import INSTANCE_METAVISOR_MODE
from brkt_cli.instance_config import GuestFile
from brkt_cli.validation import ValidationError
from brkt_cli.instance_config_args import (
    instance_config_from_values,
    setup_instance_config_args
)
log = logging.getLogger(__name__)


def _add_files_to_instance_config(instance_cfg, files_list):
    
    for fname in files_list:
        try:
            with open(fname, 'r') as f:
                file_contents = f.read()
        except IOError:
            log.error('Input file not readable: %s', fname)
            raise Exception('Unable to read file: %s' % (fname,))
        instance_cfg.add_brkt_file(os.path.basename(fname), file_contents)

        
def _add_guest_files_to_instance_config(instance_cfg, guest_files):
    
    for guest_file in guest_files:
        try:
            with open(guest_file.dest_file, 'r') as f:
                guest_file.file_contents = f.read()
        except IOError:
            raise ValidationError('Unable to read file: %s' % guest_file.dest_file)
        instance_cfg.add_guest_file(guest_file)
        
        
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

        setup_instance_config_args(parser, parsed_config)

        parser.add_argument(
            '-v',
            '--verbose',
            dest='make_user_data_verbose',
            action='store_true',
            help='Print status information to the console'
        )
        parser.add_argument(
            '--brkt-file',
            metavar='FILENAME',
            dest='make_user_data_brkt_files',
            action='append',
            help=argparse.SUPPRESS
        )
        parser.add_argument(
            '--guest-user-data-file',
            metavar='FILENAME:TYPE',
            dest='make_user_data_guest_files',
            action='append',
            help=('User-data file and MIME contents type to be passed to the '
                  'guest instance. Can be specified multiple times.')
        )
        # Certain customers need to set the FQDN of the guest instance, which
        # is used by Metavisor as the CN field of the Subject DN in the cert
        # requests it submits to an EST server (for North-South VPN tunneling).
        parser.add_argument(
            '--guest-fqdn',
            metavar='FQDN',
            dest='make_user_data_guest_fqdn',
            help=argparse.SUPPRESS
        )

    def verbose(self, values):
        return values.make_user_data_verbose

    def run(self, values, out=sys.stdout):
        instance_cfg = instance_config_from_values(values,
            mode=INSTANCE_METAVISOR_MODE)

        if values.make_user_data_brkt_files:
            _add_files_to_instance_config(instance_cfg,
                                          values.make_user_data_brkt_files)

        if values.make_user_data_guest_files:
            guest_files = []
            for fname in values.make_user_data_guest_files:
                match = re.match('(.+):(.+)', fname)
                if match:
                    guest_file = GuestFile(match.group(1), match.group(2), None)
                    guest_files.append(guest_file)
                else:
                    raise ValidationError('Unable to parse guest file and type: %s' % fname)
            _add_guest_files_to_instance_config(instance_cfg, guest_files)

        if values.make_user_data_guest_fqdn:
            vpn_config = 'fqdn: %s\n' % (values.make_user_data_guest_fqdn,)
            instance_cfg.add_brkt_file('vpn.yaml', vpn_config)

        out.write(instance_cfg.make_userdata())
        return 0


def get_subcommands():
    return [MakeUserDataSubcommand()]
