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

from brkt_cli.aws import encrypt_ami_args, update_encrypted_ami_args
from brkt_cli.module import ModuleInterface


class AWSModuleInterface(ModuleInterface):

    def get_subcommands(self):
        return ['encrypt-ami', 'update-encrypted-ami']

    def get_exposed_subcommands(self):
        return self.get_subcommands()

    def get_loggers(self):
        return []

    def register_subcommand(self, subparsers, subcommand):
        if subcommand == 'encrypt-ami':
            encrypt_ami_parser = subparsers.add_parser(
                'encrypt-ami',
                description='Create an encrypted AMI from an existing AMI.'
            )
            encrypt_ami_args.setup_encrypt_ami_args(encrypt_ami_parser)

        if subcommand == 'update-encrypted-ami':
            update_encrypted_ami_parser = subparsers.add_parser(
                'update-encrypted-ami',
                description=(
                    'Update an encrypted AMI with the latest Metavisor '
                    'release.'
                )
            )
            update_encrypted_ami_args.setup_update_encrypted_ami(
                update_encrypted_ami_parser)

    def run_subcommand(self, subcommand, values):
        if values.subparser_name == 'encrypt-ami':
            # return command_encrypt_ami(values, log)
            print subcommand
        if values.subparser_name == 'update-encrypted-ami':
            # return command_update_encrypted_ami(values, log)
            print subcommand


INTERFACE = AWSModuleInterface()
