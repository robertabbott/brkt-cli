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


def setup_update_encrypted_ami(parser):
    parser.add_argument(
        'ami',
        metavar='ID',
        help='The encrypted AMI that will be updated'
    )
    parser.add_argument(
        '--encrypted-ami-name',
        metavar='NAME',
        dest='encrypted_ami_name',
        help='Specify the name of the generated encrypted AMI',
        required=False
    )
    parser.add_argument(
        '--guest-instance-type',
        metavar='TYPE',
        dest='guest_instance_type',
        help=(
            'The instance type to use when running the encrypted guest '
            'instance. Default: m3.medium'),
        default='m3.medium'
    )
    parser.add_argument(
        '--updater-instance-type',
        metavar='TYPE',
        dest='updater_instance_type',
        help=(
            'The instance type to use when running the updater '
            'instance. Default: m3.medium'),
        default='m3.medium'
    )
    parser.add_argument(
        '--pv',
        action='store_true',
        help='Use the PV encryptor',
        dest='pv'
    )
    parser.add_argument(
        '--no-validate',
        dest='validate',
        action='store_false',
        default=True,
        help="Don't validate AMIs, subnet, and security groups"
    )
    parser.add_argument(
        '--region',
        metavar='REGION',
        help='AWS region (e.g. us-west-2)',
        dest='region',
        required=True
    )
    parser.add_argument(
        '--security-group',
        metavar='ID',
        dest='security_group_ids',
        action='append',
        help=(
            'Use this security group when running the encryptor instance. '
            'May be specified multiple times.'
        )
    )
    parser.add_argument(
        '--subnet',
        metavar='ID',
        dest='subnet_id',
        help='Launch instances in this subnet'
    )
    # Optional EC2 SSH key pair name to use for launching the guest
    # and encryptor instances.  This argument is hidden because it's only
    # used for development.
    parser.add_argument(
        '--key',
        metavar='KEY',
        help=argparse.SUPPRESS,
        dest='key_name'
    )
    parser.add_argument(
        '--tag',
        metavar='KEY=VALUE',
        dest='tags',
        action='append',
        help=(
            'Set an AWS tag on resources created during update. '
            'May be specified multiple times.'
        )
    )
    parser.add_argument(
        '-v',
        '--verbose',
        dest='update_encrypted_ami_verbose',
        action='store_true',
        help='Print status information to the console'
    )
    # Optional hidden argument for specifying the metavisor AMI.  This
    # argument is hidden because it's only used for development.  It can
    # also be used to override the default AMI if it's determined to be
    # unstable.
    parser.add_argument(
        '--encryptor-ami',
        metavar='ID',
        help=argparse.SUPPRESS,
        dest='encryptor_ami'
    )
    # Optional arguments for changing the behavior of our retry logic.  We
    # use these options internally, to avoid intermittent AWS service failures
    # when running concurrent encryption processes in integration tests.
    parser.add_argument(
        '--retry-timeout',
        metavar='SECONDS',
        type=float,
        help=argparse.SUPPRESS,
        default=10.0
    )
    parser.add_argument(
        '--retry-initial-sleep-seconds',
        metavar='SECONDS',
        type=float,
        help=argparse.SUPPRESS,
        default=0.25
    )
