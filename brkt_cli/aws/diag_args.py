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


def setup_diag_args(parser):
    parser.add_argument(
        '--snapshot',
        metavar='ID',
        dest='snapshot_id',
        help='The snapshot with Bracket system logs'
    )
    parser.add_argument(
        '--instance',
        metavar='ID',
        dest='instance_id',
        help='The instance with Bracket system logs'
    )
    parser.add_argument(
        '--diag-instance-type',
        metavar='TYPE',
        dest='diag_instance_type',
        help=(
            'The instance type to use when running the diag instance'),
        default='m3.medium'
    )
    parser.add_argument(
        '--no-validate',
        dest='validate',
        action='store_false',
        default=True,
        help="Don't validate instances and snapshots"
    )
    parser.add_argument(
        '--region',
        metavar='NAME',
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
    parser.add_argument(
        '--tag',
        metavar='KEY=VALUE',
        dest='tags',
        action='append',
        help=(
            'Custom tag for resources created during encryption. '
            'May be specified multiple times.'
        )
    )
    parser.add_argument(
        '-v',
        '--verbose',
        dest='diag_verbose',
        action='store_true',
        help='Print status information to the console'
    )
    parser.add_argument(
        '--key',
        metavar='NAME',
        help='ssh keypair name to be used to connect to diag instance.',
        required=True,
        dest='key_name'
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
