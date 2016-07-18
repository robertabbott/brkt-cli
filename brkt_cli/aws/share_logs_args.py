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


def setup_share_logs_args(parser):
    parser.add_argument(
        '--snapshot',
        metavar='ID',
        dest='snapshot_id',
        help='The snapshot with Bracket system logs to be shared'
    )
    parser.add_argument(
        '--instance',
        metavar='ID',
        dest='instance_id',
        help='The instance with Bracket system logs to be shared'
    )
    parser.add_argument(
        '--no-validate',
        dest='validate',
        action='store_false',
        default=True,
        help="Don't validate instance has AMI with Bracket tags"
    )
    parser.add_argument(
        '--region',
        metavar='NAME',
        help='AWS region (e.g. us-west-2)',
        dest='region',
        required=True
    )
    parser.add_argument(
        '-v',
        '--verbose',
        dest='share_logs_verbose',
        action='store_true',
        help='Print status information to the console'
    )
    # Hidden argument to specify AWS account to share account with - used
    # for developer testing
    parser.add_argument(
        '--bracket-aws-account',
        metavar='ID',
        dest='bracket_aws_account',
        default=164337164081,
        help=argparse.SUPPRESS
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
