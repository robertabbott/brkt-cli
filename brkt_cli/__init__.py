# Copyright 2015 Bracket Computing, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# https://github.com/brkt/brkt-sdk-java/blob/master/LICENSE
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function

import argparse
import getpass
import os

import boto
import boto.ec2
import boto.vpc
import logging
import sys
import warnings

from boto.exception import EC2ResponseError, NoAuthHandlerFound
from requests.packages import urllib3

from brkt_cli import aws_service
from brkt_cli import encrypt_ami
from brkt_cli import encrypt_ami_args
from brkt_cli import encryptor_service
from brkt_cli import util
from brkt_cli.bracket_service import BracketService, BracketAuthError

PROD_API_ROOT = 'https://api.mgmt.brkt.com'
STAGE_API_ROOT = 'https://api.stage.mgmt.brkt.com'
VERSION = '0.9.5'

log = None

EULA_CONFIRMATION_TEXT = \
    """Please take a moment to review the terms of the Bracket
Computing, Inc. Evaluation Agreement, which govern the access
to and use of the Bracket Service. You can find it at

    https://brkt.com/license.html

You must accept these terms to access the Bracket Service. Type
"YES" to accept the terms of the Bracket Computing, Inc. Evaluation
Agreement: """


def _check_eula(api_root, username, password, verify_cert=True):
    """ Authenticate with the Bracket service, and ask the user to accept
        the EULA if necessary.
    :return: True if the EULA was accepted
    :raise IOEError if the connection fails
    :raise BracketAuthError if auth fails
    """
    # Authenticate and verify that the user has registered and signed the
    # EULA.
    brkt_svc = BracketService(
        api_root, username, password, verify_cert=verify_cert)
    brkt_svc.authenticate()

    if not brkt_svc.is_eula_accepted():
        sys.stdout.write(EULA_CONFIRMATION_TEXT)
        accepted = raw_input()
        if accepted.strip().lower() != 'yes':
            return False
        brkt_svc.accept_eula()
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-u', '--username',
        metavar='EMAIL',
        dest='username',
        help='Bracket service user email address',
        required=True
    )
    parser.add_argument(
        '-p', '--password',
        metavar='PASSWORD',
        dest='password',
        help='Bracket service password'
    )
    parser.add_argument(
        '-v',
        '--verbose',
        dest='verbose',
        action='store_true',
        help='Print status information to the console'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='brkt-cli version %s' % VERSION
    )
    # Tell the HTTP client to accept self-signed certs.  This option is
    # hidden because it's only used for development.
    parser.add_argument(
        '--no-verify-cert',
        action='store_false',
        dest='verify_cert',
        default=True,
        help=argparse.SUPPRESS
    )

    # Optional Bracket server API root.  This argument is hidden because
    # it's only used for development.
    parser.add_argument(
        '--api-root',
        metavar='URL',
        help=argparse.SUPPRESS,
        dest='api_root'
    )
    subparsers = parser.add_subparsers()

    encrypt_ami_parser = subparsers.add_parser('encrypt-ami')
    encrypt_ami_args.setup_encrypt_ami_args(encrypt_ami_parser)

    argv = sys.argv[1:]
    values = parser.parse_args(argv)
    region = values.region

    # Initialize logging.  Log messages are written to stderr and are
    # prefixed with a compact timestamp, so that the user knows how long
    # each operation took.
    if values.verbose:
        log_level = logging.DEBUG
    else:
        # Boto logs auth errors and 401s at ERROR level by default.
        boto.log.setLevel(logging.FATAL)
        log_level = logging.INFO

    # Set the log level of our modules explicitly.  We can't set the
    # default log level to INFO because we would see INFO messages from
    # boto and other 3rd party libraries in the command output.
    logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%H:%M:%S')
    global log
    log = logging.getLogger(__name__)
    log.setLevel(log_level)
    aws_service.log.setLevel(log_level)
    encryptor_service.log.setLevel(log_level)
    bracket_service.log.setLevel(log_level)

    if not values.verify_cert:
        warnings.filterwarnings(
            'ignore',
            category=urllib3.exceptions.InsecureRequestWarning
        )

    # Validate the AMI name.
    if values.encrypted_ami_name:
        try:
            aws_service.validate_image_name(values.encrypted_ami_name)
        except aws_service.ImageNameError as e:
            print(e.message, file=sys.stderr)
            return 1

    password = values.password or getpass.getpass('Password:')
    if values.api_root:
        api_root = values.api_root
    else:
        if os.getenv('BRACKET_ENVIRONMENT') == 'stage':
            api_root = STAGE_API_ROOT
        else:
            api_root = PROD_API_ROOT

    try:
        eula_accepted = _check_eula(
            api_root,
            values.username,
            password,
            verify_cert=values.verify_cert
        )
        if not eula_accepted:
            return 1
    except BracketAuthError:
        print('Invalid username or password', file=sys.stderr)
        return 1
    except IOError as e:
        if values.verbose:
            log.exception('Unable to connect to the Bracket Service')
        else:
            print('Unable to connect to the Bracket Service: %s' % e)
        return 1

    # Validate the region.
    regions = [str(r.name) for r in boto.vpc.regions()]
    if region not in regions:
        print(
            'Invalid region %s.  Must be one of %s.' %
            (region, str(regions)),
            file=sys.stderr
        )
        return 1

    encryptor_ami = values.encryptor_ami
    if not encryptor_ami:
        try:
            encryptor_ami = encrypt_ami.get_encryptor_ami(region)
        except:
            log.exception('Failed to get encryptor AMI.')
            return 1

    session_id = util.make_nonce()
    default_tags = encrypt_ami.get_default_tags(session_id, encryptor_ami)

    try:
        # Connect to AWS.
        aws_svc = aws_service.AWSService(
            session_id, encryptor_ami, default_tags=default_tags)
        aws_svc.connect(region, key_name=values.key_name)
    except NoAuthHandlerFound:
        msg = (
            'Unable to connect to AWS.  Are your AWS_ACCESS_KEY_ID and '
            'AWS_SECRET_ACCESS_KEY environment variables set?'
        )
        if values.verbose:
            log.exception(msg)
        else:
            log.error(msg)
        return 1

    try:
        if values.key_name:
            # Validate the key pair name.
            aws_svc.get_key_pair(values.key_name)

        if not values.no_validate_ami:
            error = aws_svc.validate_guest_ami(values.ami)
            if error:
                print(error, file=sys.stderr)
                return 1

            error = aws_svc.validate_encryptor_ami(encryptor_ami)
            if error:
                print(error, file=sys.stderr)
                return 1

        log.info('Starting encryptor session %s', aws_svc.session_id)

        encrypted_image_id = encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=encryptor_service.EncryptorService,
            image_id=values.ami,
            encryptor_ami=encryptor_ami,
            encrypted_ami_name=values.encrypted_ami_name
        )
        # Print the AMI ID to stdout, in case the caller wants to process
        # the output.  Log messages go to stderr.
        print(encrypted_image_id)
        return 0
    except EC2ResponseError as e:
        if e.error_code == 'AuthFailure':
            msg = 'Check your AWS login credentials and permissions'
            if values.verbose:
                log.exception(msg)
            else:
                log.error(msg + ': ' + e.error_message)
        elif e.error_code == 'InvalidKeyPair.NotFound':
            if values.verbose:
                log.exception(e.error_message)
            else:
                log.error(e.error_message)
        elif e.error_code == 'UnauthorizedOperation':
            if values.verbose:
                log.exception(e.error_message)
            else:
                log.error(e.error_message)
            log.error(
                'Unauthorized operation.  Check the IAM policy for your '
                'AWS account.'
            )
        else:
            raise
    except util.BracketError as e:
        if values.verbose:
            log.exception(e.message)
        else:
            log.error(e.message)
    except KeyboardInterrupt:
        if values.verbose:
            log.exception('Interrupted by user')
        else:
            log.error('Interrupted by user')
    return 1

if __name__ == '__main__':
    exit_status = main()
    exit(exit_status)
