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
import boto
import boto.ec2
import boto.vpc
import logging
import sys

from boto.exception import EC2ResponseError, NoAuthHandlerFound

from brkt_cli import encrypt_ami
from brkt_cli import encrypt_ami_args
from brkt_cli import service
from brkt_cli import util

VERSION = '0.9.3'

log = None


def main():
    parser = argparse.ArgumentParser()
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
    logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%H:%M:%S')
    global log
    log = logging.getLogger(__name__)
    log.setLevel(log_level)
    service.log.setLevel(log_level)

    if values.encrypted_ami_name:
        try:
            service.validate_image_name(values.encrypted_ami_name)
        except service.ImageNameError as e:
            print(e.message, file=sys.stderr)
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
        aws_svc = service.AWSService(
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
            enc_svc_cls=service.EncryptorService,
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
