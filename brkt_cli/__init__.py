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

from brkt_cli import aws_service
from brkt_cli import encrypt_ami
from brkt_cli import encrypt_ami_args
from brkt_cli import update_encrypted_ami
from brkt_cli import update_encrypted_ami_args
from brkt_cli import encryptor_service
from brkt_cli import util

VERSION = '0.9.6'

log = None


def _validate_subnet_and_security_groups(aws_svc,
                                         subnet_id=None,
                                         security_group_ids=None):
    """ Verify that the given subnet and security groups all exist and are
    in the same subnet.

    :return True if all of the ids are valid and in the same VPC
    :raise EC2ResponseError if any of the ids are invalid
    """
    vpc_ids = set()
    if subnet_id:
        # Validate the subnet.
        subnet = aws_svc.get_subnet(subnet_id)
        vpc_ids.add(subnet.vpc_id)

    if security_group_ids:
        # Validate the security groups.
        for id in security_group_ids:
            sg = aws_svc.get_security_group(id, retry=False)
            vpc_ids.add(sg.vpc_id)

    return len(vpc_ids) <= 1


def command_encrypt_ami(values, log):
    region = values.region

    if values.encrypted_ami_name:
        try:
            aws_service.validate_image_name(values.encrypted_ami_name)
        except aws_service.ImageNameError as e:
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
        aws_svc = aws_service.AWSService(
            session_id, default_tags=default_tags)
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

        if not _validate_subnet_and_security_groups(
            aws_svc,
            subnet_id=values.subnet_id,
            security_group_ids=values.security_group_ids
        ):
            log.error('Subnet and security groups must be in the same VPC.')
            return 1

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
            encrypted_ami_name=values.encrypted_ami_name,
            subnet_id=values.subnet_id,
            security_group_ids=values.security_group_ids
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
        elif e.error_code in (
                'InvalidKeyPair.NotFound',
                'InvalidSubnetID.NotFound',
                'InvalidGroup.NotFound'):
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


def command_update_encrypted_ami(values, log):
    encrypted_ami_name = None
    if values.encrypted_ami_name:
        try:
            aws_service.validate_image_name(values.encrypted_ami_name)
            encrypted_ami_name = values.encrypted_ami_name
        except aws_service.ImageNameError as e:
            print(e.message, file=sys.stderr)
            return 1
    region = values.region
    nonce = util.make_nonce()
    default_tags = encrypt_ami.get_default_tags(nonce, '')
    aws_svc = aws_service.AWSService(
        nonce, default_tags=default_tags)
    if not aws_svc.validate_region(region):
        print ('Invalid region %s' % region,
               file=sys.stderr)
        return 1
    aws_svc.connect(region)
    encrypted_ami = values.ami
    if not values.no_validate_ami:
        guest_ami_error = aws_svc.validate_guest_encrypted_ami(encrypted_ami)
        if guest_ami_error:
            print ('Encrypted AMI verification failed: %s' % guest_ami_error,
                   file=sys.stderr)
            return 1
    else:
        log.info('skipping AMI verification')
    updater_ami = values.updater_ami
    updater_ami_error = aws_svc.validate_encryptor_ami(values.updater_ami)
    if updater_ami_error:
        log.error('Update failed: %s', updater_ami_error)
        return 1
    # Initial validation done
    log.info('Updating %s', encrypted_ami)
    # snapshot the guest's volume
    guest_snapshot, volume_info, error = \
        update_encrypted_ami.retrieve_guest_volume_snapshot(
            aws_svc,
            encrypted_ami)
    if not guest_snapshot:
        log.error('failed to launch instance %s: %s' % (encrypted_ami, error))
        return 1
    log.info('Launching metavisor update encryptor instance')
    updater_ami_block_devices = \
        update_encrypted_ami.snapshot_updater_ami_block_devices(
            aws_svc,
            encrypted_ami,
            updater_ami,
            guest_snapshot.id,
            volume_info['size'])
    ami = encrypt_ami.register_new_ami(
        aws_svc,
        updater_ami_block_devices[encrypt_ami.NAME_METAVISOR_GRUB_SNAPSHOT],
        updater_ami_block_devices[encrypt_ami.NAME_METAVISOR_ROOT_SNAPSHOT],
        updater_ami_block_devices[encrypt_ami.NAME_METAVISOR_LOG_SNAPSHOT],
        guest_snapshot,
        volume_info['type'],
        volume_info['iops'],
        encrypted_ami,
        encrypted_ami_name=encrypted_ami_name)
    log.info('Done.')
    print(ami)
    return 0


def main():
    # Check Python version.
    version = '%d.%d' % (sys.version_info.major, sys.version_info.minor)
    if version != '2.7':
        print(
            'brkt-cli requires Python 2.7.  Version',
            version,
            'is not supported.',
            file=sys.stderr
        )
        return 1

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

    subparsers = parser.add_subparsers(dest='subparser_name')

    encrypt_ami_parser = subparsers.add_parser('encrypt-ami')
    encrypt_ami_args.setup_encrypt_ami_args(encrypt_ami_parser)

    update_encrypted_ami_parser = \
        subparsers.add_parser('update-encrypted-ami')
    update_encrypted_ami_args.setup_update_encrypted_ami(
        update_encrypted_ami_parser)

    argv = sys.argv[1:]
    values = parser.parse_args(argv)
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
    if values.subparser_name == 'encrypt-ami':
        return command_encrypt_ami(values, log)
    if values.subparser_name == 'update-encrypted-ami':
        return command_update_encrypted_ami(values, log)


if __name__ == '__main__':
    exit_status = main()
    exit(exit_status)
