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
import re

import boto
from boto.exception import EC2ResponseError, NoAuthHandlerFound

import brkt_cli
from brkt_cli import encryptor_service, util
from brkt_cli.aws import aws_service, encrypt_ami
from brkt_cli.subcommand import Subcommand
from brkt_cli.validation import ValidationError
from encrypt_ami import (
    TAG_ENCRYPTOR,
    TAG_ENCRYPTOR_AMI,
    TAG_ENCRYPTOR_SESSION_ID)
import encrypt_ami_args
import update_encrypted_ami_args
from update_ami import update_ami

log = logging.getLogger(__name__)


METAVISOR_AMI_REGION_NAMES = ['us-east-1', 'us-west-1', 'us-west-2']


class EncryptAMISubcommand(Subcommand):

    def name(self):
        return 'encrypt-ami'

    def init_logging(self, verbose):
        # Set boto logging to FATAL, since boto logs auth errors and 401s
        # at ERROR level.
        boto.log.setLevel(logging.FATAL)

    def verbose(self, values):
        return values.encrypt_ami_verbose

    def register(self, subparsers):
        encrypt_ami_parser = subparsers.add_parser(
            'encrypt-ami',
            description='Create an encrypted AMI from an existing AMI.'
        )
        encrypt_ami_args.setup_encrypt_ami_args(encrypt_ami_parser)

    def run(self, values):
        return _run_subcommand(self.name(), values)


class UpdateAMISubcommand(Subcommand):

    def name(self):
        return 'update-encrypted-ami'

    def init_logging(self, verbose):
        # Set boto logging to FATAL, since boto logs auth errors and 401s
        # at ERROR level.
        boto.log.setLevel(logging.FATAL)

    def verbose(self, values):
        return values.update_encrypted_ami_verbose

    def register(self, subparsers):
        update_encrypted_ami_parser = subparsers.add_parser(
            'update-encrypted-ami',
            description=(
                'Update an encrypted AMI with the latest Metavisor '
                'release.'
            )
        )
        update_encrypted_ami_args.setup_update_encrypted_ami(
            update_encrypted_ami_parser)

    def run(self, values):
        return _run_subcommand(self.name(), values)


def get_subcommands():
    return [EncryptAMISubcommand(), UpdateAMISubcommand()]


def _run_subcommand(subcommand, values):
    try:
        if subcommand == 'encrypt-ami':
            return command_encrypt_ami(values, log)
        if subcommand == 'update-encrypted-ami':
            return command_update_encrypted_ami(values, log)
    except NoAuthHandlerFound:
        msg = (
            'Unable to connect to AWS.  Are your AWS_ACCESS_KEY_ID and '
            'AWS_SECRET_ACCESS_KEY environment variables set?'
        )
        if values.verbose:
            log.exception(msg)
        else:
            log.error(msg)
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
            'InvalidGroup.NotFound'
        ):
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

    return 1


def _validate_subnet_and_security_groups(aws_svc,
                                         subnet_id=None,
                                         security_group_ids=None):
    """ Verify that the given subnet and security groups all exist and are
    in the same subnet.

    :return True if all of the ids are valid and in the same VPC
    :raise EC2ResponseError or ValidationError if any of the ids are invalid
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

    if len(vpc_ids) > 1:
        raise ValidationError(
            'Subnet and security groups must be in the same VPC.')

    if not subnet_id and vpc_ids:
        # Security groups were specified but subnet wasn't.  Make sure that
        # the security groups are in the default VPC.
        (vpc_id,) = vpc_ids
        default_vpc = aws_svc.get_default_vpc()
        log.debug(
            'Default VPC: %s, security group VPC IDs: %s',
            default_vpc,
            vpc_ids
        )

        # Perform the check as long as there's a default VPC.  In
        # EC2-Classic, there is no default VPC and the vpc_id field is null.
        if vpc_id and default_vpc:
            if vpc_id != default_vpc.id:
                raise ValidationError(
                    'Security groups must be in the default VPC when '
                    'a subnet is not specified.'
                )


def _validate_ami(aws_svc, ami_id):
    """
    @return the Image object
    @raise ValidationError if the image doesn't exist
    """
    try:
        image = aws_svc.get_image(ami_id)
    except EC2ResponseError, e:
        if e.error_code.startswith('InvalidAMIID'):
            raise ValidationError(
                'Could not find ' + ami_id + ': ' + e.error_code)
        else:
            raise ValidationError(e.error_message)
    if not image:
        raise ValidationError('Could not find ' + ami_id)
    return image


def _validate_guest_ami(aws_svc, ami_id):
    """ Validate that we are able to encrypt this image.

    :return: None if the image is valid, or an error string if not
    """
    image = _validate_ami(aws_svc, ami_id)
    if TAG_ENCRYPTOR in image.tags:
        return '%s is already an encrypted image' % ami_id

    # Amazon's API only returns 'windows' or nothing.  We're not currently
    # able to detect individual Linux distros.
    if image.platform == 'windows':
        return 'Windows is not a supported platform'

    if image.root_device_type != 'ebs':
        return '%s does not use EBS storage.' % ami_id
    if image.hypervisor != 'xen':
        return '%s uses hypervisor %s.  Only xen is supported' % (
            ami_id, image.hypervisor)
    return None


def _validate_guest_encrypted_ami(aws_svc, ami_id, encryptor_ami_id):
    """ Validate that this image was encrypted by Bracket by checking
        tags.

    :raise: ValidationError if validation fails
    :return: the Image object
    """
    ami = _validate_ami(aws_svc, ami_id)

    # Is this encrypted by Bracket?
    tags = ami.tags
    expected_tags = (TAG_ENCRYPTOR,
                     TAG_ENCRYPTOR_SESSION_ID,
                     TAG_ENCRYPTOR_AMI)
    missing_tags = set(expected_tags) - set(tags.keys())
    if missing_tags:
        raise ValidationError(
            '%s is missing tags: %s' % (ami.id, ', '.join(missing_tags)))

    # See if this image was already encrypted by the given encryptor AMI.
    original_encryptor_id = tags.get(TAG_ENCRYPTOR_AMI)
    if original_encryptor_id == encryptor_ami_id:
        msg = '%s was already encrypted with Bracket Encryptor %s' % (
            ami.id,
            encryptor_ami_id
        )
        raise ValidationError(msg)

    return ami


def _validate_encryptor_ami(aws_svc, ami_id):
    """ Validate that the image exists and is a Bracket encryptor image.

    @raise ValidationError if validation fails
    """
    image = _validate_ami(aws_svc, ami_id)
    if 'brkt-avatar' not in image.name:
        raise ValidationError(
            '%s (%s) is not a Bracket Encryptor image' % (ami_id, image.name)
        )
    return None


def _connect_and_validate(aws_svc, values, encryptor_ami_id):
    """ Connect to the AWS service and validate command-line options

    :param aws_svc: the BaseAWSService implementation
    :param values: object that was generated by argparse
    """
    if values.encrypted_ami_name:
        aws_service.validate_image_name(values.encrypted_ami_name)

    aws_svc.connect(values.region, key_name=values.key_name)

    try:
        if values.key_name:
            aws_svc.get_key_pair(values.key_name)

        if values.validate:
            _validate_subnet_and_security_groups(
                aws_svc, values.subnet_id, values.security_group_ids)
            _validate_encryptor_ami(aws_svc, encryptor_ami_id)
        else:
            log.debug('Skipping validation')

        if values.encrypted_ami_name:
            filters = {'name': values.encrypted_ami_name}
            if aws_svc.get_images(filters=filters, owners=['self']):
                raise ValidationError(
                    'You already own an image named %s' %
                    values.encrypted_ami_name
                )
    except EC2ResponseError as e:
        raise ValidationError(e.message)


def _validate_region(aws_svc, values):
    """ Check that the specified region is one that contains published
    metavisor AMIs.  If --encryptor-ami is specified, check against the
    entire set of AWS regions, since this option may be used for testing
    new regions.

    :raise ValidationError if the region is invalid
    """
    if values.encryptor_ami:
        region_names = [r.name for r in aws_svc.get_regions()]
    else:
        region_names = METAVISOR_AMI_REGION_NAMES

    if values.region not in region_names:
        raise ValidationError(
            'Invalid region %s.  Supported regions: %s.' %
            (values.region, ', '.join(region_names)))


def command_encrypt_ami(values, log):
    session_id = util.make_nonce()

    aws_svc = aws_service.AWSService(session_id)

    # Validate the specified region.
    if values.validate:
        _validate_region(aws_svc, values)

    encryptor_ami = (
        values.encryptor_ami or
        encrypt_ami.get_encryptor_ami(values.region, hvm=values.hvm)
    )

    default_tags = encrypt_ami.get_default_tags(session_id, encryptor_ami)
    default_tags.update(brkt_cli.parse_tags(values.tags))
    aws_svc.default_tags = default_tags
    brkt_cli.validate_ntp_servers(values.ntp_servers)

    _connect_and_validate(aws_svc, values, encryptor_ami)
    error_msg = _validate_guest_ami(aws_svc, values.ami)
    if error_msg:
        raise ValidationError(error_msg)

    brkt_env = None
    if values.brkt_env:
        brkt_env = brkt_cli.parse_brkt_env(values.brkt_env)

    proxy_config = brkt_cli.get_proxy_config(values)
    jwt = brkt_cli.validate_jwt(values.jwt)

    encrypted_image_id = encrypt_ami.encrypt(
        aws_svc=aws_svc,
        enc_svc_cls=encryptor_service.EncryptorService,
        image_id=values.ami,
        encryptor_ami=encryptor_ami,
        encrypted_ami_name=values.encrypted_ami_name,
        subnet_id=values.subnet_id,
        security_group_ids=values.security_group_ids,
        brkt_env=brkt_env,
        ntp_servers=values.ntp_servers,
        proxy_config=proxy_config,
        guest_instance_type=values.guest_instance_type,
        jwt=jwt
    )
    # Print the AMI ID to stdout, in case the caller wants to process
    # the output.  Log messages go to stderr.
    print(encrypted_image_id)
    return 0


def _get_updated_image_name(image_name, session_id):
    """ Generate a new name, based on the existing name of the encrypted
    image and the session id.

    @return the new name
    """
    # Replace session id in the image name.
    m = re.match('(.+) \(encrypted (\S+)\)', image_name)
    suffix = ' (encrypted %s)' % session_id
    if m:
        encrypted_ami_name = util.append_suffix(
            m.group(1), suffix, max_length=128)
    else:
        encrypted_ami_name = util.append_suffix(
            image_name, suffix, max_length=128)
    return encrypted_ami_name


def command_update_encrypted_ami(values, log):
    nonce = util.make_nonce()

    aws_svc = aws_service.AWSService(nonce)
    _validate_region(aws_svc, values)
    encryptor_ami = (
        values.encryptor_ami or
        encrypt_ami.get_encryptor_ami(values.region, hvm=values.hvm)
    )

    default_tags = encrypt_ami.get_default_tags(nonce, encryptor_ami)
    default_tags.update(brkt_cli.parse_tags(values.tags))
    aws_svc.default_tags = default_tags

    brkt_cli.validate_ntp_servers(values.ntp_servers)
    _connect_and_validate(aws_svc, values, encryptor_ami)

    encrypted_ami = values.ami
    if values.validate:
        guest_image = _validate_guest_encrypted_ami(
            aws_svc, encrypted_ami, encryptor_ami)
    else:
        log.info('Skipping AMI validation.')
        guest_image = aws_svc.get_image(encrypted_ami)

    mv_image = aws_svc.get_image(encryptor_ami)
    if (guest_image.virtualization_type !=
            mv_image.virtualization_type):
        log.error(
            'Virtualization type mismatch.  %s is %s, but encryptor %s is '
            '%s.',
            guest_image.id,
            guest_image.virtualization_type,
            mv_image.id,
            mv_image.virtualization_type
        )
        return 1

    encrypted_ami_name = values.encrypted_ami_name
    if encrypted_ami_name:
        # Check for name collision.
        filters = {'name': encrypted_ami_name}
        if aws_svc.get_images(filters=filters, owners=['self']):
            raise ValidationError(
                'You already own image named %s' % encrypted_ami_name)
    else:
        encrypted_ami_name = _get_updated_image_name(guest_image.name, nonce)
    log.debug('Image name: %s', encrypted_ami_name)
    aws_service.validate_image_name(encrypted_ami_name)

    brkt_env = None
    if values.brkt_env:
        brkt_env = brkt_cli.parse_brkt_env(values.brkt_env)
    proxy_config = brkt_cli.get_proxy_config(values)
    jwt = brkt_cli.validate_jwt(values.jwt)

    # Initial validation done
    log.info('Updating %s with new metavisor %s', encrypted_ami, encryptor_ami)

    updated_ami_id = update_ami(
        aws_svc, encrypted_ami, encryptor_ami, encrypted_ami_name,
        subnet_id=values.subnet_id,
        security_group_ids=values.security_group_ids,
        ntp_servers=values.ntp_servers,
        brkt_env=brkt_env,
        guest_instance_type=values.guest_instance_type,
        proxy_config=proxy_config,
        jwt=jwt
    )
    print(updated_ami_id)
    return 0

