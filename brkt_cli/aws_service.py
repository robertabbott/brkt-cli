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

import abc
import re
import boto
import boto.sts
import logging
from boto.exception import EC2ResponseError
import time

from encrypt_ami import (
    TAG_ENCRYPTOR,
    TAG_ENCRYPTOR_SESSION_ID,
    TAG_ENCRYPTOR_AMI
)

PLATFORM_WINDOWS = 'windows'

log = logging.getLogger(__name__)


class BaseAWSService(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, session_id):
        self.session_id = session_id

    @abc.abstractmethod
    def get_regions(self):
        pass

    @abc.abstractmethod
    def connect(self, region, key_name=None):
        pass

    @abc.abstractmethod
    def run_instance(self,
                     image_id,
                     security_group_ids=None,
                     instance_type='c3.xlarge',
                     placement=None,
                     block_device_map=None,
                     subnet_id=None,
                     user_data=None,
                     ebs_optimized=True,
                     instance_profile_name=None):
        pass

    @abc.abstractmethod
    def get_instance(self, instance_id):
        pass

    @abc.abstractmethod
    def create_tags(self, resource_id, name=None, description=None):
        pass

    @abc.abstractmethod
    def stop_instance(self, instance_id):
        pass

    @abc.abstractmethod
    def terminate_instance(self, instance_id):
        pass

    @abc.abstractmethod
    def get_volume(self, volume_id):
        pass

    @abc.abstractmethod
    def get_volumes(self, tag_key=None, tag_value=None):
        pass

    @abc.abstractmethod
    def get_snapshots(self, *snapshot_ids):
        pass

    @abc.abstractmethod
    def get_snapshot(self, snapshot_id):
        pass

    @abc.abstractmethod
    def create_snapshot(self, volume_id, name=None, description=None):
        pass

    @abc.abstractmethod
    def create_volume(self,
                      size,
                      zone,
                      snapshot=None,
                      volume_type=None,
                      encrypted=False):
        pass

    @abc.abstractmethod
    def delete_volume(self, volume_id):
        """ Delete the given volume.
        :return: True if the volume was deleted
        :raise: EC2ResponseError if an error occurred
        """
        pass

    @abc.abstractmethod
    def validate_guest_ami(self, ami_id):
        pass

    @abc.abstractmethod
    def validate_encryptor_ami(self, ami_id):
        pass

    @abc.abstractmethod
    def register_image(self,
                       kernel_id,
                       block_device_map,
                       name=None,
                       description=None):
        pass

    @abc.abstractmethod
    def get_image(self, image_id):
        pass

    @abc.abstractmethod
    def get_images(self, filters=None):
        pass

    @abc.abstractmethod
    def delete_snapshot(self, snapshot_id):
        pass

    @abc.abstractmethod
    def create_security_group(self, name, description, vpc_id=None):
        pass

    @abc.abstractmethod
    def get_security_group(self, sg_id, retry=False):
        pass

    @abc.abstractmethod
    def add_security_group_rule(self, sg_id, **kwargs):
        pass

    @abc.abstractmethod
    def delete_security_group(self, sg_id):
        pass

    @abc.abstractmethod
    def get_key_pair(self, keyname):
        pass

    @abc.abstractmethod
    def get_console_output(self, instance_id):
        pass

    @abc.abstractmethod
    def get_subnet(self, subnet_id):
        pass

    def create_image(self,
                     instance_id,
                     name,
                     description=None,
                     no_reboot=True,
                     block_device_mapping=None):
        pass

    @abc.abstractmethod
    def detach_volume(self, vol_id, instance_id=None, force=True):
        pass

    @abc.abstractmethod
    def attach_volume(self, vol_id, instance_id, device):
        pass


def retry_boto(error_code_regexp, max_retries=5, initial_sleep_seconds=0.25):
    """ Call a boto function repeatedly until it succeeds.  If the call
    fails with the expected error code, sleep and retry up to max_retries
    times.  If the error code does not match error_code_regexp, fail
    immediately.  The sleep interval is doubled on each retry.  With the
    default settings, the total maximum sleep time is 7.75 seconds
    (.25 + .50 + 1 + 2 + 4).
    """
    def retry_decorator(func):
        def func_wrapper(*args, **kwargs):
            retries = 0
            sleep_seconds = initial_sleep_seconds

            while True:
                try:
                    return func(*args, **kwargs)
                except EC2ResponseError as e:
                    if retries >= max_retries:
                        log.error(
                            'Exceeded %d retries for %s',
                            max_retries,
                            func.__name__
                        )
                        raise

                    m = re.match(error_code_regexp, e.error_code)
                    if not m:
                        raise

                time.sleep(sleep_seconds)
                retries += 1
                sleep_seconds *= 2

        return func_wrapper

    return retry_decorator


def _get_first_element(list, error_status):
    """ Return the first element in the list.  If the list is empty, raise
    an EC2ResponseError with the given error status.  This is a workaround
    for the case where the AWS API erroneously returns an empty list instead
    of an error.
    """
    if list:
        return list[0]
    else:
        raise EC2ResponseError(
            error_status, 'AWS API returned an empty response')


class AWSService(BaseAWSService):

    def __init__(
            self,
            encryptor_session_id,
            default_tags=None):
        super(AWSService, self).__init__(encryptor_session_id)

        self.default_tags = default_tags or {}

        # These will be initialized by connect().
        self.key_name = None
        self.region = None
        self.conn = None

    def get_regions(self):
        return boto.vpc.regions()

    def connect(self, region, key_name=None):
        self.region = region
        self.key_name = key_name
        self.conn = boto.vpc.connect_to_region(region)

    def connect_as(self, role, region, session_name):
        sts_conn = boto.sts.connect_to_region(region)
        creds = sts_conn.assume_role(role, session_name)
        conn = boto.vpc.connect_to_region(
            region,
            aws_access_key_id=creds.credentials.access_key,
            aws_secret_access_key=creds.credentials.secret_key,
            security_token=creds.credentials.session_token)
        self.region = region
        self.conn = conn

    def run_instance(self,
                     image_id,
                     security_group_ids=None,
                     instance_type='c3.xlarge',
                     placement=None,
                     block_device_map=None,
                     subnet_id=None,
                     user_data=None,
                     ebs_optimized=True,
                     instance_profile_name=None):
        if security_group_ids is None:
            security_group_ids = []
        log.debug('Starting a new instance based on %s', image_id)
        if security_group_ids:
            log.debug(
                'Using security groups %s', ', '.join(security_group_ids))
        if subnet_id:
            log.debug('Running instance in %s', subnet_id)

        try:
            reservation = self.conn.run_instances(
                image_id=image_id,
                placement=placement,
                key_name=self.key_name,
                instance_type=instance_type,
                block_device_map=block_device_map,
                security_group_ids=security_group_ids,
                subnet_id=subnet_id,
                ebs_optimized=ebs_optimized,
                user_data=user_data,
                instance_profile_name=instance_profile_name
            )
            return reservation.instances[0]
        except EC2ResponseError:
            log.debug('Failed to launch instance for %s', image_id)
            raise

    @retry_boto(error_code_regexp=r'InvalidInstanceID\.NotFound')
    def get_instance(self, instance_id):
        instances = self.conn.get_only_instances([instance_id])
        return _get_first_element(instances, 'InvalidInstanceID.NotFound')

    @retry_boto(error_code_regexp=r'.*\.NotFound')
    def create_tags(self, resource_id, name=None, description=None):
        tags = dict(self.default_tags)
        if name:
            tags['Name'] = name
        if description:
            tags['Description'] = description
        log.debug('Tagging %s with %s', resource_id, tags)
        self.conn.create_tags([resource_id], tags)

    def stop_instance(self, instance_id):
        log.debug('Stopping instance %s', instance_id)
        instances = self.conn.stop_instances([instance_id])
        return instances[0]

    def terminate_instance(self, instance_id):
        log.debug('Terminating instance %s', instance_id)
        self.conn.terminate_instances([instance_id])

    @retry_boto(error_code_regexp=r'InvalidVolume\.NotFound')
    def get_volume(self, volume_id):
        volumes = self.conn.get_all_volumes(volume_ids=[volume_id])
        return _get_first_element(volumes, 'InvalidVolume.NotFound')

    def get_volumes(self, tag_key=None, tag_value=None):
        filters = {}
        if tag_key and tag_value:
            filters['tag:%s' % tag_key] = tag_value

        return self.conn.get_all_volumes(filters=filters)

    @retry_boto(error_code_regexp=r'InvalidSnapshot\.NotFound')
    def get_snapshots(self, *snapshot_ids):
        return self.conn.get_all_snapshots(snapshot_ids)

    @retry_boto(error_code_regexp=r'InvalidSnapshot\.NotFound')
    def get_snapshot(self, snapshot_id):
        snapshots = self.conn.get_all_snapshots([snapshot_id])
        return _get_first_element(snapshots, 'InvalidSnapshot.NotFound')

    def create_snapshot(self, volume_id, name=None, description=None):
        log.debug('Creating snapshot of %s', volume_id)
        snapshot = self.conn.create_snapshot(volume_id, description)
        self.create_tags(snapshot.id, name=name)
        return snapshot

    def create_volume(self,
                      size,
                      zone,
                      snapshot=None,
                      volume_type=None,
                      encrypted=None):
        return self.conn.create_volume(size,
                                       zone,
                                       snapshot=snapshot,
                                       volume_type=volume_type,
                                       encrypted=encrypted
        )

    @retry_boto(error_code_regexp=r'VolumeInUse')
    def delete_volume(self, volume_id):
        log.debug('Deleting volume %s', volume_id)
        try:
            self.conn.delete_volume(volume_id)
        except EC2ResponseError as e:
            if e.error_code != 'InvalidVolume.NotFound':
                raise
        return True

    def validate_guest_ami(self, ami_id):
        try:
            images = self.conn.get_all_images([ami_id])
        except EC2ResponseError, e:
            if e.error_code == 'InvalidAMIID.NotFound':
                return e.error_message
            else:
                raise
        if len(images) == 0:
            return '%s is no longer available' % ami_id
        image = images[0]
        # Amazon's API only returns 'windows' or nothing.  We're not currently
        # able to detect individual Linux distros.
        if image.platform == PLATFORM_WINDOWS:
            return '%s is not a supported platform for %s' % (
                PLATFORM_WINDOWS, ami_id)

        if image.root_device_type != 'ebs':
            return '%s does not use EBS storage.' % ami_id
        if image.hypervisor != 'xen':
            return '%s uses hypervisor %s.  Only xen is supported' % (
                ami_id, image.hypervisor)
        return None

    def validate_guest_encrypted_ami(self, ami_id):
        # Is this the right type of AMI?
        error = self.validate_guest_ami(ami_id)
        if error:
            return error
        # Is this encrypted by Bracket?
        image = self.conn.get_all_images([ami_id])[0]
        tags = image.tags
        expected_tags = (TAG_ENCRYPTOR,
                         TAG_ENCRYPTOR_SESSION_ID,
                         TAG_ENCRYPTOR_AMI)
        missing_tags = set(expected_tags) - set(tags.keys())
        if missing_tags:
            return 'Missing tags %s' % str(missing_tags)
        return None

    def validate_encryptor_ami(self, ami_id):
        try:
            images = self.conn.get_all_images([ami_id])
        except EC2ResponseError, e:
            return e.error_message
        if len(images) == 0:
            return 'Bracket encryptor image %s is no longer available' % ami_id
        image = images[0]
        if 'brkt-avatar' not in image.name:
            return '%s (%s) is not a Bracket Encryptor image' % (
                ami_id, image.name)
        return None

    def register_image(self,
                       kernel_id,
                       block_device_map,
                       name=None,
                       description=None):
        log.debug('Registering image.')
        return self.conn.register_image(
            name=name,
            description=description,
            architecture='x86_64',
            kernel=kernel_id,
            root_device_name='/dev/sda1',
            virtualization_type='paravirtual'
        )

    def get_images(self, filters=None):
        return self.conn.get_all_images(filters=filters)

    @retry_boto(error_code_regexp=r'InvalidAMIID\.NotFound')
    def get_image(self, image_id):
        return self.conn.get_image(image_id)

    def delete_snapshot(self, snapshot_id):
        return self.conn.delete_snapshot(snapshot_id)

    def create_security_group(self, name, description, vpc_id=None):
        log.debug(
            'Creating security group: name=%s, description=%s',
            name, description
        )
        if vpc_id:
            log.debug('Using %s', vpc_id)

        return self.conn.create_security_group(
                    name, description, vpc_id=vpc_id
               )

    def get_security_group(self, sg_id, retry=True):
        if retry:
            @retry_boto(error_code_regexp=r'InvalidGroup\.NotFound')
            def get_with_retry(sg_id):
                groups = self.conn.get_all_security_groups(group_ids=[sg_id])
                return _get_first_element(groups, 'InvalidGroup.NotFound')

            get_with_retry(sg_id)
        else:
            groups = self.conn.get_all_security_groups(group_ids=[sg_id])
            return _get_first_element(groups, 'InvalidGroup.NotFound')

    def add_security_group_rule(self, sg_id, **kwargs):
        kwargs['group_id'] = sg_id
        ok = self.conn.authorize_security_group(**kwargs)
        if not ok:
            raise Exception('Unknown error while adding security group rule')

    @retry_boto(error_code_regexp=r'InvalidGroup\.InUse|DependencyViolation')
    def delete_security_group(self, sg_id):
        ok = self.conn.delete_security_group(group_id=sg_id)
        if not ok:
            raise Exception('Unknown error while deleting security group')

    def get_key_pair(self, keyname):
        key_pairs = self.conn.get_all_key_pairs(keynames=[keyname])
        return _get_first_element(key_pairs, 'InvalidKeyPair.NotFound')

    def get_console_output(self, instance_id):
        return self.conn.get_console_output(instance_id)

    def get_subnet(self, subnet_id):
        subnets = self.conn.get_all_subnets(subnet_ids=[subnet_id])
        return _get_first_element(subnets, 'InvalidSubnetID.NotFound')

    @retry_boto(max_retries=20, error_code_regexp=r'InvalidParameterValue')
    def create_image(self,
                     instance_id,
                     name,
                     description=None,
                     no_reboot=True,
                     block_device_mapping=None):
        return self.conn.create_image(instance_id,
                                      name,
                                      description=description,
                                      no_reboot=no_reboot,
                                      block_device_mapping=block_device_mapping
        )

    def detach_volume(self, vol_id, instance_id=None, force=True):
        return self.conn.detach_volume(vol_id,
                                       instance_id=instance_id,
                                       force=force
        )

    @retry_boto(error_code_regexp=r'VolumeInUse')
    def attach_volume(self, vol_id, instance_id, device):
        return self.conn.attach_volume(vol_id, instance_id, device)


class ImageNameError(Exception):
    pass


def validate_image_name(name):
    """ Verify that the name is a valid EC2 image name.  Return the name
        if it's valid.

    :raises ImageNameError
    """
    if not (name and 3 <= len(name) <= 128):
        raise ImageNameError(
            'Image name must be between 3 and 128 characters long')

    m = re.match(r'[A-Za-z0-9()\[\] ./\-\'@_]+$', name)
    if not m:
        raise ImageNameError(
            "Image name may only contain letters, numbers, spaces, "
            "and the following characters: ()[]./-'@_"
        )
    return name
