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

import abc
import re
import ssl
import tempfile

import boto
import boto.sts
import boto.vpc
import logging
from boto.exception import EC2ResponseError, BotoServerError

from brkt_cli import util
from brkt_cli.util import Deadline, BracketError
from brkt_cli.validation import ValidationError

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
    def register_image(self,
                       kernel_id,
                       block_device_map,
                       name=None,
                       description=None):
        pass

    @abc.abstractmethod
    def get_image(self, image_id, retry=False):
        pass

    @abc.abstractmethod
    def get_images(self, filters=None, owners=None):
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

    @abc.abstractmethod
    def get_default_vpc(self):
        pass

    @abc.abstractmethod
    def get_instance_attribute(self, instance_id, attribute, dry_run=False):
        pass

    @abc.abstractmethod
    def retry(self, function, error_code_regexp=None, timeout=None):
        pass


class BotoRetryExceptionChecker(util.RetryExceptionChecker):

    def __init__(self, error_code_regexp=None):
        self.error_code_regexp = error_code_regexp

    def is_expected(self, exception):
        if isinstance(exception, ssl.SSLError):
            # We've seen this in the field.
            return True
        if not isinstance(exception, BotoServerError):
            return False
        if exception.status == 503:
            # This can happen when the AWS request limit has been exceeded.
            return True
        if self.error_code_regexp:
            m = re.match(self.error_code_regexp, exception.error_code)
            return bool(m)
        return False


def retry_boto(function, error_code_regexp=None, timeout=10.0,
               initial_sleep_seconds=0.25):
    """ Retry an AWS API call.  Handle known intermittent errors and expected
    error codes.
    """
    return util.retry(
        function,
        exception_checker=BotoRetryExceptionChecker(error_code_regexp),
        timeout=timeout,
        initial_sleep_seconds=initial_sleep_seconds
    )


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
            default_tags=None,
            retry_timeout=10.0,
            retry_initial_sleep_seconds=0.25):
        super(AWSService, self).__init__(encryptor_session_id)

        self.default_tags = default_tags or {}
        self.retry_timeout = retry_timeout
        self.retry_initial_sleep_seconds = retry_initial_sleep_seconds

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

    def retry(self, function, error_code_regexp=None, timeout=None):
        """ Call the retry_boto function with this object's timeout and
        initial sleep time values.
        """
        timeout = timeout or self.retry_timeout
        return retry_boto(
            function,
            error_code_regexp,
            timeout=timeout,
            initial_sleep_seconds=self.retry_initial_sleep_seconds
        )

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
        log.debug(
            'run_instance: %s, security groups=%s, subnet=%s, '
            'type=%s',
            image_id, security_group_ids, subnet_id, instance_type
        )
        if user_data and log.isEnabledFor(logging.DEBUG):
            with tempfile.NamedTemporaryFile(
                prefix='user-data-',
                delete=False
            ) as f:
                log.debug('Writing instance user data to %s', f.name)
                f.write(user_data)

        try:
            run_instances = self.retry(self.conn.run_instances)
            reservation = run_instances(
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
            instance = reservation.instances[0]
            log.debug('Launched instance %s', instance.id)
            return instance
        except EC2ResponseError:
            log.debug('Failed to launch instance for %s', image_id)
            raise

    def get_instance(self, instance_id):
        get_only_instances = self.retry(
            self.conn.get_only_instances, r'InvalidInstanceID\.NotFound')
        instances = get_only_instances([instance_id])
        return _get_first_element(instances, 'InvalidInstanceID.NotFound')

    def create_tags(self, resource_id, name=None, description=None):
        tags = dict(self.default_tags)
        if name:
            tags['Name'] = name
        if description:
            tags['Description'] = description
        log.debug('Tagging %s with %s', resource_id, tags)
        create_tags = self.retry(self.conn.create_tags, r'.*\.NotFound')
        create_tags([resource_id], tags)

    def stop_instance(self, instance_id):
        log.debug('Stopping instance %s', instance_id)
        stop_instances = self.retry(self.conn.stop_instances)
        instances = stop_instances([instance_id])
        return instances[0]

    def terminate_instance(self, instance_id):
        log.debug('Terminating instance %s', instance_id)
        terminate_instances = self.retry(self.conn.terminate_instances)
        terminate_instances([instance_id])

    def get_volume(self, volume_id):
        get_all_volumes = self.retry(
            self.conn.get_all_volumes, r'InvalidVolume\.NotFound')
        volumes = get_all_volumes(volume_ids=[volume_id])
        return _get_first_element(volumes, 'InvalidVolume.NotFound')

    def get_volumes(self, tag_key=None, tag_value=None):
        filters = {}
        if tag_key and tag_value:
            filters['tag:%s' % tag_key] = tag_value

        get_all_volumes = self.retry(self.conn.get_all_volumes)
        return get_all_volumes(filters=filters)

    def get_snapshots(self, *snapshot_ids):
        get_all_snapshots = self.retry(
            self.conn.get_all_snapshots, r'InvalidSnapshot\.NotFound')
        return get_all_snapshots(snapshot_ids)

    def get_snapshot(self, snapshot_id):
        snapshots = self.get_snapshots(snapshot_id)
        return _get_first_element(snapshots, 'InvalidSnapshot.NotFound')

    def create_snapshot(self, volume_id, name=None, description=None):
        log.debug('Creating snapshot of %s', volume_id)
        create_snapshot = self.retry(self.conn.create_snapshot)
        snapshot = create_snapshot(volume_id, description)
        self.create_tags(snapshot.id, name=name)
        return snapshot

    def create_volume(self,
                      size,
                      zone,
                      snapshot=None,
                      volume_type=None,
                      encrypted=None):
        create_volume = self.retry(self.conn.create_volume)
        return create_volume(
            size,
            zone,
            snapshot=snapshot,
            volume_type=volume_type,
            encrypted=encrypted)

    def delete_volume(self, volume_id):
        log.debug('Deleting volume %s', volume_id)
        try:
            delete_volume = self.retry(
                self.conn.delete_volume, r'VolumeInUse')
            delete_volume(volume_id)
        except EC2ResponseError as e:
            if e.error_code != 'InvalidVolume.NotFound':
                raise
        return True

    def register_image(self,
                       kernel_id,
                       block_device_map,
                       name=None,
                       description=None):
        log.debug('Registering image.')
        register_image = self.retry(self.conn.register_image)
        return register_image(
            name=name,
            description=description,
            architecture='x86_64',
            kernel=kernel_id,
            root_device_name='/dev/sda1',
            virtualization_type='paravirtual'
        )

    def get_images(self, filters=None, owners=None):
        get_all_images = self.retry(self.conn.get_all_images)
        return get_all_images(filters=filters, owners=owners)

    def get_image(self, image_id, retry=False):
        get_image = self.conn.get_image
        if retry:
            get_image = self.retry(
                self.conn.get_image, r'InvalidAMIID\.NotFound')

        return get_image(image_id)

    def delete_snapshot(self, snapshot_id):
        delete_snapshot = self.retry(self.conn.delete_snapshot)
        return delete_snapshot(snapshot_id)

    def create_security_group(self, name, description, vpc_id=None):
        log.debug(
            'Creating security group: name=%s, description=%s',
            name, description
        )
        if vpc_id:
            log.debug('Using %s', vpc_id)

        create_security_group = self.retry(self.conn.create_security_group)
        return create_security_group(
            name, description, vpc_id=vpc_id
        )

    def get_security_group(self, sg_id, retry=True):
        get_all_security_groups = self.conn.get_all_security_groups
        if retry:
            get_all_security_groups = self.retry(
                self.conn.get_all_security_groups, r'InvalidGroup\.NotFound')

        groups = get_all_security_groups(group_ids=[sg_id])
        return _get_first_element(groups, 'InvalidGroup.NotFound')

    def add_security_group_rule(self, sg_id, **kwargs):
        kwargs['group_id'] = sg_id
        authorize_security_group = self.retry(
            self.conn.authorize_security_group)
        ok = authorize_security_group(**kwargs)
        if not ok:
            raise Exception('Unknown error while adding security group rule')

    def delete_security_group(self, sg_id):
        delete_security_group = self.retry(
            self.conn.delete_security_group,
            r'InvalidGroup\.InUse|DependencyViolation'
        )
        ok = delete_security_group(group_id=sg_id)
        if not ok:
            raise Exception('Unknown error while deleting security group')

    def get_key_pair(self, keyname):
        get_all_key_pairs = self.retry(self.conn.get_all_key_pairs)
        key_pairs = get_all_key_pairs(keynames=[keyname])
        return _get_first_element(key_pairs, 'InvalidKeyPair.NotFound')

    def get_console_output(self, instance_id):
        return self.conn.get_console_output(instance_id)

    def get_subnet(self, subnet_id):
        subnets = self.conn.get_all_subnets(subnet_ids=[subnet_id])
        return _get_first_element(subnets, 'InvalidSubnetID.NotFound')

    def create_image(self,
                     instance_id,
                     name,
                     description=None,
                     no_reboot=True,
                     block_device_mapping=None):
        timeout = float(60 * 60)  # One hour.
        create_image = self.retry(
            self.conn.create_image, r'InvalidParameterValue', timeout=timeout)
        return create_image(
            instance_id,
            name,
            description=description,
            no_reboot=no_reboot,
            block_device_mapping=block_device_mapping
        )

    def detach_volume(self, vol_id, instance_id=None, force=True):
        detach_volume = self.retry(self.conn.detach_volume)
        return detach_volume(
            vol_id, instance_id=instance_id, force=force)

    def attach_volume(self, vol_id, instance_id, device):
        attach_volume = self.retry(self.conn.attach_volume, r'VolumeInUse')
        return attach_volume(vol_id, instance_id, device)

    def get_default_vpc(self):
        get_all_vpcs = self.retry(self.conn.get_all_vpcs)
        vpcs = get_all_vpcs(filters={'is-default': 'true'})
        if len(vpcs) > 0:
            return vpcs[0]
        return None

    def get_instance_attribute(self, instance_id, attribute, dry_run=False):
        get_instance_attribute = self.retry(self.conn.get_instance_attribute)
        return get_instance_attribute(
            instance_id,
            attribute,
            dry_run=dry_run
        )


def validate_image_name(name):
    """ Verify that the name is a valid EC2 image name.  Return the name
        if it's valid.

    :raises ValidationError if the name is invalid
    """
    if not (name and 3 <= len(name) <= 128):
        raise ValidationError(
            'Image name must be between 3 and 128 characters long')

    m = re.match(r'[A-Za-z0-9()\[\] ./\-\'@_]+$', name)
    if not m:
        raise ValidationError(
            "Image name may only contain letters, numbers, spaces, "
            "and the following characters: ()[]./-'@_"
        )
    return name


def validate_tag_key(key):
    """ Verify that the key is a valid EC2 tag key.

    :return: the key if it's valid
    :raises ValidationError if the key is invalid
    """
    if len(key) > 127:
        raise ValidationError(
            'Tag key cannot be longer than 127 characters'
        )
    if key.startswith('aws:'):
        raise ValidationError(
            'Tag key cannot start with "aws:"'
        )
    return key


def validate_tag_value(value):
    """ Verify that the value is a valid EC2 tag value.

    :return: the value if it's valid
    :raises ValidationError if the value is invalid
    """
    if len(value) > 255:
        raise ValidationError(
            'Tag value cannot be longer than 255 characters'
        )
    if value.startswith('aws:'):
        raise ValidationError(
            'Tag value cannot start with "aws:"'
        )
    return value


class VolumeError(BracketError):
    pass


def wait_for_volume(aws_svc, volume_id, timeout=600.0, state='available'):
    """ Wait for the volume to be in the specified state.

    :return the Volume object
    :raise VolumeError if the timeout is exceeded
    """
    log.debug(
        'Waiting for %s, timeout=%.02f, state=%s',
        volume_id, timeout, state)

    deadline = Deadline(timeout)
    sleep_time = 0.5
    while not deadline.is_expired():
        volume = aws_svc.get_volume(volume_id)
        if volume.status == state:
            return volume
        util.sleep(sleep_time)
        sleep_time *= 2
    raise VolumeError(
        'Timed out waiting for %s to be in the %s state' %
        (volume_id, state)
    )
