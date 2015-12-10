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
from boto.ec2.keypair import KeyPair
from boto.ec2.securitygroup import SecurityGroup
from boto.exception import EC2ResponseError
from boto.vpc import Subnet

import brkt_cli
import logging
import os
import unittest
import uuid

from boto.ec2.blockdevicemapping import BlockDeviceType, BlockDeviceMapping
from boto.ec2.image import Image
from boto.ec2.instance import Instance, ConsoleOutput
from boto.ec2.snapshot import Snapshot
from boto.ec2.volume import Volume
from brkt_cli import (
    encrypt_ami,
    encryptor_service
)
from brkt_cli import aws_service

brkt_cli.log = logging.getLogger(__name__)

# Uncomment the next line to turn on logging when running unit tests.
# logging.basicConfig(level=logging.DEBUG)

CONSOLE_OUTPUT_TEXT = 'Starting up.\nAll systems go!\n'


def _new_id():
    return uuid.uuid4().hex[:6]


class DummyEncryptorService(encryptor_service.BaseEncryptorService):

    def __init__(self, hostname='test-host', port=8000):
        super(DummyEncryptorService, self).__init__(hostname, port)
        self.is_up = False
        self.progress = 0

    def is_encryptor_up(self):
        """ The first call returns False.  Subsequent calls return True.
        """
        ret_val = self.is_up
        if not self.is_up:
            self.is_up = True
        return ret_val

    def get_status(self):
        """ Return progress in increments of 20% for each call.
        """
        ret_val = {
            'state': encryptor_service.ENCRYPT_ENCRYPTING,
            'percent_complete': self.progress,
        }
        if self.progress < 100:
            self.progress += 20
        else:
            ret_val['state'] = 'finished'
        return ret_val


class DummyAWSService(aws_service.BaseAWSService):

    def __init__(self):
        super(DummyAWSService, self).__init__(_new_id())
        self.instances = {}
        self.volumes = {}
        self.snapshots = {}
        self.transition_to_running = {}
        self.transition_to_completed = {}
        self.images = {}
        self.console_output_text = CONSOLE_OUTPUT_TEXT
        self.tagged_volumes = []
        self.subnets = {}
        self.security_groups = {}

        # Callbacks.
        self.run_instance_callback = None
        self.create_security_group_callback = None

    def run_instance(self,
                     image_id,
                     security_group_ids=None,
                     instance_type='m3.medium',
                     user_data="",
                     block_device_map=None,
                     subnet_id=None):
        instance = Instance()
        instance.id = _new_id()
        instance.root_device_name = '/dev/sda1'
        instance._state.code = 0
        instance._state.name = 'pending'

        # Create volumes based on block device data from the image.
        image = self.get_image(image_id)
        instance_bdm = BlockDeviceMapping()
        for device_name, bdm in image.block_device_mapping.iteritems():
            # Create a new volume and attach it to the instance.
            volume = Volume()
            volume.size = 8
            volume.id = _new_id()
            self.volumes[volume.id] = volume

            bdt = BlockDeviceType(volume_id=volume.id, size=8)
            instance_bdm[device_name] = bdt

        instance.block_device_mapping = instance_bdm
        self.instances[instance.id] = instance

        if self.run_instance_callback:
            self.run_instance_callback(security_group_ids, subnet_id)

        return instance

    def get_instance(self, instance_id):
        instance = self.instances[instance_id]

        # Transition from pending to running on subsequent calls.
        if instance.state == 'pending':
            if self.transition_to_running.get(instance_id):
                # We returned pending last time.  Transition to running.
                instance._state.code = 16
                instance._state.name = 'running'
                del(self.transition_to_running[instance_id])
            else:
                # Transition to running next time.
                self.transition_to_running[instance_id] = True
        return instance

    def create_tags(self, resource_id, name=None, description=None):
        pass

    def stop_instance(self, instance_id):
        instance = self.instances[instance_id]
        instance._state.code = 80
        instance._state.name = 'stopped'
        return instance

    def terminate_instance(self, instance_id):
        instance = self.instances[instance_id]
        instance._state.code = 48
        instance._state.name = 'terminated'
        return instance

    def get_volume(self, volume_id):
        return self.volumes.get(volume_id)

    def get_volumes(self, tag_key=None, tag_value=None):
        if tag_key and tag_value:
            return self.tagged_volumes
        else:
            return []

    def get_snapshots(self, *snapshot_ids):
        return [self.get_snapshot(id) for id in snapshot_ids]

    def get_snapshot(self, snapshot_id):
        snapshot = self.snapshots[snapshot_id]

        # Transition from pending to completed on subsequent calls.
        if snapshot.status == 'pending':
            if self.transition_to_completed.get(snapshot_id):
                # We returned pending last time.  Transition to completed.
                snapshot.status = 'completed'
                del(self.transition_to_completed[snapshot_id])
            else:
                # Transition to completed next time.
                self.transition_to_completed[snapshot_id] = True
        return snapshot

    def create_snapshot(self, volume_id, name=None, description=None):
        snapshot = Snapshot()
        snapshot.id = _new_id()
        snapshot.status = 'pending'
        self.snapshots[snapshot.id] = snapshot
        return snapshot

    def delete_volume(self, volume_id):
        del(self.volumes[volume_id])

    def validate_guest_ami(self, ami_id):
        pass

    def validate_encryptor_ami(self, ami_id):
        pass

    def register_image(self,
                       kernel_id,
                       block_device_map,
                       name=None,
                       description=None):
        image = Image()
        image.id = _new_id()
        image.block_device_mapping = block_device_map
        image.state = 'available'
        image.name = name
        image.description = description
        self.images[image.id] = image
        return image.id

    def wait_for_image(self, image_id):
        pass

    def get_image(self, image_id):
        return self.images[image_id]

    def delete_snapshot(self, snapshot_id):
        del(self.snapshots[snapshot_id])

    def create_security_group(self, name, description, vpc_id=None):
        if self.create_security_group_callback:
            self.create_security_group_callback(vpc_id)
        sg = SecurityGroup()
        sg.id = 'sg-%s' % _new_id()
        sg.vpc_id = vpc_id
        self.security_groups[sg.id] = sg
        return sg

    def get_security_group(self, sg_id, retry=False):
        return self.security_groups[sg_id]

    def add_security_group_rule(self, sg_id, **kwargs):
        pass

    def delete_security_group(self, sg_id):
        pass

    def get_key_pair(self, keyname):
        kp = KeyPair()
        kp.name = keyname
        return kp

    def get_console_output(self, instance_id):
        console_output = ConsoleOutput()
        console_output.output = self.console_output_text
        return console_output

    def get_subnet(self, subnet_id):
        return self.subnets[subnet_id]


class TestSnapshotProgress(unittest.TestCase):

    def test_snapshot_progress_text(self):
        # One snapshot.
        s1 = Snapshot()
        s1.id = '1'
        s1.progress = u'25%'
        self.assertEqual(
            '1: 25%',
            encrypt_ami._get_snapshot_progress_text([s1])
        )

        # Two snapshots.
        s2 = Snapshot()
        s2.id = '2'
        s2.progress = u'50%'

        self.assertEqual(
            '1: 25%, 2: 50%',
            encrypt_ami._get_snapshot_progress_text([s1, s2])
        )


class TestEncryptedImageName(unittest.TestCase):

    def test_encrypted_image_suffix(self):
        """ Test that generated suffixes are unique.
        """
        s1 = encrypt_ami.get_encrypted_suffix()
        s2 = encrypt_ami.get_encrypted_suffix()
        self.assertNotEqual(s1, s2)

    def test_append_suffix(self):
        """ Test that we append the suffix and truncate the original name.
        """
        name = 'Boogie nights are always the best in town'
        suffix = ' (except Tuesday)'
        encrypted_name = encrypt_ami.append_suffix(
            name, suffix, max_length=128)
        self.assertTrue(encrypted_name.startswith(name))
        self.assertTrue(encrypted_name.endswith(suffix))

        # Make sure we truncate the original name when it's too long.
        name += ('X' * 100)
        encrypted_name = encrypt_ami.append_suffix(
            name, suffix, max_length=128)
        self.assertEqual(128, len(encrypted_name))
        self.assertTrue(encrypted_name.startswith('Boogie nights'))

    def test_name_validation(self):
        name = 'Test123 ()[]./-\'@_'
        self.assertEquals(name, aws_service.validate_image_name(name))
        with self.assertRaises(aws_service.ImageNameError):
            aws_service.validate_image_name(None)
        with self.assertRaises(aws_service.ImageNameError):
            aws_service.validate_image_name('ab')
        with self.assertRaises(aws_service.ImageNameError):
            aws_service.validate_image_name('a' * 129)
        for c in '?!#$%^&*~`{}\|"<>':
            with self.assertRaises(aws_service.ImageNameError):
                aws_service.validate_image_name('test' + c)


def _build_aws_service():
    aws_svc = DummyAWSService()

    # Encryptor image
    bdm = BlockDeviceMapping()
    for n in (1, 2, 3, 5):
        device_name = '/dev/sda%d' % n
        bdm[device_name] = BlockDeviceType()
    id = aws_svc.register_image(
        kernel_id=None, name='Encryptor image', block_device_map=bdm)
    encryptor_image = aws_svc.get_image(id)

    # Guest image
    bdm = BlockDeviceMapping()
    bdm['/dev/sda1'] = BlockDeviceType()
    id = aws_svc.register_image(
        kernel_id=None, name='Guest image', block_device_map=bdm)
    guest_image = aws_svc.get_image(id)

    return aws_svc, encryptor_image, guest_image


class TestRun(unittest.TestCase):

    def test_smoke(self):
        """ Run the entire process and test that nothing obvious is broken.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        encrypt_ami.SLEEP_ENABLED = False
        encrypted_ami_id = encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            brkt_env=None,
            encryptor_ami=encryptor_image.id
        )
        self.assertIsNotNone(encrypted_ami_id)

    def test_encryption_error_console_output_available(self):
        """ Test that when an encryption failure occurs, we write the
        console log to a temp file.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        encrypt_ami.SLEEP_ENABLED = False
        try:
            encrypt_ami.encrypt(
                aws_svc=aws_svc,
                enc_svc_cls=FailedEncryptionService,
                image_id=guest_image.id,
                brkt_env=None,
                encryptor_ami=encryptor_image.id
            )
            self.fail('Encryption should have failed')
        except encrypt_ami.EncryptionError as e:
            with open(e.console_output_file.name) as f:
                content = f.read()
                self.assertEquals(CONSOLE_OUTPUT_TEXT, content)
            os.remove(e.console_output_file.name)

    def test_encryption_error_console_output_not_available(self):
        """ Test that we handle the case when encryption fails and console
        output is not available.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        encrypt_ami.SLEEP_ENABLED = False
        aws_svc.console_output_text = None

        try:
            encrypt_ami.encrypt(
                aws_svc=aws_svc,
                enc_svc_cls=FailedEncryptionService,
                image_id=guest_image.id,
                brkt_env=None,
                encryptor_ami=encryptor_image.id
            )
            self.fail('Encryption should have failed')
        except encrypt_ami.EncryptionError as e:
            self.assertIsNone(e.console_output_file)

    def test_delete_orphaned_volumes(self):
        """ Test that we clean up instance volumes that are orphaned by AWS.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        encrypt_ami.SLEEP_ENABLED = False

        # Simulate a tagged orphaned volume.
        volume = Volume()
        volume.id = _new_id()
        aws_svc.volumes[volume.id] = volume
        aws_svc.tagged_volumes.append(volume)

        # Verify that lookup succeeds before encrypt().
        self.assertEqual(volume, aws_svc.get_volume(volume.id))
        self.assertEqual(
            [volume],
            aws_svc.get_volumes(
                tag_key=encrypt_ami.TAG_ENCRYPTOR_SESSION_ID, tag_value='123')
        )

        encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            brkt_env=None,
            encryptor_ami=encryptor_image.id
        )

        # Verify that the volume was deleted.
        self.assertIsNone(aws_svc.get_volume(volume.id))

    def test_encrypted_ami_name(self):
        """ Test that the name is set on the encrypted AMI when specified.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        encrypt_ami.SLEEP_ENABLED = False

        name = 'Am I an AMI?'
        image_id = encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            encryptor_ami=encryptor_image.id,
            brkt_env=None,
            encrypted_ami_name=name
        )
        ami = aws_svc.get_image(image_id)
        self.assertEqual(name, ami.name)

    def test_subnet_with_security_groups(self):
        """ Test that the subnet and security groups are passed to the
        calls to AWSService.run_instance().
        """
        self.call_count = 0

        def run_instance_callback(security_group_ids, subnet_id):
            self.call_count += 1
            self.assertEqual('subnet-1', subnet_id)
            if self.call_count == 1:
                # Snapshotter.
                self.assertIsNone(security_group_ids)
            elif self.call_count == 2:
                # Encryptor.
                self.assertEqual(['sg-1', 'sg-2'], security_group_ids)
            else:
                self.fail('Unexpected number of calls to run_instance()')

        aws_svc, encryptor_image, guest_image = _build_aws_service()
        aws_svc.run_instance_callback = run_instance_callback
        encrypt_ami.SLEEP_ENABLED = False
        encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            encryptor_ami=encryptor_image.id,
            brkt_env=None,
            subnet_id='subnet-1',
            security_group_ids=['sg-1', 'sg-2']
        )

    def test_subnet_without_security_groups(self):
        """ Test that we create the temporary security group in the subnet
        that the user specified.
        """
        self.security_group_was_created = False

        def create_security_group_callback(vpc_id):
            self.security_group_was_created = True
            self.assertEqual('vpc-1', vpc_id)

        aws_svc, encryptor_image, guest_image = _build_aws_service()
        aws_svc.create_security_group_callback = \
            create_security_group_callback
        encrypt_ami.SLEEP_ENABLED = False

        subnet = Subnet()
        subnet.id = 'subnet-1'
        subnet.vpc_id = 'vpc-1'
        aws_svc.subnets = {subnet.id: subnet}

        encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            brkt_env=None,
            encryptor_ami=encryptor_image.id,
            subnet_id='subnet-1'
        )
        self.assertTrue(self.security_group_was_created)


class ExpiredDeadline(object):
    def is_expired(self):
        return True


class FailedEncryptionService(encryptor_service.BaseEncryptorService):
    def is_encryptor_up(self):
        return True

    def get_status(self):
        return {
            'state': encryptor_service.ENCRYPT_FAILED,
            'percent_complete': 50,
        }


class TestEncryptionService(unittest.TestCase):

    def setUp(self):
        encrypt_ami.SLEEP_ENABLED = False

    def test_service_fails_to_come_up(self):
        svc = DummyEncryptorService()
        deadline = ExpiredDeadline()
        with self.assertRaisesRegexp(Exception, 'Unable to contact'):
            encrypt_ami.wait_for_encryptor_up(svc, deadline)

    def test_encryption_fails(self):
        svc = FailedEncryptionService('192.168.1.1')
        with self.assertRaisesRegexp(
                encrypt_ami.EncryptionError, 'Encryption failed'):
            encrypt_ami.wait_for_encryption(svc)

    def test_unsupported_guest(self):
        class UnsupportedGuestService(encryptor_service.BaseEncryptorService):
            def __init__(self):
                super(UnsupportedGuestService, self).__init__('localhost', 80)

            def is_encryptor_up(self):
                return True

            def get_status(self):
                return {
                    'state': encryptor_service.ENCRYPT_FAILED,
                    'failure_code': encryptor_service.FAILURE_CODE_UNSUPPORTED_GUEST,
                    'percent_complete': 0
                }

        with self.assertRaises(encrypt_ami.UnsupportedGuestError):
            encrypt_ami.wait_for_encryption(UnsupportedGuestService())

    def test_encryption_progress_timeout(self):
        class NoProgressService(encryptor_service.BaseEncryptorService):
            def __init__(self):
                super(NoProgressService, self).__init__('localhost', 80)

            def is_encryptor_up(self):
                return True

            def get_status(self):
                return {
                    'state': encryptor_service.ENCRYPT_ENCRYPTING,
                    'percent_complete': 0
                }

        with self.assertRaises(encrypt_ami.EncryptionError):
            encrypt_ami.wait_for_encryption(
                NoProgressService(),
                progress_timeout=0.100
            )


class TestRetry(unittest.TestCase):

    def setUp(self):
        self.num_calls = 0

    @aws_service.retry_boto(
        error_code_regexp='InvalidInstanceID.*',
        initial_sleep_seconds=0,
        max_retries=5
    )
    def _fail_for_n_calls(self, n, error_code='InvalidInstanceID.NotFound'):
        self.num_calls += 1
        if self.num_calls <= n:
            e = EC2ResponseError(None, None)
            e.error_code = error_code
            raise e

    def test_five_failures(self):
        self._fail_for_n_calls(5)

    def test_six_failures(self):
        with self.assertRaises(EC2ResponseError):
            self._fail_for_n_calls(6)

    def test_regexp_does_not_match(self):
        with self.assertRaises(EC2ResponseError):
            self._fail_for_n_calls(1, error_code='InvalidVolumeID.NotFound')


class TestInstance(unittest.TestCase):

    def setUp(self):
        encrypt_ami.SLEEP_ENABLED = False

    def test_wait_for_instance_terminated(self):
        """ Test waiting for an instance to terminate.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        instance = aws_svc.run_instance(guest_image.id)
        aws_svc.terminate_instance(instance.id)
        result = encrypt_ami.wait_for_instance(
            aws_svc, instance.id, state='terminated', timeout=100)
        self.assertEquals(instance, result)

    def test_instance_error_state(self):
        """ Test that we raise an exception when an instance goes into
            an error state while we're waiting for it.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        instance = aws_svc.run_instance(guest_image.id)
        instance._state.name = 'error'
        try:
            encrypt_ami.wait_for_instance(aws_svc, instance.id, timeout=100)
        except encrypt_ami.InstanceError as e:
            self.assertTrue('error state' in e.message)

    def test_wait_for_instance_unexpectedly_terminated(self):
        """ Test that we handle the edge case when an instance is
            terminated on startup.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        instance = aws_svc.run_instance(guest_image.id)
        aws_svc.terminate_instance(instance.id)
        try:
            encrypt_ami.wait_for_instance(
                aws_svc, instance.id, state='running', timeout=100)
        except encrypt_ami.InstanceError as e:
            self.assertTrue('unexpectedly terminated' in e.message)


class TestEncryptCommand(unittest.TestCase):

    def test_validate_subnet_and_security_groups(self):
        aws_svc, encryptor_image, guest_image = _build_aws_service()

        # Subnet, no security groups.
        subnet = Subnet()
        subnet.id = 'subnet-1'
        subnet.vpc_id = 'vpc-1'
        aws_svc.subnets[subnet.id] = subnet

        self.assertTrue(brkt_cli._validate_subnet_and_security_groups(
            aws_svc, subnet_id=subnet.id))

        # Security groups, no subnet.
        sg1 = aws_svc.create_security_group('test1', 'test', vpc_id='vpc-1')
        sg2 = aws_svc.create_security_group('test2', 'test', vpc_id='vpc-1')
        self.assertTrue(brkt_cli._validate_subnet_and_security_groups(
            aws_svc, security_group_ids=[sg1.id, sg2.id]
        ))

        # Security groups in different VPCs.
        sg3 = aws_svc.create_security_group('test3', 'test', vpc_id='vpc-2')
        self.assertFalse(brkt_cli._validate_subnet_and_security_groups(
            aws_svc, security_group_ids=[sg1.id, sg2.id, sg3.id]
        ))

        # Security group and subnet in different VPCs.
        self.assertFalse(brkt_cli._validate_subnet_and_security_groups(
            aws_svc, subnet_id=subnet.id, security_group_ids=[sg3.id]
        ))
