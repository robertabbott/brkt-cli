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
import importlib
import json
import tempfile

import yaml
from boto.ec2.keypair import KeyPair
from boto.ec2.securitygroup import SecurityGroup
from boto.exception import EC2ResponseError
from boto.regioninfo import RegionInfo
from boto.vpc import Subnet, VPC

import brkt_cli
import brkt_cli.util
from brkt_cli.proxy import Proxy
from brkt_cli.user_data import (
    UserDataContainer,
    BRKT_CONFIG_CONTENT_TYPE,
    BRKT_FILES_CONTENT_TYPE
)
from brkt_cli.validation import ValidationError
import email
import inspect
import logging
import os
import unittest
import uuid
import zlib

from boto.ec2.blockdevicemapping import BlockDeviceType, BlockDeviceMapping
from boto.ec2.image import Image
from boto.ec2.instance import Instance, ConsoleOutput
from boto.ec2.snapshot import Snapshot
from boto.ec2.volume import Volume
from brkt_cli import (
    encrypt_ami,
    encryptor_service,
    update_ami
)
from brkt_cli import aws_service, proxy, user_data

brkt_cli.log = logging.getLogger(__name__)

# Uncomment the next line to turn on logging when running unit tests.
# logging.basicConfig(level=logging.DEBUG)

CONSOLE_OUTPUT_TEXT = 'Starting up.\nAll systems go!\n'


def _new_id():
    return uuid.uuid4().hex[:6]


class TestException(Exception):
    pass


class DummyEncryptorService(encryptor_service.BaseEncryptorService):

    def __init__(self, hostnames=['test-host'], port=8000):
        super(DummyEncryptorService, self).__init__(hostnames, port)
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


class RunInstanceArgs(object):
    def __init__(self):
        self.image_id = None
        self.instance_type = None
        self.ebs_optimized = None
        self.security_group_ids = None
        self.subnet_id = None
        self.user_data = None


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
        self.regions = [RegionInfo(name='us-west-2')]
        self.volumes = {}

        vpc = VPC()
        vpc.id = 'vpc-' + _new_id()
        vpc.is_default = True
        self.default_vpc = vpc

        # Callbacks.
        self.run_instance_callback = None
        self.create_security_group_callback = None
        self.get_instance_callback = None
        self.terminate_instance_callback = None
        self.create_snapshot_callback = None
        self.get_snapshot_callback = None
        self.delete_snapshot_callback = None

    def get_regions(self):
        return self.regions

    def connect(self, region, key_name=None):
        pass

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
            args = RunInstanceArgs()
            args.image_id = image_id
            args.instance_type = instance_type
            args.ebs_optimized = ebs_optimized
            args.security_group_ids = security_group_ids
            args.subnet_id = subnet_id
            args.user_data = user_data
            self.run_instance_callback(args)

        return instance

    def get_instance(self, instance_id):
        instance = self.instances[instance_id]
        if self.get_instance_callback:
            self.get_instance_callback(instance)

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
        if self.terminate_instance_callback:
            self.terminate_instance_callback(instance)

        instance._state.code = 48
        instance._state.name = 'terminated'
        return instance

    def get_volume(self, volume_id):
        return self.volumes[volume_id]

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

        if self.get_snapshot_callback:
            self.get_snapshot_callback(snapshot)

        return snapshot

    def create_snapshot(self, volume_id, name=None, description=None):
        snapshot = Snapshot()
        snapshot.id = _new_id()
        snapshot.status = 'pending'
        self.snapshots[snapshot.id] = snapshot

        if self.create_snapshot_callback:
            self.create_snapshot_callback(volume_id, snapshot)

        return snapshot

    def attach_volume(self, vol_id, instance_id, device):
        instance = self.get_instance(instance_id)
        bdt = BlockDeviceType(volume_id=vol_id, size=8)
        instance.block_device_mapping[device] = bdt
        return True

    def create_image(self, instance_id, name, **kwargs):
        image = Image()
        image.id = instance_id
        image.block_device_mapping = kwargs['block_device_mapping']
        image.state = 'available'
        image.name = name
        image.description = 'This is a test'
        image.virtualization_type = 'paravirtual'
        image.root_device_name = '/dev/sda1'
        i = self.get_instance(instance_id)
        rdn = image.root_device_name
        # create_image creates this implicitly
        image.block_device_mapping[rdn] = i.block_device_mapping[rdn]
        self.images[image.id] = image
        return image.id

    def create_volume(self, size, zone, **kwargs):
        volume = Volume()
        volume.id = 'vol-' + _new_id()
        volume.size = size
        volume.zone = zone
        volume.status = 'available'
        self.volumes[volume.id] = volume
        return volume

    def detach_volume(self, vol_id, **kwargs):
        pass

    def delete_volume(self, volume_id):
        del(self.volumes[volume_id])

    def register_image(self,
                       kernel_id,
                       block_device_map,
                       name=None,
                       description=None):
        image = Image()
        image.id = 'ami-' + _new_id()
        image.block_device_mapping = block_device_map
        image.state = 'available'
        image.name = name
        image.description = description
        image.virtualization_type = 'paravirtual'
        image.root_device_type = 'ebs'
        image.hypervisor = 'xen'
        self.images[image.id] = image
        return image.id

    def wait_for_image(self, image_id):
        pass

    def get_image(self, image_id, retry=False):
        image = self.images.get(image_id)
        if image:
            return image
        else:
            e = EC2ResponseError(None, None)
            e.error_code = 'InvalidAMIID.NotFound'
            raise e

    def get_images(self, filters=None, owners=None):
        # Only filtering by name is currently supported.
        name = filters.get('name', None)
        images = []
        if name:
            for i in self.images.values():
                if i.name == name:
                    images.append(i)
        return images

    def delete_snapshot(self, snapshot_id):
        del(self.snapshots[snapshot_id])
        if self.delete_snapshot_callback:
            self.delete_snapshot_callback(snapshot_id)

    def create_security_group(self, name, description, vpc_id=None):
        if self.create_security_group_callback:
            self.create_security_group_callback(vpc_id)
        sg = SecurityGroup()
        sg.id = 'sg-%s' % _new_id()
        sg.vpc_id = vpc_id or self.default_vpc.id
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

    def get_default_vpc(self):
        return self.default_vpc

    def get_instance_attribute(self, instance_id, attribute, dry_run=False):
        if (attribute == "sriovNetSupport"):
            return dict()
        return None


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
        encrypted_name = brkt_cli.util.append_suffix(
            name, suffix, max_length=128)
        self.assertTrue(encrypted_name.startswith(name))
        self.assertTrue(encrypted_name.endswith(suffix))

        # Make sure we truncate the original name when it's too long.
        name += ('X' * 100)
        encrypted_name = brkt_cli.util.append_suffix(
            name, suffix, max_length=128)
        self.assertEqual(128, len(encrypted_name))
        self.assertTrue(encrypted_name.startswith('Boogie nights'))

    def test_name_validation(self):
        name = 'Test123 ()[]./-\'@_'
        self.assertEquals(name, aws_service.validate_image_name(name))
        with self.assertRaises(ValidationError):
            aws_service.validate_image_name(None)
        with self.assertRaises(ValidationError):
            aws_service.validate_image_name('ab')
        with self.assertRaises(ValidationError):
            aws_service.validate_image_name('a' * 129)
        for c in '?!#$%^&*~`{}\|"<>':
            with self.assertRaises(ValidationError):
                aws_service.validate_image_name('test' + c)


def _build_aws_service():
    aws_svc = DummyAWSService()

    # Encryptor image
    bdm = BlockDeviceMapping()
    for n in (1, 2, 3, 5):
        device_name = '/dev/sda%d' % n
        bdm[device_name] = BlockDeviceType()
    id = aws_svc.register_image(
        kernel_id=None, name='brkt-avatar', block_device_map=bdm)
    encryptor_image = aws_svc.get_image(id)

    # Guest image
    bdm = BlockDeviceMapping()
    bdm['/dev/sda1'] = BlockDeviceType()
    id = aws_svc.register_image(
        kernel_id=None, name='Guest image', block_device_map=bdm)
    guest_image = aws_svc.get_image(id)

    return aws_svc, encryptor_image, guest_image


class TestRunEncryption(unittest.TestCase):

    def setUp(self):
        brkt_cli.util.SLEEP_ENABLED = False

    def test_smoke(self):
        """ Run the entire process and test that nothing obvious is broken.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
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
        try:
            encrypt_ami.encrypt(
                aws_svc=aws_svc,
                enc_svc_cls=FailedEncryptionService,
                image_id=guest_image.id,
                brkt_env=None,
                encryptor_ami=encryptor_image.id
            )
            self.fail('Encryption should have failed')
        except encryptor_service.EncryptionError as e:
            with open(e.console_output_file.name) as f:
                content = f.read()
                self.assertEquals(CONSOLE_OUTPUT_TEXT, content)
            os.remove(e.console_output_file.name)

    def test_encryption_error_console_output_not_available(self):
        """ Test that we handle the case when encryption fails and console
        output is not available.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
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
        except encryptor_service.EncryptionError as e:
            self.assertIsNone(e.console_output_file)

    def test_delete_orphaned_volumes(self):
        """ Test that we clean up instance volumes that are orphaned by AWS.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()

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
        self.assertIsNone(aws_svc.volumes.get(volume.id, None))

    def test_encrypted_ami_name(self):
        """ Test that the name is set on the encrypted AMI when specified.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()

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

        def run_instance_callback(args):
            self.call_count += 1
            self.assertEqual('subnet-1', args.subnet_id)
            if self.call_count == 1:
                # Snapshotter.
                self.assertIsNone(args.security_group_ids)
            elif self.call_count == 2:
                # Encryptor.
                self.assertEqual(['sg-1', 'sg-2'], args.security_group_ids)
            else:
                self.fail('Unexpected number of calls to run_instance()')

        aws_svc, encryptor_image, guest_image = _build_aws_service()
        aws_svc.run_instance_callback = run_instance_callback
        encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            encryptor_ami=encryptor_image.id,
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

        subnet = Subnet()
        subnet.id = 'subnet-1'
        subnet.vpc_id = 'vpc-1'
        aws_svc.subnets = {subnet.id: subnet}

        encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            encryptor_ami=encryptor_image.id,
            subnet_id='subnet-1'
        )
        self.assertTrue(self.security_group_was_created)

    def test_instance_type(self):
        """ Test that we launch the guest as m3.medium and the encryptor
        as c3.xlarge.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()

        def run_instance_callback(args):
            if args.image_id == guest_image.id:
                self.assertEqual('m3.medium', args.instance_type)
                self.assertFalse(args.ebs_optimized)
            elif args.image_id == encryptor_image.id:
                self.assertEqual('c3.xlarge', args.instance_type)
                self.assertTrue(args.ebs_optimized)
            else:
                self.fail('Unexpected image id: ' + args.image_id)

        aws_svc.run_instance_callback = run_instance_callback
        encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            encryptor_ami=encryptor_image.id
        )

    def test_guest_instance_type(self):
        """ Test that we use the specified instance type to launch the guest
        instance.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()

        def run_instance_callback(args):
            if args.image_id == guest_image.id:
                self.assertEqual('t2.micro', args.instance_type)

        aws_svc.run_instance_callback = run_instance_callback
        encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            encryptor_ami=encryptor_image.id,
            guest_instance_type='t2.micro'
        )

    def test_terminate_guest(self):
        """ Test that we terminate the guest instance if an exception is
        raised while waiting for it to come up.
        """
        self.terminate_instance_called = False
        self.instance_id = None

        def get_instance_callback(instance):
            self.instance_id = instance.id
            raise TestException('Test')

        def terminate_instance_callback(instance):
            self.terminate_instance_called = True
            self.assertEqual(self.instance_id, instance.id)

        aws_svc, encryptor_image, guest_image = _build_aws_service()
        aws_svc.get_instance_callback = get_instance_callback
        aws_svc.terminate_instance_callback = terminate_instance_callback

        try:
            encrypt_ami.encrypt(
                aws_svc=aws_svc,
                enc_svc_cls=DummyEncryptorService,
                image_id=guest_image.id,
                encryptor_ami=encryptor_image.id
            )
        except TestException:
            pass

        self.assertTrue(self.terminate_instance_called)

    def test_register_ami_hvm(self):
        """ Test the new (non-legacy) code path in register_ami().
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        encryptor_instance = aws_svc.run_instance(encryptor_image.id)
        guest_instance = aws_svc.run_instance(guest_image.id)
        mv_bdm = encryptor_instance.block_device_mapping
        mv_root_volume_id = mv_bdm['/dev/sda1'].volume_id
        encrypt_ami.register_ami(
            aws_svc,
            encryptor_instance,
            encryptor_image,
            'Name',
            'Description',
            legacy=False,
            guest_instance=guest_instance,
            mv_root_id=mv_root_volume_id
        )

    def test_clean_up_root_snapshot(self):
        """ Test that we clean up the root snapshot if an exception is
        raised while waiting for it to complete.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        guest_instance = aws_svc.run_instance(guest_image.id)
        self.snapshot = None
        self.snapshot_was_deleted = False

        def get_snapshot_callback(snapshot):
            """ Simulate an exception being raised while waiting for the
            snapshot to complete.
            """
            raise TestException()

        def create_snapshot_callback(volume_id, snapshot):
            self.snapshot = snapshot

        def delete_snapshot_callback(snapshot_id):
            self.assertEqual(self.snapshot.id, snapshot_id)
            self.snapshot_was_deleted = True

        aws_svc.get_snapshot_callback = get_snapshot_callback
        aws_svc.create_snapshot_callback = create_snapshot_callback
        aws_svc.delete_snapshot_callback = delete_snapshot_callback

        with self.assertRaises(TestException):
            encrypt_ami._snapshot_root_volume(
                aws_svc, guest_instance, guest_image.id)
        self.assertTrue(self.snapshot_was_deleted)


class TestBrktEnv(unittest.TestCase):

    def setUp(self):
        brkt_cli.util.SLEEP_ENABLED = False

    def _get_brkt_config_from_mime(self, compressed_mime_data):
        """Look for a 'brkt-config' part in the multi-part MIME input"""
        data = zlib.decompress(compressed_mime_data, 16 + zlib.MAX_WBITS)
        msg = email.message_from_string(data)
        for part in msg.walk():
            if part.get_content_type() == BRKT_CONFIG_CONTENT_TYPE:
                return part.get_payload(decode=True)
        self.assertTrue(False, 'Did not find brkt-config part in userdata')

    def test_brkt_env_encrypt(self):
        """ Test that we parse the brkt_env value and pass the correct
        values to user_data when launching the encryptor instance.
        """

        api_host_port = 'api.example.com:777'
        hsmproxy_host_port = 'hsmproxy.example.com:888'
        aws_svc, encryptor_image, guest_image = _build_aws_service()

        def run_instance_callback(args):
            if args.image_id == encryptor_image.id:
                brkt_config = self._get_brkt_config_from_mime(args.user_data)
                d = json.loads(brkt_config)
                self.assertEquals(
                    api_host_port,
                    d['brkt']['api_host']
                )
                self.assertEquals(
                    hsmproxy_host_port,
                    d['brkt']['hsmproxy_host']
                )

        brkt_env = brkt_cli._parse_brkt_env(
            api_host_port + ',' + hsmproxy_host_port)
        aws_svc.run_instance_callback = run_instance_callback
        encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            brkt_env=brkt_env,
            encryptor_ami=encryptor_image.id
        )

    def test_brkt_env_update(self):
        """ Test that the Bracket environment is passed through to metavisor
        user data.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        encrypted_ami_id = encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            encryptor_ami=encryptor_image.id
        )

        api_host_port = 'api.example.com:777'
        hsmproxy_host_port = 'hsmproxy.example.com:888'
        brkt_env = brkt_cli._parse_brkt_env(
            api_host_port + ',' + hsmproxy_host_port)

        def run_instance_callback(args):
            if args.image_id == encryptor_image.id:
                brkt_config = self._get_brkt_config_from_mime(args.user_data)
                d = json.loads(brkt_config)
                self.assertEquals(
                    api_host_port,
                    d['brkt']['api_host']
                )
                self.assertEquals(
                    hsmproxy_host_port,
                    d['brkt']['hsmproxy_host']
                )
                self.assertEquals(
                    'updater',
                    d['brkt']['solo_mode']
                )

        aws_svc.run_instance_callback = run_instance_callback
        update_ami(
            aws_svc, encrypted_ami_id, encryptor_image.id,
            'Test updated AMI',
            enc_svc_class=DummyEncryptorService,
            brkt_env=brkt_env
        )


class TestRunUpdate(unittest.TestCase):

    def setUp(self):
        encrypt_ami.SLEEP_ENABLED = False

    def test_subnet_and_security_groups(self):
        """ Test that the subnet and security group ids are passed through
        to run_instance().
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        encrypted_ami_id = encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            brkt_env=None,
            encryptor_ami=encryptor_image.id
        )

        self.call_count = 0

        def run_instance_callback(args):
            self.call_count += 1
            self.assertEqual('subnet-1', args.subnet_id)
            self.assertEqual(['sg-1', 'sg-2'], args.security_group_ids)

        aws_svc.run_instance_callback = run_instance_callback
        ami_id = update_ami(
            aws_svc, encrypted_ami_id, encryptor_image.id,
            'Test updated AMI',
            subnet_id='subnet-1', security_group_ids=['sg-1', 'sg-2'],
            enc_svc_class=DummyEncryptorService
        )

        self.assertEqual(2, self.call_count)
        self.assertIsNotNone(ami_id)

    def test_guest_instance_type(self):
        """ Test that the guest instance type is passed through
        to run_instance().
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        encrypted_ami_id = encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            brkt_env=None,
            encryptor_ami=encryptor_image.id
        )

        def run_instance_callback(args):
            if args.image_id == encrypted_ami_id:
                self.assertEqual('t2.micro', args.instance_type)
            elif args.image_id == encryptor_image.id:
                self.assertEqual('c3.large', args.instance_type)
            else:
                self.fail('Unexpected image: ' + args.image_id)

        aws_svc.run_instance_callback = run_instance_callback
        update_ami(
            aws_svc, encrypted_ami_id, encryptor_image.id, 'Test updated AMI',
            subnet_id='subnet-1', security_group_ids=['sg-1', 'sg-2'],
            enc_svc_class=DummyEncryptorService, guest_instance_type='t2.micro'
        )


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
        brkt_cli.util.SLEEP_ENABLED = False

    def test_service_fails_to_come_up(self):
        svc = DummyEncryptorService()
        deadline = ExpiredDeadline()
        with self.assertRaisesRegexp(Exception, 'Unable to contact'):
            encryptor_service.wait_for_encryptor_up(svc, deadline)

    def test_encryption_fails(self):
        svc = FailedEncryptionService('192.168.1.1')
        with self.assertRaisesRegexp(
                encryptor_service.EncryptionError, 'Encryption failed'):
            encryptor_service.wait_for_encryption(svc)

    def test_unsupported_guest(self):
        class UnsupportedGuestService(encryptor_service.BaseEncryptorService):
            def __init__(self):
                super(UnsupportedGuestService, self).__init__('localhost', 80)

            def is_encryptor_up(self):
                return True

            def get_status(self):
                return {
                    'state': encryptor_service.ENCRYPT_FAILED,
                    'failure_code':
                        encryptor_service.FAILURE_CODE_UNSUPPORTED_GUEST,
                    'percent_complete': 0
                }

        with self.assertRaises(encryptor_service.UnsupportedGuestError):
            encryptor_service.wait_for_encryption(UnsupportedGuestService())

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

        with self.assertRaises(encryptor_service.EncryptionError):
            encryptor_service.wait_for_encryption(
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
        brkt_cli.util.SLEEP_ENABLED = False

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


class DummyValues(object):

    def __init__(self):
        self.encrypted_ami_name = None
        self.region = 'us-west-2'
        self.key_name = None
        self.subnet_id = None
        self.security_group_ids = []
        self.validate = True
        self.ami = None
        self.encryptor_ami = None
        self.proxies = []
        self.proxy_config_file = None


class TestValidation(unittest.TestCase):

    def test_validate_subnet_and_security_groups(self):
        aws_svc, encryptor_image, guest_image = _build_aws_service()

        # Subnet, no security groups.
        subnet = Subnet()
        subnet.id = 'subnet-1'
        subnet.vpc_id = 'vpc-1'
        aws_svc.subnets[subnet.id] = subnet

        brkt_cli._validate_subnet_and_security_groups(
            aws_svc, subnet_id=subnet.id)

        # Security groups, no subnet.
        sg1 = aws_svc.create_security_group('test1', 'test')
        sg2 = aws_svc.create_security_group('test2', 'test')
        brkt_cli._validate_subnet_and_security_groups(
            aws_svc, security_group_ids=[sg1.id, sg2.id]
        )

        # Security group and subnet.
        sg3 = aws_svc.create_security_group(
            'test3', 'test', vpc_id=subnet.vpc_id)
        brkt_cli._validate_subnet_and_security_groups(
            aws_svc, subnet_id=subnet.id, security_group_ids=[sg3.id])

        # Security groups in different VPCs.
        with self.assertRaises(ValidationError):
            brkt_cli._validate_subnet_and_security_groups(
                aws_svc, security_group_ids=[sg1.id, sg2.id, sg3.id])

        # Security group not in default subnet.
        with self.assertRaises(ValidationError):
            brkt_cli._validate_subnet_and_security_groups(
                aws_svc, security_group_ids=[sg3.id])

        # Security group and subnet in different VPCs.
        sg4 = aws_svc.create_security_group(
            'test4', 'test', vpc_id='vpc-2')
        with self.assertRaises(ValidationError):
            brkt_cli._validate_subnet_and_security_groups(
                aws_svc, subnet_id=subnet.id, security_group_ids=[sg4.id])

        # We don't validate security groups that have no vpc_id.
        sg5 = aws_svc.create_security_group('test5', 'test', vpc_id='vpc-2')
        sg5.vpc_id = None
        brkt_cli._validate_subnet_and_security_groups(
            aws_svc, security_group_ids=[sg5.id])

    def test_duplicate_image_name(self):
        """ Test that we detect name collisions with the encrypted image.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()

        # No name.
        values = DummyValues()
        values.ami = guest_image.id
        brkt_cli._connect_and_validate(aws_svc, values, encryptor_image.id)

        # Unique name.
        guest_image.name = 'My image'
        values.encrypted_ami_name = 'Proposed name'
        brkt_cli._connect_and_validate(aws_svc, values, encryptor_image.id)

        # Name collision.
        values.encrypted_ami_name = guest_image.name
        with self.assertRaises(ValidationError):
            brkt_cli._connect_and_validate(aws_svc, values, encryptor_image.id)

    def test_no_validate(self):
        """ Test that the --no-validate option turns off validation.
        """
        aws_svc, encryptor_image, guest_image = _build_aws_service()
        sg = aws_svc.create_security_group('test', 'test', vpc_id='vpc-1')

        values = DummyValues()
        values.security_group_ids = [sg.id]

        # Validation checks that the security group is not in the default
        # subnet.
        with self.assertRaises(ValidationError):
            brkt_cli._connect_and_validate(aws_svc, values, encryptor_image.id)

        # Exception is not raised when we turn off validation.
        values.validate = False
        brkt_cli._connect_and_validate(aws_svc, values, encryptor_image.id)

    def test_detect_double_encryption(self):
        """ Test that we disallow encryption of an already encrypted AMI.
        """
        aws_svc = DummyAWSService()

        # Register guest image
        bdm = BlockDeviceMapping()
        bdm['/dev/sda1'] = BlockDeviceType()
        id = aws_svc.register_image(
            kernel_id=None, name='Guest image', block_device_map=bdm)
        guest_image = aws_svc.get_image(id)

        # Make the guest image look like it was already encrypted and
        # make sure that validation fails.
        guest_image.tags[encrypt_ami.TAG_ENCRYPTOR] = 'ami-' + _new_id()
        self.assertTrue(
            'encrypted' in brkt_cli._validate_guest_ami(aws_svc, id))

    def test_validate_guest_image(self):
        """ Test validation of an encrypted guest image.
        """
        image = Image()
        image.id = _new_id()
        old_encryptor_id = _new_id()
        new_encryptor_id = _new_id()
        image.tags[encrypt_ami.TAG_ENCRYPTOR] = 'True'
        image.tags[encrypt_ami.TAG_ENCRYPTOR_AMI] = old_encryptor_id

        aws_svc = DummyAWSService()
        aws_svc.images[image.id] = image

        # Missing tag.
        with self.assertRaises(ValidationError):
            brkt_cli._validate_guest_encrypted_ami(
                aws_svc, image.id, new_encryptor_id)

        # No missing tag.
        image.tags[encrypt_ami.TAG_ENCRYPTOR_SESSION_ID] = _new_id()
        result = brkt_cli._validate_guest_encrypted_ami(
            aws_svc, image.id, new_encryptor_id)
        self.assertEquals(image, result)

        # Attempting to encrypt with the same encryptor AMI.
        with self.assertRaises(ValidationError):
            brkt_cli._validate_guest_encrypted_ami(
                aws_svc, image.id, old_encryptor_id)

        # Invalid image ID.
        with self.assertRaises(ValidationError):
            brkt_cli._validate_guest_encrypted_ami(
                aws_svc, 'ami-123456', new_encryptor_id
            )

    def test_validate_encryptor_ami(self):
        """ Test validation of the encryptor AMI.
        """
        aws_svc = DummyAWSService()
        image = Image()
        image.id = _new_id()
        image.name = 'brkt-avatar'
        aws_svc.images[image.id] = image

        # Valid image.
        brkt_cli._validate_encryptor_ami(aws_svc, image.id)

        # Unexpected name.
        image.name = 'foobar'
        with self.assertRaises(ValidationError):
            brkt_cli._validate_encryptor_ami(aws_svc, image.id)

        # Invalid id.
        id = _new_id()
        with self.assertRaises(ValidationError):
            brkt_cli._validate_encryptor_ami(aws_svc, id)

        # Service returned None.  Apparently this can happen when the account
        # does not have access to the image.
        aws_svc.images[id] = None
        with self.assertRaises(ValidationError):
            brkt_cli._validate_encryptor_ami(aws_svc, id)

    def test_detect_valid_ntp_server(self):
        """ Test that we allow only valid host names or IPv4 addresses to
            to be configured as ntp servers.
        """

        # first test a valid collection of host names/IPv4 addresses
        ntp_servers = ["0.netbsd.pool.ntp.org", "10.10.10.1",
                       "ec2-52-36-60-215.us-west-2.compute.amazonaws.com",
                       "abc.com."]
        brkt_cli._validate_ntp_servers(ntp_servers)

        # test invalid host name is rejected
        ntp_servers = ["ec2_52_36_60_215.us-west-2.compute.amazonaws.com"]
        with self.assertRaises(ValidationError):
            brkt_cli._validate_ntp_servers(ntp_servers)

        # test IPv6 address is rejected
        ntp_servers = ["2001:db8:a0b:12f0::1"]
        with self.assertRaises(ValidationError):
            brkt_cli._validate_ntp_servers(ntp_servers)
        ntp_servers = ["2001:0db8:0a0b:12f0:0001:0001:0001:0001"]
        with self.assertRaises(ValidationError):
            brkt_cli._validate_ntp_servers(ntp_servers)

    def test_updated_image_name(self):
        """ Test updating the name of an encrypted image.
        """
        # Existing image name contains the session id.
        self.assertEquals(
            'abc (encrypted 456)',
            brkt_cli._get_updated_image_name('abc (encrypted 123)', '456')
        )

        # Long name, contains session id.
        existing = 'x' * 112 + ' (encrypted 123)'
        self.assertEquals(
            'x' * 109 + ' (encrypted 123456)',
            brkt_cli._get_updated_image_name(existing, '123456')
        )

        # Existing image name doesn't contain the session id.
        self.assertEquals(
            'abc (encrypted 123)',
            brkt_cli._get_updated_image_name('abc', '123')
        )

        # Long name, does not contain session id.
        self.assertEquals(
            'x' * 112 + ' (encrypted 123)',
            brkt_cli._get_updated_image_name('x' * 128, '123')
        )


class TestEncryptAMIBackwardsCompatibility(unittest.TestCase):

    def test_attributes(self):
        required_attributes = (
            'AMI_NAME_MAX_LENGTH',
            'DESCRIPTION_SNAPSHOT',
            'NAME_ENCRYPTOR',
            'NAME_METAVISOR_ROOT_VOLUME',
            'NAME_METAVISOR_GRUB_VOLUME',
            'NAME_METAVISOR_LOG_VOLUME'
        )
        for attr in required_attributes:
            self.assertTrue(
                hasattr(encrypt_ami, attr),
                'Did not find attribute encrypt_ami.%s' % attr
            )

    def test_method_signatures(self):
        required_method_signatures = (
            ('append_suffix',
             ['name', 'suffix', 'max_length']),
            ('clean_up',
             ['aws_svc', 'instance_ids', 'security_group_ids']),
            ('get_encrypted_suffix', []),
            ('snapshot_encrypted_instance',
             ['aws_svc', 'enc_svc_cls', 'encryptor_instance',
              'encryptor_image', 'legacy']),
            ('register_ami',
             ['aws_svc', 'encryptor_instance', 'encryptor_image', 'name',
              'description', 'mv_bdm', 'legacy', 'mv_root_id']),
            ('wait_for_instance',
             ['aws_svc', 'instance_id']),
            ('create_encryptor_security_group', ['aws_svc'])
        )
        for mthd, args in required_method_signatures:
            self.assertTrue(
                hasattr(encrypt_ami, mthd),
                'Did not find method encrypt_ami.%s' % mthd
            )
            method_ref = encrypt_ami.__dict__[mthd]
            method_args = inspect.getargspec(method_ref)[0]
            for arg in args:
                self.assertIn(
                    arg, method_args,
                    'Did not find argument "%s" for method encrypt_ami.%s' % (
                        arg, mthd)
                )


class TestCustomTags(unittest.TestCase):

    def test_tag_validation(self):
        # Key
        key = 'x' * 127
        self.assertEquals(key, aws_service.validate_tag_key(key))
        with self.assertRaises(ValidationError):
            aws_service.validate_tag_key(key + 'x')
        with self.assertRaises(ValidationError):
            aws_service.validate_tag_key('aws:foobar')

        # Value
        value = 'x' * 255
        self.assertEquals(value, aws_service.validate_tag_value(value))
        with self.assertRaises(ValidationError):
            aws_service.validate_tag_value(value + 'x')
        with self.assertRaises(ValidationError):
            aws_service.validate_tag_value('aws:foobar')


class TestVersionCheck(unittest.TestCase):

    def test_is_version_supported(self):
        supported = [
            '0.9.8', '0.9.9', '0.9.9.1', '0.9.10', '0.9.11', '0.9.12'
        ]
        self.assertFalse(
            brkt_cli._is_version_supported('0.9.7', supported)
        )
        self.assertTrue(
            brkt_cli._is_version_supported('0.9.8', supported)
        )
        self.assertTrue(
            brkt_cli._is_version_supported('0.9.12', supported)
        )
        self.assertTrue(
            brkt_cli._is_version_supported('0.9.13pre1', supported)
        )
        self.assertTrue(
            brkt_cli._is_version_supported('0.9.13', supported)
        )

    def test_is_later_version_available(self):
        supported = [
            '0.9.8', '0.9.9', '0.9.9.1', '0.9.10', '0.9.11', '0.9.12'
        ]
        self.assertTrue(
            brkt_cli._is_later_version_available('0.9.11', supported)
        )
        self.assertFalse(
            brkt_cli._is_later_version_available('0.9.12', supported)
        )
        self.assertFalse(
            brkt_cli._is_later_version_available('0.9.13pre1', supported)
        )


class TestProxy(unittest.TestCase):

    def test_generate_proxy_config(self):
        """ Test generating proxy.yaml from Proxy objects.
        """
        p1 = Proxy(host='proxy1.example.com', port=8001)
        p2 = Proxy(host='proxy2.example.com', port=8002)
        proxy_yaml = proxy.generate_proxy_config(p1, p2)
        proxy.validate_proxy_config(proxy_yaml)
        d = yaml.load(proxy_yaml)

        self.assertEquals('proxy1.example.com', d['proxies'][0]['host'])
        self.assertEquals(8001, d['proxies'][0]['port'])
        self.assertEqual('https', d['proxies'][0]['protocol'])
        self.assertEqual('encryptor', d['proxies'][0]['usage'])

        self.assertEquals('proxy2.example.com', d['proxies'][1]['host'])
        self.assertEquals(8002, d['proxies'][1]['port'])

    def test_validate_proxy_config(self):
        """ Test that proxy.yaml validation fails unless we specify at least
        one complete proxy configuration.
        """
        d = {}
        with self.assertRaises(ValidationError):
            proxy.validate_proxy_config(yaml.dump(d))

        d['proxies'] = []
        with self.assertRaises(ValidationError):
            proxy.validate_proxy_config(yaml.dump(d))

        proxies = {}
        d['proxies'].append(proxies)
        with self.assertRaises(ValidationError):
            proxy.validate_proxy_config(yaml.dump(d))

        proxies['host'] = 'proxy.example.com'
        with self.assertRaises(ValidationError):
            proxy.validate_proxy_config(yaml.dump(d))

        proxies['port'] = 8001
        proxy.validate_proxy_config(yaml.dump(d))


class TestUserData(unittest.TestCase):

    def test_user_data_container(self):
        udc = UserDataContainer()
        udc.add_file('test.txt', '1 2 3', 'text/plain')
        mime = udc.to_mime_text()
        self.assertTrue('test.txt: {contents: 1 2 3}' in mime)

    def test_combine_user_data(self):
        """ Test combining Bracket config data with HTTP proxy config data.
        """
        brkt_config = {'foo': 'bar'}
        p = Proxy(host='proxy1.example.com', port=8001)
        proxy_config = proxy.generate_proxy_config(p)
        compressed_mime_data = user_data.combine_user_data(
            brkt_config,
            proxy_config
        )
        mime_data = zlib.decompress(compressed_mime_data, 16 + zlib.MAX_WBITS)

        msg = email.message_from_string(mime_data)
        found_brkt_config = False
        found_brkt_files = False

        for part in msg.walk():
            if part.get_content_type() == BRKT_CONFIG_CONTENT_TYPE:
                found_brkt_config = True
                content = part.get_payload(decode=True)
                self.assertEqual('{"foo": "bar"}', content)
            if part.get_content_type() == BRKT_FILES_CONTENT_TYPE:
                found_brkt_files = True
                content = part.get_payload(decode=True)
                self.assertTrue('/var/brkt/ami_config/proxy.yaml:' in content)

        self.assertTrue(found_brkt_config)
        self.assertTrue(found_brkt_files)


class TestCommandLineOptions(unittest.TestCase):
    """ Test handling of command line options."""

    def test_parse_tags(self):
        # Valid tag strings
        self.assertEquals(
            {'a': 'b', 'foo': 'bar'},
            brkt_cli._parse_tags(['a=b', 'foo=bar']))

        # Invalid tag string
        with self.assertRaises(ValidationError):
            brkt_cli._parse_tags(['abc'])

    def test_parse_proxies(self):
        """ Test parsing host:port strings to Proxy objects.
        """
        # Valid
        proxies = brkt_cli._parse_proxies(
            'example1.com:8001',
            'example2.com:8002',
            '192.168.1.1:8003'
        )
        self.assertEquals(3, len(proxies))
        (p1, p2, p3) = proxies[0:3]

        self.assertEquals('example1.com', p1.host)
        self.assertEquals(8001, p1.port)
        self.assertEquals('example2.com', p2.host)
        self.assertEquals(8002, p2.port)
        self.assertEquals('192.168.1.1', p3.host)
        self.assertEquals(8003, p3.port)

        # Invalid
        with self.assertRaises(ValidationError):
            brkt_cli._parse_proxies('example.com')
        with self.assertRaises(ValidationError):
            brkt_cli._parse_proxies('example.com:1:2')
        with self.assertRaises(ValidationError):
            brkt_cli._parse_proxies('example.com:1a')
        with self.assertRaises(ValidationError):
            brkt_cli._parse_proxies('invalid_hostname.example.com:8001')

    def test_parse_brkt_env(self):
        """ Test parsing of the command-line --brkt-env value.
        """
        be = brkt_cli._parse_brkt_env(
            'api.example.com:777,hsmproxy.example.com:888')
        self.assertEqual('api.example.com', be.api_host)
        self.assertEqual(777, be.api_port)
        self.assertEqual('hsmproxy.example.com', be.hsmproxy_host)
        self.assertEqual(888, be.hsmproxy_port)

        with self.assertRaises(ValidationError):
            brkt_cli._parse_brkt_env('a')
        with self.assertRaises(ValidationError):
            brkt_cli._parse_brkt_env('a:7,b:8:9')
        with self.assertRaises(ValidationError):
            brkt_cli._parse_brkt_env('a:7,b?:8')

    def test_get_proxy_config(self):
        """ Test reading proxy config from the --proxy and --proxy-config-file
        command line options.
        """
        # No proxy.
        values = DummyValues()
        self.assertIsNone(brkt_cli._get_proxy_config(values))

        # --proxy specified.
        values.proxies = ['proxy.example.com:8000']
        proxy_yaml = brkt_cli._get_proxy_config(values)
        d = yaml.load(proxy_yaml)
        self.assertEquals('proxy.example.com', d['proxies'][0]['host'])

        # --proxy-config-file references a file that doesn't exist.
        values.proxy = None
        values.proxy_config_file = 'bogus.yaml'
        with self.assertRaises(ValidationError):
            brkt_cli._get_proxy_config(values)

        # --proxy-config-file references a valid file.
        with tempfile.NamedTemporaryFile() as f:
            f.write(proxy_yaml)
            f.flush()
            values.proxy_config_file = f.name
            proxy_yaml = brkt_cli._get_proxy_config(values)

        d = yaml.load(proxy_yaml)
        self.assertEquals('proxy.example.com', d['proxies'][0]['host'])


class TestSubmodule(unittest.TestCase):

    def test_aws_module(self):
        """ Test that the AWS module is installed by setuptools.
        """
        importlib.import_module('brkt_cli.aws')
