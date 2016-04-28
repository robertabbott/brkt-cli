import logging
import time
import unittest
import uuid

import brkt_cli
import test

from brkt_cli.validation import ValidationError
from brkt_cli import util
from brkt_cli import encrypt_gce_image
from brkt_cli import update_gce_image
from brkt_cli import gce_service

NONEXISTANT_IMAGE = 'image'
NONEXISTANT_PROJECT = 'project'
TOKEN = 'token'

log = logging.getLogger(__name__)

def _new_id():
    return uuid.uuid4().hex[:6]


class DummyGCEService(gce_service.BaseGCEService):
    def __init__(self):
        super(DummyGCEService, self).__init__('testproject', _new_id(), log)

    def cleanup(self, zone):
        for disk in self.disks[:]:
            if self.disk_exists(zone, disk):
                self.wait_for_detach(zone, disk)
                self.delete_disk(zone, disk)
        for instance in self.instances:
            self.delete_instance(zone, instance)

    def list_zones(self):
        return ['us-central1-a']

    def get_session_id(self):
        return self.session_id

    def get_snapshot(self, name):
        return {'status':'READY'}

    def wait_snapshot(self, snapshot):
        while True:
            if self.get_snapshot(snapshot)['status'] == 'READY':
                return
            time.sleep(5)

    def get_image(self, image, image_project):
        if image == NONEXISTANT_IMAGE:
            raise
        if image_project and image_project == NONEXISTANT_PROJECT:
            raise
        return True

    def image_exists(self, image, image_project=None):
        try:
            self.get_image(image, image_project)
        except:
            return False
        return True

    def delete_instance(self, zone, instance):
        if instance in self.instances:
            self.instances.remove(instance)

    def delete_disk(self, zone, disk):
        if disk in self.disks:
            self.disks.remove(disk)
            return
        raise test.TestException('disk doesnt exist')


    def wait_instance(self, name, zone):
        return

    def get_instance_ip(self, name, zone):
        return

    def detach_disk(self, zone, instance, diskName):
        return self.wait_for_detach(zone, diskName)

    def wait_for_disk(self, zone, diskName):
        return

    def get_disk_size(self, zone, diskName):
        return 10

    def wait_for_detach(self, zone, diskName):
        return

    def disk_exists(self, zone, name):
        if name == NONEXISTANT_IMAGE:
            return False
        return True

    def create_snapshot(self, zone, disk, snapshot_name):
        return

    def delete_snapshot(self, snapshot_name):
        return

    def disk_from_snapshot(self, zone, snapshot, name):
        return

    def create_disk(self, zone, name, size):
        self.disks.append(name)

    def create_gce_image_from_disk(self, zone, image_name, disk_name):
        return

    def create_gce_image_from_file(self, zone, image_name, file_name, bucket):
        return

    def wait_image(self, image_name):
        pass

    def get_younger(self, new, old):
        pass

    def get_image_file(self, bucket):
        pass

    def get_latest_encryptor_image(self,
                                   zone,
                                   image_name,
                                   bucket,
                                   image_file=None):
        pass

    def run_instance(self,
                     zone,
                     name,
                     image,
                     disks=[],
                     metadata={},
                     delete_boot=False,
                     instance_type='n1-standard-4',
                     image_project=None):
        self.instances.append(name)
        if not delete_boot:
            self.disks.append(name)

    def get_disk(self, zone, disk_name):
        source_disk = "projects/%s/zones/%s/disks/%s" % (self.project, zone, disk_name)
        return {
            'boot': False,
            'autoDelete': False,
            'source': self.gce_res_uri + source_disk,
        }


class TestEncryptedImageName(unittest.TestCase):

    def test_get_image_name(self):
        image_name = 'test'
        n1 = gce_service.get_image_name(None, image_name)
        n2 = gce_service.get_image_name(None, image_name)
        self.assertNotEqual(n1, n2)

    def test_long_image_name(self):
        image_name = 'test-image-with-long-name-encrypted-so-we-hit-63-char-limit'
        n1 = gce_service.get_image_name(None, image_name)
        n2 = gce_service.get_image_name(None, image_name)
        self.assertNotEqual(n1, n2)
        self.assertTrue('63-char-limit' not in n1 and '63-char-limit' not in n2)

    def test_user_supplied_name(self):
        encrypted_image_name = 'something'
        image_name = 'something_else'
        n1 = gce_service.get_image_name(encrypted_image_name, image_name)
        n2 = gce_service.get_image_name(encrypted_image_name, None)
        self.assertEqual(n1, n2)
        self.assertEqual(n1, encrypted_image_name)

    def test_image_name(self):
        encrypted_image_name = 'valid-name'
        self.assertEquals(encrypted_image_name,
            gce_service.validate_image_name(encrypted_image_name))
        with self.assertRaises(ValidationError):
            gce_service.validate_image_name(None)
        with self.assertRaises(ValidationError):
            gce_service.validate_image_name('Valid-Name')
        with self.assertRaises(ValidationError):
            gce_service.validate_image_name('validname-')
        with self.assertRaises(ValidationError):
            gce_service.validate_image_name('a' * 64)
        for c in '?!#$%^&*~`{}\|"<>()[]./\'@_':
            with self.assertRaises(ValidationError):
                gce_service.validate_image_name('valid' + c)


class TestRunEncryption(unittest.TestCase):

    def setUp(self):
        brkt_cli.util.SLEEP_ENABLED = False

    def test_smoke(self):
        gce_svc = DummyGCEService()
        encrypted_image = encrypt_gce_image.encrypt(
            gce_svc=gce_svc,
            enc_svc_cls=test.DummyEncryptorService,
            image_id='test-ubuntu',
            encryptor_image='encryptor-image',
            encrypted_image_name='ubuntu-encrypted',
            zone='us-central1-a',
            brkt_env=None,
            token=TOKEN,
        )
        self.assertIsNotNone(encrypted_image)
        self.assertEqual(len(gce_svc.disks), 0)
        self.assertEqual(len(gce_svc.instances), 0)

    def test_cleanup(self):
        gce_svc = DummyGCEService()
        encrypt_gce_image.encrypt(
            gce_svc=gce_svc,
            enc_svc_cls=test.DummyEncryptorService,
            image_id='test-ubuntu',
            encryptor_image='encryptor-image',
            encrypted_image_name='ubuntu-encrypted',
            zone='us-central1-a',
            brkt_env=None,
            token=TOKEN,
        )
        self.assertEqual(len(gce_svc.disks), 0)
        self.assertEqual(len(gce_svc.instances), 0)

    def test_cleanup_on_fail(self):
        gce_svc = DummyGCEService()
        with self.assertRaises(Exception):
             encrypt_gce_image.encrypt(
                gce_svc=gce_svc,
                enc_svc_cls=test.FailedEncryptionService,
                image_id='test-ubuntu',
                encryptor_image='encryptor-image',
                encrypted_image_name='ubuntu-encrypted',
                zone='us-central1-a',
                brkt_env=None,
                token=TOKEN,
            )
        self.assertEqual(len(gce_svc.disks), 0)
        self.assertEqual(len(gce_svc.instances), 0)


class TestImageValidation(unittest.TestCase):

    def setUp(self):
        brkt_cli.util.SLEEP_ENABLED = False

    def test_nonexistant_encryptor(self):
        gce_svc = DummyGCEService()
        with self.assertRaises(ValidationError):
            encrypt_gce_image.validate_images(
                gce_svc=gce_svc,
                guest_image='test-ubuntu',
                # encrypted_image_name shouldn't exist
                encrypted_image_name=NONEXISTANT_IMAGE,
                encryptor=NONEXISTANT_IMAGE,
                image_project=None,
            )

    def test_nonexistant_guest(self):
        gce_svc = DummyGCEService()
        with self.assertRaises(ValidationError):
            encrypt_gce_image.validate_images(
                gce_svc=gce_svc,
                guest_image=NONEXISTANT_IMAGE,
                encryptor='americium',
                encrypted_image_name=NONEXISTANT_IMAGE,
                image_project=None,
            )

    def test_desired_output_image_exists(self):
        gce_svc = DummyGCEService()
        with self.assertRaises(ValidationError):
            encrypt_gce_image.validate_images(
                gce_svc=gce_svc,
                guest_image='test-ubuntu',
                encryptor='americium',
                encrypted_image_name='deuterium',
                image_project=None,
            )

    def test_nonexistant_image_project(self):
        gce_svc = DummyGCEService()
        with self.assertRaises(ValidationError):
            encrypt_gce_image.validate_images(
                gce_svc=gce_svc,
                guest_image='test-ubuntu',
                encryptor='americium',
                encrypted_image_name='deuterium',
                image_project=NONEXISTANT_IMAGE,
             )


class TestBrktEnv(unittest.TestCase):

    def setUp(self):
        brkt_cli.util.SLEEP_ENABLED = False

    def test_add_brkt_env_to_user_data(self):
        userdata = {}
        api_host_port = 'api.example.com:777'
        hsmproxy_host_port = 'hsmproxy.example.com:888'
        expected_userdata = {'brkt':{'api_host': api_host_port, 'hsmproxy_host': hsmproxy_host_port}}
        brkt_env = brkt_cli._parse_brkt_env(
            api_host_port + ',' + hsmproxy_host_port)
        util.add_brkt_env_to_brkt_config(brkt_env, userdata)
        self.assertEqual(userdata, expected_userdata)


class TestRunUpdate(unittest.TestCase):

    def setUp(self):
        brkt_cli.util.SLEEP_ENABLED = False

    def test_cleanup_on_fail(self):
        gce_svc = DummyGCEService()
        with self.assertRaises(Exception):
             update_gce_image.update_gce_image(
                gce_svc=gce_svc,
                enc_svc_cls=test.FailedEncryptionService,
                image_id='test-ubuntu',
                encryptor_image='encryptor-image',
                encrypted_image_name='ubuntu-encrypted',
                zone='us-central1-a',
                brkt_env=None
            )
        self.assertEqual(len(gce_svc.disks), 0)
        self.assertEqual(len(gce_svc.instances), 0)

    def test_cleanup(self):
        gce_svc = DummyGCEService()
        encrypted_image = update_gce_image.update_gce_image(
            gce_svc=gce_svc,
            enc_svc_cls=test.DummyEncryptorService,
            image_id='test-ubuntu',
            encryptor_image='encryptor-image',
            encrypted_image_name='ubuntu-encrypted',
            zone='us-central1-a',
            brkt_env=None
        )

        self.assertIsNotNone(encrypted_image)
        self.assertEqual(len(gce_svc.disks), 0)
        self.assertEqual(len(gce_svc.instances), 0)
