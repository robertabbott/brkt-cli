import logging
import unittest
import datetime

#import test
from brkt_cli import util
from brkt_cli.esx import encrypt_vmdk
from brkt_cli.esx import update_vmdk
from brkt_cli.esx import esx_service
from brkt_cli.test_encryptor_service import (
    DummyEncryptorService,
    FailedEncryptionService
)
from brkt_cli.instance_config import INSTANCE_UPDATER_MODE

TOKEN = 'token'

log = logging.getLogger(__name__)


class NullHandler(logging.Handler):
    def emit(self, record):
        pass

class DummyDisk(object):
    def __init__(self, size, filename):
        self.size = size
        self.filename = filename

class DummyVM(object):
    def __init__(self, name, cpu, memory, poweron=False, template=False):
        self.name = name
        self.cpu = cpu
        self.memory = memory
        self.poweron = poweron
        self.template = template
        self.userdata = None
        self.disks = dict()

    def add_disk(self, disk, unit_number):
        self.disks[unit_number] = disk

    def remove_disk(self, unit_number):
        self.disks.pop(unit_number)


class DummyOVF(object):
    def __init__(self, vm, name):
        self.vm = vm
        self.name = name


class DummyVCenterService(esx_service.BaseVCenterService):
    def __init__(self):
        self.vms = dict()
        self.disks = dict()
        self.connection = False
        super(DummyVCenterService, self).__init__(
            'testhost', 'testuser', 'testpass', 'testport', 'testdcname',
            'testdsname', False, 'testclustername', 1, 1024, 123)

    def connect(self):
        self.connection = True

    def disconnect(self):
        self.connection = False

    def connected(self):
        return self.connect

    def get_session_id(self):
        return self.session_id

    def get_datastore_path(self, vmdk_name):
        return vmdk_name

    def find_vm(self, vm_name):
        return self.vms.get(vm_name)

    def power_on(self, vm):
        vm.poweron = True

    def power_off(self, vm):
        vm.poweron = False

    def destroy_vm(self, vm):
        disk_list = vm.disks.keys()
        for c_unit in disk_list:
            c_disk = vm.disks.get(c_unit)
            self.disks.pop(c_disk.filename)
        self.vms.pop(vm.name)

    def get_ip_address(self, vm):
        return ("10.10.10.1")

    def create_vm(self, memoryGB=1, numCPUs=1, network_name="VM Network"):
        timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
        vm_name = "VM-" + timestamp
        vm = DummyVM(vm_name, numCPUs, memoryGB)
        self.vms[vm_name] = vm
        return vm

    def reconfigure_vm_cpu_ram(self, vm):
        vm.cpu = self.no_of_cpus
        vm.memory = self.memoryGB

    def add_disk(self, vm, disk_size=12*1024*1024,
                 filename=None, unit_number=0):
        diskname = vm.name + str(unit_number)
        if filename:
            disk = self.disks[filename]
            disk_size = disk.size
        disk = DummyDisk(disk_size, diskname)
        vm.add_disk(disk, unit_number)
        self.disks[diskname] = disk

    def detach_disk(self, vm, unit_number=2):
        disk = vm.disks.get(unit_number)
        vm.remove_disk(unit_number)
        return disk

    def clone_disk(self, source_disk, dest_disk=None, dest_disk_name=None):
        if (dest_disk_name is None):
            if (dest_disk is None):
                raise Exception("Cannot clone disk as destination "
                                "not specified")
            dest_disk_name = source_disk.filename + dest_disk.filename
        disk = DummyDisk(source_disk.size, dest_disk_name)
        self.disks[dest_disk_name] = disk
        return dest_disk_name

    def get_disk(self, vm, unit_number):
        # return vim.vm.device.VirtualDisk
        return vm.disks.get(unit_number)

    def get_disk_size(self, vm, unit_number):
        disk = vm.disks.get(unit_number)
        return disk.size

    def clone_vm(self, vm, powerOn=False, vm_name=None, template=False):
        if (vm_name is None):
            timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
            vm_name = "template-vm-" + timestamp
        clone_vm = DummyVM(vm_name, vm.cpu, vm.memory,
                           poweron=powerOn, template=template)
        disk_list = vm.disks.keys()
        for c_unit in disk_list:
            c_disk = vm.disks.get(c_unit)
            self.add_disk(clone_vm, c_disk.size, unit_number=c_unit)
        self.vms[vm_name] = clone_vm
        return clone_vm

    def create_userdata_str(self, instance_config, update=False,
                            ssh_key_file=None,
                            rescue_proto=None, rescue_url=None):
        brkt_config = {}
        if instance_config:
            brkt_config = instance_config.get_brkt_config()
        if update is True:
            brkt_config['solo_mode'] = 'updater'
            instance_config.set_mode(INSTANCE_UPDATER_MODE)
        if ssh_key_file:
            with open(ssh_key_file, 'r') as f:
                key_value = (f.read()).strip()
            brkt_config['ssh-public-key'] = key_value
        if rescue_proto:
            brkt_config = dict()
            brkt_config['rescue'] = dict()
            brkt_config['rescue']['protocol'] = rescue_proto
            brkt_config['rescue']['url'] = rescue_url
        instance_config.set_brkt_config(brkt_config)
        user_data = instance_config.make_userdata()
        return user_data

    def send_userdata(self, vm, user_data_str):
        vm.userdata = user_data_str

    def keep_lease_alive(self, lease):
        return

    def export_to_ovf(self, vm, target_path, ovf_name=None):
        ovf = DummyOVF(vm, ovf_name)
        return ovf

    def convert_ovf_to_ova(self, ovftool_path, ovf_path):
        return

    def convert_ova_to_ovf(self, ovftool_path, ova_path):
        return

    def get_ovf_descriptor(self, ovf_path):
        return ovf_path

    def upload_ovf_to_vcenter(self, target_path, ovf_name):
        ovf = target_path
        if target_path == "./":
            ovf = self.ovfs[0]
        return self.clone_vm(ovf.vm, vm_name = ovf_name)

    def get_vm_name(self, vm):
        return vm.name

    def get_disk_name(self, disk):
        return disk.filename


class TestRunEncryption(unittest.TestCase):

    def setUp(self):
        util.SLEEP_ENABLED = False
        h = NullHandler()
        logging.getLogger("brkt_cli").addHandler(h)

    def test_smoke(self):
        vc_swc = DummyVCenterService()
        mv_vm = DummyVM("mv_image", 1, 1024)
        disk = DummyDisk(12*1024*1024, None)
        mv_vm.add_disk(disk, 0)
        mv_ovf = DummyOVF(mv_vm, "mv-ovf")
        vc_swc.ovfs = [mv_ovf]
        guest_vmdk = "guest-vmdk"
        guest_vmdk_disk = DummyDisk(16*1024*1024, guest_vmdk)
        vc_swc.disks[guest_vmdk] = guest_vmdk_disk
        encrypt_vmdk.encrypt_from_s3(
            vc_swc,
            DummyEncryptorService,
            guest_vmdk,
            vm_name="template-encrypted",
            create_ovf=False, create_ova=False,
            target_path=mv_ovf,
            image_name=None,
            ovftool_path=None,
            ovf_name="mv-ovf",
            download_file_list=[],
            user_data_str=None
        )
        self.assertEqual(len(vc_swc.vms), 1)
        self.assertEqual(len(vc_swc.disks), 4)
        template_vm = (vc_swc.vms.values())[0]
        self.assertEqual(len(template_vm.disks), 2)
        self.assertEqual(template_vm.name, "template-encrypted")
        self.assertEqual(template_vm.disks[0].size, 12*1024*1024)
        self.assertEqual(template_vm.disks[1].size, 33*1024*1024)
        self.assertTrue(template_vm.template)

    def test_cleanup_on_bad_guest_image(self):
        vc_swc = DummyVCenterService()
        mv_vm = DummyVM("mv_image", 1, 1024)
        disk = DummyDisk(12*1024*1024, None)
        mv_vm.add_disk(disk, 0)
        mv_ovf = DummyOVF(mv_vm, "mv-ovf")
        vc_swc.ovfs = [mv_ovf]
        guest_vmdk = "guest-vmdk"
        with self.assertRaises(Exception):
            encrypt_vmdk.encrypt_from_s3(
                vc_swc,
                DummyEncryptorService,
                guest_vmdk,
                vm_name="template-encrypted",
                create_ovf=False, create_ova=False,
                target_path=mv_ovf,
                image_name=None,
                ovftool_path=None,
                ovf_name="mv-ovf",
                download_file_list=[],
                user_data_str=None
            )
        self.assertEqual(len(vc_swc.vms), 0)
        self.assertEqual(len(vc_swc.disks), 0)

    def test_cleanup_bad_mv_image(self):
        vc_swc = DummyVCenterService()
        mv_vm = DummyVM("mv_image", 1, 1024)
        disk = DummyDisk(12*1024*1024, None)
        mv_vm.add_disk(disk, 0)
        mv_ovf = DummyOVF(mv_vm, "mv-ovf")
        vc_swc.ovfs = []
        guest_vmdk = "guest-vmdk"
        with self.assertRaises(Exception):
            encrypt_vmdk.encrypt_from_s3(
                vc_swc,
                DummyEncryptorService,
                guest_vmdk,
                vm_name="template-encrypted",
                create_ovf=False, create_ova=False,
                target_path=mv_ovf,
                image_name=None,
                ovftool_path=None,
                ovf_name="mv-ovf",
                download_file_list=[],
                user_data_str=None
            )
        self.assertEqual(len(vc_swc.vms), 0)
        self.assertEqual(len(vc_swc.disks), 0)

    def test_cleanup_bad_encryption(self):
        vc_swc = DummyVCenterService()
        mv_vm = DummyVM("mv_image", 1, 1024)
        disk = DummyDisk(12*1024*1024, None)
        mv_vm.add_disk(disk, 0)
        mv_ovf = DummyOVF(mv_vm, "mv-ovf")
        vc_swc.ovfs = [mv_ovf]
        guest_vmdk = "guest-vmdk"
        guest_vmdk_disk = DummyDisk(16*1024*1024, guest_vmdk)
        vc_swc.disks[guest_vmdk] = guest_vmdk_disk
        try:
            encrypt_vmdk.encrypt_from_s3(
                vc_swc,
                FailedEncryptionService,
                guest_vmdk,
                vm_name="template-encrypted",
                create_ovf=False, create_ova=False,
                target_path=mv_ovf,
                image_name=None,
                ovftool_path=None,
                ovf_name="mv-ovf",
                download_file_list=[],
                user_data_str=None
            )
            self.fail('Encryption should have failed')
        except Exception:
            self.assertEqual(len(vc_swc.vms), 1)
            self.assertEqual(len(vc_swc.disks), 4)


class TestRunUpdate(unittest.TestCase):

    def setUp(self):
        util.SLEEP_ENABLED = False
        h = NullHandler()
        logging.getLogger("brkt_cli").addHandler(h)

    def test_smoke(self):
        vc_swc = DummyVCenterService()
        mv_vm = DummyVM("mv_image", 1, 1024)
        disk = DummyDisk(14*1024*1024, None)
        mv_vm.add_disk(disk, 0)
        mv_ovf = DummyOVF(mv_vm, "mv-ovf")
        vc_swc.ovfs = [mv_ovf]
        template_vm = vc_swc.create_vm(1024, 1)
        template_vm_name = template_vm.name
        template_vm.template = True
        vc_swc.add_disk(template_vm, disk_size=12*1024*1024, unit_number=0)
        vc_swc.add_disk(template_vm, disk_size=33*1024*1024, unit_number=1)
        update_vmdk.update_from_s3(
            vc_swc,
            DummyEncryptorService,
            template_vm_name=template_vm_name,
            target_path=mv_ovf,
            ovf_name = None,
            ova_name = None,
            mv_ovf_name="mv-ovf",
            download_file_list=[],
            user_data_str=None
        )
        self.assertEqual(len(vc_swc.vms), 1)
        self.assertEqual(len(vc_swc.disks), 3)
        template_vm = (vc_swc.vms.values())[0]
        self.assertEqual(len(template_vm.disks), 2)
        self.assertEqual(template_vm.name, template_vm_name)
        self.assertEqual(template_vm.disks[0].size, 14*1024*1024)
        self.assertEqual(template_vm.disks[1].size, 33*1024*1024)
        self.assertTrue(template_vm.template)

    def test_cleanup_bad_mv_image(self):
        vc_swc = DummyVCenterService()
        mv_vm = DummyVM("mv_image", 1, 1024)
        disk = DummyDisk(14*1024*1024, None)
        mv_vm.add_disk(disk, 0)
        mv_ovf = DummyOVF(mv_vm, "mv-ovf")
        vc_swc.ovfs = []
        template_vm = vc_swc.create_vm(1024, 1)
        template_vm_name = template_vm.name
        template_vm.template = True
        vc_swc.add_disk(template_vm, disk_size=12*1024*1024, unit_number=0)
        vc_swc.add_disk(template_vm, disk_size=33*1024*1024, unit_number=1)
        with self.assertRaises(Exception):
            encrypt_vmdk.update_from_s3(
                vc_swc,
                DummyEncryptorService,
                template_vm_name=template_vm_name,
                target_path=mv_ovf,
                ovf_name = None,
                ova_name = None,
                image_name=None,
                mv_ovf_name="mv-ovf",
                download_file_list=[],
                user_data_str=None
            )
        self.assertEqual(len(vc_swc.vms), 1)
        self.assertEqual(len(vc_swc.disks), 2)
        template_vm = (vc_swc.vms.values())[0]
        self.assertEqual(len(template_vm.disks), 2)
        self.assertEqual(template_vm.name, template_vm_name)
        self.assertEqual(template_vm.disks[0].size, 12*1024*1024)
        self.assertEqual(template_vm.disks[1].size, 33*1024*1024)
        self.assertTrue(template_vm.template)

    def test_cleanup_bad_encryption(self):
        vc_swc = DummyVCenterService()
        mv_vm = DummyVM("mv_image", 1, 1024)
        disk = DummyDisk(14*1024*1024, None)
        mv_vm.add_disk(disk, 0)
        mv_ovf = DummyOVF(mv_vm, "mv-ovf")
        vc_swc.ovfs = [mv_ovf]
        template_vm = vc_swc.create_vm(1024, 1)
        template_vm_name = template_vm.name
        template_vm.template = True
        vc_swc.add_disk(template_vm, disk_size=12*1024*1024, unit_number=0)
        vc_swc.add_disk(template_vm, disk_size=33*1024*1024, unit_number=1)
        with self.assertRaises(Exception):
            encrypt_vmdk.update_from_s3(
                vc_swc,
                FailedEncryptionService,
                template_vm_name=template_vm_name,
                target_path=mv_ovf,
                ovf_name = None,
                ova_name = None,
                image_name=None,
                mv_ovf_name="mv-ovf",
                download_file_list=[],
                user_data_str=None
            )
        self.assertEqual(len(vc_swc.vms), 1)
        self.assertEqual(len(vc_swc.disks), 2)
        template_vm = (vc_swc.vms.values())[0]
        self.assertEqual(len(template_vm.disks), 2)
        self.assertEqual(template_vm.name, template_vm_name)
        self.assertEqual(template_vm.disks[0].size, 12*1024*1024)
        self.assertEqual(template_vm.disks[1].size, 33*1024*1024)
        self.assertTrue(template_vm.template)
