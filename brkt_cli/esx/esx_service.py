# Copyright 2016 Bracket Computing, Inc. All Rights Reserved.
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
import json
import logging
import time
import datetime
import ssl
import atexit
import os
import signal
import errno
import hashlib
import boto.s3

from functools import wraps
from threading import Thread
from pyVim import connect
from pyVmomi import vmodl
from pyVmomi import vim
from brkt_cli.util import (
    retry,
    RetryExceptionChecker
)
from brkt_cli.instance_config import INSTANCE_UPDATER_MODE
from brkt_cli.validation import ValidationError
from boto.s3.key import Key


log = logging.getLogger(__name__)


class TimeoutError(Exception):
    pass

def timeout(seconds=30, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wraps(func)(wrapper)

    return decorator


def compute_sha1_of_file(filename):
    hash_sha1 = hashlib.sha1()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()


class BaseVCenterService(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, host, user, password, port,
                 datacenter_name, datastore_name, esx_host,
                 cluster_name, no_of_cpus, memoryGB, session_id):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.datacenter_name = datacenter_name
        self.datastore_name = datastore_name
        self.datastore_path = "[" + datastore_name + "] "
        self.esx_host = esx_host
        self.cluster_name = cluster_name
        self.no_of_cpus = no_of_cpus
        self.memoryGB = memoryGB
        self.session_id = session_id
        self.no_teardown = False
        self.si = None
        self.thindisk = True
        self.eagerscrub = False

    def is_esx_host(self):
        return self.esx_host

    @abc.abstractmethod
    def connect(self):
        pass

    @abc.abstractmethod
    def disconnect(self):
        pass

    @abc.abstractmethod
    def connected(self):
        pass

    @abc.abstractmethod
    def get_session_id(self):
        pass

    @abc.abstractmethod
    def get_datastore_path(self, vmdk_name):
        pass

    @abc.abstractmethod
    def find_vm(self, vm_name):
        pass

    @abc.abstractmethod
    def power_on(self, vm):
        pass

    @abc.abstractmethod
    def power_off(self, vm):
        pass

    @abc.abstractmethod
    def destroy_vm(self, vm):
        pass

    @abc.abstractmethod
    def get_ip_address(self, vm):
        pass

    @abc.abstractmethod
    def create_vm(self, memoryGB=1, numCPUs=1,
                  network_name="VM Network"):
        pass

    @abc.abstractmethod
    def reconfigure_vm_cpu_ram(self, vm):
        pass

    @abc.abstractmethod
    def add_disk(self, vm, disk_size=12*1024*1024,
                 filename=None, unit_number=0):
        pass

    @abc.abstractmethod
    def detach_disk(self, vm, unit_number=2):
        pass

    @abc.abstractmethod
    def clone_disk(self, source_disk, dest_disk=None, dest_disk_name=None):
        pass

    @abc.abstractmethod
    def get_disk(self, vm, unit_number):
        pass

    @abc.abstractmethod
    def get_disk_size(self, vm, unit_number):
        pass

    @abc.abstractmethod
    def clone_vm(self, vm, powerOn=False, vm_name=None, template=False):
        pass

    @abc.abstractmethod
    def create_userdata_str(self, instance_config, update=False,
                            ssh_key_file=None,
                            rescue_proto=None, rescue_url=None):
        pass

    @abc.abstractmethod
    def send_userdata(self, vm, user_data_str):
        pass

    @abc.abstractmethod
    def keep_lease_alive(self, lease):
        pass

    @abc.abstractmethod
    def export_to_ovf(self, vm, target_path, ovf_name=None):
        pass

    @abc.abstractmethod
    def convert_ovf_to_ova(self, ovftool_path, ovf_path):
        pass

    @abc.abstractmethod
    def convert_ova_to_ovf(self, ovftool_path, ova_path):
        pass

    @abc.abstractmethod
    def get_ovf_descriptor(self, ovf_path):
        pass

    @abc.abstractmethod
    def upload_ovf_to_vcenter(self, target_path, ovf_name):
        pass

    @abc.abstractmethod
    def get_vm_name(self, vm):
        pass

    @abc.abstractmethod
    def get_disk_name(self, disk):
        pass

    def set_teardown(self, no_teardown):
        self.no_teardown = no_teardown

    def set_thin_disk(self, thin_disk):
        self.thindisk = thin_disk

    def set_eager_scrub(self, eager_scrub):
        self.eagerscrub = eager_scrub

class VmodlExceptionChecker(RetryExceptionChecker):
    def __init__(self, message):
        self.message = None

    def is_expected(self, exception):
        if isinstance(exception, TimeoutError):
            log.info("vCenter connection timed out, trying again")
            return True
        if isinstance(exception, ssl.SSLError):
            return True
        if isinstance(exception, vmodl.MethodFault):
            if ("STREAM ioctl timeout" in exception.msg):
                log.info("Stream IOCTL timeout, retrying")
                return True
            if ("Device timeout" in exception.msg):
                log.info("Device timeout, retrying")
                return True
            if ("Timer expired" in exception.msg):
                log.info("Timer expired, retrying")
                return True
        return False


class VCenterService(BaseVCenterService):
    def __init__(self, host, user, password, port,
                 datacenter_name, datastore_name, esx_host,
                 cluster_name, no_of_cpus, memoryGB, session_id):
        super(VCenterService, self).__init__(
            host, user, password, port, datacenter_name, datastore_name,
            esx_host, cluster_name, no_of_cpus, memoryGB, session_id)

    @timeout(30)
    def _s_connect(self):
        context = None
        try:
            context = ssl.SSLContext
        except:
            context = None
        if (context is not None):
            # Change ssl context due to bug in pyvmomi
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode = ssl.CERT_NONE
            self.si = connect.SmartConnect(host=self.host,
                                           user=self.user,
                                           pwd=self.password,
                                           port=self.port,
                                           sslContext=context)
        else:
            self.si = connect.SmartConnect(host=self.host,
                                           user=self.user,
                                           pwd=self.password,
                                           port=self.port)
        atexit.register(connect.Disconnect, self.si)

    def connect(self):
        try:
            retry(self._s_connect,
                  exception_checker=VmodlExceptionChecker(None),
                  timeout=1000,
                  initial_sleep_seconds=15)()
        except vmodl.MethodFault as error:
            log.exception("Caught vmodl fault : %s", error.msg)
            raise

        # set datastore name
        if self.datastore_name is None:
            content = self.si.RetrieveContent()
            datastore = self.__get_obj(content, [vim.Datastore], None)
            self.datastore_name = datastore.info.name
            self.datastore_path = "[" + self.datastore_name + "] "

    def disconnect(self):
        connect.Disconnect(self.si)
        self.si = None

    def connected(self):
        if self.si is None:
            return False
        return True

    def get_session_id(self):
        return self.session_id

    def get_datastore_path(self, vmdk_name):
        if vmdk_name is None:
            return None
        vmdk_path = self.datastore_path + vmdk_name
        return vmdk_path

    def __get_obj(self, content, vimtype, name):
        obj = None
        container = content.viewManager.CreateContainerView(
            content.rootFolder, vimtype, True)
        for c in container.view:
            if name:
                if c.name == name:
                    obj = c
                    break
            else:
                obj = c
                break
        return obj

    def __wait_for_task(self, task):
        while True:
            if task.info.state == 'success':
                return task.info.result
            if task.info.state == 'error':
                raise Exception('Task failed to finish with error %s' %
                                task.info.error)

    def find_vm(self, vm_name):
        content = self.si.RetrieveContent()
        vm = self.__get_obj(content, [vim.VirtualMachine], vm_name)
        return vm

    def power_on(self, vm):
        if format(vm.runtime.powerState) == "poweredOn":
            return
        task = vm.PowerOnVM_Task()
        self.__wait_for_task(task)

    def power_off(self, vm):
        if format(vm.runtime.powerState) != "poweredOn":
            return
        task = vm.PowerOffVM_Task()
        self.__wait_for_task(task)

    def destroy_vm(self, vm):
        log.info("Destroying VM %s", vm.config.name)
        content = self.si.RetrieveContent()
        f = self.si.content.fileManager
        vm_disk_name = vm.config.name.replace(':', '_')
        self.power_off(vm)
        vm.UnregisterVM()
        if self.esx_host:
            vm_disk_url = "https://" + self.host + "/folder/" + vm_disk_name + "?dsName=" + self.datastore_name
            task = f.DeleteDatastoreFile_Task(vm_disk_url)
        else:
            vm_disk_name = self.datastore_path + vm_disk_name
            datacenter = self.__get_obj(content, [vim.Datacenter],
                                        self.datacenter_name)
            task = f.DeleteDatastoreFile_Task(vm_disk_name, datacenter)
        self.__wait_for_task(task)

    def get_ip_address(self, vm):
        retry = 0
        while (vm.guest.ipAddress is None):
            if retry > 60:
                raise Exception('Cannot get VMs IP address')
            time.sleep(10)
            retry = retry + 1
        return (vm.guest.ipAddress)

    def create_vm(self, memoryGB=1, numCPUs=1,
                  network_name="VM Network"):
        content = self.si.RetrieveContent()
        datacenter = self.__get_obj(content, [vim.Datacenter],
                                    self.datacenter_name)
        vmfolder = datacenter.vmFolder
        if self.esx_host:
            cluster = self.__get_obj(content, [vim.ComputeResource], None)
        else:
            cluster = self.__get_obj(content, [vim.ClusterComputeResource],
                                     self.cluster_name)
        pool = cluster.resourcePool
        timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
        vm_name = "VM-" + timestamp
        vmx_file = vim.vm.FileInfo(logDirectory=None,
                                   snapshotDirectory=None,
                                   suspendDirectory=None,
                                   vmPathName=self.datastore_path)
        dev_changes = []
        # Add SCSI controller
        controller = vim.vm.device.VirtualLsiLogicController()
        controller.key = -1
        controller.sharedBus = \
            vim.vm.device.VirtualSCSIController.Sharing.noSharing
        controller.hotAddRemove = True
        controller.busNumber = 0
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        disk_spec.device = controller
        dev_changes.append(disk_spec)
        # Add network interface
        n_intf = vim.vm.device.VirtualVmxnet3()
        n_intf.key = -1
        n_intf.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
        n_intf.backing.deviceName = network_name
        disk_spec_2 = vim.vm.device.VirtualDeviceSpec()
        disk_spec_2.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        disk_spec_2.device = n_intf
        dev_changes.append(disk_spec_2)
        # Create the VM
        config = vim.vm.ConfigSpec(name=vm_name,
                                   memoryMB=(memoryGB*1024),
                                   numCPUs=numCPUs,
                                   files=vmx_file,
                                   guestId='otherGuest64',
                                   version='vmx-11',
                                   deviceChange=dev_changes)
        task = vmfolder.CreateVM_Task(config=config, pool=pool)
        self.__wait_for_task(task)
        log.info("VM %s created", vm_name)
        content = self.si.RetrieveContent()
        vm = self.__get_obj(content, [vim.VirtualMachine], vm_name)
        return vm

    def reconfigure_vm_cpu_ram(self, vm):
        vm_name = vm.config.name
        spec = vim.vm.ConfigSpec(name=vm_name,
                                 memoryMB=(1024*int(self.memoryGB)),
                                 numCPUs=int(self.no_of_cpus))
        task = vm.ReconfigVM_Task(spec=spec)
        self.__wait_for_task(task)

    def add_serial_port_to_file(self, vm, filename):
        content = self.si.RetrieveContent()
        spec = vim.vm.ConfigSpec()
        port_spec = vim.vm.device.VirtualDeviceSpec()
        port_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        sport = vim.vm.device.VirtualSerialPort()
        sport.key = -1
        sport.backing = vim.vm.device.VirtualSerialPort.FileBackingInfo()
        sport.backing.fileName = self.get_datastore_path(filename)
        datastore = self.__get_obj(content, [vim.Datastore],
                                   self.datastore_name)
        sport.backing.datastore = datastore
        port_spec.device = sport
        dev_changes = []
        dev_changes.append(port_spec)
        spec.deviceChange = dev_changes
        task = vm.ReconfigVM_Task(spec=spec)
        self.__wait_for_task(task)
        log.info("Console messages will be dumped to file %s", filename)

    def delete_serial_port_to_file(self, vm, filename):
        delete_device = None
        backing_filename = self.get_datastore_path(filename)
        for device in vm.config.hardware.device:
            if (isinstance(device, vim.vm.device.VirtualSerialPort)):
                if device.backing.fileName == backing_filename:
                    delete_device = device
        if (delete_device is None):
            return
        spec = vim.vm.ConfigSpec()
        dev_changes = []
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
        disk_spec.device = delete_device
        dev_changes.append(disk_spec)
        spec.deviceChange = dev_changes
        task = vm.ReconfigVM_Task(spec=spec)
        self.__wait_for_task(task)
        log.info("Console message will no longer be dumped to file %s",
                 filename)

    def add_disk(self, vm, disk_size=12*1024*1024,
                 filename=None, unit_number=0):
        spec = vim.vm.ConfigSpec()
        controller = None
        for dev in vm.config.hardware.device:
            if isinstance(dev, vim.vm.device.VirtualSCSIController):
                controller = dev
                break
        if controller is None:
            raise Exception("Did not find SCSI controller in the "
                            "Encryptor VM %s" % (vm.config.name,))
        dev_changes = []
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        disk_spec.device = vim.vm.device.VirtualDisk()
        disk_spec.device.backing = \
            vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
        if filename is not None:
            disk_spec.device.backing.fileName = filename
            disk_spec.device.capacityInKB = -1
        else:
            disk_spec.device.capacityInKB = disk_size
            disk_spec.device.backing.thinProvisioned = self.thindisk
            if self.thindisk is False:
                disk_spec.device.backing.eagerlyScrub = self.eagerscrub
            disk_spec.fileOperation = "create"
        disk_spec.device.backing.diskMode = 'persistent'
        disk_spec.device.unitNumber = unit_number
        disk_spec.device.controllerKey = controller.key
        dev_changes.append(disk_spec)
        spec.deviceChange = dev_changes
        task = vm.ReconfigVM_Task(spec=spec)
        self.__wait_for_task(task)
        if (filename):
            log.info("%s disk added to VM %s", filename, vm.config.name)
        else:
            log.info("%dKB empty disk added to %s", disk_size, vm.config.name)

    def detach_disk(self, vm, unit_number=2):
        delete_device = None
        for device in vm.config.hardware.device:
            if (isinstance(device, vim.vm.device.VirtualDisk)):
                if (device.unitNumber == unit_number):
                    delete_device = device
        if (delete_device is None):
            log.error("No disk found at %d in VM to detach",
                      unit_number, vm.config.name)
            return
        spec = vim.vm.ConfigSpec()
        dev_changes = []
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
        disk_spec.device = delete_device
        dev_changes.append(disk_spec)
        spec.deviceChange = dev_changes
        task = vm.ReconfigVM_Task(spec=spec)
        self.__wait_for_task(task)
        log.info("Disk at %d detached from VM %s",
                 unit_number, vm.config.name)
        return delete_device

    def clone_disk(self, source_disk, dest_disk=None, dest_disk_name=None):
        content = self.si.RetrieveContent()
        source_disk_name = source_disk.backing.fileName
        if (dest_disk_name is None):
            if (dest_disk is None):
                raise Exception("Cannot clone disk as destination "
                                "not specified")
            source = source_disk_name.split("/")
            dest = dest_disk.backing.fileName.split("/")
            dest_disk_name = source[0] + "/" + dest[1]
        virtualDiskManager = self.si.content.virtualDiskManager
        if self.esx_host:
            source_disk_url = "https://" + self.host + "/folder/" + source_disk_name + "?dsName=" + self.datastore_name
            dest_disk_url = "https://" + self.host + "/folder/" + dest_disk_name + "?dsName=" + self.datastore_name
            task = virtualDiskManager.CopyVirtualDisk(
                source_disk_url, None,
                dest_disk_url, None)
        else:
            datacenter = self.__get_obj(content, [vim.Datacenter],
                                        self.datacenter_name)
            task = virtualDiskManager.CopyVirtualDisk(
                source_disk_name,
                datacenter,
                dest_disk_name,
                datacenter)
        self.__wait_for_task(task)
        return dest_disk_name

    def get_disk(self, vm, unit_number):
        for device in vm.config.hardware.device:
            if (isinstance(device, vim.vm.device.VirtualDisk)):
                if (device.unitNumber == unit_number):
                    return device
        return None

    def get_disk_size(self, vm, unit_number):
        for device in vm.config.hardware.device:
            if (isinstance(device, vim.vm.device.VirtualDisk)):
                if (device.unitNumber == unit_number):
                    s = (device.deviceInfo.summary.split())[0]
                    size = int(s.replace(',', ''))
                    return size
        raise Exception("Did not find disk at %d of VM %s" %
                        (unit_number, vm.config.name))

    def clone_vm(self, vm, powerOn=False, vm_name=None, template=False):
        if self.esx_host:
            log.error("Cannot create template VM when connected to ESX host")
            return None
        content = self.si.RetrieveContent()
        datacenter = self.__get_obj(content, [vim.Datacenter],
                                    self.datacenter_name)
        destfolder = datacenter.vmFolder
        cluster = self.__get_obj(content, [vim.ClusterComputeResource],
                                 self.cluster_name)
        pool = cluster.resourcePool
        datastore = self.__get_obj(content, [vim.Datastore],
                                   self.datastore_name)
        relospec = vim.vm.RelocateSpec()
        relospec.datastore = datastore
        relospec.pool = pool
        clonespec = vim.vm.CloneSpec()
        clonespec.location = relospec
        clonespec.powerOn = powerOn
        clonespec.template = template
        if (vm_name is None):
            timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
            vm_name = "template-vm-" + timestamp
        task = vm.Clone(folder=destfolder, name=vm_name, spec=clonespec)
        self.__wait_for_task(task)
        vm = self.__get_obj(content, [vim.VirtualMachine], vm_name)
        return vm

    def create_userdata_str(self, instance_config, update=False,
                            ssh_key_file=None,
                            rescue_proto=None, rescue_url=None):
        try:
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
            if instance_config:
                instance_config.set_brkt_config(brkt_config)
                return instance_config.make_userdata()
            return json.dumps({'brkt': brkt_config})
        except Exception as e:
            log.exception("Failed to create user-data %s" % e)
            raise

    def send_userdata(self, vm, user_data_str):
        spec = vim.vm.ConfigSpec()
        option_n = vim.option.OptionValue()
        spec.extraConfig = []
        option_n.key = 'guestinfo.bracket'
        option_n.value = user_data_str
        spec.extraConfig.append(option_n)
        task = vm.ReconfigVM_Task(spec)
        self.__wait_for_task(task)

    def keep_lease_alive(self, lease):
        while(True):
            time.sleep(5)
            try:
                # Choosing arbitrary percentage to keep the lease alive.
                lease.HttpNfcLeaseProgress(50)
                if (lease.state == vim.HttpNfcLease.State.done):
                    return
                # If the lease is released, we get an exception.
                # Returning to kill the thread.
            except:
                return

    def export_to_ovf(self, vm, target_path, ovf_name=None):
        if (os.path.exists(target_path) is False):
            raise Exception("OVF target path does not exist")
        if (ovf_name is None):
            timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
            timestamp = timestamp.replace(':', '_')
            timestamp = timestamp.replace('.', '_')
            ovf_name = "Encrypted-Guest-OVF-" + timestamp
        ovf_file_name = ovf_name + ".ovf"
        lease = vm.ExportVm()
        while (True):
            hls = lease.state
            if (hls == vim.HttpNfcLease.State.ready):
                break
            if (hls == vim.HttpNfcLease.State.error):
                log.error("Lease not obtained to create OVF. "
                          "Error %s" % lease.error)
                raise Exception("Failed to get lease to create OVF")
        lease_info = lease.info
        lease_info.leaseTimeout = 10000
        dev_urls = lease_info.deviceUrl
        ovf_files = []
        try:
            for url in dev_urls:
                devid = url.key
                devurl = url.url
                if self.esx_host:
                    host_name = "https://" + self.host
                    devurl = url.url.replace("https://*", host_name)
                file_name = url.url[url.url.rfind('/') + 1:]
                target_file = os.path.join(target_path, file_name)
                keepalive_thread = Thread(target=self.keep_lease_alive,
                                          args=(lease,))
                keepalive_thread.start()
                curl_cmd = (
                    "curl -Ss -X GET %s --insecure -H 'Content-Type: \
                    application/x-vnd.vmware-streamVmdk' -o %s" %
                    (devurl, target_file))
                os.system(curl_cmd)
                size = os.path.getsize(target_file)
                ovf_file = vim.OvfManager.OvfFile()
                ovf_file.deviceId = devid
                ovf_file.path = target_file
                ovf_file.size = size
                ovf_files.append(ovf_file)
            desc = vim.OvfManager.CreateDescriptorParams()
            desc.ovfFiles = ovf_files
            manager = self.si.content.ovfManager
            desc_result = manager.CreateDescriptor(vm, desc)
            ovf_path = os.path.join(target_path, ovf_file_name)
            with open(ovf_path, 'w') as f:
                f.write(desc_result.ovfDescriptor)
        except Exception as e:
            log.error("Exception while creating OVF %s" % e)
            raise
        finally:
            lease.HttpNfcLeaseComplete()
        return ovf_path

    def convert_ovf_to_ova(self, ovftool_path, ovf_path):
        ova_list = list(ovf_path)
        ova_list[len(ova_list)-1] = 'a'
        ova_path = "".join(ova_list)
        ovftool_cmd = ovftool_path + " " + ovf_path + " " + ova_path
        os.system(ovftool_cmd)
        return ova_path

    def convert_ova_to_ovf(self, ovftool_path, ova_path):
        ovf_list = list(ova_path)
        ovf_list[len(ovf_list)-1] = 'f'
        ovf_path = "".join(ovf_list)
        ovftool_cmd = ovftool_path + " " + ova_path + " " + ovf_path
        os.system(ovftool_cmd)
        return ovf_path

    def get_ovf_descriptor(self, ovf_path):
        if os.path.exists(ovf_path):
            with open(ovf_path, 'r') as f:
                ovfd = f.read()
                f.close()
                return ovfd
        return None

    def upload_ovf_to_vcenter(self, target_path, ovf_name):
        vm = None
        content = self.si.RetrieveContent()
        manager = self.si.content.ovfManager
        # Load checksums for each file
        mf_checksum = None
        mf_file_name = ovf_name[:ovf_name.find(".ovf")] + ".mf"
        mf_path = os.path.join(target_path, mf_file_name)
        with open(mf_path, 'r') as mf_file:
            mf_checksum = json.load(mf_file)
        # Validate ovf file
        ovf_path = os.path.join(target_path, ovf_name)
        ovf_checksum = mf_checksum[(os.path.split(ovf_path))[1]]
        if ovf_checksum != compute_sha1_of_file(ovf_path):
            raise ValidationError("OVF file checksum does not match. "
                                  "Validate the Metavisor OVF image.")
        # Load the OVF file
        spec_params = vim.OvfManager.CreateImportSpecParams()
        ovfd = self.get_ovf_descriptor(ovf_path)
        datacenter = self.__get_obj(content, [vim.Datacenter],
                                    self.datacenter_name)
        datastore = self.__get_obj(content, [vim.Datastore],
                                   self.datastore_name)
        if self.esx_host:
            cluster = self.__get_obj(content, [vim.ComputeResource], None)
        else:
            cluster = self.__get_obj(content, [vim.ClusterComputeResource],
                                     self.cluster_name)
        resource_pool = cluster.resourcePool
        destfolder = datacenter.vmFolder
        import_spec = manager.CreateImportSpec(ovfd,
                                               resource_pool,
                                               datastore,
                                               spec_params)
        timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
        vm_name = "Encryptor-VM-" + timestamp
        import_spec.importSpec.configSpec.name = vm_name
        lease = resource_pool.ImportVApp(import_spec.importSpec, destfolder)
        while (True):
            hls = lease.state
            if (hls == vim.HttpNfcLease.State.ready):
                break
            if (hls == vim.HttpNfcLease.State.error):
                log.error("Lease not obtained to upload OVF. "
                          "Error %s" % lease.error)
                vm = self.__get_obj(content, [vim.VirtualMachine], vm_name)
                if vm:
                    self.destroy_vm(vm)
                raise Exception("Failed to get lease to upload OVF")
        keepalive_thread = Thread(target=self.keep_lease_alive, args=(lease,))
        keepalive_thread.start()
        try:
            count = 0
            for device_url in lease.info.deviceUrl:
                d_file_name = (os.path.split(import_spec.fileItem[count].path))[1]
                file_path = os.path.join(target_path,
                                         import_spec.fileItem[count].path)
                if os.path.exists(file_path) is False:
                    # lets try getting the fine-name from url
                    file_name = device_url.url[device_url.url.rfind('/') + 1:]
                    file_path = os.path.join(target_path, file_name)
                if os.path.exists(file_path) is False:
                    log.error("Cannot find disk %s" % (device_url.url))
                    vm = self.__get_obj(content, [vim.VirtualMachine], vm_name)
                    if vm:
                        lease.HttpNfcLeaseComplete()
                        self.destroy_vm(vm)
                    raise Exception("Failed to find VMDKs for the Metavisor OVF")
                # Validate the checksum of the file
                file_checksum = mf_checksum[d_file_name]
                if file_checksum != compute_sha1_of_file(file_path):
                    raise ValidationError("Disk file %s checksum does not match. "
                                          "Validate the Metavisor OVF image."
                                          % d_file_name)
                count = count + 1
                dev_url = device_url.url
                if self.esx_host:
                    host_name = "https://" + self.host
                    dev_url = device_url.url.replace("https://*", host_name)
                curl_cmd = (
                    "curl -Ss -X POST --insecure -T %s -H 'Content-Type: \
                    application/x-vnd.vmware-streamVmdk' %s" %
                    (file_path, dev_url))
                os.system(curl_cmd)
            vm = self.__get_obj(content, [vim.VirtualMachine], vm_name)
        except Exception as e:
            log.error("Exception while uploading OVF %s" % e)
            vm = self.__get_obj(content, [vim.VirtualMachine], vm_name)
            if vm:
                lease.HttpNfcLeaseComplete()
                self.destroy_vm(vm)
            raise
        finally:
            if (lease.state != vim.HttpNfcLease.State.done):
                lease.HttpNfcLeaseComplete()
        return vm

    def get_vm_name(self, vm):
        return vm.config.name

    def get_disk_name(self, disk):
        return disk.backing.fileName

def initialize_vcenter(host, user, password, port,
                       datacenter_name, datastore_name, esx_host,
                       cluster_name, no_of_cpus, memory_gb, session_id):
    vc_swc = VCenterService(host, user, password, port,
                            datacenter_name, datastore_name, esx_host,
                            cluster_name, no_of_cpus, memory_gb, session_id)
    vc_swc.connect()
    return vc_swc


def download_ovf_from_s3(bucket_name, image_name=None):
    log.info("Fetching Metavisor OVF from S3")
    if bucket_name is None:
        log.error("Bucket-name is unknown, cannot get metavisor OVF")
        raise Exception("Invalid bucket-name")
    ovf_name = None
    download_file_list = []
    try:
        conn = boto.connect_s3(None, None, anon=True,
                               host="s3.amazonaws.com")
        bucket = boto.s3.bucket.Bucket(connection=conn, name=bucket_name)
        if (image_name is None):
            # Get the last one
            c_list = list(bucket.list("", "/"))
            dir_list = []
            for content in c_list:
                dir_name = str(content.name)
                if "release" in dir_name:
                    dir_list.append(dir_name)
            image_name = (sorted(dir_list))[len(dir_list)-1]
        file_list_obj = list(bucket.list(image_name))
        if len(file_list_obj) is 0:
            log.error("Directory %s in bucket %s is empty." % (image_name,
                     bucket_name))
            return (None, None)
        file_list = []
        for content in file_list_obj:
            file_list.append(str(content.name))
        for file in file_list:
            file_name = file[file.rfind('/')+1:]
            target_file = os.path.join("./", file_name)
            certificate = Key(bucket)
            certificate.key = file
            certificate.get_contents_to_filename(target_file)
            if (".ovf" in file_name):
                ovf_name = target_file
            download_file_list.append(target_file)
        if ovf_name is None:
            log.error("No OVF file in directory %s in bucket "
                     "%s" % (image_name, bucket_name))
            return (None, None)
        return (ovf_name, download_file_list)
    except Exception as e:
        log.exception("Exception downloading OVF from S3 %s" % e)
        raise


def launch_mv_vm_from_s3(vc_swc, ovf_name, download_file_list):
    # Launch OVF
    log.info("Launching VM from OVF %s", ovf_name)
    vm = vc_swc.upload_ovf_to_vcenter("./", ovf_name)
    # Clean up the downloaded files
    for file_name in download_file_list:
        rm_cmd = "rm -f %s" % (file_name)
        os.system(rm_cmd)
    return vm
