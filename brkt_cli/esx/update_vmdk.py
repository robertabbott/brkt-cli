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
import logging
import os
from brkt_cli.encryptor_service import (
    wait_for_encryptor_up,
    wait_for_encryption,
    ENCRYPTOR_STATUS_PORT
)
from brkt_cli.util import Deadline
from brkt_cli.esx.esx_service import launch_mv_vm_from_s3


log = logging.getLogger(__name__)


def update_ovf_image_mv_vm(vc_swc, enc_svc_cls, guest_vm, mv_vm,
                           template_vm_name, target_path, ovf_name,
                           ova_name, ovftool_path, user_data_str,
                           status_port=ENCRYPTOR_STATUS_PORT):
    try:
        # Reconfigure VM with more CPUs and memory
        vc_swc.reconfigure_vm_cpu_ram(mv_vm)
        # Power on the MV VM and wait for encryption
        vc_swc.power_on(mv_vm)
        # Send user data
        vc_swc.send_userdata(mv_vm, user_data_str)
        ip_addr = vc_swc.get_ip_address(mv_vm)
        log.info("MV VM ip address is %s", ip_addr)
        # wait for encryption to complete
        host_ips = [ip_addr]
        enc_svc = enc_svc_cls(host_ips, port=status_port)
        log.info('Waiting for updater service on port %s on %s',
                 enc_svc.port, ', '.join(host_ips))
        wait_for_encryptor_up(enc_svc, Deadline(600))
        try:
            wait_for_encryption(enc_svc)
        except Exception as e:
            log.exception("Update failed with error %s", e)
            raise
        # Power off the VMs
        vc_swc.power_off(guest_vm)
        vc_swc.power_off(mv_vm)
        # Detach disks from guest_vm
        guest_old_disk = vc_swc.detach_disk(guest_vm, unit_number=1)
        mv_old_disk = vc_swc.detach_disk(guest_vm, unit_number=0)
        # Get the new MV disk
        new_disk = vc_swc.get_disk(mv_vm, unit_number=0)
        # Clone and attach new MV disk to guest VM
        log.info("Cloning Metavisor disk")
        u_disk_name = vc_swc.clone_disk(new_disk, dest_disk=mv_old_disk)
        # Add disks to guest VM
        vc_swc.add_disk(guest_vm, filename=u_disk_name, unit_number=0)
        vc_swc.add_disk(guest_vm, filename=vc_swc.get_disk_name(guest_old_disk),
                        unit_number=1)
        if ((ovf_name) or (ova_name)):
            if(ova_name):
                ovf_name = ova_name
            log.info("Creating images")
            if target_path is None:
                raise Exception("Cannot create ova/ovf as target path is None")
            if (ova_name):
                # delete the old mf file
                rm_cmd = "rm -f %s" % (os.path.join(target_path,
                                                    ova_name + ".mf"))
                os.system(rm_cmd)
            # import the new OVF
            ovf = vc_swc.export_to_ovf(guest_vm, target_path, ovf_name=ovf_name)
            if ova_name:
                if ovftool_path is not None:
                    # delete the old ova
                    rm_cmd = "rm -f %s" % (os.path.join(target_path,
                                                        ova_name + ".ova"))
                    os.system(rm_cmd)
                    ova = vc_swc.convert_ovf_to_ova(ovftool_path, ovf)
                    print(ova)
            else:
                print(ovf)
        else:
            # delete the old vm template
            log.info("Deleting the old template")
            template_vm = vc_swc.find_vm(template_vm_name)
            if (template_vm):
                vc_swc.destroy_vm(template_vm)
            # clone the vm to create template
            log.info("Creating the template VM")
            template_vm = vc_swc.clone_vm(guest_vm, vm_name=template_vm_name,
                                          template=True)
            print(vc_swc.get_vm_name(template_vm))
    except Exception as e:
        log.exception("Failed to update the image with error %s", e)
        raise
    finally:
        vc_swc.destroy_vm(guest_vm)
        vc_swc.destroy_vm(mv_vm)
    log.info("Done")


def launch_guest_vm(vc_swc, template_vm_name, target_path, ovf_name,
                    ova_name, ovftool_path):
    log.info("Launching encrypted guest VM")
    if template_vm_name:
        template_vm = vc_swc.find_vm(template_vm_name)
        vm = vc_swc.clone_vm(template_vm)
    elif ova_name:
        ova = os.path.join(target_path, ova_name + ".ova")
        vc_swc.convert_ova_to_ovf(ovftool_path, ova)
        ovf_name = ova_name + ".ovf"
        vm = vc_swc.upload_ovf_to_vcenter(target_path, ovf_name)
    elif ovf_name:
        vm = vc_swc.upload_ovf_to_vcenter(target_path, ovf_name + ".ovf")
    else:
        log.error("Cannot launch guest VM without template VM/OVF/OVA")
        vm = None
    return vm


def update_from_s3(vc_swc, enc_svc_cls, template_vm_name=None,
                   target_path=None, ovf_name=None, ova_name=None,
                   ovftool_path=None, mv_ovf_name=None,
                   download_file_list=None, user_data_str=None,
                   status_port=ENCRYPTOR_STATUS_PORT):
    guest_vm = None
    mv_vm = None
    try:
        guest_vm = launch_guest_vm(vc_swc, template_vm_name, target_path,
                                   ovf_name, ova_name, ovftool_path)
    except Exception as e:
        log.exception("Failed to lauch guest VM (%s)", e)
        if (guest_vm is not None):
            vc_swc.destroy_vm(guest_vm)
        raise
    try:
        if (mv_ovf_name is None or download_file_list is None):
            log.error("Cannot get metavisor OVF from S3")
            raise Exception("Invalid MV OVF")
        mv_vm = launch_mv_vm_from_s3(vc_swc, mv_ovf_name, download_file_list)
    except Exception as e:
        log.exception("Failed to launch metavisor OVF from S3 (%s)", e)
        if (mv_vm is not None):
            vc_swc.destroy_vm(mv_vm)
        if (guest_vm is not None):
            vc_swc.destroy_vm(guest_vm)
        raise
    update_ovf_image_mv_vm(vc_swc, enc_svc_cls, guest_vm, mv_vm,
                           template_vm_name, target_path, ovf_name,
                           ova_name, ovftool_path, user_data_str, status_port)


def update_from_local_ovf(vc_swc, enc_svc_cls, template_vm_name=None,
                          target_path=None, ovf_name=None, ova_name=None,
                          ovftool_path=None, source_image_path=None,
                          ovf_image_name=None, user_data_str=None,
                          status_port=ENCRYPTOR_STATUS_PORT):
    guest_vm = None
    mv_vm = None
    if ((source_image_path is None) or
        (ovf_image_name is None)):
        log.error("Metavisor OVF path needs to be specified")
        return
    try:
        guest_vm = launch_guest_vm(vc_swc, template_vm_name, target_path,
                                   ovf_name, ova_name, ovftool_path)
    except Exception as e:
        log.exception("Failed to lauch guest VM (%s)", e)
        if (guest_vm is not None):
            vc_swc.destroy_vm(guest_vm)
        raise
    try:
        log.info("Launching MV VM from local OVF")
        mv_vm = vc_swc.upload_ovf_to_vcenter(source_image_path,
                                             ovf_image_name)
    except Exception as e:
        log.exception("Failed to launch from metavisor OVF (%s)", e)
        if (mv_vm is not None):
            vc_swc.destroy_vm(mv_vm)
        if (guest_vm is not None):
            vc_swc.destroy_vm(guest_vm)
        raise
    update_ovf_image_mv_vm(vc_swc, enc_svc_cls, guest_vm, mv_vm,
                           template_vm_name, target_path, ovf_name,
                           ova_name, ovftool_path, user_data_str, status_port)


def update_from_vmdk(vc_swc, enc_svc_cls, template_vm_name=None,
                     target_path=None, ovf_name=None, ova_name=None,
                     ovftool_path=None, metavisor_vmdk=None,
                     user_data_str=None, status_port=ENCRYPTOR_STATUS_PORT):
    guest_vm = None
    mv_vm = None
    if (metavisor_vmdk is None):
        log.error("Metavisor VMDK is not specified")
        return
    try:
        guest_vm = launch_guest_vm(vc_swc, template_vm_name, target_path,
                                   ovf_name, ova_name, ovftool_path)
    except Exception as e:
        log.exception("Failed to lauch guest VM (%s)", e)
        if (guest_vm is not None):
            vc_swc.destroy_vm(guest_vm)
        raise
    try:
        # Add datastore path to the vmdk
        metavisor_vmdk_path = vc_swc.get_datastore_path(metavisor_vmdk)
        # Create a metavisor VM
        vm = vc_swc.create_vm()
        # Attach metavisor vmdk as root disk
        vc_swc.add_disk(vm, filename=metavisor_vmdk_path, unit_number=0)
    except Exception as e:
        log.exception("Failed to launch metavisor VMDK (%s)", e)
        if (mv_vm is not None):
            vc_swc.destroy_vm(mv_vm)
        if (guest_vm is not None):
            vc_swc.destroy_vm(guest_vm)
        raise
    update_ovf_image_mv_vm(vc_swc, enc_svc_cls, guest_vm, mv_vm,
                           template_vm_name, target_path, ovf_name,
                           ova_name, ovftool_path, user_data_str, status_port)
