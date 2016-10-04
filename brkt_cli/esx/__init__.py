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
import brkt_cli
import logging
import os
import subprocess

from brkt_cli.subcommand import Subcommand

from brkt_cli import (
    encryptor_service,
    util
)
from brkt_cli.instance_config import (
    INSTANCE_CREATOR_MODE,
    INSTANCE_UPDATER_MODE
)
from brkt_cli.instance_config_args import (
    instance_config_from_values,
    setup_instance_config_args
)

from brkt_cli.esx import (
    encrypt_vmdk,
    encrypt_vmdk_args,
    esx_service,
    rescue_metavisor,
    rescue_metavisor_args,
    update_vmdk,
    update_encrypted_vmdk_args,
)
from brkt_cli.validation import ValidationError

log = logging.getLogger(__name__)


def _check_env_vars_set(*var_names):
    for n in var_names:
        if not os.getenv(n):
            raise ValidationError("Environment variable %s is not set" % (n,))


class EncryptVMDKSubcommand(Subcommand):

    def name(self):
        return 'encrypt-vmdk'

    def register(self, subparsers, parsed_config):
        self.config = parsed_config
        encrypt_vmdk_parser = subparsers.add_parser(
            'encrypt-vmdk',
            description='Create an encrypted VMDK from an existing VMDK',
            help='Encrypt a VMDK',
            formatter_class=brkt_cli.SortingHelpFormatter
        )
        encrypt_vmdk_args.setup_encrypt_vmdk_args(
            encrypt_vmdk_parser)
        setup_instance_config_args(encrypt_vmdk_parser)

    def run(self, values):
        return _run_subcommand(self.name(), values, self.config)


class UpdateVMDKSubcommand(Subcommand):

    def name(self):
        return 'update-vmdk'

    def register(self, subparsers, parsed_config):
        self.config = parsed_config
        update_encrypted_vmdk_parser = subparsers.add_parser(
            'update-vmdk',
            description='Update an encrypted VMDK with the latest Metavisor',
            help='Update an encrypted VMDK',
            formatter_class=brkt_cli.SortingHelpFormatter
        )
        update_encrypted_vmdk_args.setup_update_vmdk_args(
            update_encrypted_vmdk_parser)
        setup_instance_config_args(update_encrypted_vmdk_parser)

    def run(self, values):
        return _run_subcommand(self.name(), values, self.config)

class RescueMetavisorSubcommand(Subcommand):

    def name(self):
        return 'rescue-metavisor'

    def register(self, subparsers, parsed_config):
        self.config = parsed_config
        rescue_metavisor_parser = subparsers.add_parser(
            'rescue-metavisor',
            description=(
                'Upload a Metavisor VM cores and diagonstics to an URL'
            ),
            help='Upload Metavisor VM and cores to URL',
            formatter_class=brkt_cli.SortingHelpFormatter
        )
        rescue_metavisor_args.setup_rescue_metavisor_args(rescue_metavisor_parser)

    def run(self, values):
        return _run_subcommand(self.name(), values, self.config)


def get_subcommands():
    return [EncryptVMDKSubcommand(),
            UpdateVMDKSubcommand(),
            RescueMetavisorSubcommand()]


def _run_subcommand(subcommand, values, parsed_config):
    if subcommand == 'encrypt-vmdk':
        return command_encrypt_vmdk(values, parsed_config, log)
    if subcommand == 'update-vmdk':
        return command_update_encrypted_vmdk(values, parsed_config, log)
    if subcommand == 'rescue-metavisor':
        return command_rescue_metavisor(values, parsed_config, log)


def command_update_encrypted_vmdk(values, parsed_config, log):
    session_id = util.make_nonce()
    if (values.encrypted_ovf_name or values.encrypted_ova_name):
        # verify we have a valid input directory
        if (values.target_path is None):
            raise ValidationError("Missing directory path to fetch "
                                  "encrypted OVF/OVA images from")
        if (values.encrypted_ovf_name):
            name = os.path.join(values.target_path,
                                values.encrypted_ovf_name + ".ovf")
            if (os.path.exists(name) is False):
                raise ValidationError("Encrypted OVF image not found at "
                                      "%s", name)
        else:
            name = os.path.join(values.target_path,
                                values.encrypted_ova_name + ".ova")
            if (os.path.exists(name) is False):
                raise ValidationError("Encrypted OVA image not found at "
                                      "%s", name)
            # verify ovftool is present
            try:
                cmd = [values.ovftool_path, '-v']
                subprocess.check_call(cmd)
            except:
                raise ValidationError("OVFtool not present. "
                                      "Cannot process OVA")
    else:
        if values.esx_host:
            raise ValidationError("Cannot use template VMs for "
                                  "updation on a single ESX host")
        if (values.template_vm_name is None):
            raise ValidationError("Encrypted image not provided")
    if (values.source_image_path is not None and values.image_name is None):
        raise ValidationError("Specify the Metavisor OVF file.")
    _check_env_vars_set('VCENTER_USER_NAME', 'VCENTER_PASSWORD')
    brkt_cli.validate_ntp_servers(values.ntp_servers)
    brkt_env = brkt_cli.brkt_env_from_values(values)
    if brkt_env is None:
        _, brkt_env = parsed_config.get_current_env()
    if not values.token:
        raise ValidationError('Must provide a token')

    # Download images from S3
    try:
        if (values.encryptor_vmdk is None and
            values.source_image_path is None):
            (ovf_name, download_file_list) = \
                esx_service.download_ovf_from_s3(
                    values.bucket_name,
                    image_name=values.image_name
                )
            if ovf_name is None:
                raise ValidationError("Did not find MV OVF images")
    except Exception as e:
        raise ValidationError("Failed to download MV image from S3: ", e)
    # Connect to vCenter
    try:
        vc_swc = esx_service.initialize_vcenter(
            host=values.vcenter_host,
            user=os.getenv('VCENTER_USER_NAME'),
            password=os.getenv('VCENTER_PASSWORD'),
            port=values.vcenter_port,
            datacenter_name=values.vcenter_datacenter,
            datastore_name=values.vcenter_datastore,
            esx_host=values.esx_host,
            cluster_name=values.vcenter_cluster,
            no_of_cpus=values.no_of_cpus,
            memory_gb=values.memory_gb,
            session_id=session_id,
        )
    except Exception as e:
        raise ValidationError("Failed to connect to vCenter: ", e)
    if values.template_vm_name:
        if vc_swc.find_vm(values.template_vm_name) is None:
            raise ValidationError("Template VM %s not found" %
                                  values.template_vm_name)
    try:
        instance_config = instance_config_from_values(
            values, mode=INSTANCE_UPDATER_MODE, cli_config=parsed_config)
        user_data_str = vc_swc.create_userdata_str(instance_config,
            update=True, ssh_key_file=values.ssh_public_key_file)
        if (values.encryptor_vmdk is not None):
            # Create from MV VMDK
            update_vmdk.update_from_vmdk(
                vc_swc, encryptor_service.EncryptorService,
                template_vm_name=values.template_vm_name,
                target_path=values.target_path,
                ovf_name=values.encrypted_ovf_name,
                ova_name=values.encrypted_ova_name,
                ovftool_path=values.ovftool_path,
                metavisor_vmdk=values.encryptor_vmdk,
                user_data_str=user_data_str,
                status_port=values.status_port,
            )
        elif (values.source_image_path is not None):
            # Create from MV OVF in local directory
            update_vmdk.update_from_local_ovf(
                vc_swc, encryptor_service.EncryptorService,
                template_vm_name=values.template_vm_name,
                target_path=values.target_path,
                ovf_name=values.encrypted_ovf_name,
                ova_name=values.encrypted_ova_name,
                ovftool_path=values.ovftool_path,
                source_image_path=values.source_image_path,
                ovf_image_name=values.image_name,
                user_data_str=user_data_str,
                status_port=values.status_port,
            )
        else:
            # Create from MV OVF in S3
            update_vmdk.update_from_s3(
                vc_swc, encryptor_service.EncryptorService,
                template_vm_name=values.template_vm_name,
                target_path=values.target_path,
                ovf_name=values.encrypted_ovf_name,
                ova_name=values.encrypted_ova_name,
                ovftool_path=values.ovftool_path,
                mv_ovf_name=ovf_name,
                download_file_list=download_file_list,
                user_data_str=user_data_str,
                status_port=values.status_port,
            )
        return 0
    except:
        log.error("Failed to update encrypted VMDK");
        return 1


def command_encrypt_vmdk(values, parsed_config, log):
    session_id = util.make_nonce()
    if ((values.create_ovf is True) or (values.create_ova is True)):
        # verify we have a valid output directory
        if (values.target_path is None):
            raise ValidationError("Missing directory path to store "
                                  "final OVF/OVA images")
        if (os.path.exists(values.target_path) is False):
            raise ValidationError("Target path %s not present",
                                  values.target_path)
        if (values.create_ova is True):
            # verify ovftool is present
            try:
                cmd = [values.ovftool_path, '-v']
                subprocess.check_call(cmd)
            except:
                raise ValidationError("OVFtool not present. "
                                      "Cannot create OVA")
    else:
        if values.esx_host is False and values.template_vm_name is None:
            raise ValidationError("Missing template-vm-name for the "
                                  "template VM")
    if (values.source_image_path is not None and values.image_name is None):
        raise ValidationError("Specify the Metavisor OVF file.")
    _check_env_vars_set('VCENTER_USER_NAME', 'VCENTER_PASSWORD')
    brkt_cli.validate_ntp_servers(values.ntp_servers)
    brkt_env = brkt_cli.brkt_env_from_values(values)
    if brkt_env is None:
        _, brkt_env = parsed_config.get_current_env()
    if not values.token:
        raise ValidationError('Must provide a token')
    # Download images from S3
    try:
        if (values.encryptor_vmdk is None and
            values.source_image_path is None):
            (ovf, file_list) = \
                esx_service.download_ovf_from_s3(
                    values.bucket_name,
                    image_name=values.image_name
                )
            if ovf is None:
                raise ValidationError("Did not find MV OVF images")
    except Exception as e:
        raise ValidationError("Failed to download MV image from S3: ", e)
    # Connect to vCenter
    try:
        vc_swc = esx_service.initialize_vcenter(
            host=values.vcenter_host,
            user=os.getenv('VCENTER_USER_NAME'),
            password=os.getenv('VCENTER_PASSWORD'),
            port=values.vcenter_port,
            datacenter_name=values.vcenter_datacenter,
            datastore_name=values.vcenter_datastore,
            esx_host=values.esx_host,
            cluster_name=values.vcenter_cluster,
            no_of_cpus=values.no_of_cpus,
            memory_gb=values.memory_gb,
            session_id=session_id,
        )
    except Exception as e:
        raise ValidationError("Failed to connect to vCenter: ", e)
    # Validate that template does not already exist
    if values.template_vm_name:
        if vc_swc.find_vm(values.template_vm_name):
            raise ValidationError("VM with the same name as requested "
                                  "template VM name %s already exists" %
                                  values.template_vm_name)
    # Set tear-down
    vc_swc.set_teardown(values.no_teardown)
    # Set the disk-type
    if values.disk_type == "thin":
        vc_swc.set_thin_disk(True)
        vc_swc.set_eager_scrub(False)
    elif values.disk_type == "thick-lazy-zeroed":
        vc_swc.set_thin_disk(False)
        vc_swc.set_eager_scrub(False)
    elif values.disk_type == "thick-eager-zeroed":
        vc_swc.set_thin_disk(False)
        vc_swc.set_eager_scrub(True)
    else:
        raise ValidationError("Disk Type %s not correct. Can only be "
                              "thin, thick-lazy-zeroed or "
                              "thick-eager-zeroed" % (values.disk_type,))

    try:
        instance_config = instance_config_from_values(
            values, mode=INSTANCE_CREATOR_MODE, cli_config=parsed_config)
        user_data_str = vc_swc.create_userdata_str(instance_config,
            update=False, ssh_key_file=values.ssh_public_key_file)
        if (values.encryptor_vmdk is not None):
            # Create from MV VMDK
            encrypt_vmdk.encrypt_from_vmdk(
                vc_swc, encryptor_service.EncryptorService,
                values.vmdk, vm_name=values.template_vm_name,
                create_ovf=values.create_ovf,
                create_ova=values.create_ova,
                target_path=values.target_path,
                image_name=values.encrypted_ovf_name,
                ovftool_path=values.ovftool_path,
                metavisor_vmdk=values.encryptor_vmdk,
                user_data_str=user_data_str,
                serial_port_file_name=values.serial_port_file_name,
                status_port=values.status_port,
            )
        elif (values.source_image_path is not None):
            # Create from MV OVF in local directory
            encrypt_vmdk.encrypt_from_local_ovf(
                vc_swc, encryptor_service.EncryptorService,
                values.vmdk, vm_name=values.template_vm_name,
                create_ovf=values.create_ovf,
                create_ova=values.create_ova,
                target_path=values.target_path,
                image_name=values.encrypted_ovf_name,
                ovftool_path=values.ovftool_path,
                source_image_path=values.source_image_path,
                ovf_image_name=values.image_name,
                user_data_str=user_data_str,
                serial_port_file_name=values.serial_port_file_name,
                status_port=values.status_port,
            )
        else:
            # Create from MV OVF in S3
            encrypt_vmdk.encrypt_from_s3(
                vc_swc, encryptor_service.EncryptorService,
                values.vmdk, vm_name=values.template_vm_name,
                create_ovf=values.create_ovf,
                create_ova=values.create_ova,
                target_path=values.target_path,
                image_name=values.encrypted_ovf_name,
                ovftool_path=values.ovftool_path,
                ovf_name=ovf,
                download_file_list=file_list,
                user_data_str=user_data_str,
                serial_port_file_name=values.serial_port_file_name,
                status_port=values.status_port,
            )
        return 0
    except Exception as e:
        log.error("Failed to encrypt the guest VMDK: %s", e)
        return 1


def command_rescue_metavisor(values, parsed_config, log):
    session_id = util.make_nonce()
    if values.protocol != 'http':
        raise ValidationError("Unsupported rescue protocol %s",
                              values.protocol)
    _check_env_vars_set('VCENTER_USER_NAME', 'VCENTER_PASSWORD')
    # Connect to vCenter
    try:
        vc_swc = esx_service.initialize_vcenter(
            host=values.vcenter_host,
            user=os.getenv('VCENTER_USER_NAME'),
            password=os.getenv('VCENTER_PASSWORD'),
            port=values.vcenter_port,
            datacenter_name=values.vcenter_datacenter,
            datastore_name=values.vcenter_datastore,
            esx_host=False,
            cluster_name=values.vcenter_cluster,
            no_of_cpus=None,
            memory_gb=None,
            session_id=session_id,
        )
    except Exception as e:
        raise ValidationError("Failed to connect to vCenter ", e)
    try:
        user_data_str = vc_swc.create_userdata_str(None,
            rescue_proto=values.protocol,
            rescue_url=values.url)
        rescue_metavisor.rescue_metavisor_vcenter(
            vc_swc, user_data_str, values.vm_name
        )
        return 0
    except Exception as e:
        log.exception("Failed to put Metavisor in rescue mode %s", e)
        return 1
