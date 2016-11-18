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
import argparse


def setup_update_with_esx_host_args(parser):
    parser.add_argument(
        "--esx-host",
        help="IP address/DNS Name of the ESX host",
        dest="vcenter_host",
        metavar='DNS_NAME',
        required=True)
    parser.add_argument(
        "--esx-port",
        help="Port Number of the ESX Server",
        metavar='N',
        dest="vcenter_port",
        default="443",
        required=False)
    parser.add_argument(
        "--esx-datastore",
        help="ESX datastore to use",
        dest="vcenter_datastore",
        metavar='NAME',
        default=None,
        required=False)
    parser.add_argument(
        "--cpu-count",
        help="Number of CPUs to assign to Encryptor VM",
        metavar='N',
        dest="no_of_cpus",
        default="8",
        required=False)
    parser.add_argument(
        "--memory",
        help="Memory to assign to Encryptor VM",
        metavar='GB',
        dest="memory_gb",
        default="32",
        required=False)
    parser.add_argument(
        '--encrypted-image-name',
        metavar='NAME',
        dest='encrypted_ovf_name',
        help='Specify the name of the generated OVF/OVA',
        required=False
    )
    parser.add_argument(
        '--template-vm-name',
        metavar='NAME',
        dest='template_vm_name',
        help='Specify the name of the template VM',
        required=False
    )
    parser.add_argument(
        '--update-ovf',
        dest='create_ovf',
        action='store_true',
        default=False,
        help="Update OVF package"
    )
    parser.add_argument(
        '--update-ova',
        dest='create_ova',
        action='store_true',
        default=False,
        help="Update OVA package"
    )
    parser.add_argument(
        '--encrypted-image-directory',
        metavar='NAME',
        dest='target_path',
        help='Directory to store the generated OVF/OVA image',
        default=None,
        required=False
    )
    parser.add_argument(
        '--ovftool-path',
        metavar='PATH',
        dest='ovftool_path',
        help='ovftool executable path',
        default="ovftool",
        required=False
    )
    parser.add_argument(
        '--ovf-source-directory',
        metavar='PATH',
        dest='source_image_path',
        help='Local path to the OVF directory',
        default=None,
        required=False
    )
    parser.add_argument(
        '--metavisor-ovf-image-name',
        metavar='NAME',
        dest='image_name',
        help='Metavisor OVF name',
        default=None,
        required=False
    )
    parser.add_argument(
        '--console-file-name',
        metavar='NAME',
        dest='serial_port_file_name',
        help='File name to dump console messages to',
        default=None,
        required=False
    )

    parser.add_argument(
        '--disk-type',
        metavar='TYPE',
        dest='disk_type',
        help='thin/thick-lazy-zeroed/thick-eager-zeroed (default: thin)',
        default='thin',
        required=False
    )

    # Optional VMDK that's used to launch the encryptor instance.  This
    # argument is hidden because it's only used for development.
    parser.add_argument(
        '--encryptor-vmdk',
        metavar='VMDK-NAME',
        dest='encryptor_vmdk',
        help=argparse.SUPPRESS
    )
    # Optional ssh-public key to be put into the Metavisor.
    # Use only with debug instances.
    # Hidden because it is used only for development.
    parser.add_argument(
        '--ssh-public-key',
        metavar='PATH',
        dest='ssh_public_key_file',
        default=None,
        help=argparse.SUPPRESS
    )
    # Optional no-teardown will not tear down the
    # Encryptor/Updater VM in case of error.
    # Hidden because it is used only for development.
    parser.add_argument(
        '--no-teardown',
        dest='no_teardown',
        action='store_true',
        default=False,
        help=argparse.SUPPRESS
    )
    # Optional bucket-name in case dev/qa need to use
    # other internal buckets to fetch the MV image from
    parser.add_argument(
        '--bucket-name',
        metavar='NAME',
        dest='bucket_name',
        help=argparse.SUPPRESS,
        default="solo-brkt-prod-ovf-image"
    )
