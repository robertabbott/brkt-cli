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


def setup_update_vmdk_args(parser):
    parser.add_argument(
        "--vcenter-host",
        help="IP address/DNS Name of the vCenter host",
        dest="vcenter_host",
        metavar='DNS_NAME',
        required=True)
    parser.add_argument(
        "--vcenter-port",
        help="Port Number of the vCenter Server",
        metavar='N',
        dest="vcenter_port",
        default="443",
        required=False)
    parser.add_argument(
        "--vcenter-datacenter",
        help="vCenter Datacenter to use",
        dest="vcenter_datacenter",
        metavar='NAME',
        required=True)
    parser.add_argument(
        "--vcenter-datastore",
        help="vCenter datastore to use",
        dest="vcenter_datastore",
        metavar='NAME',
        default=None,
        required=False)
    parser.add_argument(
        "--vcenter-cluster",
        help="vCenter cluster to use",
        dest="vcenter_cluster",
        metavar='NAME',
        required=True)
    parser.add_argument(
        "--cpu-count",
        help="Number of CPUs to assign to Encryptor VM",
        metavar='N',
        dest="no_of_cpus",
        default="1",
        required=False)
    parser.add_argument(
        "--memory",
        help="Memory to assign to Encryptor VM",
        metavar='GB',
        dest="memory_gb",
        default="1",
        required=False)
    parser.add_argument(
        '--template-vm-name',
        metavar='NAME',
        dest='template_vm_name',
        help='Specify the name of the template VM to be updated',
        required=False
    )
    parser.add_argument(
        '--encrypted-image-directory',
        metavar='NAME',
        dest='target_path',
        #help='Directory to fetch the encrypted OVF/OVA image',
        help=argparse.SUPPRESS,
        default=None,
        required=False
    )
    parser.add_argument(
        '--ovftool-path',
        metavar='PATH',
        dest='ovftool_path',
        #help='ovftool executable path',
        help=argparse.SUPPRESS,
        default="ovftool",
        required=False
    )
    parser.add_argument(
        '--encrypted-ovf-image-name',
        metavar='NAME',
        dest='encrypted_ovf_name',
        #help='Specify the name of the encrypted OVF image to update',
        help=argparse.SUPPRESS,
        required=False
    )
    parser.add_argument(
        '--encrypted-ova-image-name',
        metavar='NAME',
        dest='encrypted_ova_name',
        #help='Specify the name of the encrypted OVA image to update',
        help=argparse.SUPPRESS,
        required=False
    )
    parser.add_argument(
        '--no-validate',
        dest='validate',
        action='store_false',
        default=True,
        help="Don't validate VMDKs and vCenter credentials"
    )
    parser.add_argument(
        '--ovf-source-directory',
        metavar='PATH',
        dest='source_image_path',
        help='Local path to the Metavisor OVF directory',
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
        '--use-esx-host',
        dest='esx_host',
        action='store_true',
        default=False,
        help="Use single ESX host for encrytion instead of vCenter"
    )
    # Optional MV VMDK that's used to launch the updator instance.  This
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
