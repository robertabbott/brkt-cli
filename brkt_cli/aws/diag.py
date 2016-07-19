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

import logging
import time
from brkt_cli.aws.encrypt_ami import (
    wait_for_instance,
)

from boto.ec2.blockdevicemapping import (
    BlockDeviceMapping,
    EBSBlockDeviceType,
)

from brkt_cli.aws.share_logs import snapshot_log_volume
from brkt_cli.util import make_nonce

# Security group names
NAME_DIAG_SECURITY_GROUP = 'Bracket Diag %(nonce)s'
DESCRIPTION_DIAG_SECURITY_GROUP = (
    "Allows ssh access to diag instance.")

# Diag instance names.
NAME_DIAG_INSTANCE = 'Bracket Diag for snapshot %(snapshot_id)s'
DESCRIPTION_DIAG_INSTANCE = \
    'Diag instance with logs from %(snapshot_id)s'

# NetBSD 6.1.5 images taken from https://wiki.netbsd.org/amazon_ec2/amis/
# as of 7/18/2016
DIAG_IMAGES_BY_REGION = {
    "us-east-1": "ami-bc2c94d4",
    "us-west-1": "ami-415a4f04",
    "us-west-2": "ami-6ffbb75f",
}


log = logging.getLogger(__name__)


def create_diag_security_group(aws_svc, vpc_id=None):
    sg_name = NAME_DIAG_SECURITY_GROUP % {'nonce': make_nonce()}
    sg_desc = DESCRIPTION_DIAG_SECURITY_GROUP
    sg = aws_svc.create_security_group(sg_name, sg_desc, vpc_id=vpc_id)
    log.info('Created temporary security group with id %s', sg.id)
    try:
        aws_svc.add_security_group_rule(
            sg.id, ip_protocol='tcp',
            from_port=22,
            to_port=22,
            cidr_ip='0.0.0.0/0')
    except Exception as e:
        log.error('Failed adding security group rule to %s: %s', sg.id, e)
        try:
            log.info('Cleaning up temporary security group %s', sg.id)
            aws_svc.delete_security_group(sg.id)
        except Exception as e2:
            log.warn('Failed deleting temporary security group: %s', e2)
        raise
    if aws_svc.default_tags:
        aws_svc.create_tags(sg.id)
    return sg


def diag(aws_svc=None, region='us-west-2',
         instance_id=None, snapshot_id=None,
         vpc_id=None, subnet_id=None, security_group_ids=None,
         diag_instance_type='m3.medium', ssh_keypair=None):
    if instance_id:
        snapshot_id = snapshot_log_volume(aws_svc, instance_id).id
        log.info("Waiting for 30 seconds for snapshot to be available")
        time.sleep(30)

    diag_image = DIAG_IMAGES_BY_REGION[region]

    log.info("Launching diag instance")

    if not security_group_ids:
        vpc_id = None
        if subnet_id:
            subnet = aws_svc.get_subnet(subnet_id)
            vpc_id = subnet.vpc_id
        temp_sg_id = create_diag_security_group(aws_svc, vpc_id=vpc_id).id
        security_group_ids = [temp_sg_id]

    log_volume = EBSBlockDeviceType(
        delete_on_termination=True,
        snapshot_id=snapshot_id)
    bdm = BlockDeviceMapping()

    # Choose /dev/sda3 since it is the first free mountpoint
    bdm['/dev/sda3'] = log_volume

    diag_instance = aws_svc.run_instance(
        diag_image,
        instance_type=diag_instance_type,
        ebs_optimized=False,
        subnet_id=subnet_id,
        security_group_ids=security_group_ids,
        block_device_map=bdm)

    aws_svc.create_tags(
        diag_instance.id,
        name=NAME_DIAG_INSTANCE % {'snapshot_id': snapshot_id},
        description=DESCRIPTION_DIAG_INSTANCE % {'snapshot_id': snapshot_id}
    )

    wait_for_instance(aws_svc, diag_instance.id)

    diag_instance = aws_svc.get_instance(diag_instance.id)
    print "Diag instance id: %s" % diag_instance.id
    if diag_instance.ip_address:
        print "IP address: %s" % diag_instance.ip_address
    if diag_instance.private_ip_address:
        print "Private IP address: %s" % diag_instance.private_ip_address
    print "User: root"
    print "SSH Keypair: %s" % ssh_keypair
    print "Log volume mountpoint: /dev/xbd2a for PV, /dev/xbd2e for HVM"
