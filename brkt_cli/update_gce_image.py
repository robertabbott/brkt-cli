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

from brkt_cli.util import (
    Deadline,
)
import encrypt_ami
from encrypt_ami import wait_for_encryption
from encrypt_ami import wait_for_encryptor_up
from encrypt_gce_image import gce_metadata_from_userdata
from encrypt_gce_image import cleanup

"""
Create an encrypted GCE image (with new metavisor) based
on an existing encrypted GCE image.
"""

log = logging.getLogger(__name__)


def update_gce_image(gce_svc, enc_svc_cls, image_id, encryptor_image,
            encrypted_image_name, zone, brkt_env):
    snap_created = None
    instance = None

    try:
        instance_name = 'brkt-updater-' + gce_svc.get_session_id()
        updater = instance_name + '-metavisor'
        encrypted_image_disk = instance_name + '-guest'

        # Create disk from encrypted guest snapshot. This disk
        # won't be altered it will be re-snapshotted and paired
        # with the new encrypted image.
        gce_svc.disk_from_snapshot(zone, image_id, encrypted_image_disk)
        gce_svc.wait_for_disk(zone, encrypted_image_disk)
        log.info("Creating snapshot of encrypted image disk")
        gce_svc.create_snapshot(zone, encrypted_image_disk, encrypted_image_name)
        snap_created = True

        log.info("Launching encrypted updater")
        brkt_data = {'brkt': {'solo_mode': 'updater'}}
        encrypt_ami.add_brkt_env_to_user_data(brkt_env, brkt_data)
        user_data = gce_metadata_from_userdata(brkt_data)
        gce_svc.run_instance(zone,
                             updater,
                             encryptor_image,
                             disks=[],
                             metadata=user_data)
        instance = True
        enc_svc = enc_svc_cls([gce_svc.get_instance_ip(updater, zone)])

        # wait for updater to finish and guest root disk
        wait_for_encryptor_up(enc_svc, Deadline(600))
        try:
            wait_for_encryption(enc_svc)
        except:
            raise

        # delete updater instance
        log.info('Deleting updater instance')
        gce_svc.delete_instance(zone, updater)
        instance = None

        # wait for updater root disk
        gce_svc.wait_for_detach(zone, updater)

        # create image from mv root disk and snapshot
        # encrypted guest root disk
        log.info("Creating updated metavisor image")
        gce_svc.create_gce_image_from_disk(zone, encrypted_image_name, updater)
        gce_svc.wait_image(encrypted_image_name)
        gce_svc.wait_snapshot(encrypted_image_name)
    except:
        log.info("Update failed. Cleaning up")
        if snap_created:
            gce_svc.delete_snapshot(encrypted_image_name)
        if instance:
            gce_svc.delete_instance(zone, updater)
        cleanup(gce_svc, zone, [updater, encrypted_image_disk])
        raise
    finally:
        cleanup(gce_svc, zone, [updater, encrypted_image_disk])
