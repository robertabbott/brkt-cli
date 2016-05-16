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

from brkt_cli.gce import encrypt_gce_image
from brkt_cli.util import (
    add_brkt_env_to_brkt_config,
    add_token_to_user_data,
    Deadline,
)
from brkt_cli.encryptor_service import wait_for_encryption
from brkt_cli.encryptor_service import wait_for_encryptor_up
from gce_service import gce_metadata_from_userdata

"""
Create an encrypted GCE image (with new metavisor) based
on an existing encrypted GCE image.
"""

log = logging.getLogger(__name__)

def update_gce_image(gce_svc, enc_svc_cls, image_id, encryptor_image,
            encrypted_image_name, zone, brkt_env, token, keep_encryptor=False,
            image_file=None, image_bucket=None):
    snap_created = None
    try:
        # create image from file in GCS bucket
        log.info('Retrieving encryptor image from GCS bucket')
        if not encryptor_image:
            encryptor_image = gce_svc.get_latest_encryptor_image(zone,
                image_bucket, image_file=image_file)

        encrypt_gce_image.validate_images(gce_svc, encrypted_image_name,
            encryptor_image, image_id)
        instance_name = 'brkt-updater-' + gce_svc.get_session_id()
        updater = instance_name + '-metavisor'
        encrypted_image_disk = instance_name + '-guest'

        # Create disk from encrypted guest snapshot. This disk
        # won't be altered. It will be re-snapshotted and paired
        # with the new encryptor image.
        gce_svc.disk_from_snapshot(zone, image_id, encrypted_image_disk)
        gce_svc.wait_for_disk(zone, encrypted_image_disk)
        log.info("Creating snapshot of encrypted image disk")
        gce_svc.create_snapshot(zone, encrypted_image_disk, encrypted_image_name)
        snap_created = True

        log.info("Launching encrypted updater")
        brkt_data = {'brkt': {'solo_mode': 'updater'}}
        add_brkt_env_to_brkt_config(brkt_env, brkt_data)
        add_token_to_user_data(token, brkt_data)
        user_data = gce_metadata_from_userdata(brkt_data)
        gce_svc.run_instance(zone,
                             updater,
                             encryptor_image,
                             disks=[],
                             metadata=user_data)
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
        gce_svc.cleanup(zone, encryptor_image, keep_encryptor)
        raise
    finally:
        gce_svc.cleanup(zone, encryptor_image, keep_encryptor)
    return encrypted_image_name
