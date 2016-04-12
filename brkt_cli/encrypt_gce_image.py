#!/usr/bin/env python

import logging

from brkt_cli.util import (
    add_brkt_env_to_user_data,
    Deadline,
)

from gce_service import gce_metadata_from_userdata
from encryptor_service import wait_for_encryption
from encryptor_service import wait_for_encryptor_up


log = logging.getLogger(__name__)


def encrypt(gce_svc, enc_svc_cls, image_id, encryptor_image,
            encrypted_image_name, zone, brkt_env):
    brkt_data = {}
    deleted = None
    try:
        add_brkt_env_to_user_data(brkt_env, brkt_data)
        instance_name = 'brkt-guest-' + gce_svc.get_session_id()
        encryptor = instance_name + '-encryptor'
        encrypted_image_disk = 'encrypted-image-' + gce_svc.get_session_id()

        gce_svc.run_instance(zone, instance_name, image_id)
        gce_svc.delete_instance(zone, instance_name)
        log.info('Guest instance terminated')
        log.info('Waiting for guest root disk to become ready')
        gce_svc.wait_for_detach(zone, instance_name)

        guest_size = gce_svc.get_disk_size(zone, instance_name)
        # create blank disk. the encrypted image will be
        # dd'd to this disk. Blank disk should be 2x the size
        # of the unencrypted guest root
        log.info('Creating disk for encrypted image')
        gce_svc.create_disk(zone, encrypted_image_disk, guest_size * 2 + 1)

        # run encryptor instance with avatar_creator as root,
        # customer image and blank disk
        log.info('Launching encryptor instance')
        gce_svc.run_instance(zone,
                             encryptor,
                             encryptor_image,
                             disks=[gce_svc.get_disk(zone, instance_name),
                                    gce_svc.get_disk(zone, encrypted_image_disk)],
                             metadata=gce_metadata_from_userdata(brkt_data))

        enc_svc = enc_svc_cls([gce_svc.get_instance_ip(encryptor, zone)])
        wait_for_encryptor_up(enc_svc, Deadline(600))
        wait_for_encryption(enc_svc)
        gce_svc.delete_instance(zone, encryptor)
        deleted = True
        # snapshot encrypted guest disk
        log.info("Creating snapshot of encrypted image disk")
        gce_svc.create_snapshot(zone, encrypted_image_disk, encrypted_image_name)
        # create image from encryptor root
        gce_svc.wait_for_detach(zone, encryptor)

        # create image from mv root disk and snapshot
        # encrypted guest root disk
        log.info("Creating metavisor image")
        gce_svc.create_gce_image_from_disk(zone, encrypted_image_name, encryptor)
        gce_svc.wait_image(encrypted_image_name)
        gce_svc.wait_snapshot(encrypted_image_name)
        log.info("Image %s successfully created!", encrypted_image_name)
    finally:
        if not deleted:
            gce_svc.delete_instance(zone, encryptor)
        # delete all the disks that were created
        log.info("Cleaning up")
        cleanup(gce_svc, zone, [instance_name,
                                encryptor,
                                encrypted_image_disk])

        return encrypted_image_name


def cleanup(gce_svc, zone, disks):
    for disk in disks:
        if gce_svc.disk_exists(zone, disk):
            gce_svc.wait_for_detach(zone, disk)
            gce_svc.delete_disk(zone, disk)
