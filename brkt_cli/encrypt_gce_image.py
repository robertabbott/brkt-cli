#!/usr/bin/env python

import logging

from brkt_cli.util import (
    add_brkt_env_to_brkt_config,
    add_token_to_user_data,
    Deadline,
)

from brkt_cli.validation import ValidationError
from gce_service import gce_metadata_from_userdata
from encryptor_service import wait_for_encryption
from encryptor_service import wait_for_encryptor_up


log = logging.getLogger(__name__)

def validate_images(gce_svc, encrypted_image_name,  encryptor, guest_image, image_project=None):
    # check that image to be updated exists
    if not gce_svc.image_exists(guest_image, image_project):
        raise ValidationError('Image %s does not exist. Cannot update.' % guest_image)

    # check that encryptor exists
    if not gce_svc.image_exists(encryptor):
        raise ValidationError('Encryptor image %s does not exist. Encryption failed.' % encryptor)

    # check that there is no existing image named encrypted_image_name
    if gce_svc.image_exists(encrypted_image_name):
        raise ValidationError('An image already exists with name %s. Encryption Failed.' % encrypted_image_name)


def setup_encryption(gce_svc,
                     image_id,
                     encrypted_image_disk,
                     instance_name,
                     zone,
                     brkt_env,
                     brkt_data,
                     image_project):
    try:
        log.info('Launching guest instance')
        gce_svc.run_instance(zone, instance_name, image_id, block_project_ssh_keys=True, image_project=image_project)
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
    except Exception as e:
        log.info('Encryption setup failed')
        raise e


def do_encryption(gce_svc,
                   enc_svc_cls,
                   zone,
                   encryptor,
                   encryptor_image,
                   instance_name,
                   encrypted_image_disk,
                   brkt_data):
    try:
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
    except Exception as e:
        raise e


def create_image(gce_svc, zone, encrypted_image_disk, encrypted_image_name, encryptor):
    try:
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
    except Exception as e:
        log.info('Image creation failed')
        raise e


def encrypt(gce_svc, enc_svc_cls, image_id, encryptor_image,
            encrypted_image_name, zone, brkt_env, token, image_project=None,
            keep_encryptor=False, image_file=None, image_bucket=None):
    brkt_data = {}
    try:
        # create image from file in GCS bucket
        log.info('Retrieving encryptor image from GCS bucket')
        gce_svc.get_latest_encryptor_image(zone, encryptor_image,
            image_bucket, image_file=image_file)

        validate_images(gce_svc, encrypted_image_name, encryptor_image, image_id, image_project)

        add_brkt_env_to_brkt_config(brkt_env, brkt_data)
        add_token_to_user_data(token, brkt_data)
        instance_name = 'brkt-guest-' + gce_svc.get_session_id()
        encryptor = instance_name + '-encryptor'
        encrypted_image_disk = 'encrypted-image-' + gce_svc.get_session_id()

        # create guest root disk and blank disk to dd to
        setup_encryption(gce_svc, image_id, encrypted_image_disk, instance_name, zone, brkt_env, brkt_data, image_project)

        # run encryptor instance with avatar_creator as root,
        # customer image and blank disk
        do_encryption(gce_svc, enc_svc_cls, zone, encryptor, encryptor_image, instance_name, encrypted_image_disk, brkt_data)

        # create image
        create_image(gce_svc, zone, encrypted_image_disk, encrypted_image_name, encryptor)

        return encrypted_image_name
    finally:
        log.info("Cleaning up")
        gce_svc.cleanup(zone, encryptor_image, keep_encryptor)
