#!/usr/bin/env python

import httplib
import logging
import socket

from brkt_cli.encryptor_service import (
    ENCRYPTOR_STATUS_PORT,
    wait_for_encryption,
    wait_for_encryptor_up
)
from brkt_cli.gce.gce_service import gce_metadata_from_userdata
from brkt_cli.util import Deadline, retry
from googleapiclient import errors


log = logging.getLogger(__name__)


def setup_encryption(gce_svc,
                     image_id,
                     encrypted_image_disk,
                     instance_name,
                     zone,
                     image_project):
    try:
        # create disk from guest image
        gce_svc.disk_from_image(zone, image_id, instance_name, image_project)
        log.info('Waiting for guest root disk to become ready')
        gce_svc.wait_for_detach(zone, instance_name)

        guest_size = gce_svc.get_disk_size(zone, instance_name)
        # create blank disk. the encrypted image will be
        # dd'd to this disk. Blank disk should be 2x the size
        # of the unencrypted guest root
        log.info('Creating disk for encrypted image')
        gce_svc.create_disk(zone, encrypted_image_disk, guest_size * 2 + 1)
    except:
        log.info('Encryption setup failed')
        raise


def do_encryption(gce_svc,
                  enc_svc_cls,
                  zone,
                  encryptor,
                  encryptor_image,
                  instance_name,
                  instance_config,
                  encrypted_image_disk,
                  network,
                  subnetwork,
                  status_port=ENCRYPTOR_STATUS_PORT):
    metadata = gce_metadata_from_userdata(instance_config.make_userdata())
    log.info('Launching encryptor instance')
    gce_svc.run_instance(zone=zone,
                         name=encryptor,
                         image=encryptor_image,
                         network=network,
                         subnet=subnetwork,
                         disks=[gce_svc.get_disk(zone, instance_name),
                                gce_svc.get_disk(zone, encrypted_image_disk)],
                         metadata=metadata)

    try:
        ip = gce_svc.get_instance_ip(encryptor, zone)
        enc_svc = enc_svc_cls([ip], port=status_port)
        wait_for_encryptor_up(enc_svc, Deadline(600))
        log.info(
            'Waiting for encryption service on %s (%s:%s)',
            encryptor, ip, enc_svc.port
        )
        wait_for_encryption(enc_svc)
    except:
        f = gce_svc.write_serial_console_file(zone, encryptor)
        if f:
            log.info('Encryption failed. Writing console to %s' % f)
        raise
    retry(function=gce_svc.delete_instance,
            on=[httplib.BadStatusLine, socket.error, errors.HttpError])(zone, encryptor)


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
        log.info('Image creation failed: ', e)
        raise


def encrypt(gce_svc, enc_svc_cls, image_id, encryptor_image,
            encrypted_image_name, zone, instance_config, image_project=None,
            keep_encryptor=False, image_file=None, image_bucket=None,
            network=None, subnetwork=None, status_port=ENCRYPTOR_STATUS_PORT):
    try:
        # create metavisor image from file in GCS bucket
        log.info('Retrieving encryptor image from GCS bucket')
        if not encryptor_image:
            try:
                encryptor_image = gce_svc.get_latest_encryptor_image(zone,
                    image_bucket, image_file=image_file)
            except errors.HttpError as e:
                encryptor_image = None
                log.exception('GCE API call to create image from file failed: ', e)
                return
        else:
            # Keep user provided encryptor image
            keep_encryptor = True

        instance_name = 'brkt-guest-' + gce_svc.get_session_id()
        encryptor = instance_name + '-encryptor'
        encrypted_image_disk = 'encrypted-image-' + gce_svc.get_session_id()

        # create guest root disk and blank disk to dd to
        setup_encryption(gce_svc, image_id, encrypted_image_disk,
                         instance_name, zone, image_project)

        # run encryptor instance with avatar_creator as root,
        # customer image and blank disk
        do_encryption(gce_svc, enc_svc_cls, zone, encryptor, encryptor_image,
                      instance_name, instance_config, encrypted_image_disk,
                      network, subnetwork, status_port=status_port)

        # create image
        create_image(gce_svc, zone, encrypted_image_disk, encrypted_image_name, encryptor)

        return encrypted_image_name
    except errors.HttpError as e:
        #log.exception('GCE API request failed: ', exc_info=True)
        log.exception('GCE API request failed: {}'.format(e.message))
    finally:
        log.info("Cleaning up")
        gce_svc.cleanup(zone, encryptor_image, keep_encryptor)
