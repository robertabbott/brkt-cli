import boto
import logging
import sys
import time
from boto.exception import EC2ResponseError
from brkt_cli import (
    encrypt_ami,
    encryptor_service,
    util)
from brkt_cli.util import Deadline

log = logging.getLogger(__name__)


def snapshot_updater_ami_block_devices(aws_service,
                                       guest_encrypted_image,
                                       mv_updater_ami,
                                       guest_snapshot,
                                       volume_size):
    # Retrieves the most recent updater AMI, launches it, snapshots
    # its volumes, returns the snapshots
    sg_id = encrypt_ami.create_encryptor_security_group(aws_service)
    mv_instance = encrypt_ami.run_encryptor_instance(
        aws_service,
        mv_updater_ami,
        guest_snapshot,
        volume_size,
        guest_encrypted_image,
        sg_id,
        update_ami=True)
    host_ip = mv_instance.ip_address
    enc_svc = encryptor_service.EncryptorService(host_ip)
    log.info('Waiting for encryption service on %s at %s',
             mv_instance.id, host_ip)
    encrypt_ami.wait_for_encryptor_up(enc_svc, Deadline(600))
    try:
        encrypt_ami.wait_for_encryption(enc_svc)
    except EncryptionError as e:
        log.error(
            'Update failed.  Check console output of instance %s '
            'for details.',
            mv_instance.id
        )

        e.console_output_file = encrypt_ami.write_console_output(
            aws_service, mv_instance.id)
        if e.console_output_file:
            log.error(
                'Wrote console output for instance %s to %s',
                mv_instance.id,
                e.console_output_file.name
            )
        else:
            log.error(
                'Encryptor console output is not currently available.  '
                'Wait a minute and check the console output for '
                'instance %s in the EC2 Management '
                'Console.',
                mv_instance.id
            )
        raise e
    bdm = mv_instance.block_device_mapping
    log.info('Stopping metavisor updater instance %s', mv_instance.id)
    aws_service.stop_instance(mv_instance.id)
    description = \
        encrypt_ami.DESCRIPTION_SNAPSHOT % {'image_id': guest_encrypted_image}

    # Snapshot volumes.
    mv_root_snapshot = aws_service.create_snapshot(
        bdm['/dev/sda2'].volume_id,
        name=encrypt_ami.NAME_METAVISOR_ROOT_SNAPSHOT,
        description=description
    )
    mv_grub_snapshot = aws_service.create_snapshot(
        bdm['/dev/sda1'].volume_id,
        name=encrypt_ami.NAME_METAVISOR_GRUB_SNAPSHOT,
        description=description
    )
    mv_log_snapshot = aws_service.create_snapshot(
        bdm['/dev/sda3'].volume_id,
        name=encrypt_ami.NAME_METAVISOR_LOG_SNAPSHOT,
        description=description
    )
    log.info('waiting for snapshot ready')
    encrypt_ami.wait_for_snapshots(
        aws_service,
        mv_root_snapshot.id,
        mv_grub_snapshot.id,
        mv_log_snapshot.id)
    log.info('metavisor updater snapshots ready')
    encrypt_ami.terminate_instance(
        aws_service,
        id=mv_instance.id,
        name='encryptor',
        terminated_instance_ids=set()
    )
    return {
        encrypt_ami.NAME_METAVISOR_ROOT_SNAPSHOT: mv_root_snapshot,
        encrypt_ami.NAME_METAVISOR_GRUB_SNAPSHOT: mv_grub_snapshot,
        encrypt_ami.NAME_METAVISOR_LOG_SNAPSHOT: mv_log_snapshot
    }


def retrieve_guest_volume_snapshot(aws_service,
                                   encrypted_ami_id):
    # Verify expected device mapping is present, return with info
    encrypted_image = aws_service.get_image(encrypted_ami_id)
    guest_volume_mapping = \
        encrypted_image.block_device_mapping.get('/dev/sda5')
    if not guest_volume_mapping:
        return None, None,\
            'Invalid block device mapping: /dev/sda5 not present'
    # Need to recover the volume iops and size
    volume_info = {'iops': guest_volume_mapping.iops,
                   'size': guest_volume_mapping.size,
                   'type': guest_volume_mapping.volume_type}
    guest_volume_snapshot = aws_service.get_snapshot(
        guest_volume_mapping.snapshot_id)
    return guest_volume_snapshot, volume_info, None
