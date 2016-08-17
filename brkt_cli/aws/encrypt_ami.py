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

"""
Create an encrypted AMI based on an existing unencrypted AMI.

Overview of the process:
    * Start an instance based on the unencrypted guest AMI.
    * Stop that instance
    * Snapshot the root volume of the unencrypted instance.
    * Start a Bracket Encryptor instance.
    * Attach the unencrypted root volume to the Encryptor instance.
    * The Bracket Encryptor copies the unencrypted root volume to a new
        encrypted volume that's 2x the size of the original.
    * Detach the Bracket Encryptor root volume
    * Snapshot the Bracket Encryptor system volumes and the new encrypted
        root volume.
    * Attach the Bracket Encryptor root volume to the stopped guest instance
    * Create a new AMI based on the snapshots and stopped guest instance.
    * Terminate the Bracket Encryptor instance.
    * Terminate the original guest instance.
    * Delete the unencrypted snapshot.

Before running brkt encrypt-ami, set the AWS_ACCESS_KEY_ID and
AWS_SECRET_ACCESS_KEY environment variables, like you would when
running the AWS command line utility.
"""

import logging
import os
import string
import tempfile
import time

from boto.ec2.blockdevicemapping import (
    BlockDeviceMapping,
    EBSBlockDeviceType,
)
from boto.ec2.instance import InstanceAttribute
from boto.exception import EC2ResponseError

from brkt_cli import encryptor_service
from brkt_cli.aws import aws_service
from brkt_cli.instance_config import InstanceConfig
from brkt_cli.user_data import gzip_user_data
from brkt_cli.util import (
    BracketError,
    Deadline,
    make_nonce,
    sleep,
    append_suffix)
from datetime import datetime

# End user-visible terminology.  These are resource names and descriptions
# that the user will see in his or her EC2 console.

# Snapshot names.
NAME_LOG_SNAPSHOT = 'Bracket logs from %(instance_id)s'
DESCRIPTION_LOG_SNAPSHOT = \
    'Bracket logs from %(instance_id)s in AWS account %(aws_account)s '\
    'taken at %(timestamp)s'


# Guest instance names.
NAME_GUEST_CREATOR = 'Bracket guest'
DESCRIPTION_GUEST_CREATOR = \
    'Used to create an encrypted guest root volume from %(image_id)s'

# Updater instance
NAME_METAVISOR_UPDATER = 'Bracket Updater'
DESCRIPTION_METAVISOR_UPDATER = \
    'Used to upgrade existing encrypted AMI with latest metavisor'

# Security group names
NAME_ENCRYPTOR_SECURITY_GROUP = 'Bracket Encryptor %(nonce)s'
DESCRIPTION_ENCRYPTOR_SECURITY_GROUP = (
    "Allows access to the encryption service.")

# Encryptor instance names.
NAME_ENCRYPTOR = 'Bracket volume encryptor'
DESCRIPTION_ENCRYPTOR = \
    'Copies the root snapshot from %(image_id)s to a new encrypted volume'

# Snapshot names.
NAME_ORIGINAL_SNAPSHOT = 'Bracket encryptor original volume'
DESCRIPTION_ORIGINAL_SNAPSHOT = \
    'Original unencrypted root volume from %(image_id)s'
NAME_ENCRYPTED_ROOT_SNAPSHOT = 'Bracket encrypted root volume'
NAME_METAVISOR_ROOT_SNAPSHOT = 'Bracket system root'
NAME_METAVISOR_GRUB_SNAPSHOT = 'Bracket system GRUB'
NAME_METAVISOR_LOG_SNAPSHOT = 'Bracket system log'
DESCRIPTION_SNAPSHOT = 'Based on %(image_id)s'

# Volume names.
NAME_ORIGINAL_VOLUME = 'Original unencrypted root volume from %(image_id)s'
NAME_ENCRYPTED_ROOT_VOLUME = 'Bracket encrypted root volume'
NAME_METAVISOR_ROOT_VOLUME = 'Bracket system root'
NAME_METAVISOR_GRUB_VOLUME = 'Bracket system GRUB'
NAME_METAVISOR_LOG_VOLUME = 'Bracket system log'

# Tag names.
TAG_ENCRYPTOR = 'BrktEncryptor'
TAG_ENCRYPTOR_SESSION_ID = 'BrktEncryptorSessionID'
TAG_ENCRYPTOR_AMI = 'BrktEncryptorAMI'
TAG_DESCRIPTION = 'Description'

NAME_ENCRYPTED_IMAGE = '%(original_image_name)s %(encrypted_suffix)s'
NAME_ENCRYPTED_IMAGE_SUFFIX = ' (encrypted %(nonce)s)'
SUFFIX_ENCRYPTED_IMAGE = (
    ' - based on %(image_id)s, encrypted by Bracket Computing'
)
DEFAULT_DESCRIPTION_ENCRYPTED_IMAGE = \
    'Based on %(image_id)s, encrypted by Bracket Computing'

AMI_NAME_MAX_LENGTH = 128

log = logging.getLogger(__name__)


# boto2 does not support this attribute, and this attribute needs to be
# queried for as metavisor does not support sriovNet
if 'sriovNetSupport' not in InstanceAttribute.ValidValues:
    InstanceAttribute.ValidValues.append('sriovNetSupport')


def get_default_tags(session_id, encryptor_ami):
    default_tags = {
        TAG_ENCRYPTOR: True,
        TAG_ENCRYPTOR_SESSION_ID: session_id,
        TAG_ENCRYPTOR_AMI: encryptor_ami
    }
    return default_tags


class SnapshotError(BracketError):
    pass


class InstanceError(BracketError):
    pass


def _get_snapshot_progress_text(snapshots):
    elements = [
        '%s: %s' % (str(s.id), str(s.progress))
        for s in snapshots
    ]
    return ', '.join(elements)


def wait_for_instance(
        aws_svc, instance_id, timeout=600, state='running'):
    """ Wait for up to timeout seconds for an instance to be in the
    given state.  Sleep for 2 seconds between checks.

    :return: The Instance object
    :raises InstanceError if a timeout occurs or the instance unexpectedly
        goes into an error or terminated state
    """

    log.debug(
        'Waiting for %s, timeout=%d, state=%s',
        instance_id, timeout, state)

    deadline = Deadline(timeout)
    while not deadline.is_expired():
        instance = aws_svc.get_instance(instance_id)
        log.debug('Instance %s state=%s', instance.id, instance.state)
        if instance.state == state:
            return instance
        if instance.state == 'error':
            raise InstanceError(
                'Instance %s is in an error state.  Cannot proceed.' %
                instance_id
            )
        if state != 'terminated' and instance.state == 'terminated':
            raise InstanceError(
                'Instance %s was unexpectedly terminated.' % instance_id
            )
        sleep(2)
    raise InstanceError(
        'Timed out waiting for %s to be in the %s state' %
        (instance_id, state)
    )


def stop_and_wait(aws_svc, instance_id):
    """ Stop the given instance and wait for it to be in the stopped state.
    If an exception is thrown, log the error and return.
    """
    try:
        aws_svc.stop_instance(instance_id)
        wait_for_instance(aws_svc, instance_id, state='stopped')
    except:
        log.exception(
            'Error while waiting for instance %s to stop', instance_id)


def get_encrypted_suffix():
    """ Return a suffix that will be appended to the encrypted image name.
    The suffix is in the format "(encrypted 787ace7a)".  The nonce portion of
    the suffix is necessary because Amazon requires image names to be unique.
    """
    return NAME_ENCRYPTED_IMAGE_SUFFIX % {'nonce': make_nonce()}


def get_name_from_image(image):
    name = append_suffix(
        image.name,
        get_encrypted_suffix(),
        max_length=AMI_NAME_MAX_LENGTH
    )
    return name


def get_description_from_image(image):
    if image.description:
        suffix = SUFFIX_ENCRYPTED_IMAGE % {'image_id': image.id}
        description = append_suffix(
            image.description, suffix, max_length=255)
    else:
        description = DEFAULT_DESCRIPTION_ENCRYPTED_IMAGE % {
            'image_id': image.id
        }
    return description


def wait_for_image(aws_svc, image_id):
    log.debug('Waiting for %s to become available.', image_id)
    for i in range(180):
        sleep(5)
        try:
            image = aws_svc.get_image(image_id)
        except EC2ResponseError, e:
            if e.error_code == 'InvalidAMIID.NotFound':
                log.debug('AWS threw a NotFound, ignoring')
                continue
            else:
                log.warn('Unknown AWS error: %s', e)
        # These two attributes are optional in the response and only
        # show up sometimes. So we have to getattr them.
        reason = repr(getattr(image, 'stateReason', None))
        code = repr(getattr(image, 'code', None))
        log.debug("%s: %s reason: %s code: %s",
                  image.id, image.state, reason, code)
        if image.state == 'available':
            break
        if image.state == 'failed':
            raise BracketError('Image state became failed')
    else:
        raise BracketError(
            'Image failed to become available (%s)' % (image.state,))


def wait_for_snapshots(aws_svc, *snapshot_ids):
    log.debug('Waiting for status "completed" for %s', str(snapshot_ids))
    last_progress_log = time.time()

    # Give AWS some time to propagate the snapshot creation.
    # If we create and get immediately, AWS may return 400.
    sleep(20)

    while True:
        snapshots = aws_svc.get_snapshots(*snapshot_ids)
        log.debug('%s', {s.id: s.status for s in snapshots})

        done = True
        error_ids = []
        for snapshot in snapshots:
            if snapshot.status == 'error':
                error_ids.append(snapshot.id)
            if snapshot.status != 'completed':
                done = False

        if error_ids:
            # Get rid of unicode markers in error the message.
            error_ids = [str(id) for id in error_ids]
            raise SnapshotError(
                'Snapshots in error state: %s.  Cannot continue.' %
                str(error_ids)
            )
        if done:
            return

        # Log progress if necessary.
        now = time.time()
        if now - last_progress_log > 60:
            log.info(_get_snapshot_progress_text(snapshots))
            last_progress_log = now

        sleep(5)


def create_encryptor_security_group(aws_svc, vpc_id=None, status_port=\
                                    encryptor_service.ENCRYPTOR_STATUS_PORT):
    sg_name = NAME_ENCRYPTOR_SECURITY_GROUP % {'nonce': make_nonce()}
    sg_desc = DESCRIPTION_ENCRYPTOR_SECURITY_GROUP
    sg = aws_svc.create_security_group(sg_name, sg_desc, vpc_id=vpc_id)
    log.info('Created temporary security group with id %s', sg.id)
    try:
        aws_svc.add_security_group_rule(
            sg.id, ip_protocol='tcp',
            from_port=status_port,
            to_port=status_port,
            cidr_ip='0.0.0.0/0')
    except Exception as e:
        log.error('Failed adding security group rule to %s: %s', sg.id, e)
        try:
            log.info('Cleaning up temporary security group %s', sg.id)
            aws_svc.delete_security_group(sg.id)
        except Exception as e2:
            log.warn('Failed deleting temporary security group: %s', e2)
        raise

    aws_svc.create_tags(sg.id)
    return sg


def _run_encryptor_instance(
        aws_svc, encryptor_image_id, snapshot, root_size, guest_image_id,
        security_group_ids=None, subnet_id=None, zone=None,
        instance_config=None,
        status_port=encryptor_service.ENCRYPTOR_STATUS_PORT):
    bdm = BlockDeviceMapping()

    if instance_config is None:
        instance_config = InstanceConfig()

    image = aws_svc.get_image(encryptor_image_id)
    virtualization_type = image.virtualization_type

    # Use gp2 for fast burst I/O copying root drive
    guest_unencrypted_root = EBSBlockDeviceType(
        volume_type='gp2',
        snapshot_id=snapshot,
        delete_on_termination=True)
    # Use gp2 for fast burst I/O copying root drive
    log.info('Launching encryptor instance with snapshot %s', snapshot)
    # They are creating an encrypted AMI instead of updating it
    # Use gp2 for fast burst I/O copying root drive
    guest_encrypted_root = EBSBlockDeviceType(
        volume_type='gp2',
        delete_on_termination=True)
    guest_encrypted_root.size = 2 * root_size + 1

    if virtualization_type == 'paravirtual':
        bdm['/dev/sda4'] = guest_unencrypted_root
        bdm['/dev/sda5'] = guest_encrypted_root
    else:
        # Use 'sd' names even though AWS maps these to 'xvd'
        # The AWS GUI only exposes 'sd' names, and won't allow
        # the user to attach to an existing 'sd' name in use, but
        # would allow conflicts if we used 'xvd' names here.
        bdm['/dev/sdf'] = guest_unencrypted_root
        bdm['/dev/sdg'] = guest_encrypted_root

    # If security groups were not specified, create a temporary security
    # group that allows us to poll the metavisor for encryption progress.
    temp_sg_id = None
    instance = None

    try:
        run_instance = aws_svc.run_instance

        if not security_group_ids:
            vpc_id = None
            if subnet_id:
                subnet = aws_svc.get_subnet(subnet_id)
                vpc_id = subnet.vpc_id
            temp_sg_id = create_encryptor_security_group(
                aws_svc, vpc_id=vpc_id, status_port=status_port).id
            security_group_ids = [temp_sg_id]

            # Wrap with a retry, to handle eventual consistency issues with
            # the newly-created group.
            run_instance = aws_svc.retry(
                aws_svc.run_instance,
                error_code_regexp='InvalidGroup\.NotFound'
            )

        user_data = instance_config.make_userdata()
        compressed_user_data = gzip_user_data(user_data)

        instance = run_instance(
            encryptor_image_id,
            security_group_ids=security_group_ids,
            user_data=compressed_user_data,
            placement=zone,
            block_device_map=bdm,
            subnet_id=subnet_id
        )
        aws_svc.create_tags(
            instance.id,
            name=NAME_ENCRYPTOR,
            description=DESCRIPTION_ENCRYPTOR % {'image_id': guest_image_id}
        )
        log.info('Launching encryptor instance %s', instance.id)
        instance = wait_for_instance(aws_svc, instance.id)

        # Tag volumes.
        bdm = instance.block_device_mapping
        if virtualization_type == 'paravirtual':
            aws_svc.create_tags(
                bdm['/dev/sda5'].volume_id, name=NAME_ENCRYPTED_ROOT_VOLUME)
            aws_svc.create_tags(
                bdm['/dev/sda2'].volume_id, name=NAME_METAVISOR_ROOT_VOLUME)
            aws_svc.create_tags(
                bdm['/dev/sda1'].volume_id, name=NAME_METAVISOR_GRUB_VOLUME)
            aws_svc.create_tags(
                bdm['/dev/sda3'].volume_id, name=NAME_METAVISOR_LOG_VOLUME)
        else:
            aws_svc.create_tags(
                bdm['/dev/sda1'].volume_id, name=NAME_METAVISOR_ROOT_VOLUME)
            aws_svc.create_tags(
                bdm['/dev/sdg'].volume_id, name=NAME_ENCRYPTED_ROOT_VOLUME)
    except:
        cleanup_instance_ids = []
        cleanup_sg_ids = []
        if instance:
            cleanup_instance_ids = [instance.id]
        if temp_sg_id:
            cleanup_sg_ids = [temp_sg_id]
        clean_up(
            aws_svc,
            instance_ids=cleanup_instance_ids,
            security_group_ids=cleanup_sg_ids
        )
        raise

    return instance, temp_sg_id


def run_guest_instance(aws_svc, image_id, subnet_id=None,
                       instance_type='m3.medium'):
    instance = None

    try:
        instance = aws_svc.run_instance(
            image_id, subnet_id=subnet_id,
            instance_type=instance_type, ebs_optimized=False)
        log.info(
            'Launching instance %s to snapshot root disk for %s',
            instance.id, image_id)
        aws_svc.create_tags(
            instance.id,
            name=NAME_GUEST_CREATOR,
            description=DESCRIPTION_GUEST_CREATOR % {'image_id': image_id}
        )
    except:
        if instance:
            clean_up(aws_svc, instance_ids=[instance.id])
        raise

    return instance


def _snapshot_root_volume(aws_svc, instance, image_id):
    """ Snapshot the root volume of the given AMI.

    :except SnapshotError if the snapshot goes into an error state
    """
    log.info(
        'Stopping instance %s in order to create snapshot', instance.id)
    aws_svc.stop_instance(instance.id)
    wait_for_instance(aws_svc, instance.id, state='stopped')

    # Snapshot root volume.
    instance = aws_svc.get_instance(instance.id)
    root_dev = instance.root_device_name
    bdm = instance.block_device_mapping

    if root_dev not in bdm:
        # try stripping partition id
        root_dev = string.rstrip(root_dev, string.digits)
    root_vol = bdm[root_dev]
    vol = aws_svc.get_volume(root_vol.volume_id)
    aws_svc.create_tags(
        root_vol.volume_id,
        name=NAME_ORIGINAL_VOLUME % {'image_id': image_id}
    )

    snapshot = aws_svc.create_snapshot(
        vol.id,
        name=NAME_ORIGINAL_SNAPSHOT,
        description=DESCRIPTION_ORIGINAL_SNAPSHOT % {'image_id': image_id}
    )
    log.info(
        'Creating snapshot %s of root volume for instance %s',
        snapshot.id, instance.id
    )

    try:
        wait_for_snapshots(aws_svc, snapshot.id)

        # Now try to detach the root volume.
        log.info('Detaching root volume %s from %s',
                 root_vol.volume_id, instance.id)
        aws_svc.detach_volume(
            root_vol.volume_id,
            instance_id=instance.id,
            force=True
        )
        aws_service.wait_for_volume(aws_svc, root_vol.volume_id)
        # And now delete it
        log.info('Deleting root volume %s', root_vol.volume_id)
        aws_svc.delete_volume(root_vol.volume_id)
    except:
        clean_up(aws_svc, snapshot_ids=[snapshot.id])
        raise

    iops = None
    if vol.type == 'io1':
        iops = vol.iops

    ret_values = (
        snapshot.id, root_dev, vol.size, vol.type, iops)
    log.debug('Returning %s', str(ret_values))
    return ret_values


def write_console_output(aws_svc, instance_id):

    try:
        console_output = aws_svc.get_console_output(instance_id)
        if console_output.output:
            prefix = instance_id + '-'
            with tempfile.NamedTemporaryFile(
                    prefix=prefix, suffix='-console.txt', delete=False) as t:
                t.write(console_output.output)
            return t
    except:
        log.exception('Unable to write console output')

    return None


def terminate_instance(aws_svc, id, name, terminated_instance_ids):
    try:
        log.info('Terminating %s instance %s', name, id)
        aws_svc.terminate_instance(id)
        terminated_instance_ids.add(id)
    except Exception as e:
        log.warn('Could not terminate %s instance: %s', name, e)


def clean_up(aws_svc, instance_ids=None, volume_ids=None,
              snapshot_ids=None, security_group_ids=None):
    """ Clean up any resources that were created by the encryption process.
    Handle and log exceptions, to ensure that the script doesn't exit during
    cleanup.
    """
    instance_ids = instance_ids or []
    volume_ids = volume_ids or []
    snapshot_ids = snapshot_ids or []
    security_group_ids = security_group_ids or []

    # Delete instances and snapshots.
    terminated_instance_ids = set()
    for instance_id in instance_ids:
        try:
            log.info('Terminating instance %s', instance_id)
            aws_svc.terminate_instance(instance_id)
            terminated_instance_ids.add(instance_id)
        except EC2ResponseError as e:
            log.warn('Unable to terminate instance %s: %s', instance_id, e)
        except:
            log.exception('Unable to terminate instance %s', instance_id)

    for snapshot_id in snapshot_ids:
        try:
            log.info('Deleting snapshot %s', snapshot_id)
            aws_svc.delete_snapshot(snapshot_id)
        except EC2ResponseError as e:
            log.warn('Unable to delete snapshot %s: %s', snapshot_id, e)
        except:
            log.exception('Unable to delete snapshot %s', snapshot_id)

    # Wait for instances to terminate before deleting security groups and
    # volumes, to avoid dependency errors.
    for id in terminated_instance_ids:
        log.info('Waiting for instance %s to terminate.', id)
        try:
            wait_for_instance(aws_svc, id, state='terminated')
        except (EC2ResponseError, InstanceError) as e:
            log.warn(
                'An error occurred while waiting for instance to '
                'terminate: %s', e)
        except:
            log.exception(
                'An error occurred while waiting for instance '
                'to terminate'
            )

    # Delete volumes and security groups.
    for volume_id in volume_ids:
        try:
            log.info('Deleting volume %s', volume_id)
            aws_svc.delete_volume(volume_id)
        except EC2ResponseError as e:
            log.warn('Unable to delete volume %s: %s', volume_id, e)
        except:
            log.exception('Unable to delete volume %s', volume_id)

    for sg_id in security_group_ids:
        try:
            log.info('Deleting security group %s', sg_id)
            aws_svc.delete_security_group(sg_id)
        except EC2ResponseError as e:
            log.warn('Unable to delete security group %s: %s', sg_id, e)
        except:
            log.exception('Unable to delete security group %s', sg_id)


def log_exception_console(aws_svc, e, id):
    log.error(
        'Encryption failed.  Check console output of instance %s '
        'for details.',
        id
    )

    e.console_output_file = write_console_output(aws_svc, id)
    if e.console_output_file:
        log.error(
            'Wrote console output for instance %s to %s',
            id, e.console_output_file.name
        )
    else:
        log.error(
            'Encryptor console output is not currently available.  '
            'Wait a minute and check the console output for '
            'instance %s in the EC2 Management '
            'Console.',
            id
        )


def snapshot_log_volume(aws_svc, instance_id):
    """ Snapshot the log volume of the given instance.

    :except SnapshotError if the snapshot goes into an error state
    """

    # Snapshot root volume.
    instance = aws_svc.get_instance(instance_id)
    bdm = instance.block_device_mapping

    image = aws_svc.get_image(instance.image_id)
    if image.virtualization_type == 'paravirtual':
        log_vol = bdm["/dev/sda3"]
    elif image.virtualization_type == 'hvm':
        log_vol = bdm["/dev/sda1"]
    else:
        raise Exception('Unknown virtualization type %s' %
                        image.virtualization_type)

    vol = aws_svc.get_volume(log_vol.volume_id)

    snapshot = aws_svc.create_snapshot(
        vol.id,
        name=NAME_LOG_SNAPSHOT % {'instance_id': instance_id},
        description=DESCRIPTION_LOG_SNAPSHOT % {
            'instance_id': instance_id,
            'aws_account': image.owner_id,
            'timestamp': datetime.utcnow().strftime('%b %d %Y %I:%M%p UTC')
        }
    )
    log.info(
        'Creating snapshot %s of log volume for instance %s',
        snapshot.id, instance_id
    )

    try:
        wait_for_snapshots(aws_svc, snapshot.id)
    except:
        clean_up(aws_svc, snapshot_ids=[snapshot.id])
        raise
    return snapshot


def snapshot_encrypted_instance(aws_svc, enc_svc_cls, encryptor_instance,
                       encryptor_image, image_id=None, vol_type='', iops=None,
                       legacy=False, save_encryptor_logs=True,
                       status_port=encryptor_service.ENCRYPTOR_STATUS_PORT):
    # First wait for encryption to complete
    host_ips = []
    if encryptor_instance.ip_address:
        host_ips.append(encryptor_instance.ip_address)
    if encryptor_instance.private_ip_address:
        host_ips.append(encryptor_instance.private_ip_address)
        log.info('Adding %s to NO_PROXY environment variable' %
                 encryptor_instance.private_ip_address)
        if os.environ.get('NO_PROXY'):
            os.environ['NO_PROXY'] += "," + \
                encryptor_instance.private_ip_address
        else:
            os.environ['NO_PROXY'] = encryptor_instance.private_ip_address

    enc_svc = enc_svc_cls(host_ips, port=status_port)
    try:
        log.info('Waiting for encryption service on %s (port %s on %s)',
             encryptor_instance.id, enc_svc.port, ', '.join(host_ips))
        encryptor_service.wait_for_encryptor_up(enc_svc, Deadline(600))
        log.info('Creating encrypted root drive.')
        encryptor_service.wait_for_encryption(enc_svc)
    except (BracketError, encryptor_service.EncryptionError) as e:
        # Stop the encryptor instance, to make the console log available.
        stop_and_wait(aws_svc, encryptor_instance.id)

        log_exception_console(aws_svc, e, encryptor_instance.id)
        if save_encryptor_logs:
            log.info('Saving logs from encryptor instance in snapshot')
            log_snapshot = snapshot_log_volume(aws_svc, encryptor_instance.id)
            log.info('Encryptor logs saved in snapshot %(snapshot_id)s. '
                     'Run `brkt share-logs --region %(region)s '
                     '--snapshot-id %(snapshot_id)s` '
                     'to share this snapshot with Bracket support' %
                     {'snapshot_id': log_snapshot.id,
                      'region': aws_svc.region})
        raise

    log.info('Encrypted root drive is ready.')
    # The encryptor instance may modify its volume attachments while running,
    # so we update the encryptor instance's local attributes before reading
    # them.
    encryptor_instance = aws_svc.get_instance(encryptor_instance.id)
    encryptor_bdm = encryptor_instance.block_device_mapping

    # Stop the encryptor instance.
    log.info('Stopping encryptor instance %s', encryptor_instance.id)
    aws_svc.stop_instance(encryptor_instance.id)
    wait_for_instance(aws_svc, encryptor_instance.id, state='stopped')

    description = DESCRIPTION_SNAPSHOT % {'image_id': image_id}

    # Set up new Block Device Mappings
    log.debug('Creating block device mapping')
    new_bdm = BlockDeviceMapping()
    if not vol_type or vol_type == '':
        vol_type = 'gp2'

    # Snapshot volumes.
    if encryptor_image.virtualization_type == 'paravirtual':
        snap_guest = aws_svc.create_snapshot(
            encryptor_bdm['/dev/sda5'].volume_id,
            name=NAME_ENCRYPTED_ROOT_SNAPSHOT,
            description=description
        )
        snap_bsd = aws_svc.create_snapshot(
            encryptor_bdm['/dev/sda2'].volume_id,
            name=NAME_METAVISOR_ROOT_SNAPSHOT,
            description=description
        )
        snap_log = aws_svc.create_snapshot(
            encryptor_bdm['/dev/sda3'].volume_id,
            name=NAME_METAVISOR_LOG_SNAPSHOT,
            description=description
        )
        log.info(
            'Creating snapshots for the new encrypted AMI: %s, %s, %s',
            snap_guest.id, snap_bsd.id, snap_log.id)

        wait_for_snapshots(
            aws_svc, snap_guest.id, snap_bsd.id, snap_log.id)

        if vol_type is None:
            vol_type = "gp2"
        dev_guest_root = EBSBlockDeviceType(volume_type=vol_type,
                                    snapshot_id=snap_guest.id,
                                    iops=iops,
                                    delete_on_termination=True)
        mv_root_id = encryptor_bdm['/dev/sda1'].volume_id

        dev_mv_root = EBSBlockDeviceType(volume_type='gp2',
                                  snapshot_id=snap_bsd.id,
                                  delete_on_termination=True)
        dev_log = EBSBlockDeviceType(volume_type='gp2',
                                 snapshot_id=snap_log.id,
                                 delete_on_termination=True)
        new_bdm['/dev/sda2'] = dev_mv_root
        new_bdm['/dev/sda3'] = dev_log
        new_bdm['/dev/sda5'] = dev_guest_root
    else:
        # HVM instance type
        snap_guest = aws_svc.create_snapshot(
            encryptor_bdm['/dev/sdg'].volume_id,
            name=NAME_ENCRYPTED_ROOT_SNAPSHOT,
            description=description
        )
        log.info(
            'Creating snapshots for the new encrypted AMI: %s' % (
                    snap_guest.id)
        )
        wait_for_snapshots(aws_svc, snap_guest.id)
        dev_guest_root = EBSBlockDeviceType(volume_type=vol_type,
                                    snapshot_id=snap_guest.id,
                                    iops=iops,
                                    delete_on_termination=True)
        mv_root_id = encryptor_bdm['/dev/sda1'].volume_id
        new_bdm['/dev/sdf'] = dev_guest_root

    if not legacy:
        log.info("Detaching new guest root %s" % (mv_root_id,))
        aws_svc.detach_volume(
            mv_root_id,
            instance_id=encryptor_instance.id,
            force=True
        )
        aws_service.wait_for_volume(aws_svc, mv_root_id)
        aws_svc.create_tags(
            mv_root_id, name=NAME_METAVISOR_ROOT_VOLUME)

    if image_id:
        log.debug('Getting image %s', image_id)
        guest_image = aws_svc.get_image(image_id)
        if guest_image is None:
            raise BracketError("Can't find image %s" % image_id)

        # Propagate any ephemeral drive mappings to the soloized image
        guest_bdm = guest_image.block_device_mapping
        for key in guest_bdm.keys():
            guest_vol = guest_bdm[key]
            if guest_vol.ephemeral_name:
                log.info('Propagating block device mapping for %s at %s' %
                         (guest_vol.ephemeral_name, key))
                new_bdm[key] = guest_vol

    return mv_root_id, new_bdm


def wait_for_volume_attached(aws_svc, instance_id, device):
    """ Wait until the device appears in the block device mapping of the
    given instance.
    :return: the Instance object
    """
    # Wait for attachment to complete.
    log.debug(
        'Waiting for %s in block device mapping of %s.',
        device,
        instance_id
    )

    found = False
    instance = None

    for _ in xrange(20):
        instance = aws_svc.get_instance(instance_id)
        bdm = instance.block_device_mapping
        log.debug('Found devices: %s', bdm.keys())
        if device in bdm:
            found = True
            break
        else:
            sleep(5)

    if not found:
        raise BracketError(
            'Timed out waiting for %s to attach to %s' %
            (device, instance_id)
        )

    return instance


def register_ami(aws_svc, encryptor_instance, encryptor_image, name,
                 description, mv_bdm=None, legacy=False, guest_instance=None,
                 mv_root_id=None):
    if not mv_bdm:
        mv_bdm = BlockDeviceMapping()
    # Register the new AMI.
    if legacy:
        # The encryptor instance may modify its volume attachments while
        # running, so we update the encryptor instance's local attributes
        # before reading them.
        encryptor_instance = aws_svc.get_instance(encryptor_instance.id)
        guest_id = encryptor_instance.id
        # Explicitly detach/delete all but root drive
        bdm = encryptor_instance.block_device_mapping
        for d in ['/dev/sda2', '/dev/sda3', '/dev/sda4',
                  '/dev/sda5', '/dev/sdf', '/dev/sdg']:
            if not bdm.get(d):
                continue
            aws_svc.detach_volume(
                bdm[d].volume_id,
                instance_id=encryptor_instance.id,
                force=True
            )
            aws_service.wait_for_volume(aws_svc, bdm[d].volume_id)
            aws_svc.delete_volume(bdm[d].volume_id)
    else:
        guest_id = guest_instance.id
        root_device_name = guest_instance.root_device_name
        # Explicitly attach new mv root to guest instance
        log.info('Attaching %s to %s', mv_root_id, guest_instance.id)
        aws_svc.attach_volume(
            mv_root_id,
            guest_instance.id,
            root_device_name,
        )
        instance = wait_for_volume_attached(
            aws_svc, guest_instance.id, root_device_name)
        bdm = instance.block_device_mapping
        mv_bdm[root_device_name] = bdm[root_device_name]
        mv_bdm[root_device_name].delete_on_termination = True

    # Legacy:
    #   Create AMI from (stopped) MV instance
    # Non-legacy:
    #   Create AMI from original (stopped) guest instance. This
    #   preserves any billing information found in
    #   the identity document (i.e. billingProduct)
    ami = aws_svc.create_image(
        guest_id,
        name,
        description=description,
        no_reboot=True,
        block_device_mapping=mv_bdm
    )

    if not legacy:
        log.info("Deleting volume %s" % (mv_root_id,))
        aws_svc.detach_volume(
            mv_root_id,
            instance_id=guest_instance.id,
            force=True
        )
        aws_service.wait_for_volume(aws_svc, mv_root_id)
        aws_svc.delete_volume(mv_root_id)

    log.info('Registered AMI %s based on the snapshots.', ami)
    wait_for_image(aws_svc, ami)
    image = aws_svc.get_image(ami, retry=True)
    if encryptor_image.virtualization_type == 'paravirtual':
        name = NAME_METAVISOR_GRUB_SNAPSHOT
    else:
        name = NAME_METAVISOR_ROOT_SNAPSHOT
    snap = image.block_device_mapping[image.root_device_name]
    aws_svc.create_tags(
        snap.snapshot_id,
        name=name,
        description=description
    )
    aws_svc.create_tags(ami)

    ami_info = {}
    ami_info['volume_device_map'] = []
    result_image = aws_svc.get_image(ami, retry=True)
    for attach_point, bdt in result_image.block_device_mapping.iteritems():
        if bdt.snapshot_id:
            bdt_snapshot = aws_svc.get_snapshot(bdt.snapshot_id)
            device_details = {
                'attach_point': attach_point,
                'description': bdt_snapshot.tags.get('Name', ''),
                'size': bdt_snapshot.volume_size
            }
            ami_info['volume_device_map'].append(device_details)

    ami_info['ami'] = ami
    ami_info['name'] = name
    return ami_info


def encrypt(aws_svc, enc_svc_cls, image_id, encryptor_ami,
            encrypted_ami_name=None, subnet_id=None, security_group_ids=None,
            guest_instance_type='m3.medium', instance_config=None,
            save_encryptor_logs=True,
            status_port=encryptor_service.ENCRYPTOR_STATUS_PORT,
            terminate_encryptor_on_failure=True):
    log.info('Starting encryptor session %s', aws_svc.session_id)

    encryptor_instance = None
    ami = None
    snapshot_id = None
    guest_instance = None
    temp_sg_id = None
    guest_image = aws_svc.get_image(image_id)
    mv_image = aws_svc.get_image(encryptor_ami)

    # Normal operation is both encryptor and guest match
    # on virtualization type, but we'll support a PV encryptor
    # and a HVM guest (legacy)
    log.debug('Guest type: %s Encryptor type: %s',
        guest_image.virtualization_type, mv_image.virtualization_type)
    if (mv_image.virtualization_type == 'hvm' and
        guest_image.virtualization_type == 'paravirtual'):
            raise BracketError(
                    "Encryptor/Guest virtualization type mismatch")
    legacy = False
    if (mv_image.virtualization_type == 'paravirtual' and
        guest_image.virtualization_type == 'hvm'):
            # This will go away when HVM MV GA's
            log.warn("Must specify a paravirtual AMI type in order to "
                     "preserve guest OS license information")
            legacy = True
    root_device_name = guest_image.root_device_name
    if not guest_image.block_device_mapping.get(root_device_name):
            log.warn("AMI must have root_device_name in block_device_mapping "
                    "in order to preserve guest OS license information")
            legacy = True
    if guest_image.root_device_name != "/dev/sda1":
        log.warn("Guest Operating System license information will not be "
                 "preserved because the root disk is attached at %s "
                 "instead of /dev/sda1", guest_image.root_device_name)
        legacy = True
    try:
        guest_instance = run_guest_instance(aws_svc,
            image_id, subnet_id=subnet_id, instance_type=guest_instance_type)
        wait_for_instance(aws_svc, guest_instance.id)
        snapshot_id, root_dev, size, vol_type, iops = _snapshot_root_volume(
            aws_svc, guest_instance, image_id
        )

        if guest_image.virtualization_type == 'hvm':
            net_sriov_attr = aws_svc.get_instance_attribute(guest_instance.id,
                                                            "sriovNetSupport")
            if net_sriov_attr.get("sriovNetSupport") == "simple":
                log.warn("Guest Operating System license information will not "
                         "be preserved because guest has sriovNetSupport "
                         "enabled and metavisor does not support sriovNet")
                legacy = True

        encryptor_instance, temp_sg_id = _run_encryptor_instance(
            aws_svc=aws_svc,
            encryptor_image_id=encryptor_ami,
            snapshot=snapshot_id,
            root_size=size,
            guest_image_id=image_id,
            security_group_ids=security_group_ids,
            subnet_id=subnet_id,
            zone=guest_instance.placement,
            instance_config=instance_config,
            status_port=status_port
        )

        log.debug('Getting image %s', image_id)
        image = aws_svc.get_image(image_id)
        if image is None:
            raise BracketError("Can't find image %s" % image_id)
        if encrypted_ami_name:
            name = encrypted_ami_name
        elif image_id:
            name = get_name_from_image(image)
        description = get_description_from_image(image)

        mv_root_id, mv_bdm = snapshot_encrypted_instance(aws_svc, enc_svc_cls,
                encryptor_instance, mv_image, image_id=image_id,
                vol_type=vol_type, iops=iops, legacy=legacy,
                save_encryptor_logs=save_encryptor_logs, status_port=status_port)
        ami_info = register_ami(aws_svc, encryptor_instance, mv_image, name,
                description, legacy=legacy, guest_instance=guest_instance,
                mv_root_id=mv_root_id,
                mv_bdm=mv_bdm)
        ami = ami_info['ami']
        log.info('Created encrypted AMI %s based on %s', ami, image_id)
    finally:
        instance_ids = []
        if guest_instance:
            instance_ids.append(guest_instance.id)

        terminate_encryptor = (
            encryptor_instance and
            (ami or terminate_encryptor_on_failure)
        )

        if terminate_encryptor:
            instance_ids.append(encryptor_instance.id)
        elif encryptor_instance:
            log.info('Not terminating encryptor instance %s',
                     encryptor_instance.id)

        # Delete volumes explicitly.  They should get cleaned up during
        # instance deletion, but we've gotten reports that occasionally
        # volumes can get orphaned.
        #
        # We can't do this if we're keeping the encryptor instance around,
        # since its volumes will still be attached.
        volume_ids = None
        if terminate_encryptor:
            try:
                volumes = aws_svc.get_volumes(
                    tag_key=TAG_ENCRYPTOR_SESSION_ID,
                    tag_value=aws_svc.session_id
                )
                volume_ids = [v.id for v in volumes]
            except EC2ResponseError as e:
                log.warn('Unable to clean up orphaned volumes: %s', e)
            except:
                log.exception('Unable to clean up orphaned volumes')

        sg_ids = []
        if temp_sg_id and terminate_encryptor:
            sg_ids.append(temp_sg_id)

        snapshot_ids = []
        if snapshot_id:
            snapshot_ids.append(snapshot_id)

        clean_up(
            aws_svc,
            instance_ids=instance_ids,
            volume_ids=volume_ids,
            snapshot_ids=snapshot_ids,
            security_group_ids=sg_ids
        )

    log.info('Done.')
    return ami
