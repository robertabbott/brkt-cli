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
from brkt_cli.aws.encrypt_ami import (
    clean_up,
    wait_for_snapshots
)
from datetime import datetime

log = logging.getLogger(__name__)

# Snapshot names.
NAME_LOG_SNAPSHOT = 'Bracket logs from %(instance_id)s'
DESCRIPTION_LOG_SNAPSHOT = \
    'Bracket logs from %(instance_id)s in AWS account %(aws_account)s '\
    'taken at %(timestamp)s'


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


def _share_snapshot(snapshot, bracket_aws_account):
    log.info(
        'Sharing snapshot %s with AWS account %s',
        snapshot.id, bracket_aws_account
    )
    snapshot.share(user_ids=[bracket_aws_account])


def share(aws_svc=None, instance_id='', bracket_aws_account=''):
    snapshot = snapshot_log_volume(aws_svc, instance_id)
    _share_snapshot(snapshot, bracket_aws_account)
    print snapshot.id
