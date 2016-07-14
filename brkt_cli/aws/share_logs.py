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
    snapshot_log_volume
)

log = logging.getLogger(__name__)


def _share_snapshot(snapshot, bracket_aws_account):
    log.info(
        'Sharing snapshot %s with AWS account %s',
        snapshot.id, bracket_aws_account
    )
    snapshot.share(user_ids=[bracket_aws_account])


def share(aws_svc=None, instance_id=None, bracket_aws_account=None,
          snapshot_id=None):
    if instance_id:
        snapshot = snapshot_log_volume(aws_svc, instance_id)
    else:
        snapshot = aws_svc.get_snapshot(snapshot_id)
    _share_snapshot(snapshot, bracket_aws_account)
    print snapshot.id
