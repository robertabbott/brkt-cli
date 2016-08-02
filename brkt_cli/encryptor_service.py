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

import abc
import json
import logging
import time
import urllib2

from brkt_cli import validation
from brkt_cli.util import (
        BracketError,
        Deadline,
        sleep
)

ENCRYPT_INITIALIZING = 'initial'
ENCRYPT_DOWNLOADING = 'downloading'
ENCRYPTION_PROGRESS_TIMEOUT = 10 * 60  # 10 minutes
ENCRYPT_RUNNING = 'encrypting'
ENCRYPT_SUCCESSFUL = 'finished'
ENCRYPT_FAILED = 'failed'
ENCRYPT_ENCRYPTING = 'encrypting'
ENCRYPTOR_STATUS_PORT = 8000
FAILURE_CODE_UNSUPPORTED_GUEST = 'unsupported_guest'
FAILURE_CODE_AWS_PERMISSIONS = 'insufficient_aws_permissions'
FAILURE_CODE_INVALID_NTP_SERVERS = 'invalid_ntp_servers'

log = logging.getLogger(__name__)


class EncryptionError(BracketError):
    def __init__(self, message):
        super(EncryptionError, self).__init__(message)
        self.console_output_file = None


class UnsupportedGuestError(BracketError):
    pass


class AWSPermissionsError(BracketError):
    pass


class InvalidNtpServerError(BracketError):
    pass


class BaseEncryptorService(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, hostnames, port=ENCRYPTOR_STATUS_PORT):
        self.hostnames = hostnames
        self.port = port

    @abc.abstractmethod
    def is_encryptor_up(self):
        pass

    @abc.abstractmethod
    def get_status(self):
        pass


class EncryptorConnectionError(Exception):

    def __init__(self, port, exceptions_by_host):
        self.port = port
        # Maps the hostname to the exception that was generated.
        self.exceptions_by_host = exceptions_by_host

        msg = 'Unable to to connect to the encryptor instance '
        errors = []
        for hostname, exception in self.exceptions_by_host.iteritems():
            errors.append('at %s: %s' % (hostname, exception))
        msg += ', '.join(errors)
        super(EncryptorConnectionError, self).__init__(msg)


class EncryptorService(BaseEncryptorService):

    def is_encryptor_up(self):
        try:
            self.get_status()
            log.debug("Successfully got encryptor status")
            return True
        except Exception as e:
            log.debug("Couldn't get encryptor status: %s", e)
            return False

    def get_status(self, timeout_secs=2):
        exceptions_by_host = {}
        info = None
        successful_hostname = None

        for hostname in self.hostnames:
            url = 'http://%s:%d' % (hostname, self.port)
            try:
                r = urllib2.urlopen(url, timeout=timeout_secs)
                data = r.read()
            except IOError as e:
                log.debug(
                    'Unable to connect to %s:%s - %s',
                    hostname, self.port, e)
                exceptions_by_host[hostname] = e
                continue

            info = json.loads(data)
            info['percent_complete'] = 0
            bytes_total = info.get('bytes_total')
            if info['state'] == ENCRYPT_SUCCESSFUL:
                info['percent_complete'] = 100
            elif ((bytes_total is not None) and
                  (bytes_total > 0)):
                ratio = float(info['bytes_written']) / info['bytes_total']
                info['percent_complete'] = int(100 * ratio)
            successful_hostname = hostname
            break

        if info:
            # Don't try the other hostnames again, now that we have one that
            # is known to work.
            self.hostnames = [successful_hostname]
            return info
        else:
            raise EncryptorConnectionError(self.port, exceptions_by_host)


def wait_for_encryptor_up(enc_svc, deadline):
    start = time.time()
    while not deadline.is_expired():
        if enc_svc.is_encryptor_up():
            log.debug(
                'Encryption service is up after %.1f seconds',
                time.time() - start
            )
            return
        sleep(5)
    raise BracketError(
        'Unable to contact encryptor instance at %s.' %
        ', '.join(enc_svc.hostnames)
    )


def wait_for_encryption(enc_svc,
                        progress_timeout=ENCRYPTION_PROGRESS_TIMEOUT):
    err_count = 0
    max_errs = 10
    start_time = time.time()
    last_log_time = start_time
    progress_deadline = Deadline(progress_timeout)
    last_progress = 0
    last_state = ''

    while err_count < max_errs:
        try:
            status = enc_svc.get_status()
            err_count = 0
        except Exception as e:
            log.warn("Failed getting encryption status: %s", e)
            log.warn("Retrying. . .")
            err_count += 1
            sleep(10)
            continue

        state = status['state']
        percent_complete = status['percent_complete']
        log.debug('state=%s, percent_complete=%d', state, percent_complete)

        # Make sure that encryption progress hasn't stalled.
        if progress_deadline.is_expired():
            raise EncryptionError(
                'Waited for encryption progress for longer than %s seconds' %
                progress_timeout
            )
        if percent_complete > last_progress or state != last_state:
            last_progress = percent_complete
            last_state = state
            progress_deadline = Deadline(progress_timeout)

        # Log progress once a minute.
        now = time.time()
        if now - last_log_time >= 60:
            if state == ENCRYPT_INITIALIZING:
                log.info('Encryption process is initializing')
            else:
                state_display = 'Encryption'
                if state == ENCRYPT_DOWNLOADING:
                    state_display = 'Download from S3'
                log.info(
                    '%s is %d%% complete', state_display, percent_complete)
            last_log_time = now

        if state == ENCRYPT_SUCCESSFUL:
            log.info('Encrypted root drive created.')
            return
        elif state == ENCRYPT_FAILED:
            log.debug('Encryption failed with status %s', status)
            failure_code = status.get('failure_code')
            if failure_code == \
                    FAILURE_CODE_UNSUPPORTED_GUEST:
                raise UnsupportedGuestError(
                    'The specified AMI uses an unsupported operating system')
            if failure_code == FAILURE_CODE_AWS_PERMISSIONS:
                raise AWSPermissionsError(
                    'The specified IAM profile has insufficient permissions')
            if failure_code == \
                    FAILURE_CODE_INVALID_NTP_SERVERS:
                raise InvalidNtpServerError(
                    'Invalid NTP servers provided.')

            msg = 'Encryption failed'
            if failure_code:
                msg += ' with code %s' % failure_code
            raise EncryptionError(msg)

        sleep(10)
    # We've failed to get encryption status for _max_errs_ consecutive tries.
    # Assume that the server has crashed.
    raise EncryptionError('Encryption service unavailable')


def status_port(value):
    if not value:
        return ENCRYPTOR_STATUS_PORT
    return validation.range_int_argument(value, 1, 65535, exclusions=[81,])
