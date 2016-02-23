# Copyright 2015 Bracket Computing, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# https://github.com/brkt/brkt-sdk-java/blob/master/LICENSE
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and
# limitations under the License.

import abc
import json
import logging
import urllib2

ENCRYPT_INITIALIZING = 'initial'
ENCRYPT_DOWNLOADING = 'downloading'
ENCRYPT_RUNNING = 'encrypting'
ENCRYPT_SUCCESSFUL = 'finished'
ENCRYPT_FAILED = 'failed'
ENCRYPT_ENCRYPTING = 'encrypting'
ENCRYPTOR_STATUS_PORT = 8000
FAILURE_CODE_UNSUPPORTED_GUEST = 'unsupported_guest'
FAILURE_CODE_AWS_PERMISSIONS = 'insufficient_aws_permissions'
FAILURE_CODE_INVALID_NTP_SERVERS = 'invalid_ntp_servers'

log = logging.getLogger(__name__)


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
