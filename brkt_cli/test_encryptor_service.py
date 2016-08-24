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
import unittest

import brkt_cli
import brkt_cli.aws
import brkt_cli.util
from brkt_cli import encryptor_service


class ExpiredDeadline(object):
    def is_expired(self):
        return True


class DummyEncryptorService(encryptor_service.BaseEncryptorService):

    def __init__(self, hostnames=['test-host'], port=80):
        super(DummyEncryptorService, self).__init__(hostnames, port)
        self.is_up = False
        self.progress = 0

    def is_encryptor_up(self):
        """ The first call returns False.  Subsequent calls return True.
        """
        ret_val = self.is_up
        if not self.is_up:
            self.is_up = True
        return ret_val

    def get_status(self):
        """ Return progress in increments of 20% for each call.
        """
        ret_val = {
            'state': encryptor_service.ENCRYPT_ENCRYPTING,
            'percent_complete': self.progress,
        }
        if self.progress < 100:
            self.progress += 20
        else:
            ret_val['state'] = 'finished'
        return ret_val


class FailedEncryptionService(encryptor_service.BaseEncryptorService):
    def is_encryptor_up(self):
        return True

    def get_status(self):
        return {
            'state': encryptor_service.ENCRYPT_FAILED,
            'percent_complete': 50,
        }


class TestEncryptionService(unittest.TestCase):

    def setUp(self):
        brkt_cli.util.SLEEP_ENABLED = False

    def test_service_fails_to_come_up(self):
        svc = DummyEncryptorService()
        deadline = ExpiredDeadline()
        with self.assertRaisesRegexp(Exception, 'Unable to contact'):
            encryptor_service.wait_for_encryptor_up(svc, deadline)

    def test_encryption_fails(self):
        svc = FailedEncryptionService('192.168.1.1')
        with self.assertRaisesRegexp(
                encryptor_service.EncryptionError, 'Encryption failed'):
            encryptor_service.wait_for_encryption(svc)

    def test_unsupported_guest(self):
        class UnsupportedGuestService(encryptor_service.BaseEncryptorService):
            def __init__(self):
                super(UnsupportedGuestService, self).__init__('localhost', 80)

            def is_encryptor_up(self):
                return True

            def get_status(self):
                return {
                    'state': encryptor_service.ENCRYPT_FAILED,
                    'failure_code':
                        encryptor_service.FAILURE_CODE_UNSUPPORTED_GUEST,
                    'percent_complete': 0
                }

        with self.assertRaises(encryptor_service.UnsupportedGuestError):
            encryptor_service.wait_for_encryption(UnsupportedGuestService())

    def test_encryption_progress_timeout(self):
        class NoProgressService(encryptor_service.BaseEncryptorService):
            def __init__(self):
                super(NoProgressService, self).__init__('localhost', 80)

            def is_encryptor_up(self):
                return True

            def get_status(self):
                return {
                    'state': encryptor_service.ENCRYPT_ENCRYPTING,
                    'percent_complete': 0
                }

        with self.assertRaises(encryptor_service.EncryptionError):
            encryptor_service.wait_for_encryption(
                NoProgressService(),
                progress_timeout=0.100
            )

    def test_handle_failure_code(self):
        with self.assertRaises(encryptor_service.UnsupportedGuestError):
            encryptor_service._handle_failure_code(
                encryptor_service.FAILURE_CODE_UNSUPPORTED_GUEST)

        failure_codes = [
            encryptor_service.FAILURE_CODE_AWS_PERMISSIONS,
            encryptor_service.FAILURE_CODE_GET_YETI_CONFIG,
            encryptor_service.FAILURE_CODE_INVALID_NTP_SERVERS,
            encryptor_service.FAILURE_CODE_INVALID_SSH_KEY,
            encryptor_service.FAILURE_CODE_INVALID_USERDATA_INPUT,
            encryptor_service.FAILURE_CODE_NET_ROUTE_TIMEOUT,
            encryptor_service.FAILURE_CODE_NOT_AUTHORIZED_YETI,
            encryptor_service.FAILURE_CODE_FORBIDDEN_YETI,
            encryptor_service.FAILURE_CODE_TERMINAL_YETI_ERROR,
            'Some random unexpected thing',
            None
        ]
        for failure_code in failure_codes:
            with self.assertRaises(encryptor_service.EncryptionError):
                encryptor_service._handle_failure_code(failure_code)
