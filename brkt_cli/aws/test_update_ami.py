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

from brkt_cli.aws import (
    encrypt_ami, test_aws_service, update_ami
)
from brkt_cli.aws.test_aws_service import build_aws_service
from brkt_cli.test_encryptor_service import (
    DummyEncryptorService
)


class TestRunUpdate(unittest.TestCase):

    def setUp(self):
        encrypt_ami.SLEEP_ENABLED = False

    def test_subnet_and_security_groups(self):
        """ Test that the subnet and security group ids are passed through
        to run_instance().
        """
        aws_svc, encryptor_image, guest_image = build_aws_service()
        encrypted_ami_id = encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            encryptor_ami=encryptor_image.id
        )

        self.call_count = 0

        def run_instance_callback(args):
            self.call_count += 1
            self.assertEqual('subnet-1', args.subnet_id)
            self.assertEqual(['sg-1', 'sg-2'], args.security_group_ids)

        aws_svc.run_instance_callback = run_instance_callback
        ami_id = update_ami(
            aws_svc, encrypted_ami_id, encryptor_image.id,
            'Test updated AMI',
            subnet_id='subnet-1', security_group_ids=['sg-1', 'sg-2'],
            enc_svc_class=DummyEncryptorService
        )

        self.assertEqual(2, self.call_count)
        self.assertIsNotNone(ami_id)

    def test_guest_instance_type(self):
        """ Test that the guest instance type is passed through
        to run_instance().
        """
        aws_svc, encryptor_image, guest_image = \
            test_aws_service.build_aws_service()
        encrypted_ami_id = encrypt_ami.encrypt(
            aws_svc=aws_svc,
            enc_svc_cls=DummyEncryptorService,
            image_id=guest_image.id,
            encryptor_ami=encryptor_image.id
        )

        def run_instance_callback(args):
            if args.image_id == encrypted_ami_id:
                self.assertEqual('t2.micro', args.instance_type)
            elif args.image_id == encryptor_image.id:
                self.assertEqual('c3.large', args.instance_type)
            else:
                self.fail('Unexpected image: ' + args.image_id)

        aws_svc.run_instance_callback = run_instance_callback
        update_ami(
            aws_svc, encrypted_ami_id, encryptor_image.id, 'Test updated AMI',
            subnet_id='subnet-1', security_group_ids=['sg-1', 'sg-2'],
            enc_svc_class=DummyEncryptorService, guest_instance_type='t2.micro'
        )
