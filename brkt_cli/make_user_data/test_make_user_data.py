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

import inspect
import os
import StringIO
import unittest

from brkt_cli.make_user_data import MakeUserDataSubcommand
from brkt_cli.instance_config_args import instance_config_args_to_values


class TestMakeUserData(unittest.TestCase):

    def setUp(self):
        super(TestMakeUserData, self).setUp()
        name_fields = self.id().split('.')
        self.test_name = name_fields[-1]
        my_filename = inspect.getfile(inspect.currentframe())
        my_dir = os.path.dirname(my_filename)
        self.testdata_dir = os.path.join(my_dir, 'testdata')
        self.maxDiff = None # show full diff with knowngood multi-line strings

    def run_cmd(self, values):
        muds = MakeUserDataSubcommand()
        outstream = StringIO.StringIO()
        muds.run(values, out=outstream)
        output = outstream.getvalue()

        knowngood_file = os.path.join(self.testdata_dir,
                                      self.test_name + ".out")
        if not os.path.exists(knowngood_file):
            print 'knowngood file does not exist: %s' % (knowngood_file)
            print 'test_output = \n------\n%s\n------\n' % (output)
            raise

        with open(knowngood_file, 'r') as f:
            knowngood = f.read()

        self.assertMultiLineEqual(output, knowngood)

    def _init_values(self):
        values = instance_config_args_to_values('')
        values.make_user_data_brkt_files = None
        values.make_user_data_guest_fqdn = None
        return values

    def test_token_and_one_brkt_file(self):
        values = self._init_values()
        values.token = 'THIS_IS_NOT_A_JWT'
        infile = os.path.join(self.testdata_dir, 'logging.yaml')
        values.make_user_data_brkt_files = [ infile ]
        self.run_cmd(values)

    def test_add_one_brkt_file(self):
        values = self._init_values()
        infile = os.path.join(self.testdata_dir, 'logging.yaml')
        values.make_user_data_brkt_files = [ infile ]
        self.run_cmd(values)

    def test_add_one_binary_brkt_file(self):
        values = self._init_values()
        infile = os.path.join(self.testdata_dir, 'rand_bytes.bin')
        values.make_user_data_brkt_files = [ infile ]
        self.run_cmd(values)

    def test_proxy_and_one_brkt_file(self):
        values = self._init_values()
        values.proxies = [ '10.2.3.4:3128' ]
        infile = os.path.join(self.testdata_dir, 'colors.json')
        values.make_user_data_brkt_files = [ infile ]
        self.run_cmd(values)

    def test_add_two_brkt_files(self):
        values = self._init_values()
        infile1 = os.path.join(self.testdata_dir, 'logging.yaml')
        infile2 = os.path.join(self.testdata_dir, 'colors.json')
        values.make_user_data_brkt_files = [ infile1, infile2 ]
        self.run_cmd(values)

    def test_guest_fqdn(self):
        values = self._init_values()
        values.make_user_data_guest_fqdn = 'instance.foo.bar.com'
        self.run_cmd(values)
