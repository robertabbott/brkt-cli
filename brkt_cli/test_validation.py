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
import argparse
import unittest

from brkt_cli import validation


class TestValidation(unittest.TestCase):

    def test_min_int_argument(self):
        self.assertEqual(5, validation.min_int_argument('5', 5))
        with self.assertRaises(argparse.ArgumentTypeError):
            validation.min_int_argument('x', 1)
        with self.assertRaises(argparse.ArgumentTypeError):
            validation.min_int_argument('-1', 0)

    def test_max_int_argument(self):
        self.assertEqual(5, validation.max_int_argument('5', 5))
        with self.assertRaises(argparse.ArgumentTypeError):
            validation.max_int_argument('x', 1)
        with self.assertRaises(argparse.ArgumentTypeError):
            validation.max_int_argument('3', 2)

    def test_range_int_argument(self):
        self.assertEqual(5, validation.range_int_argument('5', 5, 12))
        self.assertEqual(5, validation.range_int_argument('5', 5, 12,
                                                        exclusions=[4,7]))
        with self.assertRaises(argparse.ArgumentTypeError):
            validation.range_int_argument('x', 5, 12)
        with self.assertRaises(argparse.ArgumentTypeError):
            validation.range_int_argument('3', 7, 12)
