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


class ValidationError(Exception):
    pass


def min_int_argument(value, min_int):
    """ Called by argparse to verify that the value is an integer that is
    greater than or equal to min_int.

    :return the parsed integer value
    :raise argparse.ArgumentTypeError if value is not an integer or is
    out of bounds
    """
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('%s is not an integer' % value)

    if n < min_int:
        raise argparse.ArgumentTypeError('must be >= %d' % min_int)

    return n


def max_int_argument(value, max_int):
    """ Called by argparse to verify that the value is an integer that is
    less than or equal to max_int.

    :return the parsed integer value
    :raise argparse.ArgumentTypeError if value is not an integer or is
    out of bounds
    """
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('%s is not an integer' % value)

    if n > max_int:
        raise argparse.ArgumentTypeError('must be <= %d' % max_int)

    return n


def range_int_argument(value, min_int, max_int, exclusions=[]):
    """ Called by argparse to verify that
    * the value is an integer and that
    * min_int <= value <= max_int
    * the value is not in the list of exclusions

    :return the parsed integer value
    :raise argparse.ArgumentTypeError if value is not an integer or is
    out of bounds or in the list of exclusions
    """
    n = min_int_argument(value, min_int)
    n = max_int_argument(n, max_int)
    if n in set(exclusions):
        raise argparse.ArgumentTypeError('cannot be one of %s' % exclusions)
    return n
