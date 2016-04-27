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
import random
import re
import socket
import time
import uuid

from googleapiclient import errors


SLEEP_ENABLED = True
MAX_BACKOFF_SECS = 5
RETRYABLE_EXCEPTIONS = (socket.error, errors.HttpError)


class BracketError(Exception):
    pass


class Deadline(object):
    """Convenience class for bounding how long execution takes."""

    def __init__(self, secs_from_now, clock=time):
        self.deadline = clock.time() + secs_from_now
        self.clock = clock

    def is_expired(self):
        """Return whether or not the deadline has passed.

        Returns:
            True if the deadline has passed. False otherwise.
        """
        return self.clock.time() >= self.deadline


class RandExpBackoff(object):
    """Provides a capped, randomized sequence of exponential backoff values.
    Adds jitter (random duration between 0 and 1 sec) to help prevent
    thundering herds.
    """

    def __init__(self, max_backoff=MAX_BACKOFF_SECS):
        self.max_backoff = max_backoff
        self.count = 0

    def get_backoff(self):
        backoff = min(self.max_backoff, 2 ** self.count)
        # Add jitter between 0.0 and 1.0 sec
        backoff += random.random()
        self.count += 1
        return backoff


def retry(meth, nattempts=3, on=RETRYABLE_EXCEPTIONS):
    def _wrapped(*args, **kwargs):
        exp_backoff = RandExpBackoff()
        for attempt in range(nattempts):
            try:
                return meth(*args, **kwargs)
            except on:
                if attempt == nattempts - 1:
                    raise
                else:
                    backoff = exp_backoff.get_backoff()
                    time.sleep(backoff)
    return _wrapped


def sleep(seconds):
    if SLEEP_ENABLED:
        time.sleep(seconds)


def add_brkt_env_to_user_data(brkt_env, user_data):
    if brkt_env:
        if 'brkt' not in user_data:
            user_data['brkt'] = {}
        api_host_port = '%s:%d' % (brkt_env.api_host, brkt_env.api_port)
        hsmproxy_host_port = '%s:%d' % (
            brkt_env.hsmproxy_host, brkt_env.hsmproxy_port)
        user_data['brkt']['api_host'] = api_host_port
        user_data['brkt']['hsmproxy_host'] = hsmproxy_host_port


def make_nonce():
    """Returns a 32bit nonce in hex encoding"""
    return str(uuid.uuid4()).split('-')[0]


def validate_dns_name_ip_address(hostname):
    """ Verifies that the input hostname is indeed a valid
    host name or ip address

    :return True if valid, returns False otherwise
    """
    # ensure length does not exceed 255 characters
    if len(hostname) > 255:
        return False
    # remove the last dot from the end
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    valid = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(valid.match(x) for x in hostname.split("."))


def append_suffix(name, suffix, max_length=None):
    """ Append the suffix to the given name.  If the appended length exceeds
    max_length, truncate the name to make room for the suffix.

    :return: The possibly truncated name with the suffix appended
    """
    if not suffix:
        return name
    if max_length:
        truncated_length = max_length - len(suffix)
        name = name[:truncated_length]
    return name + suffix
