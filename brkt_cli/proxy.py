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


PROXY_ITEM_TEMPLATE = """  - host: %(host)s
    port: %(port)d
    protocol: https
    usage: encryptor
"""


class Proxy(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port


def generate_proxy_config(*proxies):
    """ Return a proxy config YAML file based on the given proxies.

    :param proxies: a list of Proxy objects
    :return: the config file contents as a string
    """
    contents = 'version: 2.0\nproxies:\n'
    for p in proxies:
        item = PROXY_ITEM_TEMPLATE % {
            'host': p.host,
            'port': p.port
        }
        contents += item

    return contents
