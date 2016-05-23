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

from __future__ import print_function

import argparse
import importlib
import json
import logging
import re
import sys
from distutils.version import LooseVersion

import requests

from brkt_cli import (
    util
)
from brkt_cli.proxy import Proxy
from brkt_cli.util import validate_dns_name_ip_address
from brkt_cli.validation import ValidationError
from encryptor_service import BracketEnvironment

VERSION = '0.9.17pre1'
BRKT_ENV_PROD = 'yetiapi.mgmt.brkt.com:443,hsmproxy.mgmt.brkt.com:443'

# The list of modules that may be loaded.  Modules contain subcommands of
# the brkt command and CSP-specific code.
SUBCOMMAND_MODULE_NAMES = [
    'brkt_cli.aws',
    'brkt_cli.gce',
    'brkt_cli.make_user_data',
    'brkt_cli.jwt',
]

log = logging.getLogger(__name__)


def validate_ntp_servers(ntp_servers):
    if ntp_servers is None:
        return
    for server in ntp_servers:
        if not validate_dns_name_ip_address(server):
            raise ValidationError(
                'Invalid ntp-server %s specified. '
                'Should be either a host name or an IPv4 address' % server)


def parse_tags(tag_strings):
    """ Parse the tags specified on the command line.

    :param: tag_strings a list of strings in KEY=VALUE format
    :return: the tags as a dictionary
    :raise: ValidationError if any of the tags are invalid
    """
    if not tag_strings:
        return {}

    tags = {}
    for s in tag_strings:
        key, value = util.parse_name_value(s)
        tags[key] = value

    return tags


def _api_login(api_addr, api_email, api_password, https=True):
    scheme = 'https' if https else 'http'
    r = requests.post(
        '%s://%s/oauth/credentials' % (scheme, api_addr),
        json={
            'username': api_email,
            'password': api_password,
            'grant_type': 'password'
        },
        headers={'Content-Type': 'application/json'},
        verify=False)
    resp = r.json()
    if 'id_token' not in resp:
        raise Exception('No id_token in reponse %s', r.text)
    s = requests.Session()
    s.headers.update({
        'Authorization': 'Bearer %s' % resp['id_token'],
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    })
    return s


def _get_identity_token(brkt_env, api_email, api_password):
    # Use the customer facing instead of mv facing api endpoint
    # (this removes 'yetiapi.' and replaces it with 'api.')
    api_host = 'api.' + brkt_env.api_host.split('.', 1)[-1]
    session = _api_login(api_host, api_email, api_password, https=True)
    response = session.post(
        'https://%s:%d/api/v1/identity/create_token' % (
            api_host, brkt_env.api_port),
        verify=False)
    if response.status_code != 201:
        raise ValidationError(
            "Couldn't get an identity token: %s: %s" % (
                response.status_code, response.content))
    return response.json()['token']


def parse_brkt_env(brkt_env_string):
    """ Parse the --brkt-env value.  The value is in the following format:

    api_host:port,hsmproxy_host:port

    :return: a BracketEnvironment object
    :raise: ValidationError if brkt_env is malformed
    """
    error_msg = (
        '--brkt-env value must be in the following format: '
        '<api-host>:<api-port>,<hsm-proxy-host>:<hsm-proxy-port>'
    )
    endpoints = brkt_env_string.split(',')
    if len(endpoints) != 2:
        raise ValidationError(error_msg)

    def _parse_endpoint(endpoint):
        host_port_pattern = r'([^:]+):(\d+)$'
        m = re.match(host_port_pattern, endpoint)
        if not m:
            raise ValidationError(error_msg)
        host = m.group(1)
        port = int(m.group(2))

        if not util.validate_dns_name_ip_address(host):
            raise ValidationError('Invalid hostname: ' + host)
        return host, port

    be = BracketEnvironment()
    (be.api_host, be.api_port) = _parse_endpoint(endpoints[0])
    (be.hsmproxy_host, be.hsmproxy_port) = _parse_endpoint(endpoints[1])
    return be


def _parse_proxies(*proxy_host_ports):
    """ Parse proxies specified on the command line.

    :param proxy_host_ports: a list of strings in "host:port" format
    :return: a list of Proxy objects
    :raise: ValidationError if any of the items are malformed
    """
    proxies = []
    for s in proxy_host_ports:
        m = re.match(r'([^:]+):(\d+)$', s)
        if not m:
            raise ValidationError('%s is not in host:port format' % s)
        host = m.group(1)
        port = int(m.group(2))
        if not util.validate_dns_name_ip_address(host):
            raise ValidationError('%s is not a valid hostname' % host)
        proxy = Proxy(host, port)
        proxies.append(proxy)

    return proxies


def get_proxy_config(values):
    """ Read proxy config specified by either the --proxy or
    --proxy-config-file option.

    @return: the contents of the proxy.yaml file, or None if not specified
    @raise ValidationError if the file cannot be read or is malformed
    """
    proxy_config = None
    if values.proxy_config_file:
        path = values.proxy_config_file
        log.debug('Loading proxy config from %s', path)
        try:
            with open(path) as f:
                proxy_config = f.read()
        except IOError as e:
            log.debug('Unable to read %s', path, e)
            raise ValidationError('Unable to read %s' % path)
        proxy.validate_proxy_config(proxy_config)
    elif values.proxies:
        proxies = _parse_proxies(*values.proxies)
        proxy_config = proxy.generate_proxy_config(*proxies)
        log.debug('Using proxy configuration:\n%s', proxy_config)

    return proxy_config


def _base64_decode_json(base64_string):
    """ Decode the given base64 string, and return the parsed JSON as a
    dictionary.
    @raise ValidationError if either the base64 or JSON is malformed
    """
    try:
        json_string = util.urlsafe_b64decode(base64_string)
        return json.loads(json_string)
    except (TypeError, ValueError) as e:
        raise ValidationError(
            'Unable to decode %s as JSON: %s' % (base64_string, e)
        )


def _is_version_supported(version, supported_versions):
    """ Return True if the given version string is at least as high as
    the earliest version string in supported_versions.
    """
    # We use LooseVersion because StrictVersion can't deal with patch
    # releases like 0.9.9.1.
    sorted_versions = sorted(
        supported_versions,
        key=lambda v: LooseVersion(v)
    )
    return LooseVersion(version) >= LooseVersion(sorted_versions[0])


def _is_later_version_available(version, supported_versions):
    """ Return True if the given version string is the latest supported
    version.
    """
    # We use LooseVersion because StrictVersion can't deal with patch
    # releases like 0.9.9.1.
    sorted_versions = sorted(
        supported_versions,
        key=lambda v: LooseVersion(v)
    )
    return LooseVersion(version) < LooseVersion(sorted_versions[-1])


def _check_version():
    """ Check if this version of brkt-cli is still supported by checking
    our version against the versions available on PyPI.  If a
    later version is available, print a message to the console.

    :return True if this version is still supported
    """
    try:
        url = 'http://pypi.python.org/pypi/brkt-cli/json'
        r = requests.get(url)
        if r.status_code / 100 != 2:
            raise Exception(
                'Error %d when opening %s' % (r.status_code, url))
        supported_versions = r.json()['releases'].keys()
    except Exception as e:
        print(e, file=sys.stderr)
        print(
            'Version check failed.  You can bypass it with '
            '--no-check-version',
            file=sys.stderr
        )
        return False

    if not _is_version_supported(VERSION, supported_versions):
        print(
            'Version %s is no longer supported.\n'
            'Run "pip install --upgrade brkt-cli" to upgrade to the '
            'latest version.' %
            VERSION,
            file=sys.stderr
        )
        return False
    if _is_later_version_available(VERSION, supported_versions):
        print(
            'A new release of brkt-cli is available.\n'
            'Run "pip install --upgrade brkt-cli" to upgrade to the '
            'latest version.',
            file=sys.stderr
        )

    return True


def validate_jwt(jwt):
    """ Perform some simple validation on the given JWT.

    @return the JWT
    @raise ValidationError if the JWT is malformed
    """
    if not jwt:
        return None

    # Decode header, payload, and signature.
    parts = jwt.split('.')
    if len(parts) != 3:
        raise ValidationError('Malformed JWT: ' + jwt)
    header = _base64_decode_json(parts[0])
    payload = _base64_decode_json(parts[1])

    try:
        util.urlsafe_b64decode(parts[2])
    except TypeError:
        raise ValidationError('Unable to decode signature ' + parts[2])

    # Validate header.
    expected_fields = ['typ', 'alg']
    missing_fields = [f for f in expected_fields if f not in header]
    if missing_fields:
        raise ValidationError(
            'Missing fields in JWT header: %s' % ','.join(missing_fields)
        )

    # Validate payload.
    expected_fields = ['jti', 'iss', 'iat', 'kid']
    missing_fields = [f for f in expected_fields if f not in payload]
    if missing_fields:
        raise ValidationError(
            'Missing fields in JWT payload: %s' % ','.join(missing_fields)
        )

    return jwt


def main():
    parser = argparse.ArgumentParser(
        description='Command-line interface to the Bracket Computing service.'
    )
    parser.add_argument(
        '-v',
        '--verbose',
        dest='verbose',
        action='store_true',
        help='Print status information to the console'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='brkt-cli version %s' % VERSION
    )
    parser.add_argument(
        '--no-check-version',
        dest='check_version',
        action='store_false',
        default=True,
        help="Don't check whether this version of brkt-cli is supported"
    )

    # Batch up messages that are logged while loading modules.  We don't know
    # whether to log them yet, since we haven't parsed arguments.  argparse
    # seems to get confused when you parse arguments twice.
    subcommand_load_messages = []

    # Dynamically load subcommands from modules.
    subcommands = []
    for module_name in SUBCOMMAND_MODULE_NAMES:
        try:
            module = importlib.import_module(module_name)
            subcommands.extend(module.get_subcommands())
        except ImportError as e:
            subcommand_load_messages.append(
                'Skipping module %s: %s' % (module_name, e))

    # Use metavar to hide any subcommands that we don't want to expose.
    exposed_subcommand_names = [s.name() for s in subcommands if s.exposed()]
    metavar = '{%s}' % ','.join(sorted(exposed_subcommand_names))

    subparsers = parser.add_subparsers(
        dest='subparser_name',
        metavar=metavar
    )

    # Add subcommands to the parser.
    for s in subcommands:
        subcommand_load_messages.append(
            'Registering subcommand %s' % s.name())
        s.register(subparsers)

    argv = sys.argv[1:]
    values = parser.parse_args(argv)

    # Initialize logging.  Verbose logging can be specified for either
    # the top-level "brkt" command or one of the subcommands.  We support
    # both because users got confused when "brkt encrypt-ami -v" didn't work.
    log_level = logging.INFO
    if values.verbose:
        log_level = logging.DEBUG

    # Turn off logging for categories that we don't care about.
    logging.getLogger('requests').setLevel(logging.ERROR)

    # Find the matching subcommand.
    subcommand = None
    for s in subcommands:
        if s.name() == values.subparser_name:
            subcommand = s
            break
    if not subcommand:
        raise Exception('Could not find subcommand ' + values.subparser_name)

    # Initialize logging.
    verbose = values.verbose
    if subcommand.verbose(values):
        verbose = True
    subcommand.init_logging(verbose)
    if verbose:
        log_level = logging.DEBUG

    # Log messages are written to stderr and are prefixed with a compact
    # timestamp, so that the user knows how long each operation took.
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s %(message)s',
        datefmt='%H:%M:%S'
    )

    # Write messages that were logged before logging was initialized.
    for msg in subcommand_load_messages:
        log.debug(msg)

    if values.check_version:
        if not _check_version():
            return 1

    # Run the subcommand.
    try:
        result = subcommand.run(values)
        if not isinstance(result, (int, long)):
            raise Exception(
                '%s did not return an integer result' % subcommand.name())
        log.debug('%s returned %d', subcommand.name(), result)
        return result

    except ValidationError as e:
        print(e, file=sys.stderr)
    except util.BracketError as e:
        if values.verbose:
            log.exception(e.message)
        else:
            log.error(e.message)
    except KeyboardInterrupt:
        if values.verbose:
            log.exception('Interrupted by user')
        else:
            log.error('Interrupted by user')
    return 1


if __name__ == '__main__':
    exit_status = main()
    exit(exit_status)
