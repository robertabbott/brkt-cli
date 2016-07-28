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
import urllib2
from distutils.version import LooseVersion
from operator import attrgetter

from brkt_cli import (
    brkt_jwt,
    util
)
from brkt_cli.proxy import Proxy, generate_proxy_config, validate_proxy_config
from brkt_cli.util import validate_dns_name_ip_address
from brkt_cli.validation import ValidationError

VERSION = '1.0.3pre1'

# The list of modules that may be loaded.  Modules contain subcommands of
# the brkt command and CSP-specific code.
SUBCOMMAND_MODULE_PATHS = [
    'brkt_cli.aws',
    'brkt_cli.brkt_jwt',
    'brkt_cli.gce',
    'brkt_cli.get_public_key',
    'brkt_cli.make_key',
    'brkt_cli.make_user_data'
]

log = logging.getLogger(__name__)


class BracketEnvironment(object):
    def __init__(self, api_host=None, api_port=443,
                 hsmproxy_host=None, hsmproxy_port=443,
                 public_api_host=None, public_api_port=443):
        self.api_host = api_host
        self.api_port = api_port
        self.hsmproxy_host = hsmproxy_host
        self.hsmproxy_port = hsmproxy_port
        self.public_api_host = public_api_host
        self.public_api_port = public_api_port

    def __repr__(self):
        return (
            '<BracketEnvironment api={be.api_host}:{be.api_port} '
            'hsmproxy={be.hsmproxy_host}:{be.hsmproxy_port} '
            'public_api={be.public_api_host}:{be.public_api_port}>'
        ).format(be=self)


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


def brkt_env_from_domain(domain):
    """ Return a BracketEnvironment object based on the given domain
    (e.g. stage.mgmt.brkt.com).
    """
    return BracketEnvironment(
        api_host='yetiapi.' + domain,
        hsmproxy_host='hsmproxy.' + domain,
        public_api_host='api.' + domain
    )


def get_prod_brkt_env():
    """ Return a BracketEnvironment object that represents the production
    service endpoints.
    """
    return brkt_env_from_domain('mgmt.brkt.com')


def brkt_env_from_values(values):
    """ Return a BracketEnvironment object based on options specified
    on the command line.  If the environment was not specified with
    --service-domain or --brkt-env, return the production environment.
    """
    if values.service_domain:
        return brkt_env_from_domain(values.service_domain)
    elif values.brkt_env:
        return parse_brkt_env(values.brkt_env)
    else:
        return get_prod_brkt_env()


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

    :return the contents of the proxy.yaml file, or None if not specified
    :raise ValidationError if the file cannot be read or is malformed
    """
    proxy_config = None
    if values.proxy_config_file:
        path = values.proxy_config_file
        log.debug('Loading proxy config from %s', path)
        try:
            with open(path) as f:
                proxy_config = f.read()
        except IOError as e:
            log.debug('Unable to read %s: %s', path, e)
            raise ValidationError('Unable to read %s' % path)
        validate_proxy_config(proxy_config)
    elif values.proxies:
        proxies = _parse_proxies(*values.proxies)
        proxy_config = generate_proxy_config(*proxies)
        log.debug('Using proxy configuration:\n%s', proxy_config)

    return proxy_config


def _base64_decode_json(base64_string):
    """ Decode the given base64 string, and return the parsed JSON as a
    dictionary.
    :raise ValidationError if either the base64 or JSON is malformed
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
    url = 'http://pypi.python.org/pypi/brkt-cli/json'
    log.debug('Getting supported brkt-cli versions from %s', url)

    try:
        resp = urllib2.urlopen(url, timeout=5.0)
        if resp.getcode() / 100 != 2:
            raise Exception(
                'Error %d when opening %s' % (r.status_code, url))
        d = json.loads(resp.read())
        supported_versions = d['releases'].keys()
    except Exception as e:
        # If we can't get the list of versions from PyPI, print the error
        # and return true.  We don't want the version check to block people
        # from getting their work done.
        if log.isEnabledFor(logging.DEBUG):
            log.exception('')
        log.info('Unable to load brkt-cli versions from PyPI: %s', e)
        return True

    if not _is_version_supported(VERSION, supported_versions):
        log.error(
            'Version %s is no longer supported. '
            'Run "pip install --upgrade brkt-cli" to upgrade to the '
            'latest version.',
            VERSION
        )
        return False
    if _is_later_version_available(VERSION, supported_versions):
        log.info(
            'A new release of brkt-cli is available. '
            'Run "pip install --upgrade brkt-cli" to upgrade to the '
            'latest version.'
        )

    return True


def validate_jwt(jwt):
    """ Perform some simple validation on the given JWT.

    :return the JWT
    :raise ValidationError if the JWT is malformed
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
    expected_fields = ['typ', 'alg', 'kid']
    missing_fields = [f for f in expected_fields if f not in header]
    if missing_fields:
        raise ValidationError(
            'Missing fields in JWT header: %s' % ','.join(missing_fields)
        )

    # Validate payload.
    expected_fields = ['jti', 'iss', 'iat']
    missing_fields = [f for f in expected_fields if f not in payload]
    if missing_fields:
        raise ValidationError(
            'Missing fields in JWT payload: %s' % ','.join(missing_fields)
        )

    return jwt


def check_jwt_auth(brkt_env, jwt):
    """ Authenticate with Yeti using the given JWT and make sure that the
    associated public key is registered with the account.

    :param brkt_env a BracketEnvironment object
    :param jwt a JWT string
    :raise ValidationError if the token fails auth or the public key is not
    registered with the given account
    """
    kid = brkt_jwt.get_key_id(jwt)
    uri = 'https://%s:%d/api/v1/jwk/%s' % (
        brkt_env.public_api_host,
        brkt_env.public_api_port,
        kid
    )
    log.debug('Validating token against %s', uri)
    request = urllib2.Request(
        uri,
        headers={'Authorization': 'Bearer %s' % jwt}
    )
    try:
        response = urllib2.urlopen(request)
    except urllib2.HTTPError as e:
        if e.code == 401:
            raise ValidationError('Unauthorized token.')
        else:
            log.debug('Server response: %s', e.msg)
            raise ValidationError(
                'Unable to validate token.  Server returned error ' + e.code)
    except IOError:
        if log.isEnabledFor(logging.DEBUG):
            log.exception('')
        raise ValidationError(
            'Unable to validate token.  Connection to %s failed.' % uri)

    log.debug('Server returned %d', response.getcode())


def add_brkt_env_to_brkt_config(brkt_env, brkt_config):
    """ Add BracketEnvironment values to the config dictionary
    that will be passed to the metavisor via userdata.

    :param brkt_env a BracketEnvironment object
    :param brkt_config a dictionary that contains configuration data
    """
    if brkt_env:
        api_host_port = '%s:%d' % (brkt_env.api_host, brkt_env.api_port)
        hsmproxy_host_port = '%s:%d' % (
            brkt_env.hsmproxy_host, brkt_env.hsmproxy_port)
        brkt_config['api_host'] = api_host_port
        brkt_config['hsmproxy_host'] = hsmproxy_host_port


class SortingHelpFormatter(argparse.HelpFormatter):
    def add_arguments(self, actions):
        actions = sorted(actions, key=attrgetter('option_strings'))
        super(SortingHelpFormatter, self).add_arguments(actions)


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
    for module_path in SUBCOMMAND_MODULE_PATHS:
        try:
            module = importlib.import_module(module_path)
            subcommands.extend(module.get_subcommands())
        except ImportError as e:
            # Parse the module name from the module path.
            m = re.match(r'(.*\.)?(.+)', module_path)
            module_name = None
            if m:
                module_name = m.group(2)

            if module_name and \
                    e.message == ('No module named ' + module_name):
                # The subcommand module is not installed.
                subcommand_load_messages.append(
                    'Skipping module %s: %s' % (module_path, e))
            else:
                # There is an import problem inside the subcommand module.
                raise

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

    # Find the matching subcommand.
    subcommand = None
    for s in subcommands:
        if s.name() == values.subparser_name:
            subcommand = s
            break
    if not subcommand:
        raise Exception('Could not find subcommand ' + values.subparser_name)

    # Initialize logging.  Verbose logging can be specified for either
    # the top-level "brkt" command or one of the subcommands.  We support
    # both because users got confused when "brkt encrypt-ami -v" didn't work.
    log_level = logging.INFO
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
