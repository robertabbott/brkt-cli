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
import os
import re
import sys
import tempfile
import urllib2
from distutils.version import LooseVersion
from operator import attrgetter

from brkt_cli import brkt_jwt, util
from brkt_cli.config import CLIConfig, CONFIG_PATH
from brkt_cli.proxy import Proxy, generate_proxy_config, validate_proxy_config
from brkt_cli.util import validate_dns_name_ip_address
from brkt_cli.validation import ValidationError

VERSION = '1.0.3pre1'

# The list of modules that may be loaded.  Modules contain subcommands of
# the brkt command and CSP-specific code.
SUBCOMMAND_MODULE_PATHS = [
    'brkt_cli.aws',
    'brkt_cli.brkt_jwt',
    'brkt_cli.config',
    'brkt_cli.esx',
    'brkt_cli.gce',
    'brkt_cli.get_public_key',
    'brkt_cli.make_key',
    'brkt_cli.make_user_data'
]

log = logging.getLogger(__name__)


class BracketEnvironment(object):
    def __init__(self, api_host=None, api_port=443,
                 hsmproxy_host=None, hsmproxy_port=443,
                 network_host=None, network_port=443,
                 public_api_host=None, public_api_port=443):
        self.api_host = api_host
        self.api_port = api_port
        self.hsmproxy_host = hsmproxy_host
        self.hsmproxy_port = hsmproxy_port
        self.network_host = network_host
        self.network_port = network_port
        self.public_api_host = public_api_host
        self.public_api_port = public_api_port

    def __repr__(self):
        return (
            '<BracketEnvironment api={be.api_host}:{be.api_port} '
            'hsmproxy={be.hsmproxy_host}:{be.hsmproxy_port} '
            'network={be.network_host}:{be.network_port} '
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

    api_host:port,hsmproxy_host:port,network_host:port

    :return: a BracketEnvironment object
    :raise: ValidationError if brkt_env is malformed
    """
    error_msg = (
        '--brkt-env value must be in the following format: '
        '<api-host>:<api-port>,<hsm-proxy-host>:<hsm-proxy-port>,'
        '<network-host>:<network-port>'
    )
    endpoints = brkt_env_string.split(',')
    if len(endpoints) != 3:
        raise ValidationError(error_msg)

    be = BracketEnvironment()
    names = ('api', 'hsmproxy', 'network')
    for name, endpoint in zip(names, endpoints):
        try:
            parts = util.parse_endpoint(endpoint)
            if 'port' not in parts:
                raise ValidationError(error_msg)
            setattr(be, name + '_host', parts['host'])
            setattr(be, name + '_port', parts['port'])
            if name == 'api':
                # set public api host based on the same prefix assumption
                # service-domain makes. Hopefully we'll remove brkt-env
                # soon and we can get rid of it
                be.public_api_host = be.api_host.replace('yetiapi', 'api')
        except ValueError:
            raise ValidationError(error_msg)

    return be


def brkt_env_from_domain(domain):
    """ Return a BracketEnvironment object based on the given domain
    (e.g. stage.mgmt.brkt.com).
    """
    return BracketEnvironment(
        api_host='yetiapi.' + domain,
        hsmproxy_host='hsmproxy.' + domain,
        network_host='network.' + domain,
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
    --service-domain or --brkt-env, return None.
    """
    if values.service_domain:
        return brkt_env_from_domain(values.service_domain)
    elif values.brkt_env:
        return parse_brkt_env(values.brkt_env)
    else:
        return None


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
        code = resp.getcode()
        if code / 100 != 2:
            raise Exception(
                'Error %d when opening %s' % (code, url))
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
    """ Check the incoming JWT and verify that it has all of the fields that
    we require.

    :param jwt a JSON Web Token as a string
    :return the JWT string
    :raise ValidationError if validation fails
    """
    if not jwt:
        return None

    # Validate header.
    header = brkt_jwt.get_header(jwt)
    expected_fields = ['typ', 'alg', 'kid']
    missing_fields = [f for f in expected_fields if f not in header]
    if missing_fields:
        raise ValidationError(
            'Missing fields in token header: %s.  Use the %s command '
            'to generate a valid token.' % (
                ','.join(missing_fields),
                brkt_jwt.SUBCOMMAND_NAME
            )
        )

    # Validate payload.
    payload = brkt_jwt.get_payload(jwt)
    if not payload.get('jti'):
        raise ValidationError(
            'Token payload does not contain the jti field.  Use the %s '
            'command to generate a valid token.' %
            brkt_jwt.SUBCOMMAND_NAME
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
    validate_jwt(jwt)

    uri = 'https://%s:%d/api/v1/customer/self' % (
        brkt_env.public_api_host,
        brkt_env.public_api_port
    )
    log.debug('Validating token against %s', uri)
    request = urllib2.Request(
        uri,
        headers={'Authorization': 'Bearer %s' % jwt}
    )
    try:
        response = urllib2.urlopen(request, timeout=10.0)
        log.debug('Server returned %d', response.getcode())
    except urllib2.HTTPError as e:
        if e.code == 401:
            raise ValidationError('Unauthorized token.')
        elif e.code == 400:
            payload = e.read()
            if payload:
                log.error(payload)
            raise ValidationError('Invalid token.')
        else:
            # Unexpected server response.  Log a warning and continue, so
            # that we don't unnecessarily interrupt the encryption process.
            log.debug('Server response: %s', e.msg)
            log.warn(
                'Unable to validate token.  Server returned error %d.  '
                'Use --no-validate to disable validation.' % e.code
            )
    except IOError:
        if log.isEnabledFor(logging.DEBUG):
            log.exception('')
        log.warn(
            'Unable to validate token against %s.  Use --no-validate to '
            'disable validation.',
            uri
        )


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
        network_host_port = '%s:%d' % (
            brkt_env.network_host, brkt_env.network_port)
        brkt_config['api_host'] = api_host_port
        brkt_config['hsmproxy_host'] = hsmproxy_host_port
        brkt_config['network_host'] = network_host_port


class SortingHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    def add_arguments(self, actions):
        actions = sorted(actions, key=attrgetter('option_strings'))
        super(SortingHelpFormatter, self).add_arguments(actions)


def main():
    parser = argparse.ArgumentParser(
        description='Command-line interface to the Bracket Computing service.',
        formatter_class=SortingHelpFormatter
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

    config = CLIConfig()

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

    # Setup expected config sections/options before we attempt to read from
    # disk
    for s in subcommands:
        s.setup_config(config)

    # Load defaults from disk. Subcommands are expected to register config
    # sections at import time so that correct default values can be displayed
    # to users if they request help.
    subcommand_load_messages.append(
        'Reading config from %s' % (CONFIG_PATH,))
    config.read()

    # Add subcommands to the parser.
    for s in subcommands:
        subcommand_load_messages.append(
            'Registering subcommand %s' % s.name())
        s.register(subparsers, config)

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

    # Prefix log messages with a compact timestamp, so that the user
    # knows how long each operation took.
    fmt = '%(asctime)s %(message)s'
    datefmt = '%H:%M:%S'

    # Set the root log level to DEBUG.  This passes all log messages to all
    # handlers.  We then filter by log level in each handler.
    logging.root.setLevel(logging.DEBUG)

    # Log to stderr at the level specified by the user.
    stderr_handler = logging.StreamHandler()
    formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)
    stderr_handler.setFormatter(formatter)
    stderr_handler.setLevel(log_level)
    logging.root.addHandler(stderr_handler)

    # Optionally log to a temp file at debug level.  If the command succeeds,
    # we delete this file.  If the command fails, we keep it around so that
    # the user can get more details.
    debug_handler = None
    debug_log_file = None
    if subcommand.debug_log_to_temp_file() and log_level != logging.DEBUG:
        debug_log_file = tempfile.NamedTemporaryFile(
            delete=False, prefix='brkt_cli')
        debug_handler = logging.FileHandler(debug_log_file.name)
        formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)
        debug_handler.setFormatter(formatter)
        debug_handler.setLevel(logging.DEBUG)
        logging.root.addHandler(debug_handler)

    # Write messages that were logged before logging was initialized.
    for msg in subcommand_load_messages:
        log.debug(msg)

    if values.check_version:
        if not _check_version():
            return 1

    result = 1

    # Run the subcommand.
    try:
        result = subcommand.run(values)
        if not isinstance(result, (int, long)):
            raise Exception(
                '%s did not return an integer result' % subcommand.name())
        log.debug('%s returned %d', subcommand.name(), result)
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
    finally:
        if debug_handler:
            if result == 0:
                os.remove(debug_log_file.name)
            else:
                debug_handler.close()
                logging.root.removeHandler(debug_handler)
                log.info('Debug log is available at %s', debug_log_file.name)
    return result


if __name__ == '__main__':
    exit_status = main()
    exit(exit_status)
