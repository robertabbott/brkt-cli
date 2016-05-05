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
import logging
import re
import sys
from distutils.version import LooseVersion

import requests

from brkt_cli import (
    encryptor_service,
    encrypt_gce_image,
    encrypt_gce_image_args,
    gce_service,
    launch_gce_image,
    launch_gce_image_args,
    oauth_requests,
    update_gce_image,
    update_encrypted_gce_image_args,
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
MODULE_NAMES = ['brkt_cli.aws', 'brkt_cli.gce']

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
        m = re.match(r'([^=]+)=(.+)', s)
        if not m:
            raise ValidationError('Tag %s is not in the format KEY=VALUE' % s)
        tags[m.group(1)] = m.group(2)
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
    endpoints = brkt_env_string.split(',')
    if len(endpoints) != 2:
        raise ValidationError('brkt-env requires two values')

    def _parse_endpoint(endpoint):
        host_port_pattern = r'([^:]+):(\d+)$'
        m = re.match(host_port_pattern, endpoint)
        if not m:
            raise ValidationError('Malformed endpoint: %s' % endpoints[0])
        host = m.group(1)
        port = int(m.group(2))

        if not util.validate_dns_name_ip_address(host):
            raise ValidationError('Invalid hostname: ' + host)
        return host, port

    be = BracketEnvironment()
    (be.api_host, be.api_port) = _parse_endpoint(endpoints[0])
    (be.hsmproxy_host, be.hsmproxy_port) = _parse_endpoint(endpoints[1])
    return be


def command_launch_gce_image(values, log):
    gce_svc = gce_service.GCEService(values.project, None, log)
    if values.startup_script:
        metadata = {'items': [{'key': 'startup-script', 'value': values.startup_script}]}
    else:
        metadata = {}
    launch_gce_image.launch(log,
                            gce_svc,
                            values.image,
                            values.instance_name,
                            values.zone,
                            values.delete_boot,
                            values.instance_type,
                            metadata)
    return 0


def command_update_encrypted_gce_image(values, log):
    session_id = util.make_nonce()
    gce_svc = gce_service.GCEService(values.project, session_id, log)
    encrypted_image_name = gce_service.get_image_name(values.encrypted_image_name, values.image)

    gce_service.validate_image_name(encrypted_image_name)

    log.info('Starting updater session %s', gce_svc.get_session_id())

    brkt_env = None
    if values.brkt_env:
        brkt_env = parse_brkt_env(values.brkt_env)
    else:
        brkt_env = parse_brkt_env(BRKT_ENV_PROD)

    # use pre-existing image
    if values.encryptor_image:
        encryptor = values.encryptor_image
    # create image from file in GCS bucket
    else:
        log.info('Retrieving encryptor image from GCS bucket')
        encryptor = 'encryptor-%s' % gce_svc.get_session_id()
        if values.image_file:
            gce_svc.get_latest_encryptor_image(values.zone,
                                               encryptor,
                                               values.bucket,
                                               image_file=values.image_file)
        else:
            gce_svc.get_latest_encryptor_image(values.zone,
                                               encryptor,
                                               values.bucket)

    encrypt_gce_image.validate_images(gce_svc, encrypted_image_name, encryptor, values.image)
    update_gce_image.update_gce_image(
        gce_svc=gce_svc,
        enc_svc_cls=encryptor_service.EncryptorService,
        image_id=values.image,
        encryptor_image=encryptor,
        encrypted_image_name=encrypted_image_name,
        zone=values.zone,
        brkt_env=brkt_env
    )
    return 0


def command_encrypt_gce_image(values, log):
    session_id = util.make_nonce()
    gce_svc = gce_service.GCEService(values.project, session_id, log)

    brkt_env = None
    if values.brkt_env:
        brkt_env = parse_brkt_env(values.brkt_env)
    else:
        brkt_env = parse_brkt_env(BRKT_ENV_PROD)
    token = _get_identity_token(brkt_env, values.api_email, values.api_password)

    encrypted_image_name = gce_service.get_image_name(values.encrypted_image_name, values.image)
    gce_service.validate_image_name(encrypted_image_name)
    # use pre-existing image
    if values.encryptor_image:
        encryptor = values.encryptor_image
    # create image from file in GCS bucket
    else:
        log.info('Retrieving encryptor image from GCS bucket')
        encryptor = 'encryptor-%s' % gce_svc.get_session_id()
        if values.image_file:
            gce_svc.get_latest_encryptor_image(values.zone,
                                               encryptor,
                                               values.bucket,
                                               image_file=values.image_file)
        else:
            gce_svc.get_latest_encryptor_image(values.zone,
                                               encryptor,
                                               values.bucket)

    encrypt_gce_image.validate_images(gce_svc, encrypted_image_name, encryptor,
                                      values.image, values.image_project)

    log.info('Starting encryptor session %s', gce_svc.get_session_id())
    encrypted_image_id = encrypt_gce_image.encrypt(
        gce_svc=gce_svc,
        enc_svc_cls=encryptor_service.EncryptorService,
        image_id=values.image,
        encryptor_image=encryptor,
        encrypted_image_name=encrypted_image_name,
        zone=values.zone,
        brkt_env=brkt_env,
        token=token,
        image_project=values.image_project
    )
    # Print the image name to stdout, in case the caller wants to process
    # the output.  Log messages go to stderr.
    print(encrypted_image_id)
    return 0


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
    module_load_messages = []

    # Load subcommand modules dynamically.
    modules = []
    subcommand_to_module = {}

    # Load any modules that are installed.
    for module_name in MODULE_NAMES:
        try:
            module = importlib.import_module(module_name)
            modules.append(module)
        except ImportError as e:
                module_load_messages.append(
                    'Skipping module %s: %s' % (module_name, e))

    # Map each subcommand to the module that contains it.
    for module in modules:
        for subcommand in module.get_interface().get_subcommands():
            subcommand_to_module[subcommand] = module

    # Use metavar to hide any subcommands that we don't want to expose.
    exposed_subcommands = []
    for module in modules:
        exposed_subcommands.extend(
            module.get_interface().get_exposed_subcommands()
        )
    exposed_subcommands = sorted(exposed_subcommands)
    metavar = '{%s}' % ','.join(exposed_subcommands)

    subparsers = parser.add_subparsers(
        dest='subparser_name',
        metavar=metavar
    )

    # Add subcommands to the parser.
    for subcommand, module in subcommand_to_module.iteritems():
        module_load_messages.append(
            'Registering subcommand %s in %s' % (
                subcommand, module.__package__)
        )
        module.get_interface().register_subcommand(subparsers, subcommand)

    encrypt_gce_image_parser = subparsers.add_parser('encrypt-gce-image')
    encrypt_gce_image_args.setup_encrypt_gce_image_args(encrypt_gce_image_parser)

    launch_gce_image_parser = subparsers.add_parser('launch-gce-image')
    launch_gce_image_args.setup_launch_gce_image_args(launch_gce_image_parser)

    update_gce_image_parser = subparsers.add_parser('update-gce-image')
    update_encrypted_gce_image_args.setup_update_gce_image_args(update_gce_image_parser)

    argv = sys.argv[1:]
    values = parser.parse_args(argv)

    # Initialize logging.  Log messages are written to stderr and are
    # prefixed with a compact timestamp, so that the user knows how long
    # each operation took.
    log_level = logging.INFO
    if values.verbose:
        log_level = logging.DEBUG

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s %(message)s',
        datefmt='%H:%M:%S'
    )

    for module in modules:
        module.get_interface().init_logging(values.verbose)

    for msg in module_load_messages:
        log.debug(msg)

    if values.check_version:
        supported_versions = None
    try:
        subcommand = values.subparser_name
        if subcommand in subcommand_to_module:
            module = subcommand_to_module[subcommand]
            return module.get_interface().run_subcommand(subcommand, values)
        if subcommand == 'launch-gce-image':
            log.info('Warning: GCE support is still in development.')
            return command_launch_gce_image(values, log)
        if subcommand == 'encrypt-gce-image':
            log.info('Warning: GCE support is still in development.')
            return command_encrypt_gce_image(values, log)
        if subcommand == 'update-gce-image':
            log.info('Warning: GCE support is still in development.')
            return command_update_encrypted_gce_image(values, log)
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
            return 1

        if not _is_version_supported(VERSION, supported_versions):
            print(
                'Version %s is no longer supported.\n'
                'Run "pip install --upgrade brkt-cli" to upgrade to the '
                'latest version.' %
                VERSION,
                file=sys.stderr
            )
            return 1
        if _is_later_version_available(VERSION, supported_versions):
            print(
                'A new release of brkt-cli is available.\n'
                'Run "pip install --upgrade brkt-cli" to upgrade to the '
                'latest version.',
                file=sys.stderr
            )
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
