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
import collections
import errno
import logging
import os
import os.path
import sys
import tempfile
import yaml

import brkt_cli

from brkt_cli.subcommand import Subcommand
from brkt_cli.util import parse_endpoint, render_table_rows
from brkt_cli.validation import ValidationError

log = logging.getLogger(__name__)

CONFIG_DIR = os.path.expanduser('~/.brkt')
CONFIG_PATH = os.path.join(CONFIG_DIR, 'config')

VERSION = 2


class InvalidOptionError(Exception):
    def __init__(self, option):
        self.option = option


class UnknownEnvironmentError(Exception):
    def __init__(self, env):
        self.env = env


class InvalidEnvironmentError(Exception):
    def __init__(self, missing_keys):
        self.missing_keys = missing_keys


BRKT_HOSTED_ENV_NAME = 'brkt-hosted'


def _bracket_environment_to_dict(benv):
    """Convert a BracketEnvironment object to a dictionary that can be stored
    in a config.

    :param benv a BracketEnvironment object

    :return a dictionary
    """
    return {
        'api-host': benv.api_host,
        'api-port': benv.api_port,
        'keyserver-host': benv.hsmproxy_host,
        'keyserver-port': benv.hsmproxy_port,
        'public-api-host': benv.public_api_host,
        'public-api-port': benv.public_api_port,
        'network-host': benv.network_host,
        'network-port': benv.network_port,
    }


def _bracket_environment_from_dict(d):
    """Convert a bracket environment from the config into a BracketEnvironment
    object

    :param d a dictionary

    :return a BracketEnvironment object
    """
    benv = brkt_cli.BracketEnvironment()
    key_attr = {
        'api': 'api',
        'keyserver': 'hsmproxy',
        'public-api': 'public_api',
        'network': 'network',
    }
    for k, attr in key_attr.iteritems():
        for suff in ('host', 'port'):
            fk = k + '-' + suff
            if fk in d:
                setattr(benv, attr + '_' + suff, d[fk])
    return benv


def _validate_environment(benv):
    """Make sure all the necessary attributes of an environment are set.

    :raises InvalidEnvironmentError
    """
    attrs = ('api_host', 'hsmproxy_host', 'public_api_host', 'network_host')
    missing = []
    for attr in attrs:
        if getattr(benv, attr) is None:
            missing.append(attr)
    if len(missing) > 0:
        raise InvalidEnvironmentError(missing)


class CLIConfig(object):
    """CLIConfig exposes an interface that subcommands can use to retrive
    persistent configuration options.
    """

    def __init__(self):
        self._config = {
            'current-environment': None,
            'environments': {},
            'options': {},
            'version': VERSION,
        }
        self._add_prod_env()
        self._registered_options = collections.defaultdict(dict)

    def _get_env(self, env_name):
        if env_name not in self._config['environments']:
            raise UnknownEnvironmentError(env_name)
        d = self._config['environments'][env_name]
        return _bracket_environment_from_dict(d)

    def set_env(self, name, env):
        """Update the named environment.

        :param name the environment name (e.g. stage)
        :param env a BracketEnvironment instance
        """
        d = _bracket_environment_to_dict(env)
        self._config['environments'][name] = d

    def get_current_env(self):
        """Return the current environment.

        :return a tuple of environment name, BracketEnvironment
        """
        env_name = self._config['current-environment']
        return env_name, self.get_env(env_name)

    def set_current_env(self, env_name):
        """Change the current environment

        :param env_name the named env
        """
        env = self._get_env(env_name)
        _validate_environment(env)
        self._config['current-environment'] = env_name

    def get_env_meta(self):
        """Return all defined environments"""
        meta = {}
        for env_name in self._config['environments'].iterkeys():
            meta[env_name] = {
                'is_current': self._config['current-environment'] == env_name
            }
        return meta

    def get_env(self, env_name):
        """Return the named environment

        :param env_name a string

        :return a BracketEnvironment instance
        :raises UnknownEnvironmentError
        """
        return self._get_env(env_name)

    def unset_env(self, env_name):
        """Delete the named environment

        :param env_name a string
        :raises UnknownEnvironmentError
        """
        self._get_env(env_name)
        del self._config['environments'][env_name]
        if self._config['current-environment'] == env_name:
            self._config['current-environment'] = BRKT_HOSTED_ENV_NAME

    def _check_option(self, option):
        if option not in self._registered_options:
            raise InvalidOptionError(option)

    def register_option(self, option, desc):
        self._registered_options[option] = desc

    def registered_options(self):
        return self._registered_options

    def set_option(self, option, value):
        """Set the value for the supplied option.

        :param option a dot-delimited option string
        :param value the option value
        """
        self._check_option(option)
        levels = option.split('.')
        attr = levels.pop()
        cur = self._config['options']
        for level in levels:
            if level not in cur:
                cur[level] = {}
            cur = cur[level]
        cur[attr] = value

    def get_option(self, option, default=None):
        """Fetch the value for the supplied option.

        :param option a dot-delimited option string
        :param default the value to be returned if option is not present

        :return the option value
        """
        self._check_option(option)
        levels = option.split('.')
        attr = levels.pop()
        cur = self._config['options']
        for level in levels:
            if level not in cur:
                return default
            cur = cur[level]
        return cur.get(attr, default)

    def _remove_empty_dicts(self, h):
        to_remove = []
        for k in h:
            if isinstance(h[k], dict):
                self._remove_empty_dicts(h[k])
                if len(h[k]) == 0:
                    to_remove.append(k)
        for k in to_remove:
            del h[k]

    def unset_option(self, option):
        """Unset the value for the supplied option.
        :param option A dot-delimited option string
        """
        self._check_option(option)
        levels = option.split('.')
        attr = levels.pop()
        cur = self._config['options']
        for level in levels:
            if level not in cur:
                return
            cur = cur[level]
        if attr in cur:
            del cur[attr]
        # Clean up any empty sub-sections
        self._remove_empty_dicts(self._config['options'])

    def _migrate_config(self, config):
        """Handle migrating between different config versions"""
        if config['version'] == 1:
            config['environments'] = {}
            config['current-environment'] = None
            config['version'] = VERSION
        return config

    def _add_prod_env(self):
        prod_env = brkt_cli.get_prod_brkt_env()
        prod_dict = _bracket_environment_to_dict(prod_env)
        self._config['environments'][BRKT_HOSTED_ENV_NAME] = prod_dict
        if self._config.get('current-environment') is None:
            self._config['current-environment'] = BRKT_HOSTED_ENV_NAME

    def read(self):
        """Read the config from disk"""
        try:
            with open(CONFIG_PATH) as f:
                config = yaml.safe_load(f)
            self._config = self._migrate_config(config)
            self._add_prod_env()
        except IOError as e:
            if e.errno != errno.ENOENT:
                raise

    def write(self, f):
        """Write the config to disk.
        :param f A file-like object
        """
        yaml.dump(self._config, f)


class ConfigSubcommand(Subcommand):
    def __init__(self, stdout=sys.stdout):
        self.stdout = stdout

    def name(self):
        return 'config'

    def register(self, subparsers, parsed_config):
        self.parsed_config = parsed_config
        config_parser = subparsers.add_parser(
            self.name(),
            description=(
                'Display or update brkt-cli options stored in'
                ' ~/.brkt/config'),
            help='Display or update brkt-cli options'
        )

        config_subparsers = config_parser.add_subparsers(
            dest='config_subcommand'
        )

        # List all options
        config_subparsers.add_parser(
            'list',
            help='Display the values of all options set in the config file',
            description='Display the values of all options set in the config file')

        # All the options available for retrieval/mutation
        rows = []
        descs = self.parsed_config.registered_options()
        opts = sorted(descs.keys())
        for opt in opts:
            rows.append([opt, descs[opt]])
        opts_table = render_table_rows(rows, row_prefix='  ')
        epilog = "\n".join([
            'supported options:',
            '',
            opts_table
        ])

        # Set an option
        set_parser = config_subparsers.add_parser(
            'set',
            help='Set the value for an option',
            description='Set the value for an option',
            epilog=epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter)
        set_parser.add_argument(
            'option',
            help='The option name (e.g. encrypt-gce-image.project)')
        set_parser.add_argument(
            'value',
            help='The option value')

        # Get the value for an option
        get_parser = config_subparsers.add_parser(
            'get',
            help='Get the value for an option',
            description='Get the value for an option',
            epilog=epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter)
        get_parser.add_argument(
            'option',
            help='The option name (e.g. encrypt-gce-image.project)')

        # Unset the value for an option
        unset_parser = config_subparsers.add_parser(
            'unset',
            help='Unset the value for an option',
            description='Unset the value for an option',
            epilog=epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter)
        unset_parser.add_argument(
            'option',
            help='The option name (e.g. encrypt-gce-image.project)')

        # Define or update an environment
        set_env_parser = config_subparsers.add_parser(
            'set-env',
            help='Update the attributes of an environment',
            description="""
Update the attributes of an environment

Environments are persisted in your configuration and can be activated via the
`use-env` config subcommand. This command is particularly helpful if you need
to work with multiple on-prem control-plane deployments. For example, we could
define stage and prod control planes hosted at stage.foo.com and prod.foo.com,
respectively, by executing:

    > brkt config set-env stage --service-domain stage.foo.com
    > brkt config set-env prod --service-domain prod.foo.com

We can switch between the environments using the `use-env` config subcommand
like so:

    > brkt config use-env stage

We can determine the current environment using the `list-envs` config
subcommand:

    > brkt config list-envs
      brkt-hosted
      prod
    * stage
    >

The leading `*' indicates that the `stage' environment is currently active.
""",
            formatter_class=argparse.RawDescriptionHelpFormatter)
        set_env_parser.add_argument(
            'env_name',
            help='The environment name (e.g. stage)')
        set_env_parser.add_argument(
            '--api-server',
            help='The api server (host[:port]) the metavisor will connect to')
        set_env_parser.add_argument(
            '--key-server',
            help='The key server (host[:port]) the metavisor will connect to')
        set_env_parser.add_argument(
            '--network-server',
            help='The network server (host[:port]) the metavisor will connect to')
        set_env_parser.add_argument(
            '--public-api-server',
            help='The public api (host[:port])')
        set_env_parser.add_argument(
            '--service-domain',
            help=('Set server values from the service domain. This option '
                  ' assumes that each server is resolvable via a hostname'
                  ' rooted at service-domain. Specifically, api is expected to'
                  ' live at yetiapi.<service-domain>, key-server at '
                  ' hsmproxy.<service-domain>, network at '
                  ' network.<service-domain>, and public-api-server at'
                  ' api.<service-domain>.')
            )

        # Set the active environment
        use_env_parser = config_subparsers.add_parser(
            'use-env',
            help='Set the active environment',
            description='Set the active environment',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        use_env_parser.add_argument(
            'env_name',
            help='The environment name (e.g. stage)')

        # Display all defined environments
        config_subparsers.add_parser(
            'list-envs',
            help='Display all environments',
            description=(
                "Display all environments. The leading `*' indicates"
                " the currently active environment."))

        # Get the details of a specific environment
        get_env_parser = config_subparsers.add_parser(
            'get-env',
            help='Display the details of a specific environment',
            description='Display the details of an environment',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        get_env_parser.add_argument(
            'env_name',
            help='The environment name')

        # Unset a specific environment
        unset_env_parser = config_subparsers.add_parser(
            'unset-env',
            help='Delete an environment',
            description='Delete an environment')
        unset_env_parser.add_argument(
            'env_name',
            help='The environment name')

    def _unlink_noraise(self, path):
        try:
            os.unlink(path)
        except OSError as e:
            if e.errno == errno.ENOENT:
                pass
            else:
                log.exception("Failed unlinking %s", path)
        except:
            log.exception("Failed unlinking %s", path)

    def _write_config(self):
        """Create ~/.brkt if it doesn't exist and safely write out a
        new config.
        """
        try:
            os.mkdir(CONFIG_DIR, 0755)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        f = tempfile.NamedTemporaryFile(delete=False, prefix='brkt_cli')
        try:
            self.parsed_config.write(f)
            f.close()
        except:
            self._unlink_noraise(f.name)
            raise
        try:
            os.rename(f.name, CONFIG_PATH)
        except:
            self._unlink_noraise(f.name)
            raise

    def _list_options(self):
        """Display the contents of the config"""
        for opt in sorted(self.parsed_config.registered_options().keys()):
            val = self.parsed_config.get_option(opt)
            if val is not None:
                line = "%s=%s\n" % (opt, val)
                self.stdout.write(line)
        return 0

    def _get_option(self, opt):
        try:
            val = self.parsed_config.get_option(opt)
        except InvalidOptionError:
            raise ValidationError('Error: unknown option "%s".' % (opt,))
        if val:
            self.stdout.write("%s\n" % (val,))
        return 0

    def _set_option(self, opt, val):
        """Set the specified option"""
        try:
            self.parsed_config.set_option(opt, val)
        except InvalidOptionError:
            raise ValidationError('Error: unknown option "%s".' % (opt,))
        self._write_config()
        return 0

    def _unset_option(self, opt):
        """Unset the specified option"""
        try:
            self.parsed_config.unset_option(opt)
        except InvalidOptionError:
            raise ValidationError('Error: unknown option "%s".' % (opt,))
        self._write_config()
        return 0

    def _set_env(self, values):
        """Update attributes for the named environment"""
        if values.env_name == BRKT_HOSTED_ENV_NAME:
            raise ValidationError(
                'Error: cannot modify environment ' + values.env_name)
        try:
            env = self.parsed_config.get_env(values.env_name)
        except UnknownEnvironmentError:
            env = brkt_cli.BracketEnvironment()
        opt_attr = {
            'api': 'api',
            'key': 'hsmproxy',
            'public_api': 'public_api',
            'network': 'network',
        }
        for k in opt_attr.iterkeys():
            endpoint = k + '_server'
            endpoint = getattr(values, endpoint)
            if endpoint is None:
                continue
            try:
                parts = parse_endpoint(endpoint)
            except ValueError:
                raise ValidationError('Error: Invalid value for option --' + k + '-server')
            setattr(env, opt_attr[k] + '_host', parts['host'])
            setattr(env, opt_attr[k] + '_port', parts.get('port', 443))
        if values.service_domain is not None:
            env = brkt_cli.brkt_env_from_domain(values.service_domain)
        self.parsed_config.set_env(values.env_name, env)
        self._write_config()
        return 0

    def _use_env(self, values):
        """Set the active environemnt"""
        try:
            self.parsed_config.set_current_env(values.env_name)
        except UnknownEnvironmentError:
            raise ValidationError('Error: unknown environment ' + values.env_name)
        except InvalidEnvironmentError, e:
            attr_opt = {
                'api_host': 'api-server',
                'hsmproxy_host': 'key-server',
                'public_api_host': 'public-api-server',
                'network_host': 'network',
            }
            msg = ("Error: the environment %s is missing values for %s."
                   " Use `brkt config set-env` to set the appropriate values.")
            opts = []
            for attr in e.missing_keys:
                opts.append(attr_opt[attr])
            raise ValidationError(msg % (values.env_name, ', '.join(opts)))
        self._write_config()

    def _list_envs(self):
        """Display all envs"""
        meta = self.parsed_config.get_env_meta()
        rows = []
        for env_name in sorted(meta.keys()):
            marker = ' '
            if meta[env_name]['is_current']:
                marker = '*'
            rows.append((marker, env_name))
        self.stdout.write(render_table_rows(rows) + "\n")

    def _get_env(self, values):
        """Display the details of an environment"""
        try:
            env = self.parsed_config.get_env(values.env_name)
        except UnknownEnvironmentError:
            raise ValidationError('Error: unknown environment ' + values.env_name)
        attr_opt = {
            'api': 'api',
            'hsmproxy': 'key',
            'public_api': 'public-api',
            'network': 'network',
        }
        for k in sorted(attr_opt.keys()):
            host = getattr(env, k + '_host')
            if host is None:
                continue
            port = getattr(env, k + '_port')
            self.stdout.write("%s-server=%s:%d\n" % (attr_opt[k], host, port))

    def _unset_env(self, values):
        """Delete the named environment"""
        if values.env_name == BRKT_HOSTED_ENV_NAME:
            raise ValidationError(
                'Error: cannot delete environment ' + values.env_name)
        try:
            self.parsed_config.unset_env(values.env_name)
        except UnknownEnvironmentError:
            raise ValidationError('Error: unknown environment ' + values.env_name)
        self._write_config()

    def run(self, values):
        subcommand = values.config_subcommand
        if subcommand == 'list':
            self._list_options()
        elif subcommand == 'set':
            self._set_option(values.option, values.value)
        elif subcommand == 'get':
            self._get_option(values.option)
        elif subcommand == 'unset':
            self._unset_option(values.option)
        elif subcommand == 'set-env':
            self._set_env(values)
        elif subcommand == 'use-env':
            self._use_env(values)
        elif subcommand == 'list-envs':
            self._list_envs()
        elif subcommand == 'get-env':
            self._get_env(values)
        elif subcommand == 'unset-env':
            self._unset_env(values)
        return 0


def get_subcommands():
    return [ConfigSubcommand()]
