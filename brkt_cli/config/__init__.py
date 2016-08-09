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

from brkt_cli.subcommand import Subcommand
from brkt_cli.util import render_table_rows
from brkt_cli.validation import ValidationError

log = logging.getLogger(__name__)

CONFIG_DIR = os.path.expanduser('~/.brkt')
CONFIG_PATH = os.path.join(CONFIG_DIR, 'config')

VERSION = 1


class InvalidOptionError(Exception):
    def __init__(self, option):
        self.option = option


class CLIConfig(object):
    """CLIConfig exposes an interface that subcommands can use to retrive
    persistent configuration options.
    """

    def __init__(self):
        self._config = {
            'version': VERSION,
            'options': {}
        }
        self._registered_options = collections.defaultdict(dict)

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

    def read(self):
        """Read the config from disk"""
        try:
            with open(CONFIG_PATH) as f:
                config = yaml.safe_load(f)
            self._config = config
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
        return 0


def get_subcommands():
    return [ConfigSubcommand()]
