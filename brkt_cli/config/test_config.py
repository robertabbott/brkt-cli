import argparse
import StringIO
import unittest

from brkt_cli.config import CLIConfig, ConfigSubcommand
from brkt_cli.validation import ValidationError


class GetValues(object):
    def __init__(self, option):
        self.config_subcommand = 'get'
        self.option = option


class SetValues(object):
    def __init__(self, option, value):
        self.config_subcommand = 'set'
        self.option = option
        self.value = value


class UnsetValues(object):
    def __init__(self, option):
        self.config_subcommand = 'unset'
        self.option = option


class ListValues(object):
    def __init__(self):
        self.config_subcommand = 'list'


def noop():
    pass


class ConfigCommandTestCase(unittest.TestCase):
    def setUp(self):
        self.out = StringIO.StringIO()
        self.cfg = CLIConfig()
        self.cfg.register_option('test-section.test-option', 'A test')
        self.cmd = ConfigSubcommand(stdout=self.out)
        parser = argparse.ArgumentParser()
        self.cmd.register(parser.add_subparsers(), self.cfg)
        self.cmd._write_config = noop

    def test_get_unknown_option(self):
        """Verify that we raise an error if the user attempts to fetch an
        unknown option.
        """
        options = ['no-section', 'test-section.no-option']
        for option in options:
            with self.assertRaises(ValidationError):
                self.cmd.run(GetValues(option))

    def test_set_unknown_option(self):
        """Verify that we raise an error if the user attempts to set an
        unknown option.
        """
        args = (('no-section.no-option', 'foo'),
                ('test-section.no-option', 'foo'))
        for opt, val in args:
            with self.assertRaises(ValidationError):
                self.cmd.run(SetValues(opt, val))

    def test_unset_unknown_option(self):
        """Verify that we raise an error if the user attempts to unset an
        unknown option.
        """
        options = ['no-section', 'test-section.no-option']
        for option in options:
            with self.assertRaises(ValidationError):
                self.cmd.run(UnsetValues(option))

    def test_set_list_get_unset(self):
        """Verify that we can successfully set, get, and unset an existing
        option.
        """
        val = 'test-val'
        opt = 'test-section.test-option'
        self.cmd.run(SetValues(opt, val))
        self.assertEqual(self.cfg.get_option(opt), val)

        self.cmd.run(GetValues(opt))
        self.assertEqual(self.out.getvalue(), "%s\n" % (val,))

        self.cmd.run(ListValues())
        self.assertEqual(self.out.getvalue(), "%s\n%s=%s\n" % (val, opt, val))

        self.cmd.run(UnsetValues(opt))
        self.assertEqual(self.cfg.get_option(opt), None)

    def test_cleanup_empty_subsections(self):
        """Verify that we clean up empty subsections of the config"""
        opt1 = 'a.b.c'
        opt2 = 'a.d.e'
        for opt in [opt1, opt2]:
            self.cfg.register_option(opt, 'test')
            self.cmd.run(SetValues(opt, 'val'))

        self.cmd.run(UnsetValues(opt1))
        self.assertEquals(self.cfg._config['options'], {'a': {'d': {'e': 'val'}}})

        self.cmd.run(UnsetValues(opt2))
        self.assertEquals(self.cfg._config['options'], {})
