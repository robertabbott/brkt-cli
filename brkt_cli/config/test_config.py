import argparse
import StringIO
import unittest

from brkt_cli.config import (
    BRKT_HOSTED_ENV_NAME,
    CLIConfig,
    ConfigSubcommand,
    UnknownEnvironmentError
)
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


class GetEnvValues(object):
    def __init__(self, env_name):
        self.config_subcommand = 'get-env'
        self.env_name = env_name


class SetEnvValues(object):
    def __init__(self, env_name, api_server=None, key_server=None,
                 network_server=None, public_api_server=None,
                 service_domain=None):
        self.config_subcommand = 'set-env'
        self.env_name = env_name
        self.api_server = api_server
        self.key_server = key_server
        self.network_server = network_server
        self.public_api_server = public_api_server
        self.service_domain = service_domain


class UnsetEnvValues(object):
    def __init__(self, env_name):
        self.config_subcommand = 'unset-env'
        self.env_name = env_name


class ListEnvsValues(object):
    def __init__(self):
        self.config_subcommand = 'list-envs'


class UseEnvValues(object):
    def __init__(self, env_name):
        self.config_subcommand = 'use-env'
        self.env_name = env_name


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

    def test_get_default_env(self):
        """Verify that the brkt hosted environment is present by default"""
        self.cmd.run(GetEnvValues('brkt-hosted'))
        exp = "\n".join([
            'api-server=yetiapi.mgmt.brkt.com:443',
            'key-server=hsmproxy.mgmt.brkt.com:443',
            'network-server=network.mgmt.brkt.com:443',
            'public-api-server=api.mgmt.brkt.com:443'])
        self.assertEqual(self.out.getvalue(), exp + "\n")

    def test_set_default_env(self):
        """Verify that you cannot alter the default environment"""
        with self.assertRaises(ValidationError):
            self.cmd.run(SetEnvValues(BRKT_HOSTED_ENV_NAME))

    def test_set_env_from_service_domain(self):
        """Verify that you can define an environment using its service
        domain.
        """
        service_domain = 'foo.com'
        self.cmd.run(SetEnvValues('test', service_domain=service_domain))
        env = self.cfg.get_env('test')
        attr_host = {
            'api': 'yetiapi',
            'hsmproxy': 'hsmproxy',
            'network': 'network',
            'public_api': 'api',
        }
        for attr, host in attr_host.iteritems():
            exp = "%s.%s" % (host, service_domain)
            self.assertEqual(getattr(env, attr + '_host'), exp)

    def test_set_env_hosts(self):
        """Verify that you can set individual services of an environment"""
        test_cases = {
            'api': {
                'host': 'api.test.com',
                'port': 1,
                'attr': 'api',
            },
            'key': {
                'host': 'key.test.com',
                'port': 2,
                'attr': 'hsmproxy',
            },
            'network': {
                'host': 'network.test.com',
                'port': 3,
                'attr': 'network',
            },
            'public_api': {
                'host': 'public.test.com',
                'port': 4,
                'attr': 'public_api',
            },
        }
        for arg, tc in test_cases.iteritems():
            kwargs = {
                arg + '_server': '%s:%d' % (tc['host'], tc['port']),
            }
            self.cmd.run(SetEnvValues('test', **kwargs))
            env = self.cfg.get_env('test')
            host_attr = getattr(env, tc['attr'] + '_host')
            self.assertEqual(tc['host'], host_attr)
            port_attr = getattr(env, tc['attr'] + '_port')
            self.assertEqual(tc['port'], port_attr)

    def test_unset_unknown_env(self):
        """Verify that an error is raised when attempting to delete
        an unknown environment.
        """
        with self.assertRaises(ValidationError):
            self.cmd.run(UnsetEnvValues('unknown'))

    def test_unset_known_env(self):
        """Verify that we can delete an environment we have created
        """
        self.cmd.run(SetEnvValues('test', service_domain='foo.com'))
        self.cfg.get_env('test')
        self.cmd.run(UnsetEnvValues('test'))
        with self.assertRaises(UnknownEnvironmentError):
            self.cfg.get_env('test')

    def test_list_envs_default(self):
        """Verify that the hosted environment is marked as the
        active environment by default.
        """
        self.cmd.run(ListEnvsValues())
        self.assertEqual(self.out.getvalue(), "* brkt-hosted\n")

    def test_use_unknown_env(self):
        """Verify that we raise an error when the user attempts to
        activate an unknown environment.
        """
        with self.assertRaises(ValidationError):
            self.cmd.run(UseEnvValues('unknown'))

    def test_use_env(self):
        """Verify that we can switch between defined environments"""
        self.cmd.run(SetEnvValues('test1', service_domain='foo.com'))
        self.cmd.run(SetEnvValues('test2', service_domain='bar.com'))
        self.cmd.run(ListEnvsValues())
        out = "\n".join([
            "* brkt-hosted",
            "  test1      ",
            "  test2      "
        ])
        self.assertEqual(self.out.getvalue(), out + "\n")
        self.cmd.run(UseEnvValues('test2'))
        self.out.truncate(0)
        self.cmd.run(ListEnvsValues())
        out = "\n".join([
            "  brkt-hosted",
            "  test1      ",
            "* test2      "
        ])
        self.assertEqual(self.out.getvalue(), out + "\n")

    def test_use_incomplete_env(self):
        """Verify that we raise an error if a user attempts to
        use an incomplete environment.
        """
        self.cmd.run(SetEnvValues('test1', api_server='test.com'))
        with self.assertRaises(ValidationError):
            self.cmd.run(UseEnvValues('test1'))

    def test_fallback_env(self):
        """Verify that we fall back to the hosted environment if
        the user delete the current environment.
        """
        self.cmd.run(SetEnvValues('test1', service_domain='test.com'))
        self.cmd.run(UseEnvValues('test1'))
        self.cmd.run(UnsetEnvValues('test1'))
        self.cmd.run(ListEnvsValues())
        self.assertEqual(self.out.getvalue(), "* brkt-hosted\n")
