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

import inspect
import json
import os
import sys
import tempfile
import unittest

import brkt_cli
from brkt_cli import (
    proxy)
from brkt_cli.config import CLIConfig
from brkt_cli.instance_config import (
    BRKT_CONFIG_CONTENT_TYPE,
    BRKT_FILES_CONTENT_TYPE,
    InstanceConfig,
    INSTANCE_CREATOR_MODE,
    INSTANCE_METAVISOR_MODE,
    INSTANCE_UPDATER_MODE
)
from brkt_cli.instance_config_args import (
    instance_config_args_to_values,
    instance_config_from_values
)
from brkt_cli.proxy import Proxy
from brkt_cli.user_data import get_mime_part_payload
from brkt_cli.validation import ValidationError

test_jwt = (
    'eyJhbGciOiAiRVMzODQiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiYnJrdC1jb'
    'GktMC45LjE3cHJlMSIsICJpYXQiOiAxNDYzNDI5MDg1LCAianRpIjogImJlN2J'
    'mYzYwIiwgImtpZCI6ICJhYmMifQ.U2lnbmVkLCBzZWFsZWQsIGRlbGl2ZXJlZA'
)

# Some test constants
api_host_port = 'api.example.com:777'
hsmproxy_host_port = 'hsmproxy.example.com:888'
network_host_port = 'network.example.com:999'
ntp_server1 = '10.4.5.6'
ntp_server2 = '199.55.32.1'
proxy_host = '10.22.33.44'
proxy_port = 3128
proxy_host_port = '%s:%d' % (proxy_host, proxy_port)


def _get_ca_cert_filename():
    # Find the "ca_cert.pem" file in brkt_cli/assets
    my_dir = os.path.dirname(inspect.getfile(inspect.currentframe()))
    return os.path.join(my_dir, 'assets', 'ca_cert.pem')


def _verify_proxy_config_in_userdata(ut, userdata):
    brkt_files = get_mime_part_payload(userdata, BRKT_FILES_CONTENT_TYPE)
    ut.assertTrue('/var/brkt/ami_config/proxy.yaml: ' +
                    '{contents: "version: 2.0' in brkt_files)
    ut.assertTrue('host: %s' % proxy_host in brkt_files)
    ut.assertTrue('port: %d' % proxy_port in brkt_files)


class TestInstanceConfig(unittest.TestCase):

    def test_brkt_env(self):
        brkt_config_in = {
            'api_host': api_host_port,
            'hsmproxy_host': hsmproxy_host_port,
            'network_host': network_host_port
        }
        ic = InstanceConfig(brkt_config_in)
        config_json = ic.make_brkt_config_json()
        expected_json = ('{"brkt": {"api_host": "%s", ' +
            '"hsmproxy_host": "%s", "network_host": "%s"}}') % \
            (api_host_port, hsmproxy_host_port, network_host_port)
        self.assertEqual(config_json, expected_json)

    def test_ntp_servers(self):
        # First with just one server
        ic = InstanceConfig({'ntp_servers': [ntp_server1]})

        config_json = ic.make_brkt_config_json()
        expected_json = '{"brkt": {"ntp_servers": ["%s"]}}' % ntp_server1
        self.assertEqual(config_json, expected_json)

        # Now try two servers
        ic = InstanceConfig({'ntp_servers': [ntp_server1, ntp_server2]})

        config_json = ic.make_brkt_config_json()
        expected_json = '{"brkt": {"ntp_servers": ["%s", "%s"]}}' % \
                        (ntp_server1, ntp_server2)
        self.assertEqual(config_json, expected_json)

    def test_jwt(self):
        ic = InstanceConfig({'identity_token': test_jwt})
        config_json = ic.make_brkt_config_json()
        expected_json = '{"brkt": {"identity_token": "%s"}}' % test_jwt
        self.assertEqual(config_json, expected_json)

    def test_proxy_config(self):
        # The proxy file goes in a brkt-file part,
        # so the brkt config should be empty
        ic = InstanceConfig({})
        p = Proxy(host=proxy_host, port=proxy_port)
        proxy_config = proxy.generate_proxy_config(p)
        ic.add_brkt_file('proxy.yaml', proxy_config)
        _verify_proxy_config_in_userdata(self, ic.make_userdata())

    def test_multiple_options(self):
        brkt_config_in = {
            'api_host': api_host_port,
            'hsmproxy_host': hsmproxy_host_port,
            'network_host': network_host_port,
            'ntp_servers': [ntp_server1],
            'identity_token': test_jwt
        }
        ic = InstanceConfig(brkt_config_in)
        ic.add_brkt_file('ca_cert.pem.example.com', 'DUMMY CERT')
        ud = ic.make_userdata()
        brkt_config_json = get_mime_part_payload(ud, BRKT_CONFIG_CONTENT_TYPE)
        brkt_config = json.loads(brkt_config_json)['brkt']

        self.assertEqual(brkt_config['identity_token'], test_jwt)
        self.assertEqual(brkt_config['ntp_servers'], [ntp_server1])
        self.assertEqual(brkt_config['api_host'], api_host_port)
        self.assertEqual(brkt_config['hsmproxy_host'], hsmproxy_host_port)
        self.assertEqual(brkt_config['network_host'], network_host_port)

        brkt_files = get_mime_part_payload(ud, BRKT_FILES_CONTENT_TYPE)
        self.assertEqual(brkt_files,
                        "/var/brkt/ami_config/ca_cert.pem.example.com: " +
                        "{contents: DUMMY CERT}\n")

        """
        gce_metadata = ic.make_gce_metadata()
        item_list = gce_metadata['items']
        self.assertEqual(len(item_list), 1)
        brkt_item = item_list[0]
        self.assertEqual(brkt_item['key'], 'brkt')
        brkt_userdata = brkt_item['value']
        """


def _get_brkt_config_for_cli_args(cli_args='', mode=INSTANCE_CREATOR_MODE,
                                  cli_config=None):
    values = instance_config_args_to_values(cli_args)
    ic = instance_config_from_values(values, mode=mode, cli_config=cli_config)
    ud = ic.make_userdata()
    brkt_config_json = get_mime_part_payload(ud, BRKT_CONFIG_CONTENT_TYPE)
    brkt_config = json.loads(brkt_config_json)['brkt']
    return brkt_config


class TestInstanceConfigFromCliArgs(unittest.TestCase):

    def test_brkt_env(self):
        cli_args = '--brkt-env %s,%s,%s' % (
            api_host_port, hsmproxy_host_port, network_host_port)
        brkt_config = _get_brkt_config_for_cli_args(cli_args)
        self.assertEqual(brkt_config['api_host'], api_host_port)
        self.assertEqual(brkt_config['hsmproxy_host'], hsmproxy_host_port)
        self.assertEqual(brkt_config['network_host'], network_host_port)

    def test_service_domain(self):
        brkt_config = _get_brkt_config_for_cli_args(
            '--service-domain example.com'
        )
        self.assertEqual(brkt_config['api_host'], 'yetiapi.example.com:443')
        self.assertEqual(
            brkt_config['hsmproxy_host'], 'hsmproxy.example.com:443')
        self.assertEqual(
            brkt_config['network_host'], 'network.example.com:443')

    def test_default_brkt_env(self):
        """ Test that Yeti endpoints aren't set when they're not specified
        on the command line.
        """
        prod_env = brkt_cli.get_prod_brkt_env()

        # In creator and updater mode, we default to prod.
        for mode in (INSTANCE_CREATOR_MODE, INSTANCE_UPDATER_MODE):
            brkt_config = _get_brkt_config_for_cli_args(mode=mode)
            self.assertEqual(
                '%s:%d' % (prod_env.api_host, prod_env.api_port),
                brkt_config.get('api_host')
            )
            self.assertEqual(
                '%s:%d' % (prod_env.hsmproxy_host, prod_env.hsmproxy_port),
                brkt_config.get('hsmproxy_host')
            )

        # In metavisor mode, we don't default the environment.
        brkt_config = _get_brkt_config_for_cli_args(
            mode=INSTANCE_METAVISOR_MODE)
        self.assertIsNone(brkt_config.get('api_host'))
        self.assertIsNone(brkt_config.get('hsmproxy_host'))
        self.assertIsNone(brkt_config.get('network_host'))

    def test_env_from_config(self):
        """ Test that we can use a custom environment that is stored
        in the config
        """
        config = CLIConfig()
        env = brkt_cli.brkt_env_from_domain('foo.com')
        config.set_env('test', env)
        config.set_current_env('test')
        for mode in (INSTANCE_CREATOR_MODE, INSTANCE_UPDATER_MODE):
            brkt_config = _get_brkt_config_for_cli_args(
                mode=mode, cli_config=config)
            for attr in ('api', 'hsmproxy', 'network'):
                endpoint = '%s:%d' % (
                    getattr(env, attr + '_host'),
                    getattr(env, attr + '_port'))
                self.assertEqual(endpoint, brkt_config.get(attr + '_host'))

    def test_ntp_servers(self):
        cli_args = '--ntp-server %s' % ntp_server1
        brkt_config = _get_brkt_config_for_cli_args(cli_args)
        server_list = brkt_config['ntp_servers']
        self.assertEqual(server_list, [ntp_server1])

        cli_args = '--ntp-server %s --ntp-server %s' % \
                   (ntp_server1, ntp_server2)
        brkt_config = _get_brkt_config_for_cli_args(cli_args)
        server_list = brkt_config['ntp_servers']
        self.assertEqual(server_list, [ntp_server1, ntp_server2])

    def test_jwt(self):
        cli_args = '--token %s' % test_jwt
        brkt_config = _get_brkt_config_for_cli_args(cli_args)
        self.assertEqual(brkt_config['identity_token'], test_jwt)

    def test_proxy_config(self):
        cli_args = '--proxy %s' % (proxy_host_port)
        values = instance_config_args_to_values(cli_args)
        ic = instance_config_from_values(values)
        _verify_proxy_config_in_userdata(self, ic.make_userdata())

    def test_ca_cert(self):
        domain = 'dummy.foo.com'
        # First make sure that you can't use --ca-cert without specifying endpoints
        cli_args = '--ca-cert dummy.crt'
        values = instance_config_args_to_values(cli_args)
        with self.assertRaises(ValidationError):
            ic = instance_config_from_values(values)

        # Now specify endpoint args but use a bogus cert
        endpoint_args = ('--brkt-env api.%s:7777,hsmproxy.%s:8888,' +
            'network.%s:9999') % (domain, domain, domain)
        dummy_ca_cert = 'THIS IS NOT A CERTIFICATE'
        with tempfile.NamedTemporaryFile() as f:
            f.write(dummy_ca_cert)
            f.flush()
            cli_args = endpoint_args + ' --ca-cert %s' % f.name
            values = instance_config_args_to_values(cli_args)
            with self.assertRaises(ValidationError):
                ic = instance_config_from_values(values)

        # Now use endpoint args and a valid cert
        cli_args = endpoint_args + ' --ca-cert %s' % _get_ca_cert_filename()
        values = instance_config_args_to_values(cli_args)
        ic = instance_config_from_values(values)
        ud = ic.make_userdata()
        brkt_files = get_mime_part_payload(ud, BRKT_FILES_CONTENT_TYPE)
        self.assertTrue(brkt_files.startswith(
                        "/var/brkt/ami_config/ca_cert.pem.dummy.foo.com: " +
                        "{contents: '-----BEGIN CERTIFICATE-----"))

        # Make sure the --ca-cert arg is only recognized in 'creator' mode
        # prevent stderr message from parse_args
        sys.stderr = open(os.devnull, 'w')
        try:
            values = instance_config_args_to_values(cli_args,
                                                    mode=INSTANCE_METAVISOR_MODE)
        except SystemExit:
            pass
        else:
            self.assertTrue(False, 'Did not get expected exception')
        sys.stderr.close()
        sys.stderr = sys.__stderr__
