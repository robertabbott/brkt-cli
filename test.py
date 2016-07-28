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
import importlib
import json
import tempfile
import time
import unittest

import yaml

import brkt_cli
import brkt_cli.util
from brkt_cli import proxy
from brkt_cli.proxy import Proxy
from brkt_cli.validation import ValidationError


class TestVersionCheck(unittest.TestCase):

    def test_is_version_supported(self):
        supported = [
            '0.9.8', '0.9.9', '0.9.9.1', '0.9.10', '0.9.11', '0.9.12'
        ]
        self.assertFalse(
            brkt_cli._is_version_supported('0.9.7', supported)
        )
        self.assertTrue(
            brkt_cli._is_version_supported('0.9.8', supported)
        )
        self.assertTrue(
            brkt_cli._is_version_supported('0.9.12', supported)
        )
        self.assertTrue(
            brkt_cli._is_version_supported('0.9.13pre1', supported)
        )
        self.assertTrue(
            brkt_cli._is_version_supported('0.9.13', supported)
        )

    def test_is_later_version_available(self):
        supported = [
            '0.9.8', '0.9.9', '0.9.9.1', '0.9.10', '0.9.11', '0.9.12'
        ]
        self.assertTrue(
            brkt_cli._is_later_version_available('0.9.11', supported)
        )
        self.assertFalse(
            brkt_cli._is_later_version_available('0.9.12', supported)
        )
        self.assertFalse(
            brkt_cli._is_later_version_available('0.9.13pre1', supported)
        )


class TestProxy(unittest.TestCase):

    def test_generate_proxy_config(self):
        """ Test generating proxy.yaml from Proxy objects.
        """
        p1 = Proxy(host='proxy1.example.com', port=8001)
        p2 = Proxy(host='proxy2.example.com', port=8002)
        proxy_yaml = proxy.generate_proxy_config(p1, p2)
        proxy.validate_proxy_config(proxy_yaml)
        d = yaml.load(proxy_yaml)

        self.assertEquals('proxy1.example.com', d['proxies'][0]['host'])
        self.assertEquals(8001, d['proxies'][0]['port'])
        self.assertEqual('https', d['proxies'][0]['protocol'])
        self.assertEqual('encryptor', d['proxies'][0]['usage'])

        self.assertEquals('proxy2.example.com', d['proxies'][1]['host'])
        self.assertEquals(8002, d['proxies'][1]['port'])

    def test_validate_proxy_config(self):
        """ Test that proxy.yaml validation fails unless we specify at least
        one complete proxy configuration.
        """
        d = {}
        with self.assertRaises(ValidationError):
            proxy.validate_proxy_config(yaml.dump(d))

        d['proxies'] = []
        with self.assertRaises(ValidationError):
            proxy.validate_proxy_config(yaml.dump(d))

        proxies = {}
        d['proxies'].append(proxies)
        with self.assertRaises(ValidationError):
            proxy.validate_proxy_config(yaml.dump(d))

        proxies['host'] = 'proxy.example.com'
        with self.assertRaises(ValidationError):
            proxy.validate_proxy_config(yaml.dump(d))

        proxies['port'] = 8001
        proxy.validate_proxy_config(yaml.dump(d))


class DummyValues(object):

    def __init__(self):
        self.proxies = []
        self.proxy_config_file = None
        self.status_port = None
        self.brkt_env = None
        self.service_domain = None


class TestCommandLineOptions(unittest.TestCase):
    """ Test handling of command line options."""

    def test_parse_tags(self):
        # Valid tag strings
        self.assertEquals(
            {'a': 'b', 'foo': 'bar'},
            brkt_cli.parse_tags(['a=b', 'foo=bar']))

        # Invalid tag string
        with self.assertRaises(ValidationError):
            brkt_cli.parse_tags(['abc'])

    def test_parse_proxies(self):
        """ Test parsing host:port strings to Proxy objects.
        """
        # Valid
        proxies = brkt_cli._parse_proxies(
            'example1.com:8001',
            'example2.com:8002',
            '192.168.1.1:8003'
        )
        self.assertEquals(3, len(proxies))
        (p1, p2, p3) = proxies[0:3]

        self.assertEquals('example1.com', p1.host)
        self.assertEquals(8001, p1.port)
        self.assertEquals('example2.com', p2.host)
        self.assertEquals(8002, p2.port)
        self.assertEquals('192.168.1.1', p3.host)
        self.assertEquals(8003, p3.port)

        # Invalid
        with self.assertRaises(ValidationError):
            brkt_cli._parse_proxies('example.com')
        with self.assertRaises(ValidationError):
            brkt_cli._parse_proxies('example.com:1:2')
        with self.assertRaises(ValidationError):
            brkt_cli._parse_proxies('example.com:1a')
        with self.assertRaises(ValidationError):
            brkt_cli._parse_proxies('invalid_hostname.example.com:8001')

    def test_parse_brkt_env(self):
        """ Test parsing of the command-line --brkt-env value.
        """
        be = brkt_cli.parse_brkt_env(
            'api.example.com:777,hsmproxy.example.com:888')
        self.assertEqual('api.example.com', be.api_host)
        self.assertEqual(777, be.api_port)
        self.assertEqual('hsmproxy.example.com', be.hsmproxy_host)
        self.assertEqual(888, be.hsmproxy_port)

        with self.assertRaises(ValidationError):
            brkt_cli.parse_brkt_env('a:7,b:8:9')
        with self.assertRaises(ValidationError):
            brkt_cli.parse_brkt_env('a:7,b?:8')

    def test_brkt_env_from_domain(self):
        be = brkt_cli.brkt_env_from_domain('example.com')
        self.assertEqual('yetiapi.example.com', be.api_host)
        self.assertEqual(443, be.api_port)
        self.assertEqual('hsmproxy.example.com', be.hsmproxy_host)
        self.assertEqual(443, be.hsmproxy_port)
        self.assertEqual('api.example.com', be.public_api_host)
        self.assertEqual(443, be.public_api_port)

    def test_get_proxy_config(self):
        """ Test reading proxy config from the --proxy and --proxy-config-file
        command line options.
        """
        # No proxy.
        values = DummyValues()
        self.assertIsNone(brkt_cli.get_proxy_config(values))

        # --proxy specified.
        values.proxies = ['proxy.example.com:8000']
        proxy_yaml = brkt_cli.get_proxy_config(values)
        d = yaml.load(proxy_yaml)
        self.assertEquals('proxy.example.com', d['proxies'][0]['host'])

        # --proxy-config-file references a file that doesn't exist.
        values.proxy = None
        values.proxy_config_file = 'bogus.yaml'
        with self.assertRaises(ValidationError):
            brkt_cli.get_proxy_config(values)

        # --proxy-config-file references a valid file.
        with tempfile.NamedTemporaryFile() as f:
            f.write(proxy_yaml)
            f.flush()
            values.proxy_config_file = f.name
            proxy_yaml = brkt_cli.get_proxy_config(values)

        d = yaml.load(proxy_yaml)
        self.assertEquals('proxy.example.com', d['proxies'][0]['host'])


class TestSubmodule(unittest.TestCase):

    def test_aws_module(self):
        """ Test that the AWS module is installed by setuptools.
        """
        importlib.import_module('brkt_cli.aws')


class TestJWT(unittest.TestCase):

    def test_validate_jwt(self):
        self.assertIsNone(brkt_cli.validate_jwt(None))

        # Valid(ish) JWT.  The validation code doesn't currently go as far
        # as to validate the signature.
        header = {'typ': 'JWT', 'alg': 'ES384', 'kid': 'abc'}
        payload = {
            'jti': brkt_cli.util.make_nonce(),
            'iss': 'brkt-cli-' + brkt_cli.VERSION,
            'iat': int(time.time())
        }
        signature = 'Signed, sealed, delivered'

        header_json = json.dumps(header)
        payload_json = json.dumps(payload)
        base64_header = brkt_cli.util.urlsafe_b64encode(header_json)
        base64_payload = brkt_cli.util.urlsafe_b64encode(payload_json)
        base64_signature = brkt_cli.util.urlsafe_b64encode(signature)

        jwt = '%s.%s.%s' % (base64_header, base64_payload, base64_signature)
        self.assertEqual(jwt, brkt_cli.validate_jwt(jwt))

        # Malformed JWT.
        jwt = '%s.%s' % (header_json, payload_json)
        with self.assertRaises(ValidationError):
            brkt_cli.validate_jwt(jwt)

        jwt = '%s.%s.%s' % (base64_header, 'xxx', base64_signature)
        with self.assertRaises(ValidationError):
            brkt_cli.validate_jwt(jwt)

        jwt = '%s.%s.%s.%s' % (
            base64_header, base64_payload, base64_signature, 'abcd')
        with self.assertRaises(ValidationError):
            brkt_cli.validate_jwt(jwt)

        # Missing header field.
        for missing_field in ['typ', 'alg', 'kid']:
            malformed_header = dict(header)
            del(malformed_header[missing_field])
            base64_malformed_header = brkt_cli.util.urlsafe_b64encode(
                json.dumps(malformed_header))
            jwt = '%s.%s.%s' % (
                base64_malformed_header, base64_payload, base64_signature)
            with self.assertRaises(ValidationError):
                brkt_cli.validate_jwt(jwt)

        # Missing payload field.
        for missing_field in ['jti', 'iss', 'iat']:
            malformed_payload = dict(payload)
            del(malformed_payload[missing_field])
            base64_malformed_payload = brkt_cli.util.urlsafe_b64encode(
                json.dumps(malformed_payload))
            jwt = '%s.%s.%s' % (
                base64_malformed_payload, base64_payload, base64_signature)
            with self.assertRaises(ValidationError):
                brkt_cli.validate_jwt(jwt)


class TestBrktEnv(unittest.TestCase):

    def test_add_brkt_env_to_user_data(self):
        userdata = {}
        api_host_port = 'api.example.com:777'
        hsmproxy_host_port = 'hsmproxy.example.com:888'
        expected_userdata = {
            'api_host': api_host_port,
            'hsmproxy_host': hsmproxy_host_port
        }
        brkt_env = brkt_cli.parse_brkt_env(
            api_host_port + ',' + hsmproxy_host_port)
        brkt_cli.add_brkt_env_to_brkt_config(brkt_env, userdata)
        self.assertEqual(userdata, expected_userdata)

    def test_brkt_env_from_values(self):
        """ Test parsing BracketEnvironment from the --service-domain and
        --brkt-env command line options.
        """
        # No values are set.
        self.assertIsNone(brkt_cli.brkt_env_from_values(DummyValues()))

        # Test --service-domain
        values = DummyValues()
        values.service_domain = 'example.com'
        brkt_env = brkt_cli.brkt_env_from_values(values)
        self.assertEqual(
            str(brkt_cli.brkt_env_from_domain('example.com')),
            str(brkt_env)
        )

        # Test --brkt-env
        values = DummyValues()
        values.brkt_env = 'yetiapi.example.com:443,hsmproxy.example.com:443'
        brkt_env = brkt_cli.brkt_env_from_values(values)
        self.assertEqual(
            str(brkt_cli.parse_brkt_env(values.brkt_env)),
            str(brkt_env)
        )
