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
import inspect
import json
import tempfile
import time
import unittest

import yaml

import brkt_cli
import brkt_cli.aws
import brkt_cli.util
from brkt_cli import proxy
from brkt_cli.aws import (
    encrypt_ami
)
from brkt_cli.proxy import Proxy
from brkt_cli.validation import ValidationError


class TestEncryptAMIBackwardsCompatibility(unittest.TestCase):

    def test_attributes(self):
        required_attributes = (
            'AMI_NAME_MAX_LENGTH',
            'DESCRIPTION_SNAPSHOT',
            'NAME_ENCRYPTOR',
            'NAME_METAVISOR_ROOT_VOLUME',
            'NAME_METAVISOR_GRUB_VOLUME',
            'NAME_METAVISOR_LOG_VOLUME'
        )
        for attr in required_attributes:
            self.assertTrue(
                hasattr(encrypt_ami, attr),
                'Did not find attribute encrypt_ami.%s' % attr
            )

    def test_method_signatures(self):
        required_method_signatures = (
            ('append_suffix',
             ['name', 'suffix', 'max_length']),
            ('clean_up',
             ['aws_svc', 'instance_ids', 'security_group_ids']),
            ('get_encrypted_suffix', []),
            ('snapshot_encrypted_instance',
             ['aws_svc', 'enc_svc_cls', 'encryptor_instance',
              'encryptor_image', 'legacy']),
            ('register_ami',
             ['aws_svc', 'encryptor_instance', 'encryptor_image', 'name',
              'description', 'mv_bdm', 'legacy', 'mv_root_id']),
            ('wait_for_instance',
             ['aws_svc', 'instance_id']),
            ('create_encryptor_security_group', ['aws_svc'])
        )
        for mthd, args in required_method_signatures:
            self.assertTrue(
                hasattr(encrypt_ami, mthd),
                'Did not find method encrypt_ami.%s' % mthd
            )
            method_ref = encrypt_ami.__dict__[mthd]
            method_args = inspect.getargspec(method_ref)[0]
            for arg in args:
                self.assertIn(
                    arg, method_args,
                    'Did not find argument "%s" for method encrypt_ami.%s' % (
                        arg, mthd)
                )


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
            brkt_cli.parse_brkt_env('a')
        with self.assertRaises(ValidationError):
            brkt_cli.parse_brkt_env('a:7,b:8:9')
        with self.assertRaises(ValidationError):
            brkt_cli.parse_brkt_env('a:7,b?:8')

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
