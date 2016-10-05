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

import re
from setuptools import setup
import sys

# Check Python version.
python_version = '%d.%d' % (sys.version_info[0], sys.version_info[1])
if python_version != '2.7':
    sys.exit(
        'brkt-cli requires Python 2.7.  Version %s is not supported.' %
        python_version)

version = ''
with open('brkt_cli/__init__.py', 'r') as fd:
    version = re.search(r'^VERSION\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

if not version:
    raise RuntimeError('Cannot find version information')

setup(
    name='brkt-cli',
    version=version,
    description='Bracket Computing command line interface',
    url='http://brkt.com',
    license='Apache 2.0',
    packages=[
        'brkt_cli',
        'brkt_cli.aws',
        'brkt_cli.brkt_jwt',
        'brkt_cli.config',
        'brkt_cli.crypto',
        'brkt_cli.esx',
        'brkt_cli.gce',
        'brkt_cli.get_public_key',
        'brkt_cli.make_key',
        'brkt_cli.make_user_data'
    ],
    install_requires=[
        'boto>=2.38.0',
        'cryptography>=1.3.2',
        'google-api-python-client>=1.5.0',
        'iso8601>=0.1.11',
        'oauth2client<3,>= 2.0.0',
        'oauthlib>=1.1.0',
        'pyasn1>=0.1.9',
        'pyjwt>=1.4.0',
        'pyvmomi>=5.5.50,<=6.0.0',
        'PyYaml>=3.11',
        'requests>=2.7.0',
    ],
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'brkt = brkt_cli:main',
        ]
    },
    package_dir={'brkt_cli': 'brkt_cli'},
    package_data={'brkt_cli': ['assets/ca_cert.pem']},
    test_suite='test test_gce'
)
