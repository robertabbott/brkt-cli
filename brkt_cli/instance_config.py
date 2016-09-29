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

import json
import logging
import posixpath

from brkt_cli.user_data import UserDataContainer

# The directories for files saved on the Metavisor. We require that the dest
# path for all --brkt-files be within this directory.
#
# If the Metavisor is in 'creator' mode, it will only save files
# to '/var/brkt/ami_config'.
# If the Metavisor is in 'metavisor' mode, it will only save files
# to '/var/brkt/instance_config'.

BRKT_FILE_AMI_CONFIG = '/var/brkt/ami_config'
BRKT_FILE_INSTANCE_CONFIG = '/var/brkt/instance_config'

BRKT_CONFIG_CONTENT_TYPE = 'text/brkt-config'
BRKT_FILES_CONTENT_TYPE = 'text/brkt-files'
GUEST_FILES_CONTENT_TYPE = 'text/brkt-guest-files'

# Some instance config args are only supported when the Metavisor instance
# is running in 'creator' mode.
INSTANCE_METAVISOR_MODE = 1
INSTANCE_CREATOR_MODE   = 2
INSTANCE_UPDATER_MODE   = 3

log = logging.getLogger(__name__)


class BrktFile(object):
    def __init__(self, dest_filename, file_contents):
        self.dest_filename = dest_filename
        self.file_contents = file_contents


class InstanceConfig(object):
    """ Class containing common settings for Brkt instances """

    def __init__(self, brkt_config=None, mode=INSTANCE_CREATOR_MODE):
        if brkt_config is None:
            brkt_config = {}

        self.brkt_config = brkt_config
        self._brkt_files = []
        self.set_mode(mode)

    def brkt_files_dest_dir(self):
        return self._brkt_files_dest_dir

    def add_brkt_file(self, dest_filename, file_contents):
        # dest_filename will be relative to self._brkt_files_dest_dir
        dest_path = posixpath.join(self._brkt_files_dest_dir, dest_filename)
        brkt_file = BrktFile(dest_path, file_contents)
        self._brkt_files.append(brkt_file)

    def set_mode(self, mode=INSTANCE_CREATOR_MODE):
        self._mode = mode
        if mode is INSTANCE_METAVISOR_MODE:
            self._brkt_files_dest_dir = BRKT_FILE_INSTANCE_CONFIG
        else:
            self._brkt_files_dest_dir = BRKT_FILE_AMI_CONFIG

    def get_brkt_config(self):
        return self.brkt_config

    def set_brkt_config(self, brkt_config):
        self.brkt_config = brkt_config

    def make_brkt_config_json(self):
        brkt_config_dict = {'brkt': self.brkt_config}
        return json.dumps(brkt_config_dict, sort_keys=True)

    def make_userdata(self):
        udc = UserDataContainer()

        udc.add_part(BRKT_CONFIG_CONTENT_TYPE, self.make_brkt_config_json())

        for brkt_file in self._brkt_files:
            udc.add_file(brkt_file.dest_filename, brkt_file.file_contents,
                         BRKT_FILES_CONTENT_TYPE)
        return udc.to_mime_text()
