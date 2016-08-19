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
import gzip
import re
from email import charset, message_from_string
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from StringIO import StringIO

import yaml

# Load the part handler.  Note that this is only used on the guest.
# On metavisor, we handle the parts in the cloudinit handler.
file_writer_handler = """
#part-handler

import os
import yaml
import pwd
import grp


def list_types():
    return ["text/brkt-files", "text/brkt-guest-files"]


def str2oct(s):
    '''Returns an integer from an octal string.'''
    return int(s, 8)


def output(msg):
    with open('/tmp/file_writer.out', 'a') as fd:
        fd.write('file_writer.handler: %s\\n' % (msg,))
    print "file_writer.handler: %s" % (msg,)


def handle_part(data, ctype, filename, payload):
    if ctype in ('__begin__', '__end__'):
        return

    file_config = yaml.safe_load(payload)

    for filename, config in file_config.iteritems():
        output('working on %s' % (filename,))
        file_dir = os.path.dirname(filename)
        if config.get('permissions'):
            file_mask = 0777 - config['permissions']
            dir_mask = 0777 - (config['permissions'] + 0111)

        # Use the current user as the owner of the file, unless they specify
        # them
        chowner = [-1, -1]
        if config.get('owner'):
            owner = config['owner']
            if isinstance(owner, str):
                owner = pwd.getpwnam(owner).pw_uid
            chowner[0] = owner
        if config.get('group'):
            group = config['group']
            if isinstance(group, str):
                group = grp.getgrnam(group).gr_gid
            chowner[1] = group

        if not os.path.exists(file_dir):
            old_umask = None
            if config.get('permissions'):
                old_umask = os.umask(dir_mask)
            output('creating directory %s' % (file_dir,))
            os.makedirs(file_dir)
            if old_umask is not None:
                os.umask(old_umask)
            os.chown(file_dir, *chowner)

        old_umask = None
        if config.get('permissions'):
            old_umask = os.umask(file_mask)
        with open(filename, 'w') as fd:
            output('writing file %s' % (filename,))
            fd.write(config.get('contents', ''))
        if old_umask is not None:
            os.umask(old_umask)
        os.chown(filename, *chowner)
"""


# Avoid base64 encoding the MIME parts
UTF8_CHARSET = charset.Charset('utf-8')
UTF8_CHARSET.body_encoding = None  # Python defaults to BASE64


def _new_mime_part(container, content_type, payload):
    # MIMEText will prepend to the content_type
    content_type = re.sub(r'^text/', '', content_type)
    message = MIMEText(payload, content_type, 'utf-8')
    del message['Content-Transfer-Encoding']
    message.set_payload(payload, UTF8_CHARSET)
    container.attach(message)


def get_mime_part_payload(mime_data, part_content_type):
    """ Return the payload for the part with the specified content-type.

    Returns None if a part with the specified content-type is not found.
    """
    msg = message_from_string(mime_data)

    for part in msg.walk():
        if part.get_content_type() != part_content_type:
            continue
        return part.get_payload(decode=True)
    return None


class UserDataContainer(object):
    def __init__(self):
        self.parts = []
        self.files_config = {}

    def add_part_handler(self):
        self.add_part('text/part-handler', file_writer_handler)

    def add_part(self, mimetype, content):
        self.parts.append((mimetype, content))

    def add_file(self, filename, content, content_type):
        if content_type not in self.files_config:
            self.files_config[content_type] = {}
        self.files_config[content_type][filename] = {
            'contents': content,
        }

    def to_mime_text(self):
        # These hard coded strings are to avoid having diffs in userdata
        # when nothing changed. Without this AWS sees the userdata has changed
        # (the MIME boundary or "unixfrom" changed) and it relaunches the
        # instance to give it new data.
        container = MIMEMultipart(boundary='--===============HI-20131203==--')
        container._unixfrom = 'From nobody Tue Dec  3 19:00:57 2013'
        for part in self.parts:
            _new_mime_part(container, part[0], part[1])

        if self.files_config:
            for (content_type, files) in self.files_config.iteritems():
                _new_mime_part(container, content_type, yaml.safe_dump(files))

        return str(container)


def gzip_user_data(user_data_string):
    out = StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
        f.write(user_data_string)
    return out.getvalue()
