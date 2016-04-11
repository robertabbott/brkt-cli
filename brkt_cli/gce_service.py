#!/usr/bin/env python

import datetime
import logging
import json
import re
import time

from brkt_cli.util import (
    BracketError,
    Deadline,
    make_nonce,
    append_suffix
)
from brkt_cli import encrypt_ami
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials


GCE_NAME_MAX_LENGTH = 63
LATEST_IMAGE = 'latest.image.tar.gz'
log = logging.getLogger(__name__)


class InstanceError(BracketError):
    pass


brkt_image_buckets = {
    'prod': 'brkt-prod-images',
    'stage': 'brkt-stage-images',
    'shared': 'brkt-shared-images'
}


class GCEService:
    def __init__(self, project, tags, logger):
        self.log = logger
        self.project = project
        self.tags = tags
        self.credentials = GoogleCredentials.get_application_default()
        self.compute = discovery.build('compute', 'v1',
                credentials=self.credentials)
        self.storage = discovery.build('storage', 'v1',
                credentials=self.credentials)
        self.gce_res_uri = "https://www.googleapis.com/compute/v1/"

    def list_zones(self):
        zones = []
        zones_resp = self.compute.zones().list(project=self.project).execute()
        for item in zones_resp['items']:
            zones.append(item['name'])

        return zones

    # TODO have do something
    def get_instance_status(self):
        return 'running'

    def get_session_id(self):
        return self.tags[encrypt_ami.TAG_ENCRYPTOR_SESSION_ID]

    def get_snapshot(self, name):
        return self.compute.snapshots().get(project=self.project,
                snapshot=name).execute()

    def wait_snapshot(self, snapshot):
        while True:
            if self.get_snapshot(snapshot)['status'] == 'READY':
                return
            time.sleep(5)

    def get_image(self, image):
        return self.compute.images().get(project=self.project,
               image=image).execute()

    def image_exists(self, image):
        try:
            self.get_image(image)
        except:
            return False
        return True

    def delete_instance(self, zone, instance):
        return self.compute.instances().delete(project=self.project,
               zone=zone, instance=instance).execute()

    def delete_disk(self, zone, disk):
        return self.compute.disks().delete(project=self.project,
               zone=zone, disk=disk).execute()

    def wait_instance(self, name, zone):
        while True:
            instance_data = self.compute.instances().list(project=self.project,
                    zone=zone).execute()
            if 'items' in instance_data:
                for i in instance_data['items']:
                    if name == i['name'] and i['status'] == 'RUNNING':
                        return
            self.log.info('Waiting for ' + name + ' to become ready')
            time.sleep(5)

    def get_instance_ip(self, name, zone):
        for i in range(60):
            time.sleep(5)
            try:
                nw = 'networkInterfaces'
                instance = self.compute.instances().get(project=self.project,
                        zone=zone, instance=name).execute()
                if instance[nw][0]['accessConfigs'][0]['natIP']:
                    return instance[nw][0]['accessConfigs'][0]['natIP']
            except:
                pass
        self.log.info("Couldn't find an IP address for this instance.")

    def detach_disk(self, zone, instance, diskName):
        self.compute.instances().detachDisk(project=self.project,
                instance=instance, zone=zone, deviceName=diskName).execute()
        # wait for disk ready
        return self.wait_for_detach(zone, diskName)

    def wait_for_disk(self, zone, diskName):
        while True:
            self.log.info("Waiting for disk to become ready")
            if 'READY' == self.compute.disks().get(zone=zone,
                    project=self.project, disk=diskName).execute()['status']:
                return
            time.sleep(10)

    def get_disk_size(self, zone, diskName):
        disk_info = self.compute.disks().get(zone=zone, project=self.project, disk=diskName).execute()
        return int(disk_info['sizeGb'])

    def wait_for_detach(self, zone, diskName):
        while True:
            if "users" not in self.compute.disks().get(zone=zone,
                    project=self.project, disk=diskName).execute():
                return
            time.sleep(10)
            self.log.info("Waiting for disk to detach from instance")

    def disk_exists(self, zone, name):
        try:
            self.compute.disks().get(zone=zone, project=self.project,
                    disk=name).execute()
            return True
        except:
            return False

    def create_snapshot(self, zone, disk, snapshot_name):
        disk_url = "projects/%s/zones/%s/disks/%s" % (self.project, zone, disk)
        body = {'sourceDisk':disk_url, 'name':snapshot_name}
        self.compute.disks().createSnapshot(project=self.project, disk=disk, body=body, zone=zone).execute()

    def delete_snapshot(self, snapshot_name):
        self.compute.snapshots().delete(project=self.project, snapshot=snapshot_name).execute()

    def disk_from_snapshot(self, zone, snapshot, name):
        if self.disk_exists(zone, name):
            return
        snap_info = self.compute.snapshots().get(project=self.project,
                                                 snapshot=snapshot).execute()
        base = "projects/%s/zones/%s" % (self.project, zone)
        body = {
                "name": name,
                "zone": base,
                "type": base + "/diskTypes/pd-ssd",
                "sourceSnapshot": "projects/%s/global/snapshots/%s" % (self.project, snapshot),
                "sizeGb": snap_info['diskSizeGb']
        }
        self.compute.disks().insert(project=self.project,
                zone=zone, body=body).execute()

    def create_disk(self, zone, name, size=25):
        if self.disk_exists(zone, name):
            return
        base = "projects/%s/zones/%s" % (self.project, zone)
        body = {
            "name": name,
            "zone": base,
            "type": base + "/diskTypes/pd-ssd",
            "sizeGb": str(size)
        }
        self.compute.disks().insert(project=self.project,
                zone=zone, body=body).execute()
        self.wait_for_disk(zone, name)

    def create_gce_image_from_disk(self, zone, image_name, disk_name):
        build_disk = "projects/%s/zones/%s/disks/%s" % (self.project,
                zone, disk_name)
        self.compute.images().insert(body={"rawdisk": {},
            "name": image_name,
            "sourceDisk": build_disk},
            project=self.project).execute()

    def create_gce_image_from_file(self, zone, image_name, file_name, bucket):
        source = "https://storage.googleapis.com/%s/%s" % (bucket, file_name)
        self.compute.images().insert(
            body={
                "rawDisk": {
                    "source": source
                },
                "name": image_name,
            },
            project=self.project).execute()

    def wait_image(self, image_name):
        while True:
            if self.compute.images().get(image=image_name,
                    project=self.project).execute()['status'] == 'READY':
                return
            time.sleep(10)

    def get_younger(self, new, old):
        new_time = datetime.datetime.strptime(new['timeCreated'],
                                              "%Y-%m-%dT%H:%M:%S.%fZ")
        old_time = datetime.datetime.strptime(old['timeCreated'],
                                              "%Y-%m-%dT%H:%M:%S.%fZ")
        if new_time > old_time:
            return new
        else:
            return old

    def get_image_file(self, bucket):
        files = self.storage.objects().list(bucket=bucket).execute()['items']
        # if LATEST_IMAGE exists return that
        for f in files:
            if f['name'] == LATEST_IMAGE:
                return LATEST_IMAGE

        # else return the newest file that ends in .image.tar.gz
        youngest = {'timeCreated': '1992-10-01T01:50:02.942Z'}
        for f in files:
            if 'image.tar.gz' in f['name']:
                youngest = self.get_younger(f, youngest)

        return youngest['name']

    def get_latest_encryptor_image(self,
                                   zone,
                                   image_name,
                                   bucket,
                                   image_file=None):
        if bucket in brkt_image_buckets:
            bucket = brkt_image_buckets[bucket]

        # if image_file is not provided try to get latest.image.tar.gz
        # if latest.image.tar.gz doesnt exist return the newest image
        if not image_file:
            image_file = self.get_image_file(bucket)
        self.create_gce_image_from_file(zone,
                                        image_name,
                                        image_file,
                                        bucket)
        self.wait_image(image_name)

    def run_instance(self,
                     zone,
                     name,
                     image,
                     disks=[],
                     metadata={},
                     delete_boot=False,
                     instance_type='n1-standard-4'):
        source_disk_image = "projects/%s/global/images/%s" % (self.project,
                image)
        machine_type = "zones/%s/machineTypes/%s" % (zone, instance_type)

        config = {
            'name': name,
            'machineType': machine_type,

            # Specify the boot disk and the image to use as a source.
            'disks': [
                {
                    'boot': True,
                    'autoDelete': delete_boot,
                    'initializeParams': {
                        'sourceImage': self.gce_res_uri + source_disk_image,
                    },
                },
            ] + disks,

            # Specify a network interface with NAT to access the public
            # internet.
            'networkInterfaces': [{
                'network': 'global/networks/default',
                'accessConfigs': [
                    {'type': 'ONE_TO_ONE_NAT', 'name': 'External NAT'}
                ]
            }],

            # Allow the instance to access cloud storage and logging.
            'serviceAccounts': [{
                'email': 'default',
                'scopes': [
                    'https://www.googleapis.com/auth/devstorage.read_write',
                    'https://www.googleapis.com/auth/logging.write'
                ]
            }],

            # Metadata is readable from the instance and allows you to
            # pass configuration from deployment scripts to instances.
            'metadata': metadata
        }

        instance = self.compute.instances().insert(
            project=self.project,
            zone=zone,
            body=config).execute()
        self.wait_instance(name, zone)
        return instance

    def get_disk(self, zone, disk_name):
        source_disk = "projects/%s/zones/%s/disks/%s" % (self.project,
                            zone, disk_name)
        return {
            'boot': False,
            'autoDelete': False,
            'source': self.gce_res_uri + source_disk,
            }


def wait_for_instance(
        gce_svc, instance_name, timeout=300, state='running'):
    """ Wait for up to timeout seconds for an instance to be in the
        'running' state.  Sleep for 2 seconds between checks.
    :return: The Instance object, or None if a timeout occurred
    :raises InstanceError if a timeout occurs or the instance unexpectedly
        goes into an error or terminated state
    """

    deadline = Deadline(timeout)
    while not deadline.is_expired():
        status = gce_svc.get_instance_status(instance_name)
        log.info('Instance %s state=%s' % instance_name, status)
        if status == state:
            return status
        if status == 'error':
            raise InstanceError(
                'Instance %s is in an error state.  Cannot proceed.' %
                instance_name
            )
        if state != 'terminated' and status == 'terminated':
            raise InstanceError(
                'Instance %s was unexpectedly terminated.' % instance_name
            )
        time.sleep(2)
    raise InstanceError(
        'Timed out waiting for %s to be in the %s state' %
        (instance_name, status)
    )


def gce_metadata_from_userdata(brkt_data):
    gce_metadata = {}
    gce_metadata['items']= [{'key': 'brkt',
                                  'value': json.dumps(brkt_data)}]
    return gce_metadata


def get_image_name(encrypted_image_name, name):
    if encrypted_image_name:
        return encrypted_image_name

    nonce = make_nonce()
    # Replace nonce in image name
    m = re.match('(.+)\-encrypted\-', name)
    if m:
        encrypted_image_name = append_suffix(
                m.group(1),
                '-encrypted-%s' % (nonce,),
                GCE_NAME_MAX_LENGTH)
    else:
        encrypted_image_name = append_suffix(
                name,
                '-encrypted-%s' % (nonce,),
                GCE_NAME_MAX_LENGTH)
    return encrypted_image_name
