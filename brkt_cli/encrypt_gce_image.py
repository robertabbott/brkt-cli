
#!/usr/bin/env python

import logging
import time

from brkt_cli.util import (
    BracketError,
    Deadline,
)
from brkt_cli import encrypt_ami
from encrypt_ami import wait_for_encryption
from encrypt_ami import wait_for_encryptor_up
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials


log = logging.getLogger(__name__)


class InstanceError(BracketError):
    pass


class GCEService:
    def __init__(self, project, tags, logger):
        self.log = logger
        self.project = project
        self.tags = tags
        self.credentials = GoogleCredentials.get_application_default()
        self.compute = discovery.build('compute', 'v1',
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
            if 'READY' == self.compute.disks().get(zone=zone,
                    project=self.project, disk=diskName).execute()['status']:
                return
            time.sleep(10)
            self.log.info("Waiting for disk to become ready")

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

    def disk_from_snapshot(self, zone, snapshot, name):
        if self.disk_exists(zone, name):
            return
        base = "projects/%s/zones/%s" % (self.project, zone)
        body = {
                "name": name,
                "zone": base,
                "type": base + "/diskTypes/pd-standard",
                "sourceSnapshot": "projects/%s/global/snapshots/%s" % (self.project, snapshot),
                "sizeGb": "25"
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
            "type": base + "/diskTypes/pd-standard",
            "sizeGb": str(size)
        }
        self.compute.disks().insert(project=self.project,
                zone=zone, body=body).execute()

    def create_gce_image(self, zone, image_name, disk_name):
        build_disk = "projects/%s/zones/%s/disks/%s" % (self.project,
                zone, disk_name)
        self.compute.images().insert(body={"rawdisk": {},
            "name": image_name,
            "sourceDisk": build_disk},
            project=self.project).execute()

    def wait_image(self, image_name):
        while True:
            if self.compute.images().get(image=image_name, project=self.project).execute()['status'] == 'READY':
                return
            time.sleep(10)

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


# TODO if no encryptor image is provided get a metavisor image
# from GCS bucket which also has yet to be created
def encrypt(gce_svc, enc_svc_cls, image_id, encryptor_image,
            encrypted_image_name, zone, brkt_env):
    user_data = {}
    if brkt_env:
        endpoints = brkt_env.split(',')
        user_data['brkt'] = {
            'api_host': endpoints[0],
            'hsmproxy_host': endpoints[1],
        }
    instance_name = 'brkt-guest-' + gce_svc.get_session_id()
    encryptor = instance_name + '-encryptor'
    encrypted_image_disk = 'encrypted-image-' + gce_svc.get_session_id()

    gce_svc.run_instance(zone, instance_name, image_id)
    gce_svc.delete_instance(zone, instance_name)
    log.info('Guest instance terminated')
    log.info('Waiting for guest root disk to become ready')
    gce_svc.wait_for_detach(zone, instance_name)
    log.info('Launching encryptor instance')

    # create blank disk. the encrypted image will be
    # dd'd to this disk
    gce_svc.create_disk(zone, encrypted_image_disk)

    # run encryptor instance with avatar_creator as root,
    # customer image and blank disk
    gce_svc.run_instance(zone,
                         encryptor,
                         encryptor_image,
                         disks=[gce_svc.get_disk(zone, instance_name),
                                gce_svc.get_disk(zone, encrypted_image_disk)],
                         metadata=user_data)

    enc_svc = enc_svc_cls([gce_svc.get_instance_ip(encryptor, zone)])
    wait_for_encryptor_up(enc_svc, Deadline(600))
    wait_for_encryption(enc_svc)
    gce_svc.delete_instance(zone, encryptor)
    # snapshot encrypted guest disk
    log.info("Creating snapshot of encrypted image disk")
    gce_svc.create_snapshot(zone, encrypted_image_disk, encrypted_image_name)
    # create image from encryptor root
    gce_svc.wait_for_detach(zone, encryptor)

    # create image from mv root disk and snapshot
    # encrypted guest root disk
    log.info("Creating metavisor image")
    gce_svc.create_gce_image(zone, encrypted_image_name, encryptor)
    #gce_svc.create_gce_image(zone, encrypted_image_name + '-guest', encrypted_image_disk)
    gce_svc.wait_image(encrypted_image_name)
    #gce_svc.wait_image(encrypted_image_name + '-guest')
    gce_svc.wait_snapshot(encrypted_image_name)
    # delete all the disks that were created
    log.info("Cleaning up")
    cleanup(gce_svc, zone, [instance_name,
                            encryptor,
                            encrypted_image_disk])
    log.info("Image %s successfully created!", encrypted_image_name)
    return encrypted_image_name

def cleanup(gce_svc, zone, disks):
    for disk in disks:
        gce_svc.wait_for_detach(zone, disk)
        gce_svc.delete_disk(zone, disk)
