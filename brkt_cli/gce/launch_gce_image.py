import logging
import uuid

from brkt_cli.util import (
    append_suffix
)

log = logging.getLogger(__name__)

def launch(log, gce_svc, image_id, instance_name, zone, delete_boot, instance_type, network, subnetwork, metadata={}):
    if not instance_name:
        instance_name = 'brkt' + '-' + str(uuid.uuid4().hex)

    snap_name = append_suffix(instance_name, '-snap', 64)
    log.info("Creating guest root disk from snapshot")
    gce_svc.disk_from_snapshot(zone, image_id, snap_name)
    gce_svc.wait_for_disk(zone, snap_name)
    log.info("Starting instance")
    guest_disk = gce_svc.get_disk(zone, snap_name)
    guest_disk['autoDelete'] = True
    gce_svc.run_instance(zone=zone,
                         name=instance_name,
                         image=image_id,
                         disks=[guest_disk],
                         metadata=metadata,
                         delete_boot=delete_boot,
                         network=network,
                         subnet=subnetwork,
                         instance_type=instance_type)
    gce_svc.wait_instance(instance_name, zone)
    log.info("Instance %s (%s) launched successfully" % (instance_name,
             gce_svc.get_instance_ip(instance_name, zone)))

    return instance_name
