import logging
import uuid

log = logging.getLogger(__name__)

def launch(log, gce_svc, image_id, instance_name, zone, delete_boot, instance_type, metadata={}):
    if not instance_name:
        instance_name = 'brkt' + '-' + str(uuid.uuid4().hex)
    guest = instance_name + '-guest'
    log.info("Creating guest root disk from snapshot")
    gce_svc.disk_from_snapshot(zone, image_id, guest)
    gce_svc.wait_for_disk(zone, guest)
    log.info("Starting instance")
    guest_disk = gce_svc.get_disk(zone, guest)
    guest_disk['autoDelete'] = True
    gce_svc.run_instance(zone=zone,
                         name=instance_name,
                         image=image_id,
                         disks=[guest_disk],
                         metadata=metadata,
                         delete_boot=delete_boot,
                         instance_type=instance_type)
    gce_svc.wait_instance(instance_name, zone)
