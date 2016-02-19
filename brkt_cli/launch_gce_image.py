import logging


log = logging.getLogger(__name__)


def launch(log, gce_svc, image_id, instance_name, zone, delete_boot, metadata={}):
    guest = instance_name + 'guest'
    log.info("Creating guest root disk from snapshot")
    gce_svc.disk_from_snapshot(zone, image_id, guest)
    gce_svc.wait_for_disk(zone, guest)
    log.info("Starting instance")
    gce_svc.run_instance(zone,
                         instance_name,
                         image_id,
                         [gce_svc.get_disk(zone, guest)],
                         metadata,
                         delete_boot,
                         'n1-standard-1')
    gce_svc.wait_instance(instance_name, zone)
