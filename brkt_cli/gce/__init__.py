import brkt_cli
import logging

from brkt_cli.subcommand import Subcommand

from brkt_cli import encryptor_service, util
from brkt_cli.instance_config import (
    INSTANCE_CREATOR_MODE,
    INSTANCE_METAVISOR_MODE,
    INSTANCE_UPDATER_MODE
)
from brkt_cli.instance_config_args import (
    instance_config_from_values,
    setup_instance_config_args
)
from brkt_cli.gce import (
    encrypt_gce_image,
    encrypt_gce_image_args,
    gce_service,
    launch_gce_image,
    launch_gce_image_args,
    update_gce_image,
    update_encrypted_gce_image_args,
)
from brkt_cli.validation import ValidationError

log = logging.getLogger(__name__)


class EncryptGCEImageSubcommand(Subcommand):

    def name(self):
        return 'encrypt-gce-image'

    def setup_config(self, config):
        config.register_option(
            '%s.project' % (self.name(),),
            'The GCE project metavisors will be launched into')
        config.register_option(
            '%s.network' % (self.name(),),
            'The GCE network metavisors will be launched into')
        config.register_option(
            '%s.subnetwork' % (self.name(),),
            'The GCE subnetwork metavisors will be launched into')
        config.register_option(
            '%s.zone' % (self.name(),),
            'The GCE zone metavisors will be launched into')

    def register(self, subparsers, parsed_config):
        self.config = parsed_config
        encrypt_gce_image_parser = subparsers.add_parser(
            'encrypt-gce-image',
            description='Create an encrypted GCE image from an existing image',
            help='Encrypt a GCE image',
            formatter_class=brkt_cli.SortingHelpFormatter
        )
        encrypt_gce_image_args.setup_encrypt_gce_image_args(
            encrypt_gce_image_parser, parsed_config)
        setup_instance_config_args(encrypt_gce_image_parser)

    def debug_log_to_temp_file(self):
        return True

    def run(self, values):
        session_id = util.make_nonce()
        gce_svc = gce_service.GCEService(values.project, session_id, log)
        check_args(values, gce_svc, self.config)

        encrypted_image_name = gce_service.get_image_name(
            values.encrypted_image_name, values.image)
        gce_service.validate_image_name(encrypted_image_name)
        if values.validate:
            gce_service.validate_images(gce_svc,
                                        encrypted_image_name,
                                        values.encryptor_image,
                                        values.image,
                                        values.image_project)
        if not values.verbose:
            logging.getLogger('googleapiclient').setLevel(logging.ERROR)

        log.info('Starting encryptor session %s', gce_svc.get_session_id())

        encrypted_image_id = encrypt_gce_image.encrypt(
            gce_svc=gce_svc,
            enc_svc_cls=encryptor_service.EncryptorService,
            image_id=values.image,
            encryptor_image=values.encryptor_image,
            encrypted_image_name=encrypted_image_name,
            zone=values.zone,
            instance_config=instance_config_from_values(
                values, mode=INSTANCE_CREATOR_MODE, cli_config=self.config),
            image_project=values.image_project,
            keep_encryptor=values.keep_encryptor,
            image_file=values.image_file,
            image_bucket=values.bucket,
            network=values.network,
            subnetwork=values.subnetwork,
            status_port=values.status_port
        )
        # Print the image name to stdout, in case the caller wants to process
        # the output.  Log messages go to stderr.
        print(encrypted_image_id)
        return 0


class UpdateGCEImageSubcommand(Subcommand):

    def name(self):
        return 'update-gce-image'

    def register(self, subparsers, parsed_config):
        self.config = parsed_config
        update_gce_image_parser = subparsers.add_parser(
            'update-gce-image',
            description=(
                'Update an encrypted GCE image with the latest Metavisor '
                'release'),
            help='Update an encrypted GCE image',
            formatter_class=brkt_cli.SortingHelpFormatter
        )
        update_encrypted_gce_image_args.setup_update_gce_image_args(
            update_gce_image_parser)
        setup_instance_config_args(update_gce_image_parser)

    def debug_log_to_temp_file(self):
        return True

    def run(self, values):
        session_id = util.make_nonce()
        gce_svc = gce_service.GCEService(values.project, session_id, log)
        check_args(values, gce_svc, self.config)

        encrypted_image_name = gce_service.get_image_name(
            values.encrypted_image_name, values.image)
        gce_service.validate_image_name(encrypted_image_name)
        if values.validate:
            gce_service.validate_images(gce_svc,
                                        encrypted_image_name,
                                        values.encryptor_image,
                                        values.image)
        if not values.verbose:
            logging.getLogger('googleapiclient').setLevel(logging.ERROR)

        log.info('Starting updater session %s', gce_svc.get_session_id())

        updated_image_id = update_gce_image.update_gce_image(
            gce_svc=gce_svc,
            enc_svc_cls=encryptor_service.EncryptorService,
            image_id=values.image,
            encryptor_image=values.encryptor_image,
            encrypted_image_name=encrypted_image_name,
            zone=values.zone,
            instance_config=instance_config_from_values(
                values, mode=INSTANCE_UPDATER_MODE,
                cli_config=self.config),
            keep_encryptor=values.keep_encryptor,
            image_file=values.image_file,
            image_bucket=values.bucket,
            network=values.network,
            subnetwork=values.subnetwork,
            status_port=values.status_port
        )

        print(updated_image_id)
        return 0


class LaunchGCEImageSubcommand(Subcommand):

    def name(self):
        return 'launch-gce-image'

    def register(self, subparsers, parsed_config):
        self.config = parsed_config
        launch_gce_image_parser = subparsers.add_parser(
            'launch-gce-image',
            formatter_class=brkt_cli.SortingHelpFormatter,
            description='Launch a GCE image',
            help='Launch a GCE image'
        )
        launch_gce_image_args.setup_launch_gce_image_args(
            launch_gce_image_parser)
        setup_instance_config_args(launch_gce_image_parser,
                                   mode=INSTANCE_METAVISOR_MODE)

    def run(self, values):
        gce_svc = gce_service.GCEService(values.project, None, log)
        instance_config = instance_config_from_values(
            values, mode=INSTANCE_METAVISOR_MODE, cli_config=self.config)
        if values.startup_script:
            extra_items = [{
                'key': 'startup-script',
                'value': values.startup_script
            }]
        else:
            extra_items = None
        brkt_userdata = instance_config.make_userdata()
        metadata = gce_service.gce_metadata_from_userdata(
            brkt_userdata, extra_items=extra_items)
        if not values.verbose:
            logging.getLogger('googleapiclient').setLevel(logging.ERROR)

        if values.instance_name:
            gce_service.validate_image_name(values.instance_name)

        encrypted_instance_id = launch_gce_image.launch(log,
                                gce_svc,
                                values.image,
                                values.instance_name,
                                values.zone,
                                values.delete_boot,
                                values.instance_type,
                                values.network,
                                values.subnetwork,
                                metadata)
        print(encrypted_instance_id)
        return 0


def get_subcommands():
    return [EncryptGCEImageSubcommand(),
            UpdateGCEImageSubcommand(),
            LaunchGCEImageSubcommand()]


def check_args(values, gce_svc, cli_config):
    if values.encryptor_image:
        if values.bucket != 'prod':
            raise ValidationError("Please provided either an encryptor image or an image bucket")
    if not values.token:
        raise ValidationError('Must provide a token')

    if values.validate:
        if not gce_svc.project_exists(values.project):
            raise ValidationError("Project provided does not exist")
        if not gce_svc.network_exists(values.network):
            raise ValidationError("Network provided does not exist")
        brkt_env = brkt_cli.brkt_env_from_values(values)
        if brkt_env is None:
            _, brkt_env = cli_config.get_current_env()
        brkt_cli.check_jwt_auth(brkt_env, values.token)
