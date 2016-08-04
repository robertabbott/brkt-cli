import argparse
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
    make_instance_config,
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


BRKT_ENV_PROD = 'yetiapi.mgmt.brkt.com:443,hsmproxy.mgmt.brkt.com:443'


class EncryptGCEImageSubcommand(Subcommand):

    def name(self):
        return 'encrypt-gce-image'

    def register(self, subparsers, parsed_config):
        encrypt_gce_image_parser = subparsers.add_parser(
            'encrypt-gce-image',
            formatter_class=brkt_cli.SortingHelpFormatter
        )
        encrypt_gce_image_args.setup_encrypt_gce_image_args(
            encrypt_gce_image_parser, parsed_config)
        setup_instance_config_args(encrypt_gce_image_parser,
                                   brkt_env_default=BRKT_ENV_PROD)

    def setup_config(self, config):
        config.register_option(
            '%s.project' % (self.name(),),
            'The GCE project metavisors will be launched into')
        config.register_option(
            '%s.network' % (self.name(),),
            'The GCE network metavisors will be launched into')
        config.register_option(
            '%s.zone' % (self.name(),),
            'The GCE zone metavisors will be launched into')

    def run(self, values):
        return _run_subcommand(self.name(), values)


class UpdateGCEImageSubcommand(Subcommand):

    def name(self):
        return 'update-gce-image'

    def register(self, subparsers, parsed_config):
        update_gce_image_parser = subparsers.add_parser(
            'update-gce-image',
            formatter_class=brkt_cli.SortingHelpFormatter
        )
        update_encrypted_gce_image_args.setup_update_gce_image_args(update_gce_image_parser)
        setup_instance_config_args(update_gce_image_parser,
                                   brkt_env_default=BRKT_ENV_PROD)

    def run(self, values):
        return _run_subcommand(self.name(), values)


class LaunchGCEImageSubcommand(Subcommand):

    def name(self):
        return 'launch-gce-image'

    def register(self, subparsers, parsed_config):
        launch_gce_image_parser = subparsers.add_parser(
            'launch-gce-image',
            formatter_class=brkt_cli.SortingHelpFormatter
        )
        launch_gce_image_args.setup_launch_gce_image_args(launch_gce_image_parser)
        setup_instance_config_args(launch_gce_image_parser,
                                   mode=INSTANCE_METAVISOR_MODE)

    def run(self, values):
        return _run_subcommand(self.name(), values)


def get_subcommands():
    return [EncryptGCEImageSubcommand(),
            UpdateGCEImageSubcommand(),
            LaunchGCEImageSubcommand()]


def _run_subcommand(subcommand, values):
    if subcommand == 'encrypt-gce-image':
        return command_encrypt_gce_image(values, log)
    if subcommand == 'update-gce-image':
        return command_update_encrypted_gce_image(values, log)
    if subcommand == 'launch-gce-image':
        return command_launch_gce_image(values, log)


def command_launch_gce_image(values, log):
    gce_svc = gce_service.GCEService(values.project, None, log)
    brkt_env = brkt_cli.brkt_env_from_values(values)
    instance_config = make_instance_config(values, brkt_env,
                                           mode=INSTANCE_METAVISOR_MODE)
    if values.startup_script:
        extra_items = [{'key': 'startup-script', 'value': values.startup_script}]
    else:
        extra_items = None
    brkt_userdata = instance_config.make_userdata()
    metadata = gce_service.gce_metadata_from_userdata(brkt_userdata,
                                                      extra_items=extra_items)
    if not values.verbose:
        logging.getLogger('googleapiclient').setLevel(logging.ERROR)

    launch_gce_image.launch(log,
                            gce_svc,
                            values.image,
                            values.instance_name,
                            values.zone,
                            values.delete_boot,
                            values.instance_type,
                            metadata)
    return 0


def command_update_encrypted_gce_image(values, log):
    session_id = util.make_nonce()
    gce_svc = gce_service.GCEService(values.project, session_id, log)
    check_args(values, gce_svc)

    encrypted_image_name = gce_service.get_image_name(values.encrypted_image_name, values.image)

    gce_service.validate_image_name(encrypted_image_name)
    gce_service.validate_images(gce_svc,
                                encrypted_image_name,
                                values.encryptor_image,
                                values.image,
                                values.image_project)
    if not values.verbose:
        logging.getLogger('googleapiclient').setLevel(logging.ERROR)

    log.info('Starting updater session %s', gce_svc.get_session_id())

    brkt_env = (
        brkt_cli.brkt_env_from_values(values) or
        brkt_cli.get_prod_brkt_env()
    )

    updated_image_id = update_gce_image.update_gce_image(
        gce_svc=gce_svc,
        enc_svc_cls=encryptor_service.EncryptorService,
        image_id=values.image,
        encryptor_image=values.encryptor_image,
        encrypted_image_name=encrypted_image_name,
        zone=values.zone,
        instance_config=make_instance_config(
            values, brkt_env,mode=INSTANCE_UPDATER_MODE),
        keep_encryptor=values.keep_encryptor,
        image_file=values.image_file,
        image_bucket=values.bucket,
        network=values.network,
        status_port=values.status_port
    )

    print(updated_image_id)
    return 0


def command_encrypt_gce_image(values, log):
    session_id = util.make_nonce()
    gce_svc = gce_service.GCEService(values.project, session_id, log)
    check_args(values, gce_svc)

    encrypted_image_name = gce_service.get_image_name(values.encrypted_image_name, values.image)
    gce_service.validate_image_name(encrypted_image_name)
    gce_service.validate_images(gce_svc,
                                encrypted_image_name,
                                values.encryptor_image,
                                values.image,
                                values.image_project)
    if not values.verbose:
        logging.getLogger('googleapiclient').setLevel(logging.ERROR)

    log.info('Starting encryptor session %s', gce_svc.get_session_id())

    brkt_env = (
        brkt_cli.brkt_env_from_values(values) or
        brkt_cli.get_prod_brkt_env()
    )

    encrypted_image_id = encrypt_gce_image.encrypt(
        gce_svc=gce_svc,
        enc_svc_cls=encryptor_service.EncryptorService,
        image_id=values.image,
        encryptor_image=values.encryptor_image,
        encrypted_image_name=encrypted_image_name,
        zone=values.zone,
        instance_config=make_instance_config(
            values, brkt_env,mode=INSTANCE_CREATOR_MODE),
        image_project=values.image_project,
        keep_encryptor=values.keep_encryptor,
        image_file=values.image_file,
        image_bucket=values.bucket,
        network=values.network,
        status_port=values.status_port
    )
    # Print the image name to stdout, in case the caller wants to process
    # the output.  Log messages go to stderr.
    print(encrypted_image_id)
    return 0


def check_args(values, gce_svc):
    if not gce_svc.network_exists(values.network):
        raise ValidationError("Network provided does not exist")
    if values.encryptor_image:
        if values.bucket != 'prod':
            raise ValidationError("Please provided either an encryptor image or an image bucket")
    if not values.token:
        raise ValidationError('Must provide a token')

    brkt_env = brkt_cli.brkt_env_from_values(values)
    brkt_cli.check_jwt_auth(brkt_env, values.token)
