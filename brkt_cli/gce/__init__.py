import brkt_cli
import logging

from brkt_cli.subcommand import Subcommand

from brkt_cli import (
    encryptor_service,
    util
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

log = logging.getLogger(__name__)


class EncryptGCEImageSubcommand(Subcommand):

    def name(self):
        return 'encrypt-gce-image'

    def register(self, subparsers):
        encrypt_gce_image_parser = subparsers.add_parser('encrypt-gce-image')
        encrypt_gce_image_args.setup_encrypt_gce_image_args(encrypt_gce_image_parser)

    def run(self, values):
        return _run_subcommand(self.name(), values)


class UpdateGCEImageSubcommand(Subcommand):

    def name(self):
        return 'update-gce-image'

    def register(self, subparsers):
        update_gce_image_parser = subparsers.add_parser('update-gce-image')
        update_encrypted_gce_image_args.setup_update_gce_image_args(update_gce_image_parser)

    def run(self, values):
        return _run_subcommand(self.name(), values)


class LaunchGCEImageSubcommand(Subcommand):

    def name(self):
        return 'launch-gce-image'

    def register(self, subparsers):
        launch_gce_image_parser = subparsers.add_parser('launch-gce-image')
        launch_gce_image_args.setup_launch_gce_image_args(launch_gce_image_parser)

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
    if values.startup_script:
        metadata = {'items': [{'key': 'startup-script', 'value': values.startup_script}]}
    else:
        metadata = {}
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
    encrypted_image_name = gce_service.get_image_name(values.encrypted_image_name, values.image)

    brkt_env = None
    if values.brkt_env:
        brkt_env = brkt_cli.parse_brkt_env(values.brkt_env)
    else:
        brkt_env = brkt_cli.parse_brkt_env(brkt_cli.BRKT_ENV_PROD)
    token = brkt_cli._get_identity_token(brkt_env, values.api_email, values.api_password)

    gce_service.validate_image_name(encrypted_image_name)

    log.info('Starting updater session %s', gce_svc.get_session_id())
    update_gce_image.update_gce_image(
        gce_svc=gce_svc,
        enc_svc_cls=encryptor_service.EncryptorService,
        image_id=values.image,
        encryptor_image=values.encryptor_image,
        encrypted_image_name=encrypted_image_name,
        zone=values.zone,
        brkt_env=brkt_env,
        token=token,
        keep_encryptor=values.keep_encryptor,
        image_file=values.image_file,
        image_bucket=values.bucket
    )

    return 0


def command_encrypt_gce_image(values, log):
    session_id = util.make_nonce()
    gce_svc = gce_service.GCEService(values.project, session_id, log)

    brkt_env = None
    if values.brkt_env:
        brkt_env = brkt_cli.parse_brkt_env(values.brkt_env)
    else:
        brkt_env = brkt_cli.parse_brkt_env(brkt_cli.BRKT_ENV_PROD)
    token = brkt_cli._get_identity_token(brkt_env, values.api_email, values.api_password)

    encrypted_image_name = gce_service.get_image_name(values.encrypted_image_name, values.image)
    gce_service.validate_image_name(encrypted_image_name)


    log.info('Starting encryptor session %s', gce_svc.get_session_id())
    encrypted_image_id = encrypt_gce_image.encrypt(
        gce_svc=gce_svc,
        enc_svc_cls=encryptor_service.EncryptorService,
        image_id=values.image,
        encryptor_image=values.encryptor_image,
        encrypted_image_name=encrypted_image_name,
        zone=values.zone,
        brkt_env=brkt_env,
        token=token,
        image_project=values.image_project,
        keep_encryptor=values.keep_encryptor,
        image_file=values.image_file,
        image_bucket=values.bucket
    )
    # Print the image name to stdout, in case the caller wants to process
    # the output.  Log messages go to stderr.
    print(encrypted_image_id)
    return 0


