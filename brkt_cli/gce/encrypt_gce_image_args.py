import argparse


def setup_encrypt_gce_image_args(parser, parsed_config):
    parser.add_argument(
        'image',
        metavar='ID',
        help='The image that will be encrypted',
    )
    parser.add_argument(
        '--encrypted-image-name',
        metavar='NAME',
        dest='encrypted_image_name',
        help='Specify the name of the generated encrypted image',
        required=False
    )
    zone_kwargs = {
        'help': 'GCE zone to operate in',
        'dest': 'zone',
        'default': parsed_config.get_option('encrypt-gce-image.zone'),
        'required': False,
    }
    if zone_kwargs['default'] is None:
        zone_kwargs['required'] = True
    parser.add_argument(
        '--zone',
        **zone_kwargs
    )
    parser.add_argument(
        '--encryptor-image-bucket',
        help='Bucket to retrieve encryptor image from (prod, stage, shared, <custom>)',
        dest='bucket',
        default='prod',
        required=False
    )
    parser.add_argument(
        '--no-validate',
        dest='validate',
        action='store_false',
        default=True,
        help="Don't validate images or token"
    )
    proj_kwargs = {
        'help': 'GCE project name',
        'dest': 'project',
        'default': parsed_config.get_option('encrypt-gce-image.project'),
        'required': False,
    }
    if proj_kwargs['default'] is None:
        proj_kwargs['required'] = True
    parser.add_argument(
        '--project',
        **proj_kwargs)
    parser.add_argument(
        '--image-project',
        metavar='NAME',
        help='GCE project name which owns the image (e.g. centos-cloud)',
        dest='image_project',
        required=False
    )
    parser.add_argument(
        '--encryptor-image',
        dest='encryptor_image',
        required=False
    )
    parser.add_argument(
        '--network',
        dest='network',
        default=parsed_config.get_option('encrypt-gce-image.network', 'default'),
        required=False
    )
    parser.add_argument(
        '--subnetwork',
        dest='subnetwork',
        default=parsed_config.get_option('encrypt-gce-image.subnetwork', None),
        required=False
    )
    # Optional Image Name that's used to launch the encryptor instance. This
    # argument is hidden because it's only used for development.
    parser.add_argument(
        '--encryptor-image-file',
        dest='image_file',
        required=False,
        help=argparse.SUPPRESS
    )
    parser.add_argument(
        '--keep-encryptor',
        dest='keep_encryptor',
        action='store_true',
        help=argparse.SUPPRESS
    )
