import argparse


def setup_update_gce_image_args(parser, parsed_config):
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
    required_zone = parsed_config.get_option('gce.zone', None)
    parser.add_argument(
        '--zone',
        help='GCE zone to operate in',
        dest='zone',
        default=required_zone,
        required=not bool(required_zone)
    )
    parser.add_argument(
        '--encryptor-image-bucket',
        help='Bucket to retrieve encryptor image from (prod, stage, shared, <custom>)',
        dest='bucket',
        default='prod',
        required=False
    )
    required_project = parsed_config.get_option('gce.project', None)
    parser.add_argument(
        '--project',
        help='GCE project name',
        dest='project',
        default=required_project,
        required=not bool(required_project)
    )
    parser.add_argument(
        '--no-validate',
        dest='validate',
        action='store_false',
        default=True,
        help="Don't validate images or token"
    )
    parser.add_argument(
        '--encryptor-image',
        dest='encryptor_image',
        required=False
    )
    parser.add_argument(
        '--network',
        dest='network',
        default=parsed_config.get_option('gce.network', 'default'),
        required=False
    )
    parser.add_argument(
        '--subnetwork',
        dest='subnetwork',
        default=parsed_config.get_option('gce.subnetwork', None),
        required=False
    )
    # Optional arg <image name>.image.tar.gz for specifying metavisor
    # image file if you don't want to use the latest image
    parser.add_argument(
        '--encryptor-image-file',
        dest='image_file',
        required=False,
        help=argparse.SUPPRESS
    )
    parser.add_argument(
        '--no-cleanup',
        dest='cleanup',
        default=True,
        required=False,
        action='store_false',
        help=argparse.SUPPRESS
    )
    parser.add_argument(
        '--keep-encryptor',
        dest='keep_encryptor',
        action='store_true',
        help=argparse.SUPPRESS
    )
