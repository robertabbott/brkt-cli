import argparse


def setup_update_gce_image_args(parser):
    parser.add_argument(
        'image',
        metavar='ID',
        help='The image that will be encrypted',
    )
    parser.add_argument(
        '--encrypted-image-name',
        metavar='NAME',
        dest='encrypted_image_name',
        help='Specify the name of the generated encrypted Image',
        required=False
    )
    parser.add_argument(
        '--zone',
        help='GCE zone to operate in',
        dest='zone',
        default='us-central1-a',
        required=True
    )
    parser.add_argument(
        '--encryptor-image-bucket',
        help='Bucket to retrieve encryptor image from (prod, stage, shared, <custom>)',
        dest='bucket',
        default='prod',
        required=False
    )
    parser.add_argument(
         '--brkt-email',
         metavar='EMAIL',
         dest='api_email',
         help='Bracket user email',
         required=True
     )
    parser.add_argument(
         '--brkt-password',
         metavar='PASSWORD',
         dest='api_password',
         help='Bracket user password',
         required=True
     )
    parser.add_argument(
        '--project',
        help='GCE project name',
        dest='project',
        required=True
    )
    parser.add_argument(
        '--encryptor-image',
        dest='encryptor_image',
        required=False
    )

    # Optional yeti endpoints. Hidden because it's only used for development.
    parser.add_argument(
        '--brkt-env',
        dest='brkt_env',
        help=argparse.SUPPRESS
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
        '--keep-encryptor',
        dest='keep_encryptor',
        action='store_true',
        help=argparse.SUPPRESS
    )
