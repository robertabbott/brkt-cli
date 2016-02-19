import argparse


# VERY EXPERIMENTAL FEATURE
# It will not work for you
def setup_encrypt_gce_image_args(parser):
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
        '--no-validate',
        dest='validate',
        action='store_false',
        default=True,
        help="Don't validate images"
    )
    parser.add_argument(
        '--zone',
        help='GCE zone to operate in',
        dest='zone',
        default='us-central1-a',
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
        # required until theres a default way to get brkt images
        required=True
    )

    # Optional yeti endpoints. Hidden because it's only used for development.
    # If you're using this option, it should be passed as a comma separated
    # list of endpoints. ie blb.*.*.brkt.net:7002,blb.*.*.brkt.net:7001 the
    # endpoints must also be in order: api_host,hsmproxy_host
    parser.add_argument(
        '--brkt-env',
        dest='brkt_env',
        help=argparse.SUPPRESS
    )

    # Optional Image Name that's used to launch the encryptor instance. This
    # argument is hidden because it's only used for development.
