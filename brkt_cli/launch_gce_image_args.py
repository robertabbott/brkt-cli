import argparse


# VERY EXPERIMENTAL FEATURE
# It will not work for you
def setup_launch_gce_image_args(parser):
    parser.add_argument(
        'image',
        metavar='ID',
        help='The image that will be encrypted',
    )
    parser.add_argument(
        '--instance-name',
        metavar='NAME',
        dest='instance_name',
        help='Name of the instance',
        required=True
    )
    parser.add_argument(
        '--instance-type',
        help='Instance type',
        dest='instance_type',
        default='n1-standard-1',
        required=False
    )
    parser.add_argument(
        '--zone',
        help='GCE zone to operate in',
        dest='zone',
        default='us-central1-a',
        required=False
    )
    parser.add_argument(
        '--delete-boot',
        help='Delete boot disk when instance is deleted',
        dest='delete_boot',
        action='store_true'
    )
    parser.add_argument(
        '--project',
        help='GCE project name',
        dest='project',
        required=True
    )
    parser.add_argument(
        '--startup-script',
        help='GCE instance startup script',
        dest='startup_script',
        metavar='SCRIPT',
        required=False
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
