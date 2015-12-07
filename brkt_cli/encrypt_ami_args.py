import argparse


def setup_encrypt_ami_args(parser):
    parser.add_argument(
        'ami',
        metavar='ID',
        help='The AMI that will be encrypted'
    )
    parser.add_argument(
        '--encrypted-ami-name',
        metavar='NAME',
        dest='encrypted_ami_name',
        help='Specify the name of the generated encrypted AMI',
        required=False
    )
    parser.add_argument(
        '--validate-ami',
        dest='no_validate_ami',
        action='store_true',
        help="Validate AMI properties (default)"
    )
    parser.add_argument(
        '--no-validate-ami',
        dest='no_validate_ami',
        action='store_false',
        help="Don't validate AMI properties"
    )
    parser.add_argument(
        '--region',
        metavar='NAME',
        help='AWS region (e.g. us-west-2)',
        dest='region',
        required=True
    )
    parser.add_argument(
        '--security-group',
        metavar='ID',
        dest='security_group_ids',
        action='append',
        help=(
            'Use this security group when running the encryptor instance. '
            'May be specified multiple times.'
        )
    )
    parser.add_argument(
        '--subnet',
        metavar='ID',
        dest='subnet_id',
        help='Launch instances in this subnet'
    )

    # Optional AMI ID that's used to launch the encryptor instance.  This
    # argument is hidden because it's only used for development.
    parser.add_argument(
        '--encryptor-ami',
        metavar='ID',
        dest='encryptor_ami',
        help=argparse.SUPPRESS
    )

    # Optional EC2 SSH key pair name to use for launching the snapshotter
    # and encryptor instances.  This argument is hidden because it's only
    # used for development.
    parser.add_argument(
        '--key',
        metavar='NAME',
        help=argparse.SUPPRESS,
        dest='key_name'
    )
