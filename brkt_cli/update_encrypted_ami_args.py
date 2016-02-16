import argparse


def setup_update_encrypted_ami(parser):
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
        '--no-validate',
        dest='validate',
        action='store_false',
        default=True,
        help="Don't validate AMIs, subnet, and security groups"
    )
    parser.add_argument(
        '--region',
        metavar='REGION',
        help='AWS region (e.g. us-west-2)',
        dest='region',
        default='us-west-2',
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
    # Optional yeti endpoints. Hidden because it's only used for development.
    parser.add_argument(
        '--brkt-env',
        dest='brkt_env',
        help=argparse.SUPPRESS
    )
    # Optional EC2 SSH key pair name to use for launching the guest
    # and encryptor instances.  This argument is hidden because it's only
    # used for development.
    parser.add_argument(
        '--key',
        metavar='KEY',
        help=argparse.SUPPRESS,
        dest='key_name'
    )
    parser.add_argument(
        '--tag',
        metavar='KEY=VALUE',
        dest='tags',
        action='append',
        help=(
            'Custom tag for resources created during encryption. '
            'May be specified multiple times.'
        )
    )

    # Optional hidden argument for specifying the metavisor AMI.  This
    # argument is hidden because it's only used for development.  It can
    # also be used to override the default AMI if it's determined to be
    # unstable.
    parser.add_argument(
        '--encryptor-ami',
        metavar='ID',
        help=argparse.SUPPRESS,
        dest='encryptor_ami'
    )

    # Use an HVM encryptor AMI. Right now, this is hidden while HVM is in
    # development. When it is GA, we will remove the flag and assume HVM on
    # by default
    parser.add_argument(
        '--hvm',
        action='store_false',
        help=argparse.SUPPRESS,
        dest='hvm'
    )
