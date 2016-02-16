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
        '--no-validate',
        dest='validate',
        action='store_false',
        default=True,
        help="Don't validate AMIs, subnet, and security groups"
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

    # Optional yeti endpoints. Hidden because it's only used for development.
    # If you're using this option, it should be passed as a comma separated
    # list of endpoints. ie blb.*.*.brkt.net:7002,blb.*.*.brkt.net:7001 the
    # endpoints must also be in order: api_host,hsmproxy_host
    parser.add_argument(
        '--brkt-env',
        dest='brkt_env',
        help=argparse.SUPPRESS
    )

    # Optional AMI ID that's used to launch the encryptor instance.  This
    # argument is hidden because it's only used for development.
    parser.add_argument(
        '--encryptor-ami',
        metavar='ID',
        dest='encryptor_ami',
        help=argparse.SUPPRESS
    )

    # Optional EC2 SSH key pair name to use for launching the guest
    # and encryptor instances.  This argument is hidden because it's only
    # used for development.
    parser.add_argument(
        '--key',
        metavar='NAME',
        help=argparse.SUPPRESS,
        dest='key_name'
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

