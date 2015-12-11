import argparse


def setup_update_encrypted_ami(parser):
    parser.add_argument(
        'ami',
        metavar='AMI_ID',
        help='The AMI that will be encrypted'
    )
    parser.add_argument(
        '--updater-ami',
        metavar='UPDATER_AMI_ID',
        help='The metavisor updater AMI that will be used',
        dest='updater_ami',
        required=True
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
        '--encrypted-ami-name',
        metavar='NAME',
        dest='encrypted_ami_name',
        help='Specify the name of the generated encrypted AMI',
        required=False
    )
    parser.add_argument(
        '--no-validate-ami',
        dest='no_validate_ami',
        action='store_true',
        help="Don't validate encrypted AMI properties"
    )

    # Optional yeti endpoints. Hidden because it's only used for development
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
