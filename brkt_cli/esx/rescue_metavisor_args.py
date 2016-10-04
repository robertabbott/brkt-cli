def setup_rescue_metavisor_args(parser):
    parser.add_argument(
        "--vcenter-host",
        help="IP address/DNS Name of the vCenter host",
        dest="vcenter_host",
        metavar='DNS_NAME',
        required=True)
    parser.add_argument(
        "--vcenter-port",
        help="Port Number of the vCenter Server",
        metavar='N',
        dest="vcenter_port",
        default="443",
        required=False)
    parser.add_argument(
        "--vcenter-datacenter",
        help="vCenter Datacenter to use",
        dest="vcenter_datacenter",
        metavar='NAME',
        required=True)
    parser.add_argument(
        "--vcenter-datastore",
        help="vCenter datastore to use",
        dest="vcenter_datastore",
        metavar='NAME',
        required=True)
    parser.add_argument(
        "--vcenter-cluster",
        help="vCenter cluster to use",
        dest="vcenter_cluster",
        metavar='NAME',
        required=True)
    parser.add_argument(
        'vm_name',
        metavar='VM-NAME',
        help='Specify the name of the metavisor VM'
    )
    parser.add_argument(
        '--rescue-upload-protocol',
        metavar='PROTOCOL',
        choices=['http', 'https'],
        dest='protocol',
        help=(
            'Specify the protocol which metavisor '
            'will use to upload the diagnostics information'
        ),
        required=True
    )
    parser.add_argument(
        '--rescue-upload-url',
        metavar='URL',
        dest='url',
        help=(
            'Specify the URL location to which metavisor '
            'will upload the diagnostics information'
        ),
        required=True
    )
