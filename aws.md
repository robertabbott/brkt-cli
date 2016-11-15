# AWS Operations

The `aws` subcommand provides all AWS related operations for encrypting and updating images.

```
$ brkt aws --help
usage: brkt aws [-h] {diag,encrypt,share-logs,update} ...

AWS operations

positional arguments:
  {diag,encrypt,share-logs,update}
    diag                Diagnose an encrypted instance
    encrypt             Encrypt an AWS image
    share-logs          Share logs
    update              Update an encrypted AWS image

optional arguments:
  -h, --help            show this help message and exit
```

# Encrypting images in AWS

The `aws encrypt` subcommand performs the following steps to create an
encrypted image:

1. Launch an instance based on an unencrypted AMI.  We call this
the guest instance.
1. Snapshot the root volume of the guest instance.
1. Launch a Bracket Encryptor instance.
1. Attach the unencrypted guest root volume to the Bracket encryptor instance.
1. Copy the unencrypted root volume to a new, encrypted volume.
1. Create a new AMI based on the encrypted root volume and other volumes
required by the Metavisor at runtime.

## Usage
```
$ brkt aws encrypt --help
usage: brkt aws encrypt [-h] [--encrypted-ami-name NAME]
                        [--guest-instance-type TYPE] [--pv] [--no-validate]
                        --region NAME [--security-group ID] [--subnet ID]
                        [--tag KEY=VALUE] [-v] [--ntp-server DNS_NAME]
                        [--proxy HOST:PORT | --proxy-config-file PATH]
                        [--status-port PORT] [--token TOKEN]
                        ID

Create an encrypted AMI from an existing AMI.

positional arguments:
  ID                    The guest AMI that will be encrypted

optional arguments:
  --encrypted-ami-name NAME
                        Specify the name of the generated encrypted AMI
                        (default: None)
  --guest-instance-type TYPE
                        The instance type to use when running the unencrypted
                        guest instance (default: m3.medium)
  --no-validate         Don't validate AMIs, subnet, and security groups
                        (default: True)
  --ntp-server DNS Name
                        Optional NTP server to sync Metavisor clock. May be
                        specified multiple times. (default: None)
  --proxy HOST:PORT     Use this HTTPS proxy during encryption. May be
                        specified multiple times. (default: None)
  --proxy-config-file PATH
                        Path to proxy.yaml file that will be used during
                        encryption (default: None)
  --pv                  Use the PV encryptor (default: False)
  --region NAME         AWS region (e.g. us-west-2) (default: None)
  --security-group ID   Use this security group when running the encryptor
                        instance. May be specified multiple times. (default:
                        None)
  --status-port PORT    Specify the port to receive http status of encryptor.
                        Any port in range 1-65535 can be used except for port
                        81. (default: 80)
  --subnet ID           Launch instances in this subnet (default: None)
  --tag KEY=VALUE       Custom tag for resources created during encryption.
                        May be specified multiple times. (default: None)
  --token TOKEN         Token that the encrypted instance will use to
                        authenticate with the Bracket service. Use the make-
                        token subcommand to generate a token. (default: None)
  -h, --help            show this help message and exit
  -v, --verbose         Print status information to the console (default:
                        False)
```

The `aws update` subcommand updates an encrypted AMI with the latest
version of the Metavisor code.

```
$ brkt aws update --help
usage: brkt aws update [-h] [--encrypted-ami-name NAME]
                       [--guest-instance-type TYPE]
                       [--updater-instance-type TYPE] [--pv] [--no-validate]
                       --region REGION [--security-group ID] [--subnet ID]
                       [--tag KEY=VALUE] [-v] [--ntp-server DNS_NAME]
                       [--proxy HOST:PORT | --proxy-config-file PATH]
                       [--status-port PORT] [--token TOKEN]
                       ID

Update an encrypted AMI with the latest Metavisor release.

positional arguments:
  ID                    The encrypted AMI that will be updated

optional arguments:
  --encrypted-ami-name NAME
                        Specify the name of the generated encrypted AMI
                        (default: None)
  --guest-instance-type TYPE
                        The instance type to use when running the encrypted
                        guest instance. Default: m3.medium (default:
                        m3.medium)
  --no-validate         Don't validate AMIs, subnet, and security groups
                        (default: True)
  --ntp-server DNS Name
                        Optional NTP server to sync Metavisor clock. May be
                        specified multiple times. (default: None)
  --proxy HOST:PORT     Use this HTTPS proxy during encryption. May be
                        specified multiple times. (default: None)
  --proxy-config-file PATH
                        Path to proxy.yaml file that will be used during
                        encryption (default: None)
  --pv                  Use the PV encryptor (default: False)
  --region REGION       AWS region (e.g. us-west-2) (default: us-west-2)
  --security-group ID   Use this security group when running the encryptor
                        instance. May be specified multiple times. (default:
                        None)
  --status-port PORT    Specify the port to receive http status of encryptor.
                        Any port in range 1-65535 can be used except for port
                        81. (default: 80)
  --subnet ID           Launch instances in this subnet (default: None)
  --tag KEY=VALUE       Custom tag for resources created during encryption.
                        May be specified multiple times. (default: None)
  --token TOKEN         Token that the encrypted instance will use to
                        authenticate with the Bracket service. Use the make-
                        token subcommand to generate a token. (default: None)
  --updater-instance-type TYPE
                        The instance type to use when running the updater
                        instance. Default: m3.medium (default: m3.medium)
  -h, --help            show this help message and exit
  -v, --verbose         Print status information to the console (default:
                        False)
```

## Configuration

Before running the **brkt** command, make sure that you've set your AWS
environment variables:

```
$ export AWS_ACCESS_KEY_ID=<access key>
$ export AWS_SECRET_ACCESS_KEY=<secret key>
```

You'll also need to make sure that your AWS account has the required
permissions, such as running an instance, describing an image, and
creating snapshots.  See [brkt-cli-iam-permissions.json](https://github.com/brkt/brkt-cli/blob/master/reference_templates/brkt-cli-iam-permissions.json)
for the complete list of required permissions.

When launching the Encryptor or Updater instance, **brkt-cli** creates
a temporary security group that allows inbound access on port 80.
Alternately, you can use the `--security-group` option to specify one
or more existing security groups.

## Encrypting an AMI

Run **brkt aws encrypt** to create a new encrypted AMI based on an existing
image:

```
$ brkt aws encrypt --region us-east-1 --token <token> ami-76e27e1e
15:28:37 Starting encryptor session caabe51a
15:28:38 Launching instance i-703f4c99 to snapshot root disk for ami-76e27e1e
...
15:57:11 Created encrypted AMI ami-07c2a262 based on ami-76e27e1e
15:57:11 Terminating encryptor instance i-753e4d9c
15:57:12 Deleting snapshot copy of original root volume snap-847da3e1
15:57:12 Done.
ami-07c2a262
```

When the process completes, the new AMI id is written to stdout.  Log
messages are written to stderr.

## Updating an encrypted AMI

Run **brkt aws update** to update an encrypted AMI based on an existing
encrypted image:

```
$ brkt aws update --region us-east-1 --token <token> ami-72094e18
13:38:14 Using zone us-east-1a
13:38:15 Updating ami-72094e18
13:38:15 Creating guest volume snapshot
...
13:39:25 Encrypted root drive created.
...
13:39:28 waiting for snapshot ready
13:39:48 metavisor updater snapshots ready
...
13:39:54 Created encrypted AMI ami-63733e09 based on ami-72094e18
13:39:54 Done.
ami-63733e09
```

When the process completes, the new AMI id is written to stdout.  Log
messages are written to stderr.
