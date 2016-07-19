**brkt-cli** is a command-line interface to the [Bracket Computing](http://www.brkt.com)
service.  It produces an encrypted version of an Amazon Machine Image, which can then be
launched in EC2. It can also update an already encrypted version of an Amazon Machine Image,
which can then be launched in EC2.

The latest release of **brkt-cli** is [1.0.2](https://github.com/brkt/brkt-cli/releases/tag/brkt-cli-1.0.2).

## Process

The `encrypt-ami` subcommand performs the following steps to create an
encrypted image:

1. Launch an instance based on the specified unencrypted AMI.  We call this
the guest instance.
1. Snapshot the root volume of the guest instance.
1. Launch a Bracket Encryptor instance.
1. Attach the unencrypted guest root volume to the Bracket encryptor instance.
1. Copy the unencrypted root volume to a new, encrypted volume.
1. Create a new AMI based on the encrypted root volume and other volumes
required by the metavisor at runtime.

The `update-encrypted-ami` subcommand updates an encrypted AMI with the latest
version of the metavisor code.

## Requirements

In order to use the Bracket service, you must be a
registered Bracket customer.  Email support@brkt.com for
more information.

**brkt-cli** requires Python 2.7.

We recommend using [virtualenv](https://virtualenv.pypa.io/), to avoid
conflicts between **brkt-cli** dependencies and Python packages that are managed
by the operating system.  If you're not familiar with virtualenv, check out the
[Virtual Environments](http://docs.python-guide.org/en/latest/dev/virtualenvs/)
section of _The Hitchhiker's Guide to Python_.

You can also run **brkt-cli** in a [Docker container](#docker).

#### Windows and OS X

Windows and OS X users need to use [pip 8](https://pip.pypa.io/).  pip 8
supports Python Wheels, which include the binary portion of the
[cryptography](https://cryptography.io/) library.  To
[upgrade pip](https://pip.pypa.io/en/stable/installing/#upgrading-pip)
to the latest version, run

```
$ pip install -U pip
```

#### Linux

Linux users need to install several packages, which allow you to compile
the cryptography library.  Ubuntu users need to run

```
$ sudo apt-get install build-essential libssl-dev libffi-dev python-dev
```

before installing **brkt-cli**.  RHEL and CentOS users need to run

```
$ sudo yum install gcc libffi-devel python-devel openssl-devel
```

For more details, see the
[installation section](https://cryptography.io/en/latest/installation/) of
the cryptography library documentation.

## Installation

Use pip to install **brkt-cli** and its dependencies:

```
$ pip install brkt-cli
```

To install the most recent **brkt-cli** code from the tip of the master branch, run

```
$ pip install git+https://github.com/brkt/brkt-cli.git
```

The master branch has the latest features and bug fixes, but is not as thoroughly tested as the official release.

## Networking requirements

The following network connections are established during image encryption:

* **brkt-cli** talks to the Encryptor instance on port 8000 by default. This can
be overridden using the --status-port flag which support any port other than port 81.
* The Encryptor talks to the Bracket service at `yetiapi.mgmt.brkt.com`.  In
order to do this, port 443 must be accessible on the following hosts:
  * 52.32.38.106
  * 52.35.101.76
  * 52.88.55.6
* Both **brkt-cli** and the Encryptor also need to access Amazon S3.

When launching the Encryptor instance, **brkt-cli** creates a temporary
security group that allows inbound access on port 8000.  Alternately, you can
use the `--security-group` option to specify one or more existing security
groups.

## Usage
```
$ brkt encrypt-ami --help
usage: brkt encrypt-ami [-h] [--encrypted-ami-name NAME]
                        [--guest-instance-type TYPE] [--pv] [--no-validate]
                        [--proxy HOST:PORT | --proxy-config-file PATH]
                        --region NAME [--security-group ID] [--subnet ID]
                        [--tag KEY=VALUE] [--ntp-server DNS Name]
                        ID

Create an encrypted AMI from an existing AMI.

positional arguments:
  ID                    The guest AMI that will be encrypted

optional arguments:
  -h, --help            show this help message and exit
  --encrypted-ami-name NAME
                        Specify the name of the generated encrypted AMI
  --guest-instance-type TYPE
                        The instance type to use when running the unencrypted
                        guest instance
  --pv                  Use the PV encryptor
  --no-validate         Don't validate AMIs, subnet, and security groups
  --proxy HOST:PORT     Use this HTTPS proxy during encryption. May be
                        specified multiple times.
  --proxy-config-file PATH
                        Path to proxy.yaml file that will be used during
                        encryption
  --region NAME         AWS region (e.g. us-west-2)
  --security-group ID   Use this security group when running the encryptor
                        instance. May be specified multiple times.
  --status-port         By default, port 8000 is used to talk to receive
                        encryptor status. Any port in range 1-65535 except for
			port 81 can be used.
  --subnet ID           Launch instances in this subnet
  --tag KEY=VALUE       Custom tag for resources created during encryption.
                        May be specified multiple times.
  --ntp-server DNS Name
                        Optional NTP server to sync Metavisor clock. May be
                        specified multiple times.
```
```
$ brkt update-encrypted-ami --help
usage: brkt update-encrypted-ami [-h] [--encrypted-ami-name NAME]
                                 [--guest-instance-type TYPE] [--pv]
                                 [--no-validate]
                                 [--proxy HOST:PORT | --proxy-config-file PATH]
                                 --region REGION [--security-group ID]
                                 [--subnet ID] [--ntp-server DNS Name]
                                 [--tag KEY=VALUE]
                                 ID

Update an encrypted AMI with the latest Metavisor release.

positional arguments:
  ID                    The encrypted AMI that will be updated

optional arguments:
  -h, --help            show this help message and exit
  --encrypted-ami-name NAME
                        Specify the name of the generated encrypted AMI
  --guest-instance-type TYPE
                        The instance type to use when running the unencrypted
                        guest instance
  --pv                  Use the PV encryptor
  --no-validate         Don't validate AMIs, subnet, and security groups
  --proxy HOST:PORT     Use this HTTPS proxy during encryption. May be
                        specified multiple times.
  --proxy-config-file PATH
                        Path to proxy.yaml file that will be used during
                        encryption
  --region REGION       AWS region (e.g. us-west-2)
  --security-group ID   Use this security group when running the encryptor
                        instance. May be specified multiple times.
  --status-port         By default, port 8000 is used to talk to receive
                        updater status. Any port in range 1-65535 except for
			port 81 can be used.
  --subnet ID           Launch instances in this subnet
  --ntp-server DNS Name
                        Optional NTP server to sync Metavisor clock. May be
                        specified multiple times.
  --tag KEY=VALUE       Custom tag for resources created during encryption.
                        May be specified multiple times.
```

## Configuration

Before running the **brkt** command, make sure that you've set the AWS
environment variables:

```
$ export AWS_ACCESS_KEY_ID=<access key>
$ export AWS_SECRET_ACCESS_KEY=<secret key>
```

You'll also need to make sure that your AWS account has the required
permissions, such as running an instance, describing an image, and
creating snapshots.  See [brkt-cli-iam-permissions.json](https://github.com/brkt/brkt-cli/blob/master/reference_templates/brkt-cli-iam-permissions.json)
for the complete list of required permissions.

## Encrypting an AMI

Run **brkt encrypt-ami** to create a new encrypted AMI based on an existing
image:

```
$ brkt encrypt-ami --region us-east-1 ami-76e27e1e
15:28:37 Starting encryptor session caabe51a
15:28:38 Launching instance i-703f4c99 to snapshot root disk for ami-76e27e1e
...
15:57:11 Created encrypted AMI ami-07c2a262 based on ami-76e27e1e
15:57:11 Terminating encryptor instance i-753e4d9c
15:57:12 Deleting snapshot copy of original root volume snap-847da3e1
15:57:12 Done.
ami-07c2a262
```

When the process completes, the new AMI id is written to stdout.  All log
messages are written to stderr.

## Updating an encrypted AMI

Run **brkt update-encrypted-ami** to update an encrypted AMI based on an existing
encrypted image:

```
$ brkt update-encrypted-ami --region us-east-1 ami-72094e18
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

When the process completes, the new AMI id is written to stdout.  All log
messages are written to stderr.

## <a name="docker"/>Running in a Docker container

**brkt-cli** ships with a `Dockerfile`, which allows you to run the `brkt`
command in a Docker container. This creates a completely isolated environment,
and avoids issues with Python libraries and platform-specific
binaries.  To download the **brkt-cli** source and build the `brkt` container:

```
$ wget https://github.com/brkt/brkt-cli/archive/brkt-cli-<RELEASE-NUMBER>.zip
$ cd brkt-cli-brkt-cli-<RELEASE-NUMBER>
$ docker build -t brkt .
```

Be sure to substitute the actual release number for `<RELEASE-NUMBER>`.  Once
the container is built, you can run it with the `docker run`
command.  Note that you must pass any required environment variables or
files into the container.  Some examples:

```
$ docker run --rm -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
-e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
brkt encrypt-ami --region us-west-2 ami-9025e1f0
```

```
$ docker run --rm -v ~/keys:/keys brkt make-token --signing-key /keys/secret.pem
eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImU2MTNhYzI0YzRkN2ExY...
```
