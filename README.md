**brkt-cli** is a command-line interface to the
[Bracket Computing](http://www.brkt.com) service. It produces an
encrypted version of an operating system image in [Amazon Web Services]
(https://aws.amazon.com/)
(AWS) or [Google Compute Engine](https://cloud.google.com/compute/)
(GCE). The resulting encrypted image can then be launched in the same
manner as the original.

The latest release of **brkt-cli** is [1.0.2]
(https://github.com/brkt/brkt-cli/releases/tag/brkt-cli-1.0.2).

## Requirements

In order to use the Bracket service, you must be a
registered Bracket Computing customer.  Email support@brkt.com for
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

* **brkt-cli** talks to the Encryptor instance on port 80 by default. This can
be overridden using the --status-port flag which support any port other than port 81.
* The Encryptor talks to the Bracket service at `yetiapi.mgmt.brkt.com`.  In
order to do this, port 443 must be accessible on the following hosts:
  * 52.32.38.106
  * 52.35.101.76
  * 52.88.55.6
* **brkt-cli** talks to `api.mgmt.brkt.com` on port 443.
* Both **brkt-cli** and the Encryptor also need to access Amazon S3.

## Authentication

The Encryptor and Metavisor use a [JSON Web Token](https://jwt.io/)
(JWT) to authenticate with the Bracket Service. The token is derived
from an ECDSA 384 private key in PEM format. 

The process works like this:

1. Run `brkt make-key` to create a public/private key pair.
1. Register the public key with the Bracket Service (see **Token
Verification Keys** in the **Settings** section of the admin UI.
1. Run `brkt make-token` and pass your private key to generate a
token.
1. Pass the token to the encryption or update subcommand via the
`--token` option.

**brkt-cli** will then pass the token to the Encryptor or Updater,
to allow it to authenticate with the Bracket service. The token will
also be embedded into the encrypted image. This allows the encrypted
instance to authenticate with the Bracket service on startup.

#### Sample usage

```
$ brkt make-key --public-out public.pem > private.pem
Passphrase:
Reenter passphrase:

$ brkt make-token --signing-key private.pem
Encrypted private key password:
eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZC...
```

## Encrypting an image

See the [AWS](aws.md) or [GCE](gce.md) pages for platform-specific
documentation on encrypting and updating an image.

## <a name="docker"/>Running in a Docker container

**brkt-cli** ships with a `Dockerfile`, which allows you to run the `brkt`
command in a Docker container. This creates a completely isolated environment,
and avoids issues with Python libraries and platform-specific
binaries.  To download the **brkt-cli** source and build the `brkt` container:

```
$ wget https://github.com/brkt/brkt-cli/archive/brkt-cli-<RELEASE-NUMBER>.zip
$ unzip brkt-cli-<RELEASE-NUMBER>.zip
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
