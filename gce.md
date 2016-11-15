# GCE Operations

The `gce` subcommand provides all GCE related operations for encrypting, updating and launching images.

```
$ brkt gce --help
usage: brkt gce [-h] {encrypt,update,launch} ...

GCE Operations

positional arguments:
  {encrypt,update,launch}
    encrypt             Encrypt a GCE image
    update              Update an encrypted GCE image
    launch              Launch a GCE image

optional arguments:
  -h, --help            show this help message and exit
```

# Encrypting images in GCE

The `gce encrypt` subcommand creates an encrypted version of a
GCE image.

```
$ brkt gce encrypt --help
usage: brkt gce encrypt [-h] [--encrypted-image-name NAME] --zone ZONE
                        [--encryptor-image-bucket BUCKET] [--no-validate]
                        --project PROJECT [--image-project NAME]
                        [--encryptor-image ENCRYPTOR_IMAGE]
                        [--network NETWORK] [--subnetwork SUBNETWORK]
                        [--ntp-server DNS_NAME]
                        [--proxy HOST:PORT | --proxy-config-file PATH]
                        [--status-port PORT] [--token TOKEN]
                        ID

Create an encrypted GCE image from an existing image

positional arguments:
  ID                    The image that will be encrypted

optional arguments:
  --encrypted-image-name NAME
                        Specify the name of the generated encrypted image
                        (default: None)
  --encryptor-image ENCRYPTOR_IMAGE
  --encryptor-image-bucket BUCKET
                        Bucket to retrieve encryptor image from (prod, stage,
                        shared, <custom>) (default: prod)
  --image-project NAME  GCE project name which owns the image (e.g. centos-
                        cloud) (default: None
  --network NETWORK
  --no-validate         Don't validate images or token (default: True)
  --ntp-server DNS_NAME
                        Optional NTP server to sync Metavisor clock. May be
                        specified multiple times. (default: None)
  --project PROJECT     GCE project name (default: None)
  --proxy HOST:PORT     Use this HTTPS proxy during encryption. May be
                        specified multiple times. (default: None)
  --proxy-config-file PATH
                        Path to proxy.yaml file that will be used during
                        encryption (default: None)
  --status-port PORT    Specify the port to receive http status of encryptor.
                        Any port in range 1-65535 can be used except for port
                        81. (default: 80)
  --subnetwork SUBNETWORK
  --token TOKEN         Token that the encrypted instance will use to
                        authenticate with the Bracket service. Use the make-
                        token subcommand to generate a token. (default: None)
  --zone ZONE           GCE zone to operate in (default: None)
  -h, --help            show this help message and exit
```

  The `gce update` subcommand updates an encrypted
image with the latest version of the Metavisor code.

```
$ brkt gce update --help
usage: brkt gce update [-h] [--encrypted-image-name NAME] --zone ZONE
                       [--encryptor-image-bucket BUCKET] --project PROJECT
                       [--no-validate] [--encryptor-image ENCRYPTOR_IMAGE]
                       [--network NETWORK] [--subnetwork SUBNETWORK]
                       [--ntp-server DNS_NAME]
                       [--proxy HOST:PORT | --proxy-config-file PATH]
                       [--status-port PORT] [--token TOKEN]
                       ID

Update an encrypted GCE image with the latest Metavisor release

positional arguments:
  ID                    The image that will be encrypted

optional arguments:
  --encrypted-image-name NAME
                        Specify the name of the generated encrypted Image
                        (default: None)
  --encryptor-image ENCRYPTOR_IMAGE
  --encryptor-image-bucket BUCKET
                        Bucket to retrieve encryptor image from (prod, stage,
                        shared, <custom>) (default: prod)
  --network NETWORK
  --no-validate         Don't validate images or token (default: True)
  --ntp-server DNS Name
                        Optional NTP server to sync Metavisor clock. May be
                        specified multiple times. (default: None)
  --project PROJECT     GCE project name (default: None)
  --proxy HOST:PORT     Use this HTTPS proxy during encryption. May be
                        specified multiple times. (default: None)
  --proxy-config-file PATH
                        Path to proxy.yaml file that will be used during
                        encryption (default: None)
  --status-port PORT    Specify the port to receive http status of encryptor.
                        Any port in range 1-65535 can be used except for port
                        81. (default: 80)
  --subnetwork SUBNETWORK
  --token TOKEN         Token that the encrypted instance will use to
                        authenticate with the Bracket service. Use the make-
                        token subcommand to generate a token. (default: None)
  --zone ZONE           GCE zone to operate in (default: us-central1-a)
  -h, --help            show this help message and exit
```

The `gce launch` subcommand launches an encrypted GCE image.

```
$ brkt gce launch --help
usage: brkt gce launch [-h] [--instance-name NAME]
                       [--instance-type INSTANCE_TYPE] [--zone ZONE]
                       [--delete-boot] --project PROJECT [--network NETWORK]
                       [--subnetwork NAME] [--ntp-server DNS_NAME]
                       [--proxy HOST:PORT | --proxy-config-file PATH]
                       [--token TOKEN]
                       ID

Launch a GCE image

positional arguments:
  ID                    The image that will be encrypted

optional arguments:
  --delete-boot         Delete boot disk when instance is deleted (default:
                        False)
  --instance-name NAME  Name of the instance (default: None)
  --instance-type INSTANCE_TYPE
                        Instance type (default: n1-standard-1)
  --network NETWORK
  --ntp-server DNS_NAME
                        Optional NTP server to sync Metavisor clock. May be
                        specified multiple times. (default: None)
  --project PROJECT     GCE project name (default: None)
  --proxy HOST:PORT     Use this HTTPS proxy during encryption. May be
                        specified multiple times. (default: None)
  --proxy-config-file PATH
                        Path to proxy.yaml file that will be used during
                        encryption (default: None)
  --subnetwork NAME     Launch instance in this subnetwork (default: None)
  --token TOKEN         Token that the encrypted instance will use to
                        authenticate with the Bracket service. Use the make-
                        token subcommand to generate a token. (default: None)
  --zone ZONE           GCE zone to operate in (default: us-central1-a)
  -h, --help            show this help message and exit
```

## Configuration

Before running the GCE commands in **brkt-cli**, you'll need to install
[gcloud](https://cloud.google.com/sdk/gcloud/) and configure it
to work with your Google account and GCP project.

You'll also need to add a Firewall rule that allows inbound access
to the Encryptor or Updater instance on port **80**, or the port that
you specify with the **--status-port** option.

## Encrypting an image

Run **gce encrypt** to encrypt an image:

```
$ brkt gce encrypt --zone us-central1-a --project brkt-dev --token <token> --image-project ubuntu-os-cloud ubuntu-1404-trusty-v20160627
...
14:30:23 Starting encryptor session 59e3b3a7
...
14:55:18 Encryption is 99% complete
14:55:28 Encrypted root drive created.
14:55:29 Creating snapshot of encrypted image disk
14:56:21 Disk detach successful
14:56:21 Creating metavisor image
14:58:25 Image ubuntu-1404-trusty-v20160627-encrypted-a1fe1069 successfully created!
14:58:25 Cleaning up
14:58:25 deleting disk brkt-guest-59e3b3a7
14:58:25 Disk detach successful
14:58:26 deleting disk encrypted-image-59e3b3a7
14:58:26 Disk detach successful
14:58:27 deleting disk brkt-guest-59e3b3a7-encryptor
14:58:27 Disk detach successful
14:58:28 Deleting encryptor image encryptor-59e3b3a7
ubuntu-1404-trusty-v20160627-encrypted-a1fe1069
```

## Updating an image

Run **gce update** to update an encrypted image with the latest
Metavisor code:

```
$ brkt gce update --zone us-central1-a --project brkt-dev --token <token> ubuntu-1404-trusty-v20160627-encrypted-ee521b31
...
15:50:04 Starting updater session 80985e58
...
15:55:02 Encrypted root drive created.
15:55:02 Deleting updater instance
15:55:54 Disk detach successful
15:55:54 Creating updated metavisor image
15:56:45 deleting disk brkt-updater-80985e58-guest
15:56:46 Disk detach successful
15:56:46 deleting disk brkt-updater-80985e58-metavisor
15:56:47 Disk detach successful
15:56:47 Deleting encryptor image encryptor-80985e58
ubuntu-1404-trusty-v20160627-encrypted-63e57e6e
```

## Launching an image

Run **gce launch** to launch an encrypted GCE image

```
$ brkt gce launch --instance-name brkt-test-instance --project <project> --token <token> --zone us-central1-c centos-6-v20160921-encrypted-30fccdeb
18:13:54 Creating guest root disk from snapshot
18:13:54 Attempting refresh to obtain initial access_token
18:13:54 Refreshing access_token
18:13:55 Waiting for disk to become ready
18:14:05 Waiting for disk to become ready
18:14:15 Waiting for disk to become ready
18:14:26 Waiting for disk to become ready
18:14:36 Waiting for disk to become ready
18:14:46 Waiting for disk to become ready
18:14:56 Waiting for disk to become ready
18:14:56 Starting instance
18:14:58 Waiting for brkt-test-instance to become ready
18:15:03 Waiting for brkt-test-instance to become ready
...
18:15:59 Waiting for brkt-test-instance to become ready
18:16:10 Instance brkt-test-instance (104.198.44.8) launched successfully
brkt-test-instance
```
