# Encrypting images in GCE

The `encrypt-gce-image` subcommand creates an encrypted version of a
GCE image.

```
$ brkt encrypt-gce-image --help
usage: brkt encrypt-gce-image [-h] [--encrypted-image-name NAME] --zone ZONE
                              [--encryptor-image-bucket BUCKET] --project
                              PROJECT [--image-project NAME]
                              [--encryptor-image ENCRYPTOR_IMAGE]
                              [--network NETWORK] [--ntp-server DNS Name]
                              [--proxy HOST:PORT | --proxy-config-file PATH]
                              [--status-port PORT] [--token TOKEN]
                              ID

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
  --image-project NAME  GCE project name which owns the image (e.g. centos-
                        cloud) (default: None)
  --network NETWORK
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
  --token TOKEN         Token that the encrypted instance will use to
                        authenticate with the Bracket service. Use the make-
                        token subcommand to generate a token. (default: None)
  --zone ZONE           GCE zone to operate in (default: None)
  -h, --help            show this help message and exit
```

  The `update-gce-image` subcommand updates an encrypted
image with the latest version of the Metavisor code.

```
$ ./brkt update-gce-image --help
usage: brkt update-gce-image [-h] [--encrypted-image-name NAME] --zone ZONE
                             [--encryptor-image-bucket BUCKET] --project
                             PROJECT [--encryptor-image ENCRYPTOR_IMAGE]
                             [--network NETWORK] [--ntp-server DNS Name]
                             [--proxy HOST:PORT | --proxy-config-file PATH]
                             [--status-port PORT] [--token TOKEN]
                             ID

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

Run `encrypt-gce-image` to encrypt an image:

```
$ brkt encrypt-gce-image --zone us-central1-a --project brkt-dev --token <token> --image-project ubuntu-os-cloud ubuntu-1404-trusty-v20160627
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

Run `update-gce-image` to update an encrypted image with the latest
Metavisor code:

```
$ ./brkt update-gce-image --zone us-central1-a --project brkt-dev --token <token> ubuntu-1404-trusty-v20160627-encrypted-ee521b31
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
