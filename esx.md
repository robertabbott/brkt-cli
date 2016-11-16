# VMWare Operations

The `vmware` subcommand provides all VMWare related operations for encrypting and updating images, with a vCenter or directly on an ESX host.

```
$ brkt vmware --help
usage: brkt vmware [-h]
                   {encrypt-with-vcenter,encrypt-with-esx-host,update-with-vcenter,update-with-esx-host,rescue-metavisor}
                   ...

VMWare Operations

positional arguments:
  {encrypt-with-vcenter,encrypt-with-esx-host,update-with-vcenter,update-with-esx-host,rescue-metavisor}
    encrypt-with-vcenter
                        Encrypt a VMDK using vCenter
    encrypt-with-esx-host
                        Encrypt a VMDK on a ESX host
    update-with-vcenter
                        Update an encrypted VMDK using vCenter
    update-with-esx-host
                        Update an encrypted VMDK on an ESX host
    rescue-metavisor    Upload Metavisor VM cores to URL

optional arguments:
  -h, --help            show this help message and exit
```

# Encrypting images with vCenter

The `vmware encrypt-with-vcenter` creates an encrypted VMDK from a base (unencrypted) 
VMDK using a vCenter server.

## Usage
```
$ brkt vmware encrypt --help
usage: brkt vmware encrypt-with-vcenter [-h] --vcenter-host DNS_NAME
                                        [--vcenter-port N]
                                        [--vcenter-datacenter NAME]
                                        [--vcenter-datastore NAME]
                                        [--vcenter-cluster NAME]
                                        [--cpu-count N] [--memory GB]
                                        [--encrypted-image-name NAME]
                                        [--template-vm-name NAME]
                                        [--no-validate] [--create-ovf]
                                        [--create-ova]
                                        [--encrypted-image-directory NAME]
                                        [--ovftool-path PATH]
                                        [--ovf-source-directory PATH]
                                        [--metavisor-ovf-image-name NAME]
                                        [--console-file-name NAME]
                                        [--disk-type TYPE]
                                        [--ntp-server DNS_NAME]
                                        [--proxy HOST:PORT | --proxy-config-file PATH]
                                        [--status-port PORT] [--token TOKEN]
                                        VMDK-NAME

Create an encrypted VMDK from an existing VMDK using vCenter

positional arguments:
  VMDK-NAME             The Guest VMDK that will be encrypted

optional arguments:
  --console-file-name NAME
                        File name to dump console messages to (default: None)
  --cpu-count N         Number of CPUs to assign to Encryptor VM (default: 8)
  --create-ova          Create OVA package (default: False)
  --create-ovf          Create OVF package (default: False)
  --disk-type TYPE      thin/thick-lazy-zeroed/thick-eager-zeroed (default:
                        thin) (default: thin)
  --encrypted-image-directory NAME
                        Directory to store the generated OVF/OVA image
                        (default: None)
  --encrypted-image-name NAME
                        Specify the name of the generated OVF/OVA (default:
                        None)
  --memory GB           Memory to assign to Encryptor VM (default: 32)
  --metavisor-ovf-image-name NAME
                        Metavisor OVF name (default: None)
  --no-validate         Don't validate VMDKs and vCenter credentials (default:
                        True)
  --ntp-server DNS_NAME
                        Optional NTP server to sync Metavisor clock. May be
                        specified multiple times. (default: None)
  --ovf-source-directory PATH
                        Local path to the OVF directory (default: None)
  --ovftool-path PATH   ovftool executable path (default: ovftool)
  --proxy HOST:PORT     Use this HTTPS proxy during encryption. May be
                        specified multiple times. (default: None)
  --proxy-config-file PATH
                        Path to proxy.yaml file that will be used during
                        encryption (default: None)
  --status-port PORT    Specify the port to receive http status of encryptor.
                        Any port in range 1-65535 can be used except for port
                        81. (default: 80)
  --template-vm-name NAME
                        Specify the name of the template VM (default: None)
  --token TOKEN         Token that the encrypted instance will use to
                        authenticate with the Bracket service. Use the make-
                        token subcommand to generate a token. (default: None)
  --vcenter-cluster NAME
                        vCenter cluster to use (default: None)
  --vcenter-datacenter NAME
                        vCenter Datacenter to use (default: None)
  --vcenter-datastore NAME
                        vCenter datastore to use (default: None)
  --vcenter-host DNS_NAME
                        IP address/DNS Name of the vCenter host (default:
                        None)
  --vcenter-port N      Port Number of the vCenter Server (default: 443)
  -h, --help            show this help message and exit
```

The `vmware update-with-vcenter` subcommand updates an encrypted VMDK with the latest
version of the Metavisor code using vCenter.

```
$ brkt vmware update-with-vcenter --help
usage: brkt vmware update-with-vcenter [-h] --vcenter-host DNS_NAME
                                       [--vcenter-port N]
                                       [--vcenter-datacenter NAME]
                                       [--vcenter-datastore NAME]
                                       [--vcenter-cluster NAME]
                                       [--cpu-count N] [--memory GB]
                                       [--template-vm-name NAME]
                                       [--encrypted-image-directory NAME]
                                       [--ovftool-path PATH]
                                       [--encrypted-image-name NAME]
                                       [--update-ovf] [--update-ova]
                                       [--no-validate]
                                       [--ovf-source-directory PATH]
                                       [--metavisor-ovf-image-name NAME]
                                       [--use-esx-host]
                                       [--ntp-server DNS_NAME]
                                       [--proxy HOST:PORT | --proxy-config-file PATH]
                                       [--status-port PORT] [--token TOKEN]

Update an encrypted VMDK with the latest Metavisor using vCenter

optional arguments:
  --cpu-count N         Number of CPUs to assign to Encryptor VM (default: 8)
  --encrypted-image-directory NAME
                        Directory to fetch the encrypted OVF/OVA image
                        (default: None)
  --encrypted-image-name NAME
                        Specify the name of the encrypted OVF/OVA image to
                        update (default: None)
  --memory GB           Memory to assign to Encryptor VM (default: 32)
  --metavisor-ovf-image-name NAME
                        Metavisor OVF name (default: None)
  --no-validate         Don't validate VMDKs and vCenter credentials (default:
                        True)
  --ntp-server DNS_NAME
                        Optional NTP server to sync Metavisor clock. May be
                        specified multiple times. (default: None)
  --ovf-source-directory PATH
                        Local path to the Metavisor OVF directory (default:
                        None)
  --ovftool-path PATH   ovftool executable path (default: ovftool)
  --proxy HOST:PORT     Use this HTTPS proxy during encryption. May be
                        specified multiple times. (default: None)
  --proxy-config-file PATH
                        Path to proxy.yaml file that will be used during
                        encryption (default: None)
  --status-port PORT    Specify the port to receive http status of encryptor.
                        Any port in range 1-65535 can be used except for port
                        81. (default: 80)
  --template-vm-name NAME
                        Specify the name of the template VM to be updated
                        (default: None)
  --token TOKEN         Token that the encrypted instance will use to
                        authenticate with the Bracket service. Use the make-
                        token subcommand to generate a token. (default: None)
  --update-ova          Update OVA package (default: False)
  --update-ovf          Update OVF package (default: False
  --use-esx-host        Use single ESX host for encrytion instead of vCenter
                        (default: False)
  --vcenter-cluster NAME
                        vCenter cluster to use (default: None)
  --vcenter-datacenter NAME
                        vCenter Datacenter to use (default: None)
  --vcenter-datastore NAME
                        vCenter datastore to use (default: None)
  --vcenter-host DNS_NAME
                        IP address/DNS Name of the vCenter host (default:
                        None)
  --vcenter-port N      Port Number of the vCenter Server (default: 443)
  -h, --help            show this help message and exit
```

## Configuration

Before running the **brkt** command, make sure that you've set your vCenter
environment variables:

```
$ export VCENTER_USER_NAME=<user name>
$ export VCENTER_PASSWORD=<password>
```

If the VCENTER_PASSWORD is not defined, brkt-cli will prompt the user to enter the password on the terminal.

## Encrypting an VMDK with vCenter

Run **brkt vmware encrypt-with-vcenter** to create a new encrypted VMDK based on an existing
VMDK:

```
$ ./brkt vmware encrypt-with-vcenter --token <token> --vcenter-host <vcenter_host> --template-vm-name encrypt-vmdk-test --vcenter-datacenter <datacenter_name> --vcenter-datastore <datastore_name> --vcenter-cluster <cluster_name> centos66/centos66.vmdk
18:35:20 Fetching Metavisor OVF from S3
18:35:31 Launching VM from OVF ./c4ca122117c9f0bb.ovf
18:35:37 Starting new HTTPS connection (1): 10.9.1.216
/usr/local/lib/python2.7/dist-packages/requests/packages/urllib3/connectionpool.py:791: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.org/en/latest/security.html
  InsecureRequestWarning)
18:35:56 [primary] centos66/centos66.vmdk disk added to VM Encryptor-VM-2016-11-15T18:35:32.034732Z
18:35:57 34603008KB empty disk added to Encryptor-VM-2016-11-15T18:35:32.034732Z
18:36:35 VM ip address is 10.9.1.75
18:37:36 Encryption is 3% complete
...
18:46:39 Encrypted root drive created.
18:47:40 Disk at 2 detached from VM Encryptor-VM-2016-11-15T18:35:32.034732Z
18:47:41 Creating the template VM
encrypt-vmdk-test
18:51:23 Destroying VM Encryptor-VM-2016-11-15T18:35:32.034732Z
18:51:29 Done
```

When the process completes, the new VMDK with the name specified in the
`--template-vm-name` argument is created in the vCenter in the specified
vCenter datastore.

## Updating an encrypted VMDK

Run **brkt vmware update-with-vcenter** to update an encrypted VMDK with the
latest Metavisor using vCenter:

```
$ brkt vmware update-with-vcenter --token <token> --vcenter-host <vcenter_host> --template-vm-name encrypt-vmdk-test --vcenter-datacenter <datacenter_name> --vcenter-datastore <datastore_name> --vcenter-cluster <cluster_name>
17:08:40 Fetching Metavisor OVF from S3
17:21:09 Launching encrypted guest VM
17:34:12 Launching VM from OVF ./c4ca122117c9f0bb.ovf
17:34:17 Starting new HTTPS connection (1): 10.9.1.216
/usr/local/lib/python2.7/dist-packages/requests/packages/urllib3/connectionpool.py:791: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.org/en/latest/security.html
  try:
17:35:13 MV VM ip address is 10.9.1.68
17:35:13 Waiting for updater service on port 80 on 10.9.1.68
17:35:13 Encrypted root drive created.
17:35:23 Disk at 1 detached from VM template-vm-2016-11-16T17:21:10.523880Z
17:35:24 Disk at 0 detached from VM template-vm-2016-11-16T17:21:10.523880Z
17:35:24 Cloning Metavisor disk
17:37:02 [primary] Encryptor-VM-2016-11-16T17_34_12.502120Z/template-vm-2016-11-16T17_21_10.523880Z.vmdk disk added to VM template-vm-2016-11-16T17:21:10.523880Z
17:37:02 [primary] template-vm-2016-11-16T17_21_10.523880Z/template-vm-2016-11-16T17_21_10.523880Z_1.vmdk disk added to VM template-vm-2016-11-16T17:21:10.523880Z
17:37:02 Deleting the old template
17:37:03 Destroying VM encrypt-vmdk-test
17:37:11 Creating the template VM
encrypt-vmdk-test
17:54:52 Destroying VM template-vm-2016-11-16T17:21:10.523880Z
17:55:00 Destroying VM Encryptor-VM-2016-11-16T17:34:12.502120Z
17:55:05 Done
```

When the process completes, the VMDK specified in the `--template-vm-name` argument
is updated with the latest Metavisor.

# Encrypting images on an ESX host

The `vmware encrypt-with-esx-host` subcommand creates an encrypted VMDK from a base
(unencrypted) VMDK on an ESX host

```
$ brkt vmware encrypt-with-esx-host --help
usage: brkt vmware encrypt-with-esx-host [-h] --esx-host DNS_NAME
                                         [--esx-port N] [--esx-datastore NAME]
                                         [--cpu-count N] [--memory GB]
                                         [--encrypted-image-name NAME]
                                         [--template-vm-name NAME]
                                         [--no-validate] [--create-ovf]
                                         [--create-ova]
                                         [--encrypted-image-directory NAME]
                                         [--ovftool-path PATH]
                                         [--ovf-source-directory PATH]
                                         [--metavisor-ovf-image-name NAME]
                                         [--console-file-name NAME]
                                         [--disk-type TYPE]
                                         [--ntp-server DNS_NAME]
                                         [--proxy HOST:PORT | --proxy-config-file PATH]
                                         [--status-port PORT] [--token TOKEN]
                                         VMDK-NAME

Create an encrypted VMDK from an existing VMDK on an ESX host

positional arguments:
  VMDK-NAME             The Guest VMDK that will be encrypted

optional arguments:
  --console-file-name NAME
                        File name to dump console messages to (default: None)
  --cpu-count N         Number of CPUs to assign to Encryptor VM (default: 8)
  --create-ova          Create OVA package (default: False)
  --create-ovf          Create OVF package (default: False)
  --disk-type TYPE      thin/thick-lazy-zeroed/thick-eager-zeroed (default:
                        thin) (default: thin)
  --encrypted-image-directory NAME
                        Directory to store the generated OVF/OVA image
                        (default: None)
  --encrypted-image-name NAME
                        Specify the name of the generated OVF/OVA (default:
                        None)
  --esx-datastore NAME  ESX datastore to use (default: None)
  --esx-host DNS_NAME   IP address/DNS Name of the ESX host (default: None)
  --esx-port N          Port Number of the ESX Server (default: 443)
  --memory GB           Memory to assign to Encryptor VM (default: 32)
  --metavisor-ovf-image-name NAME
                        Metavisor OVF name (default: None)
  --no-validate         Don't validate VMDKs and vCenter credentials (default:
                        True)
  --ntp-server DNS_NAME
                        Optional NTP server to sync Metavisor clock. May be
                        specified multiple times. (default: None)
  --ovf-source-directory PATH
                        Local path to the OVF directory (default: None)
  --ovftool-path PATH   ovftool executable path (default: ovftool)
  --proxy HOST:PORT     Use this HTTPS proxy during encryption. May be
                        specified multiple times. (default: None)
  --proxy-config-file PATH
                        Path to proxy.yaml file that will be used during
                        encryption (default: None)
  --status-port PORT    Specify the port to receive http status of encryptor.
                        Any port in range 1-65535 can be used except for port
                        81. (default: 80)
  --template-vm-name NAME
                        Specify the name of the template VM (default: None)
  --token TOKEN         Token that the encrypted instance will use to
                        authenticate with the Bracket service. Use the make-
                        token subcommand to generate a token. (default: None)
  -h, --help            show this help message and exit
```

The `vmware update-with-esx-host` subcommand updates an encrypted VMDK with the latest Metavisor on an ESX host.

```
$ brkt vmware update-with-esx-host --help
usage: brkt vmware update-with-esx-host [-h] --esx-host DNS_NAME
                                        [--esx-port N] [--esx-datastore NAME]
                                        [--cpu-count N] [--memory GB]
                                        [--encrypted-image-name NAME]
                                        [--template-vm-name NAME]
                                        [--no-validate] [--create-ovf]
                                        [--create-ova]
                                        [--encrypted-image-directory NAME]
                                        [--ovftool-path PATH]
                                        [--ovf-source-directory PATH]
                                        [--metavisor-ovf-image-name NAME]
                                        [--console-file-name NAME]
                                        [--disk-type TYPE]
                                        [--ntp-server DNS_NAME]
                                        [--proxy HOST:PORT | --proxy-config-file PATH]
                                        [--status-port PORT] [--token TOKEN]
                                        VMDK-NAME

Update an encrypted VMDK with the latest Metavisor on an ESX host

positional arguments:
  VMDK-NAME             The Guest VMDK that will be encrypted

optional arguments:
  --console-file-name NAME
                        File name to dump console messages to (default: None)
  --cpu-count N         Number of CPUs to assign to Encryptor VM (default: 8)
  --create-ova          Create OVA package (default: False)
  --create-ovf          Create OVF package (default: False)
  --disk-type TYPE      thin/thick-lazy-zeroed/thick-eager-zeroed (default:
                        thin) (default: thin)
  --encrypted-image-directory NAME
                        Directory to store the generated OVF/OVA image
                        (default: None)
  --encrypted-image-name NAME
                        Specify the name of the generated OVF/OVA (default:
                        None)
  --esx-datastore NAME  ESX datastore to use (default: None)
  --esx-host DNS_NAME   IP address/DNS Name of the ESX host (default: None)
  --esx-port N          Port Number of the ESX Server (default: 443)
  --memory GB           Memory to assign to Encryptor VM (default: 32)
  --metavisor-ovf-image-name NAME
                        Metavisor OVF name (default: None)
  --no-validate         Don't validate VMDKs and vCenter credentials (default:
                        True)
  --ntp-server DNS_NAME
                        Optional NTP server to sync Metavisor clock. May be
                        specified multiple times. (default: None)
  --ovf-source-directory PATH
                        Local path to the OVF directory (default: None)
  --ovftool-path PATH   ovftool executable path (default: ovftool)
  --proxy HOST:PORT     Use this HTTPS proxy during encryption. May be
                        specified multiple times. (default: None)
  --proxy-config-file PATH
                        Path to proxy.yaml file that will be used during
                        encryption (default: None)
  --status-port PORT    Specify the port to receive http status of encryptor.
                        Any port in range 1-65535 can be used except for port
                        81. (default: 80)
  --template-vm-name NAME
                        Specify the name of the template VM (default: None)
  --token TOKEN         Token that the encrypted instance will use to
                        authenticate with the Bracket service. Use the make-
                        token subcommand to generate a token. (default: None)
  -h, --help            show this help message and exit
```

## Configuration

Before running the **brkt** command, make sure that you've set your ESX
environment variables:

```
$ export ESX_USER_NAME=<user name>
$ export ESX_PASSWORD=<password>
```
If the ESX_PASSWORD is not defined, brkt-cli will prompt the user to enter the password on the terminal.

## Creating an encrypted VM on an ESX Host

Run **brkt vmware encrypt-with-esx-host** to create an encrypted VM with the
latest Metavisor on an ESX host:

```
$ brkt vmware encrypt-with-esx-host --token <token> --esx-host <HOST> --esx-datastore <datastore> --encrypted-image-directory=<PATH> --encrypted-image-name=centos66encrypted_ovf  centos66-stock/centos66-stock.vmdk --template-vm-name brkt-esx-encrypted-vm
16:49:25 Fetching Metavisor OVF from S3
16:49:34 Launching VM from OVF ./c4ca122117c9f0bb.ovf
16:49:35 Starting new HTTPS connection (1): 10.9.1.216
/usr/local/lib/python2.7/dist-packages/requests/packages/urllib3/connectionpool.py:791: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.org/en/latest/security.html
  InsecureRequestWarning)
16:49:45 [ssd-primary] centos66-stock/centos66-stock.vmdk disk added to VM brkt-esx-encrypted-vm
16:49:45 34603008KB empty disk added to brkt-esx-encrypted-vm
16:50:06 VM ip address is 10.9.1.70
16:51:12 Encryption is 10% complete
16:52:12 Encryption is 23% complete
...
16:58:14 Encryption is 97% complete
16:58:35 Encrypted root drive created.
16:58:36 Disk at 2 detached from VM brkt-esx-encrypted-vm
16:58:36 Encrypted VM is brkt-esx-encrypted-vm
16:58:36 Done
```

When the command completes, it creates an encrypted VM which can be identified using the name specified by the `--template-vm-name` argument and leaves the VM in a stopped state.

## Creating an encrypted OVF on an ESX Host

Run **brkt vmware encrypt-with-esx-host** to create an encrypted OVF image with
the latest Metavisor on an ESX host.

```
$ brkt vmware encrypt-with-esx-host --token <token> --esx-host <HOST> --esx-datastore <datastore> --encrypted-image-directory=<PATH> --create-ovf --encrypted-image-name centos66encrypted --ovftool-path /usr/bin/ovftool centos66/centos66.vmdk
17:06:25 Fetching Metavisor OVF from S3
17:06:34 Launching VM from OVF ./c4ca122117c9f0bb.ovf
17:06:41 Starting new HTTPS connection (1): 10.9.1.216
/usr/local/lib/python2.7/dist-packages/requests/packages/urllib3/connectionpool.py:791: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.org/en/latest/security.html
  InsecureRequestWarning)
17:06:54 [primary] centos66/centos66.vmdk disk added to VM Encryptor-VM-2016-11-15T17:06:34.566220Z
17:06:54 34603008KB empty disk added to Encryptor-VM-2016-11-15T17:06:34.566220Z
17:07:24 VM ip address is 10.9.1.73
17:08:30 Encryption is 3% complete
17:09:30 Encryption is 7% complete
...
17:29:39 Encryption is 97% complete
17:30:19 Encrypted root drive created.
17:30:27 Disk at 2 detached from VM Encryptor-VM-2016-11-15T17:06:34.566220Z
17:30:27 Creating images
17:30:27 Starting new HTTPS connection (1): 10.9.1.216
/usr/local/lib/python2.7/dist-packages/requests/packages/urllib3/connectionpool.py:791: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.org/en/latest/security.html
  InsecureRequestWarning)
17:30:51 Starting new HTTPS connection (1): 10.9.1.216
  /usr/local/lib/python2.7/dist-packages/requests/packages/urllib3/connectionpool.py:791: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.org/en/latest/security.html
    InsecureRequestWarning)
    /attached_files/brkt_ovfs/centos66encrypted.ovf
17:54:02 Destroying VM Encryptor-VM-2016-11-15T17:06:34.566220Z
17:54:09 Done
```

When the command completes, it creates an OVF file identified by the `--encrypted-image-name` argument under the path specified by the `--encrypted-image-directory` argument. The same command can be used to create an OVA by using the `--create-ova` argument instead of `--create-ovf`.
