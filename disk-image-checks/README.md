# Citrix image-checks
Python script to check citrix images for IOCs. Based on https://github.com/fox-it/citrix-netscaler-triage/blob/main/iocitrix.py.

## Creating Citrix Netscaler disk images
Before you can run the checker you must first create disk images of your netscaler appliance(s).

### Non VPX/SDX/MPX disk images
You can use native disk exports/memory snapshots from Hyper-V, Proxmox, VMware solutions.
However you can still use the method described in the next section to create an image.

### VPX/SDX/MPX disk images
A Citrix NetScaler exposes two important block devices which can imaged for offline forensic analysis. These block device files can be found at the following paths:
* `/dev/md0`: The disk that holds the root (`/`) directory. This is a RAM disk
* `/dev/da0`: The disk that holds the `/var` and `/flash` directories. This is a persistent disk.

The root directory (`/`) of Citrix NetScaler is a RAM disk, meaning that this is a volatile disk. This disk can be found at `/dev/md0` when the NetScaler is powered-on and running, and will be unavailable when the NetScaler is powered-off. The `/var` and `/flash` directories reside on the `/dev/da0` disk as two separate partitions and is persistent.

The following commands can be used on a local linux machine to create disk of your NetScaler over SSH:

#### Create a disk image of the `/dev/da0` disk to your local machine

```shell 
local ~ $ ssh nsroot@<YOUR-NETSCALER-IP> shell dd if=/dev/da0 bs=10M status=progress | tail -c +7 | head -c -6 > da0.img
```

Do note, that this can take some time to complete. Make sure you have enough disk space on the local machine. 
A persistent disk can easily take up 20GB of space or more.
Also if you don't have `/dev/da0` it's most likely `/dev/ada0`, you can verify using the `mount` or `gpart show` command.

#### Create a disk image of the `/dev/md0` disk to your local machine
```shell
local ~ $ ssh nsroot@<YOUR-NETSCALER-IP> shell dd if=/dev/md0 bs=10M status=progress | tail -c +7 | head -c -6 > md0.img
```

**NOTE**: While it is recommended to create disk images of both `/dev/md0` and `/dev/da0`. Creating a disk image of `/dev/md0` is optional. This step could be skipped, though this can cause the checker to miss certains incicators of compromise.

## Checking your own images
This is the simplest/happy path guide on how to check your own images using this check script. This guide assumes you run on a linux system. When running on Windows check the specifics in the Usage section below.

1. Create a new python environment and install dependencies.
    - `python3 -m venv .venv && source .venv/bin/activate && python3 -m pip install .`
2. Check if `dissect` can correctly read your images:
    - Open a shell inside your image: `target-shell <path/to/image>`
    - Inside the shell check if you see the files and their contents e.g., 
      - `ll` -> Should show some directories
      - `cat /var/mastools/version.txt` -> should show some content
    - If you can't open your image/don't see files, edit the image files. Replace `<img>` in this command with the path to your image.
      - `dd if=<img> bs=10M | tail -c +7 | head -c -6 > <img>_dissect.img`
3. Run the check script:
    - `python3 ./src/cli.py <path_to_your_image> --organisation <your_org_name>`
    - Findings will be printed to the console as well as written to `output/findings/<image_name>_<datetime>/`
## Usage

### Options (run with `-h` flag to get this output)
```
usage: run-checks [-h] [--organisation [ORGANISATION]] [--checks [CHECKS ...]] [--config [CONFIG_FILE]] [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                  TARGETS [TARGETS ...]

Analyze forensic images of Citrix Netscalers for IOCs related to CVE-2025-5349, CVE-2025-5777 and CVE-2025-6543.

positional arguments:
  TARGETS               Target(s) to load. https://docs.dissect.tools/en/stable/advanced/targets.html#targets

options:
  -h, --help            show this help message and exit
  --organisation [ORGANISATION]
                        Organisation name
  --checks [CHECKS ...]
                        Check(s) to run. default: all, choices: timestomp, webshell, suspicious_content, crontab, binaries, yara, entropy, known_bad_files, mime_type,
                        core_dump, magic_bytes, all
  --config [CONFIG_FILE], -c [CONFIG_FILE]
                        Path to yaml file containing configuration with IOCs to check for. default: checks.yaml
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level (default: INFO)

Version 1.0; released by NCSC-NL (https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid).
```

### Using `uv`
Using `uv` to run the script is recommended. Read how to install `uv` [here](https://docs.astral.sh/uv/getting-started/installation/).

Clone the repo, and run
  - `cd disk-image-checks`
  - `uv venv && source .venv/bin/active && uv sync --frozen`
  - `uv run run-checks -h`

#### Example
Run all checks on an image
`uv run run-checks images/NSVPX-ESX-13.1.ovf`

Run with only the webshells check
`uv run run-checks images/image.ovf --checks webshell`

### 'plain' python
(optional) create a venv (python3.12):
- `cd disk-image-checks`
- `python3 -m venv .venv`
- `source .venv/bin/activate` or on windows: `source .venv/Scripts/activate`
- `python3 -m pip install .`
- `python3 src/cli.py TARGETS [TARGETS ...]`

## Configuration
Configuration is handled in a yaml `CONFIG_FILE` (default `checks.yaml`)

This file has the following layout:
```yaml
name: <check config name>
checks:
  - check: <check name>
    args:
      <arg>:<value>
```

For each check a pydantic Model exists in [models.py](./src/checker/models.py) which handles input validation. If you update the config file with new arguments these models need to be updated too.

The arguments in the `<name>Args` classes need to match the signatures in the `src/checker/checks.py`.

### known_paths
Multiple checks have a `known_paths` argument used for suppressing false positives. 
 - If the path ends in a `/` it will be treated as a directory match, any alert with a path starting with the allow listed value will be suppressed.
 - Otherwise, it will be treated as a file match. Only exact path matches will be suppresed.

Example:
Alerts without known_paths:
 - `path: /foo/bar/filea`
 - `path: /foo/bar/fileb`
 - `path: /xyz/config`
 - `path: /xyz/config-foo`

```
known_paths:
  - /foo/bar/
  - /xyz/config
```
Alerts with known_paths:
 - `path: /xyz/config-foo`

### suspicious_contents regex
The `suspicious_contents` argument accepts regex patterns prefixed with `regex:`. 
For example, this check will try to find the regex pattern `#[\s]*php_flag engine off` in any of the files in `/nsconfig` and `/etc/`

```yaml
  - check: suspicious_content
    confidence: high
    args:
      checks:
        - name: php_flag
          suspicious_contents:
            - regex:#[\s]*php_flag engine off
          paths: 
            - /nsconfig/
            - /etc
```

### Multiple checks of the same type
You can run multiple checks of the same type with different variables (e.g., if you want separate confidence levels for separate IOCs). To do this, duplicate the `checks` entry, for example:
```
  - check: core_dump
    confidence: medium
    args:
      extract: false
      creation_date_threshold: 2025-05-01

  - check: core_dump
    confidence: high
    args:
      extract: true
      creation_date_threshold: 2025-05-15
```

## Output
While the check is running it will output some logs about what is happening. After an image check is finished, if IOCs where found, this will printed:
```
[cli.py 15:42:32] INFO -
[cli.py 15:42:32] INFO - ********************************************************************************
[cli.py 15:42:32] INFO - ***                                                                          ***
[cli.py 15:42:32] INFO - *** There were findings for Indicators of Compromise.                        ***
[cli.py 15:42:32] INFO - *** Please consider performing further forensic investigation of the system. ***
[cli.py 15:42:32] INFO - ***                                                                          ***
[cli.py 15:42:32] INFO - ********************************************************************************
[cli.py 15:42:32] INFO -
[cli.py 15:42:32] INFO -
confidence    type                          alert                                    artefact_location
------------  ----------------------------  ---------------------------------------  ----------------------
<alert>
```
### Output files
Output will also be written to `<root>/output`:
 - `output/findings/<image_name>_<datetime>/checks.yaml` contains the config that the image check was run with.
 - `output/findings/<image_name>_<datetime>/output.jsonl` contains the IOC alerts in jsonl format
