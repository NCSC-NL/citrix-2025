> [!WARNING]
> This script is not meant to be run directly on the NetScaler itself! Please run it externally on another system.

# Citrix NetScaler core dump scan

Scan Citrix NetScaler core dump file(s) for IOCs related to CVE-2025-5349, CVE-2025-5777 and CVE-2025-6543.

## Instructions
It is highly recommended to use UV to run the script. More info on what UV is here: https://docs.astral.sh/uv/

### Collect NetScaler core dump files
Relevant NetScaler core dump file(s) can be found and downloaded from the NetScaler /var/core directory

### Setup
Install UV using the instructions here: https://docs.astral.sh/uv/getting-started/installation/

### Running the script

```bash
uv run coredump_checkscript.py
```

Or 
`pip install yara-python`
`python3 coredump_checkscript.py`

## Usage

`uv run coredump_checkscript.py -h`:
```
usage: coredump_checkscript.py [-h] [--organisation ORGANISATION] coredump_target

Scan Citrix NetScaler core dump file(s) for IOCs related to CVE-2025-5349, CVE-2025-5777 and CVE-2025-6543.

positional arguments:
  coredump_target       COREDUMP_FILE or DIRECTORY_WITH_COREDUMPS

options:
  -h, --help            show this help message and exit
  --organisation ORGANISATION
                        Your organisation name.

Version 1.0.0; released by NCSC-NL (https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid).
```

