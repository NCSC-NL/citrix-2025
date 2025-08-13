# Citrix NetScaler coredump scan

Scan Citrix NetScaler coredump file(s) for IOCs related to CVE-2025-5349, CVE-2025-5777 and CVE-2025-6543.

## Instructions
It is highly recommended to use UV to run the script.

### setup
Install UV using the instructions here: https://docs.astral.sh/uv/getting-started/installation/
### running the script

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

Scan Citrix NetScaler coredump file(s) for IOCs related to CVE-2025-5349, CVE-2025-5777 and CVE-2025-6543.

positional arguments:
  coredump_target       COREDUMP_FILE or DIRECTORY_WITH_COREDUMPS

options:
  -h, --help            show this help message and exit
  --organisation ORGANISATION
                        Your organisation name.

Version 1.0; released by NCSC-NL (https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid).
```

