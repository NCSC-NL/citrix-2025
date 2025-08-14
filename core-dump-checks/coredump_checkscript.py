# /// script
# requires-python = ">=3.11,<3.13"
# dependencies = [
#   "yara-python"
# ]
# ///
import argparse
import datetime
import gzip
import json
from pathlib import Path
import tempfile

try:
    import yara
except ImportError:
    print(
        "Error: yara-python is not installed, try `pip install yara-python` "
        "or see https://yara.readthedocs.io/en/stable/gettingstarted.html"
    )

SCRIPT_VERSION = "1.0.0"
HELP_URL = "https://www.ncsc.nl/actueel/nieuws/2025/07/22/casus-citrix-kwetsbaarheid"
SUBMIT_URL = ""
DEFAULT_CONTEXT_SIZE = 1024 * 4
GZIP_MAGIC = b"\x1f\x8b"
ELF_MAGIC = b"\x7f\x45\x4c\x46"


def export_results(results: list, output_file: str) -> None:
    """Prints nice IOC results for each file in jsonl format."""
    if any(results):
        with open(output_file, "a+") as file:
            for result in results:
                line = json.dumps(result)
                file.write(line + "\n")


def show_results_for_file(results: list) -> None:
    """Prints nice IOC results for each file."""
    if len(results) == 0:
        print(f"[+] Found 0 indicators in '{src_file}', continuing...")
        return

    print(f"[-] Found {len(results)} indicators in '{src_file}':")
    for result in results:
        confidence_level = result.get("confidence_level", "unknown")
        rulename = result.get("rulename")
        offset = result.get("offset")
        print(f" - [coredump {src_file} - confidence {confidence_level}] rule '{rulename}' matched at offset {offset}")
    print("")


def get_context(file: Path, hit: yara.StringMatchInstance, context_size: int = DEFAULT_CONTEXT_SIZE) -> bytes:
    """Returns DEFAULT_CONTEXT_SIZE bytes of context to be added to each result."""
    fh = file.open("rb")
    fh.seek(hit.offset - context_size)
    context_before = fh.read(context_size)

    fh.seek(hit.offset + hit.matched_length)
    context_after = fh.read(context_size)
    return context_before, context_after


def gunzip_file(src_file: Path) -> Path:
    """Gunzips a file to a temporary path."""
    fp = tempfile.NamedTemporaryFile(delete=False)
    with gzip.open(src_file, "rb") as file:
        fp.write(file.read())
    return Path(fp.name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan Citrix NetScaler coredump file(s) for IOCs related to CVE-2025-5349, CVE-2025-5777 and CVE-2025-6543.",
        epilog=f"Version {SCRIPT_VERSION}; released by NCSC-NL ({HELP_URL}).",
    )
    parser.add_argument("coredump_target", help="COREDUMP_FILE or DIRECTORY_WITH_COREDUMPS")
    parser.add_argument("--organisation", help="Your organisation name.")
    args = parser.parse_args()

    if not args.organisation:
        organisation = input("What is your organisation name: ")
    else:
        organisation = args.organisation

    # Coredumps to analyse
    target = args.coredump_target

    # File to write results to (windows does not allow colons)
    dt = datetime.datetime.now().isoformat(timespec="seconds").replace(":", "_")
    results_filename = f"{dt}-{organisation}-coredump-results.jsonl"
    results_file = Path(results_filename)
    results = []
    results_counter = 0

    # Yara setup
    with open("iocs.yar", "r") as file:
        YARA_RULES = file.read()
        yara_match = yara.compile(source=YARA_RULES)

    # Determine whether we're targetting one coredump or a directory of coredumps
    if Path(target).is_dir():
        files = list((x for x in Path(target).rglob("*") if x.is_file()))
    elif Path(target).is_file():
        files = [Path(target)]
    else:
        raise ValueError(f"Target path {target} not found. Exiting.")

    print(f"[+] The coredump_checkscript.py file will run against {len(files)} files:")
    for f in files:
        print(f"\t{f.name}")
    checked_files = []
    for src_file in files:
        try:
            flag_gunzipped_file = False

            # If file is compressed, uncompress it
            if src_file.open("rb").read(2) == GZIP_MAGIC:
                print(f"gunzipping file {src_file}")
                flag_gunzipped_file = True
                file = gunzip_file(src_file)
            else:
                file = src_file

            # Check whether file is an actual ELF file
            if file.open("rb").read(4) != ELF_MAGIC:
                print(
                    f"File {src_file} was not recognized as a Citrix netscaler coredump or gzipped coredump file, skipping..."
                )
                continue

            tmp_results = []
            for match in yara_match.match(str(file)):
                confidence_level = match.meta.get("confidence_level")
                tlp = match.meta.get("tlp")

                for stringmatch in match.strings:
                    for hit in stringmatch.instances:
                        context_before, context_after = get_context(file, hit)
                        result = {
                            "script_version": SCRIPT_VERSION,
                            "filename": src_file.name,
                            "tlp": tlp,
                            "confidence_level": confidence_level,
                            "offset": hit.offset,
                            "rulename": match.rule,
                            "match": hit.matched_data.decode(encoding="utf-8", errors="replace"),
                            "context_before_hex": context_before.hex(),
                            "context_after_hex": context_after.hex(),
                        }
                        tmp_results.append(result)

            results_counter += len(tmp_results)
            show_results_for_file(tmp_results)
            export_results(tmp_results, results_file)
            results += tmp_results

            if flag_gunzipped_file:
                file.unlink()
            checked_files.append(src_file)
        except Exception as e:
            print(f"ERROR. Failed checking {src_file}. Skipping this coredump. Error: {e}")

    if results_counter == 0:
        print(f"[+] Done! This script analyzed {len(checked_files)} file(s) and found 0 results.")
    else:
        print(f"[-] Done! This script analyzed {len(checked_files)} file(s) and found {results_counter} results.")
        print(f"    You can find the machine readable results in '{results_file}'.\n")

        print("Please consider submitting your results to the NCSC-NL to aid our investigation.")
        print("Follow these steps to submit your results: ")
        compression_cmd = f"7z a {dt}-{organisation}-coredumps.7z {results_filename} {target}"
        print("1. Run: `sudo apt install -y p7zip-full`")
        print(f"2. Use 7z to compress your results and coredumps: `{compression_cmd}`")
        print(f"3. Visit {SUBMIT_URL} to submit your results.")
