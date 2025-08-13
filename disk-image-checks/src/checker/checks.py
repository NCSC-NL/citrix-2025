from collections import Counter
from datetime import datetime
import logging
import math
import os
from pathlib import Path
import re
import stat
from typing import Iterator

from dissect.target import Target
from dissect.target.helpers.fsutil import stat_result
from checker.models import ConfidenceEnum, SuspiciousContentCheckArgs
from checker.utils import FindingRecord


from dissect.target.exceptions import UnsupportedPluginError

logger = logging.getLogger("checks")
logger.setLevel(logging.INFO)
EXPECTED_PHP_FILE_PERMISSION = 0o444
CORE_DUMP_CHECK_SCRIPT_URL = ""


def set_log_level(level):
    logger.setLevel(level)


def _is_known_path(path: Path, known_paths: list[str]) -> bool:
    path = str(path)
    for known_path in known_paths:
        if known_path.endswith("/"):
            if path.startswith(known_path):
                return True
        else:
            if path == known_path:
                return True
    return False


def timestomp(
    target: Target, confidence: ConfidenceEnum, paths: list[str], known_paths: list[str]
) -> Iterator[FindingRecord]:
    """
    Check for timestamp manipulation in files and directories for path

    Args:
        target: Dissect Target object
        confidence (ConfidenceEnum): Confidence level in this IOC/check
        path: path to check all files and directories (recursively)

    Yields:
        Iterator[FindingRecord]: Findings
    """
    logger.info("*** Checking for timestomped files ***")
    timestomp_dirs = paths
    for timestomp_dir in timestomp_dirs:
        for path in (
            x for x in target.fs.path(timestomp_dir).rglob("*") if x.is_file() and not _is_known_path(x, known_paths)
        ):
            stat: stat_result = path.lstat()
            if not stat.st_mtime or not stat.st_birthtime:
                logger.debug(f"Timestomp failure for {path}: {stat.st_mtime=}, {stat.st_birthtime=}")
                continue

            if stat.st_mtime < stat.st_birthtime:
                yield FindingRecord(
                    type="file/timestomp",
                    alert=f"Possibly Timestomped File Observed ({stat.st_mtime=},  {stat.st_birthtime=} seconds)",
                    confidence=confidence,
                    path=path,
                )


def _find_suspicious(file: Path, suspicious_contents: list[str]) -> Iterator[str]:
    """Check if a file contains suspicious content

    Yields:
        str: Found evil content
    """
    try:
        content = file.read_text().lower()
    except UnicodeDecodeError:
        logger.debug(f"Unicode decode error when reading {file}")
        return
    for evil in suspicious_contents:
        if evil.startswith("regex:"):
            if match := re.search(evil[len("regex:") :], content):
                yield match.group(0)
        elif evil.lower() in content:
            yield evil


def webshell(
    target: Target,
    confidence: ConfidenceEnum,
    suspicious_contents: list[str],
    paths: list[str],
    known_paths: list[str],
    permission_confidence: ConfidenceEnum,
) -> Iterator[FindingRecord]:
    """Check for possible webshells.

    Args:
        target: Dissect Target Object
        confidence (ConfidenceEnum): Confidence level in this IOC/check
        suspicious_contents (list[str]): Content to check for
        paths (list[str]): Paths to recurse
        known_paths (list[str]): Paths to exclude.
        maximum_byte_size_php_to_check_contents (int): Skip file check if larger than this value in bytes. -1 to not skip any.

    Yields:
        Iterator[FindingRecord]: Findings
    """
    logger.info("*** Checking for webshells ***")
    for start_path in paths:
        for path in (
            x for x in target.fs.path(start_path).rglob("*.php") if x.is_file() and not _is_known_path(x, known_paths)
        ):
            try:
                stat: stat_result = path.lstat()
                mode = stat.st_mode & 0o777
                if mode != EXPECTED_PHP_FILE_PERMISSION:
                    permission_printable = oct(mode)
                    yield FindingRecord(
                        alert=f"Suspicious php permission {permission_printable}",
                        confidence=permission_confidence,
                        path=path,
                        type="php-file-permission",
                    )

                for found_content in _find_suspicious(path, suspicious_contents):
                    yield FindingRecord(
                        type="php-file-contents",
                        path=path,
                        confidence=confidence,
                        alert=f"Suspicious PHP code '{found_content}'",
                    )

            except UnicodeDecodeError:
                logger.debug(f"Unicode decode error for {path}")
            except Exception as e:
                logger.debug(f"Failure in webshell check for {path}: {e}")


def suspicious_content(
    target: Target, confidence: ConfidenceEnum, checks: list[SuspiciousContentCheckArgs]
) -> Iterator[FindingRecord]:
    """Check files for suspicious content strings

    Args:
        target (Target): Dissect Target Object
        confidence (ConfidenceEnum): Confidence level in this IOC/check
        checks (list[SuspiciousContentCheckArgs]): List of checks. Each check
            has a list of paths to check and the suspicious contents to check
            the files in those paths against.
        known_paths (list[str]): List of paths known to contain suspicious contents,
            which should not raise an alert.

    Yields:
        Iterator[FindingRecord]: finding
    """

    for check in checks:
        for start_path in check.paths:
            start_path = target.fs.path(start_path)
            if start_path.is_file():
                if not _is_known_path(start_path, check.known_paths) or not start_path.is_file():
                    for found_content in _find_suspicious(
                        start_path,
                        check.suspicious_contents,
                    ):
                        yield FindingRecord(
                            type=f"suspicious-contents-{check.name}",
                            path=start_path,
                            confidence=confidence,
                            alert=f"Suspicious content '{found_content}'",
                        )
            else:
                for path in start_path.rglob("*"):
                    if path.is_file():
                        if not _is_known_path(path, check.known_paths) or not path.is_file():
                            for found_content in _find_suspicious(path, check.suspicious_contents):
                                yield FindingRecord(
                                    type=f"suspicious-contents-{check.name}",
                                    path=path,
                                    confidence=confidence,
                                    alert=f"Suspicious content '{found_content}'",
                                )


def yara(
    target: Target, confidence: ConfidenceEnum, rule_files: str, paths: list[str], max_file_size_kb: int
) -> Iterator[FindingRecord]:
    """
    Executes YARA rules against target files to identify malware signatures,
    suspicious patterns, and known threat indicators.

    Args:
        target: Dissect Target Object
        confidence (ConfidenceEnum): Confidence level in this IOC/check
        rule_files (list[str]): List of paths to YARA rules file containing detection patterns.
        paths (list[str]): Filepaths in the target to recurse and check against the rules.

    Yields:
        Iterator[FindingRecord]: Findings
    """
    logger.info("*** Checking files with yara rules ***")
    try:
        from yara import compile as yara_compile
    except ImportError:
        logger.exception(
            "Failed importing yara. Install yara-python or verify your installation. Skipping yara rule matching for now."
        )
        return

    rules = []

    for file in rule_files:
        with open(file, "rt") as f:
            rules.append(f.read())

    if any(rules):
        yara_rules_matcher = yara_compile(source="\n".join(rules))
    else:
        return

    for start_path in paths:
        for path in target.fs.path(start_path).rglob("*"):
            if path.is_file() and path.stat().st_size <= max_file_size_kb * 1024:
                try:
                    if match := yara_rules_matcher.match(data=path.read_text()):
                        yield FindingRecord(
                            type="php-file-contents-yara",
                            path=path,
                            confidence=confidence,
                            alert=f"YARA rule match on rule(s) {', '.join(list(match))}",
                        )
                except (UnicodeDecodeError, Exception) as e:
                    logging.debug(f"Failed checking {path} against yara rules. {e}")


def crontab(target: Target, confidence: ConfidenceEnum, suspicious_contents: dict[str, str]) -> Iterator[FindingRecord]:
    """
    Extract and analyze crontab configurations from filesystem

    Args:
        target: Dissect Target object
        confidence (ConfidenceEnum): Confidence level in this IOC/check
        paths: list of paths to search crontabs on

    Yields:
        Iterator[FindingRecord]: Findings
    """
    logger.info("*** Checking for cronjobs ***")
    try:
        cronjobs = target.cronjobs()
    except UnsupportedPluginError:
        logger.debug("No crontabs found")
        return

    suspicious_crontab_contents = [(key, re.compile(pattern)) for key, pattern in suspicious_contents.items()]

    for cronjob_record in cronjobs:
        if "environmentvariable" in cronjob_record._desc.name:
            continue
        if cronjob_record.username == "nobody":
            yield FindingRecord(
                type="cronjob/user",
                alert="Crontab by nobody user observed",
                confidence=confidence,
                path=cronjob_record.path,
            )
        for name, pattern in suspicious_crontab_contents:
            if match := pattern.match(cronjob_record.command):
                yield FindingRecord(
                    type="cronjob/command",
                    alert=f"{name} find in crontab comand ({match.group(0)})",
                    confidence=confidence,
                    path=cronjob_record.path,
                )


def binaries(
    target: Target, confidence: ConfidenceEnum, known_suid_binaries: list[str], known_guid_binaries: list[str]
) -> Iterator[FindingRecord]:
    """
    Check binaries for SUID and GUID flags. Filter against known good binaries

    Args:
        target: Dissect Target object
        confidence (ConfidenceEnum): Confidence level in this IOC/check
        known_suid_binaries: list of known non-malicious binaries with SUID flag
        known_guid_binaries: list of known non-malicious binaries with GUID flag

    Yields:
        Iterator[FindingRecord]: Findings
    """
    logger.info("*** Checking for SUID & GUID binaries ***")
    known_guid_binaries = set(known_guid_binaries)
    known_suid_binaries = set(known_suid_binaries)
    for record in target.fs.recurse("/"):
        bin_types = []
        if record.is_file():
            if (
                record.stat(follow_symlinks=False).st_mode & stat.S_ISUID
                and str(record.path) not in known_suid_binaries
            ):
                bin_types.append("s")

            if (
                record.stat(follow_symlinks=False).st_mode & stat.S_ISGID
                and str(record.path) not in known_guid_binaries
            ):
                bin_types.append("g")

            for bin_type in bin_types:
                yield FindingRecord(
                    type=f"binary/{bin_type}uid",
                    alert=f"Binary with {bin_type.upper()}UID bit set Observed",
                    confidence=confidence,
                    path=record.path,
                )


def _compute_entropy(data: bytes) -> int:
    byte_counts = Counter(data)
    total_bytes = len(data)
    probabilities = [counter / total_bytes for counter in byte_counts.values()]
    return -sum(probability * math.log2(probability) for probability in probabilities if probability > 0)


def entropy(
    target: Target, confidence: ConfidenceEnum, paths: list[str], threshold_entropy: int, known_high_entropy: list[str]
) -> Iterator[FindingRecord]:
    """Find files with entropy above `threshold_entropy`

    Args:
        target (Target): Dissect Target Object
        confidence (ConfidenceEnum): Confidence level in this IOC/check
        paths (list[str]): Paths to recurse
        threshold_entropy (int): threshold. Entropy higher than this value will result in a Finding
        known_high_entropy (list[str]): List of files that are known to have high entropy and non-malicious.

    Yields:
        Iterator[FindingRecord]: Findings
    """
    logger.info("*** Checking for high entropy files ***")
    if threshold_entropy < 0:
        logger.warning("Skipping entropy check as threshold is negative")
        return
    known_high_entropy = set(known_high_entropy)
    for start_path in paths:
        for path in target.fs.path(start_path).rglob("*"):
            if path.is_file() and str(path) not in known_high_entropy:
                try:
                    entropy_value = _compute_entropy(path.read_bytes())
                    logger.debug(f"{str(path)} entropy: {entropy_value}")
                    if entropy_value > threshold_entropy:
                        yield FindingRecord(
                            type="entropy-above-threshold",
                            path=path,
                            confidence=confidence,
                            alert=f"File has entropy above {threshold_entropy=}: {entropy_value:.3f}",
                        )
                except (UnicodeDecodeError, Exception) as e:
                    logging.debug(f"Failed checking {path} against yara rules. {e}")


def known_bad_files(target: Target, confidence: ConfidenceEnum, files: list[str]) -> Iterator[FindingRecord]:
    """Check if any known bad files are present.

    Args:
        target (Target): Dissect Target Object
        confidence (ConfidenceEnum): Confidence level in this IOC/check
        files (list[str]): known bad files

    Yields:
        Iterator[FindingRecord]: Findings
    """
    logger.info("*** Checking for known bad files ***")

    for file in files:
        if target.fs.is_file(file):
            yield FindingRecord(
                type="known-bad-file",
                path=file,
                confidence=confidence,
                alert=f"Known bad file {file} is present",
            )


def mime_type(
    target: Target, confidence: ConfidenceEnum, paths: list[str], suspicious_mime_types: list[str]
) -> Iterator[FindingRecord]:
    """Check if file with a suspicious MIME type exist in the image.

    Args:
        target (Target): Dissect Target Object
        confidence (ConfidenceEnum): Confidence level in this IOC/check
        paths (list[str]): Paths to recurse
        suspicious_mime_types (list[str]): MIME types to alert on.

    Yields:
        Iterator[FindingRecord]: findings
    """
    logger.info("*** Checking for suspicious MIME types***")
    try:
        import magic
    except Exception as e:
        logger.error(f"Failure when importing python-magic: {e}")
        return

    suspicious_mime_types = set(suspicious_mime_types)
    for start_path in paths:
        for path in target.fs.path(start_path).rglob("*"):
            if path.is_file():
                mime_type = magic.Magic(mime=True).from_buffer(path.open("rb").read(2048))
                if mime_type in suspicious_mime_types:
                    yield FindingRecord(
                        type="suspicious-mime-type",
                        path=path,
                        confidence=confidence,
                        alert=f"File {path} has suspicious MIME type: {mime_type} is present",
                    )


def core_dump(
    target: Target, confidence: ConfidenceEnum, output_dir: str, extract: bool, creation_date_threshold: str
) -> Iterator[FindingRecord]:
    """Check if there are core dumps of the NSPPE process present in the image.

    Args:
        target (Target): Dissect Target Object
        confidence (ConfidenceEnum): Confidence level in this IOC/check
        extract (bool): Whether to extract found coredumps from the image.

    Yields:
        Iterator[FindingRecord]: Findings
    """
    logger.info("*** Checking for known bad files ***")

    out_dir = os.path.join(output_dir, target.path.name)
    extracted = False

    threshold_timestamp = (datetime.combine(creation_date_threshold, datetime.min.time())).timestamp()
    for path in target.fs.path("/var/core").rglob("NSPPE*"):
        creation_timestamp = path.stat().st_ctime
        if creation_timestamp > threshold_timestamp:
            yield FindingRecord(
                type="core-dump",
                path=path,
                confidence=confidence,
                alert=f"NSPPE core dump created after {creation_date_threshold} ({datetime.fromtimestamp(creation_timestamp).strftime('%Y-%m-%d, %H:%M:%S')}) found {path}",
            )
            if extract:
                try:
                    os.makedirs(out_dir, exist_ok=True)
                    with open(os.path.join(out_dir, path.name), "wb") as f:
                        f.write(path.read_bytes())
                    extracted = True
                except Exception as e:
                    logger.debug(f"Error extracting coredump: {e}")
    if extracted:
        logger.warning(
            f"One or more core dumps where extract to {out_dir}.\
                       Please consider checking these core dumps with the core dump check script {CORE_DUMP_CHECK_SCRIPT_URL}."
        )


def magic_bytes(
    target: Target, confidence: ConfidenceEnum, paths: list[str], suspicious_bytes: dict[str, str]
) -> Iterator[FindingRecord]:
    """Check files against a set of suspicious magic bytes.

    Args:
        target (Target): Target
        confidence (ConfidenceEnum): confidence
        paths (list[str]): paths to recurse
        suspicious_bytes (dict[str, str]): Dictionary with name:suspicious bytes pairs where the bytes is a hex string.

    Yields:
        Iterator[FindingRecord]: Finding
    """
    logger.info("*** Checking for suspicious magic bytes types***")

    for start_path in paths:
        for path in target.fs.path(start_path).rglob("*"):
            if path.is_file():
                for filetype, bytes_str in suspicious_bytes.items():
                    expected_magic_bytes = bytes.fromhex(bytes_str)
                    if path.open("rb").read(len(expected_magic_bytes)) == expected_magic_bytes:
                        yield FindingRecord(
                            type="suspicious-magic-bytes",
                            path=path,
                            confidence=confidence,
                            alert=f"File {path} has suspicious magic bytes, likely {filetype}: '{bytes_str}' is present",
                        )
