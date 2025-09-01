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
WEB_SHELL_EXTENSIONS = {
    ".php",
    ".php3",
    ".php4",
    ".php5",
    ".php7",
    ".pht",
    ".phtml",
    ".inc",
    ".shtml",
}


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
            x
            for x in target.fs.path(timestomp_dir).rglob("*")
            if x.is_file() and not x.is_symlink() and not _is_known_path(x, known_paths)
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
            pattern = evil[len("regex:") :]
            flags = re.IGNORECASE | re.DOTALL if "(?s)" in pattern else re.IGNORECASE
            pattern = pattern.replace("(?s)", "")
            if match := re.search(pattern, content, flags=flags):
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
        for path in target.fs.path(start_path).rglob("*"):
            if not path.is_file():
                continue
            if path.is_symlink():
                continue
            if _is_known_path(path, known_paths):
                continue
            if path.suffix.lower() not in WEB_SHELL_EXTENSIONS:
                continue
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
        lowercase_exts = {ext.lower() for ext in getattr(check, 'extensions', [])}
        allowlist_regexes: list[re.Pattern] = []
        for aw in getattr(check, 'allowlist_patterns', []) or []:
            if aw.startswith("regex:"):
                allowlist_regexes.append(re.compile(aw[len("regex:") :], re.IGNORECASE))
            else:
                allowlist_regexes.append(re.compile(re.escape(aw), re.IGNORECASE))
        for start_path in check.paths:
            start_path = target.fs.path(start_path)
            if start_path.is_file():
                if start_path.is_symlink():
                    continue
                if not _is_known_path(start_path, check.known_paths) or not start_path.is_file():
                    if lowercase_exts and start_path.suffix.lower() not in lowercase_exts:
                        continue
                    for found_content in _find_suspicious(
                        start_path,
                        check.suspicious_contents,
                    ):
                        is_allowlisted = any(rx.search(found_content) for rx in allowlist_regexes)
                        alert_message = f"Suspicious content '{found_content}'"
                        if is_allowlisted:
                            alert_message += " [allowlisted]"
                        yield FindingRecord(
                            type=f"suspicious-contents-{check.name}",
                            path=start_path,
                            confidence=confidence,
                            alert=alert_message,
                        )
            else:
                for path in start_path.rglob("*"):
                    if path.is_file():
                        if path.is_symlink():
                            continue
                        if not _is_known_path(path, check.known_paths) or not path.is_file():
                            if lowercase_exts and path.suffix.lower() not in lowercase_exts:
                                continue
                            for found_content in _find_suspicious(path, check.suspicious_contents):
                                is_allowlisted = any(rx.search(found_content) for rx in allowlist_regexes)
                                alert_message = f"Suspicious content '{found_content}'"
                                if is_allowlisted:
                                    alert_message += " [allowlisted]"
                                yield FindingRecord(
                                    type=f"suspicious-contents-{check.name}",
                                    path=path,
                                    confidence=confidence,
                                    alert=alert_message,
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
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= max_file_size_kb * 1024:
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
    cronjobs = []
    try:
        if hasattr(target, "cronjobs"):
            cronjobs = target.cronjobs()
    except UnsupportedPluginError:
        logger.debug("No crontabs found via plugin; falling back to filesystem scan")
    except AttributeError:
        logger.debug("Target has no cronjobs() API; falling back to filesystem scan")

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
            if match := pattern.search(cronjob_record.command):
                yield FindingRecord(
                    type="cronjob/command",
                    alert=f"{name} found in crontab command ({match.group(0)})",
                    confidence=confidence,
                    path=cronjob_record.path,
                )

    # Fallback/augment: scan per-user crontabs typically in /var/spool/cron and /var/cron/tabs
    def _scan_spool_dir(spool_dir: str) -> None:
        base = target.fs.path(spool_dir)
        try:
            exists = base.exists()
        except Exception:
            exists = False
        if not exists or not base.is_dir():
            return
        for entry in base.iterdir():
            if not entry.is_file():
                continue
            username = entry.name
            try:
                lines = entry.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", stripped):
                    continue
                if username == "nobody":
                    yield FindingRecord(
                        type="cronjob/user",
                        alert="Crontab by nobody user observed",
                        confidence=confidence,
                        path=entry,
                    )
                for name, pattern in suspicious_crontab_contents:
                    if match := pattern.search(stripped):
                        yield FindingRecord(
                            type="cronjob/command",
                            alert=f"{name} found in crontab command ({match.group(0)})",
                            confidence=confidence,
                            path=entry,
                        )

    if hasattr(target, "fs"):
        yield from _scan_spool_dir("/var/spool/cron")
        yield from _scan_spool_dir("/var/cron/tabs")


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


def _compute_entropy(data: bytes) -> float:
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
            if path.is_file() and not path.is_symlink():
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
        if path.is_symlink():
            continue
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
            if path.is_file() and not path.is_symlink():
                for filetype, bytes_str in suspicious_bytes.items():
                    expected_magic_bytes = bytes.fromhex(bytes_str)
                    if path.open("rb").read(len(expected_magic_bytes)) == expected_magic_bytes:
                        yield FindingRecord(
                            type="suspicious-magic-bytes",
                            path=path,
                            confidence=confidence,
                            alert=f"File {path} has suspicious magic bytes, likely {filetype}: '{bytes_str}' is present",
                        )


def ns_conf(
    target: Target,
    confidence: ConfidenceEnum,
    path: str,
    suspicious_patterns: list[str],
    allowlist_patterns: list[str],
) -> Iterator[FindingRecord]:
    """Parse ns.conf for suspicious portal binding, plugins, or responder injections.

    Pattern examples to supply from YAML:
      - regex:add responder policy .* (http|https)://
      - regex:bind vpn vserver .* -portaltheme\s+(?!Default)\w+
      - regex:set vpn parameter .* -clientlessVpnMode ON
      - regex:add vpn portaltheme .* -source\s+(http|https)://
      - regex:(?s)add responder action .*?Q\("https?://
    """
    logger.info("*** Checking ns.conf for suspicious configuration ***")
    conf_path = target.fs.path(path)

    def _read_conf_with_includes(p: Path, visited: set[str]) -> str:
        text_local = ""
        try:
            text_local = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""
        text_local = re.sub(r"\\\n\s*", " ", text_local)
        includes: list[str] = []
        try:
            for m in re.finditer(r"(?m)^\s*include\s+\"?([^\s\"]+)\"?", text_local):
                includes.append(m.group(1))
        except Exception:
            includes = []
        base_dir = p.parent
        for inc in includes:
            try:
                inc_path = base_dir.joinpath(inc) if not inc.startswith("/") else target.fs.path(inc)
                if inc_path.is_symlink():
                    continue
                inc_str = str(inc_path)
                if inc_str in visited:
                    continue
                visited.add(inc_str)
                text_local += "\n" + _read_conf_with_includes(inc_path, visited)
            except Exception:
                continue
        return text_local

    try:
        text = _read_conf_with_includes(conf_path, visited=set([str(conf_path)]))
    except Exception:
        return

    def compile_list(xs: list[str]) -> list[re.Pattern]:
        compiled: list[re.Pattern] = []
        for x in xs or []:
            if x.startswith("regex:"):
                compiled.append(re.compile(x[len("regex:") :], re.IGNORECASE | re.DOTALL))
            else:
                compiled.append(re.compile(re.escape(x), re.IGNORECASE))
        return compiled

    suspicious_rx = compile_list(suspicious_patterns)
    allowlist_rx = compile_list(allowlist_patterns)

    for rx in suspicious_rx:
        for m in rx.finditer(text):
            start, end = m.span()
            line_start = text.rfind("\n", 0, start) + 1
            line_end_pos = text.find("\n", end)
            if line_end_pos == -1:
                line_end_pos = len(text)
            snippet = text[line_start:line_end_pos]
            is_allowlisted = any(a.search(snippet) for a in allowlist_rx)
            preview = snippet[:160].replace("\n", " ")
            alert = f"ns.conf match: {preview}"
            if is_allowlisted:
                alert += " [allowlisted]"
            yield FindingRecord(
                type="ns-conf/suspicious",
                path=conf_path,
                confidence=confidence,
                alert=alert,
            )

def recent_changes(
    target: Target, confidence: ConfidenceEnum, paths: list[str], days: int, extensions: list[str]
) -> Iterator[FindingRecord]:
    """List files in portal directories changed within the last N days filtered by extensions."""
    logger.info("*** Checking for recent changes in portal directories ***")

    now = datetime.now().timestamp()
    delta_seconds = days * 24 * 60 * 60
    lowercase_exts = {ext.lower() for ext in extensions}

    seen_paths = set()
    for start_path in paths:
        start = target.fs.path(start_path)
        try:
            exists = start.exists()
        except Exception:
            exists = False
        if not exists:
            continue
        for path in start.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            if lowercase_exts:
                suffix = path.suffix.lower()
                if suffix not in lowercase_exts:
                    continue
            try:
                mtime = path.stat().st_mtime
            except Exception:
                continue
            if now - mtime <= delta_seconds:
                if str(path) in seen_paths:
                    continue
                seen_paths.add(str(path))
                yield FindingRecord(
                    type="recent-change",
                    path=path,
                    confidence=confidence,
                    alert=f"File modified within last {days} days",
                )


def tiny_backdoor(
    target: Target,
    confidence: ConfidenceEnum,
    paths: list[str],
    max_size_kb: int,
    extensions: list[str],
    suspicious_patterns: list[str],
) -> Iterator[FindingRecord]:
    """Detect tiny potential backdoors in portal directories by size and pattern match.

    Scans any small, text-like files (<= max_size_kb) regardless of extension, plus PHP-open overrides.
    Extensions list remains supported but is no longer required; non-matching extensions are scanned if the file
    decodes to non-empty text.
    """
    logger.info("*** Checking for tiny potential backdoors in portal directories ***")

    compiled_regexes: list[re.Pattern] = []
    for pattern in suspicious_patterns:
        if pattern.startswith("regex:"):
            compiled_regexes.append(re.compile(pattern[len("regex:") :], re.IGNORECASE))
        else:
            compiled_regexes.append(re.compile(re.escape(pattern), re.IGNORECASE))

    lowercase_exts = {ext.lower() for ext in extensions}
    max_bytes = max_size_kb * 1024

    seen_paths = set()
    for start_path in paths:
        start = target.fs.path(start_path)
        try:
            exists = start.exists()
        except Exception:
            exists = False
        if not exists:
            continue
        for path in start.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                size = path.stat().st_size
            except Exception:
                continue
            if size > max_bytes:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            # Allow scanning tiny files with PHP open tag even if extension is non-PHP
            php_open = re.search(r"<\?(php|=)", text, re.IGNORECASE) is not None
            # Text-like heuristic: any non-whitespace content
            is_text_like = bool(text.strip())
            if lowercase_exts:
                suffix = path.suffix.lower()
                if suffix not in lowercase_exts and not (is_text_like or php_open):
                    continue
            matched = False
            for rx in compiled_regexes:
                if rx.search(text):
                    if str(path) in seen_paths:
                        matched = True
                        break
                    seen_paths.add(str(path))
                    yield FindingRecord(
                        type="tiny-backdoor",
                        path=path,
                        confidence=confidence,
                        alert=f"Tiny file ({size} bytes) matched pattern: {rx.pattern[:80]}",
                    )
                    matched = True
                    break
            # If no specific pattern matched, but file contains a PHP open tag and is not a PHP extension,
            # emit a low-specificity finding to surface parked PHP in non-PHP files.
            if not matched and php_open:
                suffix = path.suffix.lower() or ''
                if str(path) not in seen_paths:
                    seen_paths.add(str(path))
                    context = "non-PHP extension" if (lowercase_exts and suffix not in lowercase_exts) else "PHP extension"
                    yield FindingRecord(
                        type="tiny-backdoor-php-open",
                        path=path,
                        confidence=confidence,
                        alert=f"Tiny file ({size} bytes) contains PHP open tag ({context}: {suffix or 'no extension'})",
                    )
