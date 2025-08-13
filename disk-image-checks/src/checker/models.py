from datetime import date
from enum import Enum
import sys
from typing import List, Union, Literal, Annotated
from pydantic import BaseModel, Field, field_validator
import re


class ConfidenceEnum(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"

    def __str__(self):
        return self.value


class TimestompArgs(BaseModel):
    paths: list[str] = ["/"]
    known_paths: list[str] = []


def suspicious_content_validate_regex(possible_regex_strings: list[str]) -> str:
    for possible_regex_string in possible_regex_strings:
        if possible_regex_string.startswith("regex:"):
            regex_string = possible_regex_string[len("regex:") :]
            try:
                re.compile(regex_string)  # Attempt to compile the regex
            except re.error:
                raise ValueError(f"Invalid regex: {regex_string}")
    return possible_regex_strings


class WebshellArgs(BaseModel):
    suspicious_contents: list[str] = []
    paths: list[str] = ["/"]
    known_paths: list[str] = []
    permission_confidence: ConfidenceEnum = ConfidenceEnum.medium

    @field_validator("suspicious_contents")
    def validate_regex(cls, string):
        return suspicious_content_validate_regex(string)


class SuspiciousContentCheckArgs(BaseModel):
    name: str
    suspicious_contents: list[str]
    paths: list[str] = "/"
    known_paths: list[str] = []

    @field_validator("suspicious_contents")
    def validate_regex(cls, string):
        return suspicious_content_validate_regex(string)


class SuspiciousContentArgs(BaseModel):
    checks: list[SuspiciousContentCheckArgs]


class YaraArgs(BaseModel):
    rule_files: list[str] = []
    paths: list[str] = ["/"]
    max_file_size_kb: int = sys.maxsize


class CrontabArgs(BaseModel):
    suspicious_contents: dict[str, str]


class BinariesArgs(BaseModel):
    known_suid_binaries: list[str] = []
    known_guid_binaries: list[str] = []


class EntropyArgs(BaseModel):
    paths: list[str] = ["/"]
    threshold_entropy: int = -1
    known_high_entropy: list[str] = []


class KnownBadFilesArgs(BaseModel):
    files: list[str] = ["/"]


class MimeTypeArgs(BaseModel):
    paths: list[str] = []
    suspicious_mime_types: list[str] = []


class CoreDumpArgs(BaseModel):
    extract: bool = True
    creation_date_threshold: date


class MagicBytesArgs(BaseModel):
    paths: list[str] = []
    suspicious_bytes: dict[str, str] = {}


class BaseCheck(BaseModel):
    confidence: ConfidenceEnum


class TimestompCheck(BaseCheck):
    check: Literal["timestomp"] = "timestomp"
    args: TimestompArgs


class WebshellCheck(BaseCheck):
    check: Literal["webshell"] = "webshell"
    args: WebshellArgs


class SuspiciousContentCheck(BaseCheck):
    check: Literal["suspicious_content"] = "suspicious_content"
    args: SuspiciousContentArgs


class YaraCheck(BaseCheck):
    check: Literal["yara"] = "yara"
    args: YaraArgs


class CrontabCheck(BaseCheck):
    check: Literal["crontab"] = "crontab"
    args: CrontabArgs


class BinariesCheck(BaseCheck):
    check: Literal["binaries"] = "binaries"
    args: BinariesArgs


class EntropyCheck(BaseCheck):
    check: Literal["entropy"] = "entropy"
    args: EntropyArgs


class MimeTypeCheck(BaseCheck):
    check: Literal["mime_type"] = "mime_type"
    args: MimeTypeArgs


class KnownBadFilesCheck(BaseCheck):
    check: Literal["known_bad_files"] = "known_bad_files"
    args: KnownBadFilesArgs


class CoreDumpCheck(BaseCheck):
    check: Literal["core_dump"] = "core_dump"
    args: CoreDumpArgs


class MagicBytesCheck(BaseCheck):
    check: Literal["magic_bytes"] = "magic_bytes"
    args: MagicBytesArgs


ALL_CHECKS = [
    "timestomp",
    "webshell",
    "suspicious_content",
    "crontab",
    "binaries",
    "yara",
    "entropy",
    "known_bad_files",
    "mime_type",
    "core_dump",
    "magic_bytes",
]

ValidCheckType = Annotated[
    Union[
        TimestompCheck,
        WebshellCheck,
        SuspiciousContentCheck,
        CrontabCheck,
        BinariesCheck,
        YaraCheck,
        EntropyCheck,
        MimeTypeCheck,
        KnownBadFilesCheck,
        CoreDumpCheck,
        MagicBytesCheck,
    ],
    Field(discriminator="check"),
]


class ChecksConfig(BaseModel):
    name: str
    checks: List[ValidCheckType]
